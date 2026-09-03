package handler

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
	ber "github.com/go-asn1-ber/asn1-ber"
	resty "github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// keycloakHandler exposes a Keycloak realm as an LDAP backend.
// Ported from github.com/christian-2/glauth-keycloak, primarily so that
// Keycloak can act as an identity provider for vSphere (even without
// LDAP user federation). It is read-only: Bind/Search/Close are backed
// by Keycloak's REST API, while Add/Modify/Delete are rejected.
type keycloakHandler struct {
	cfg             *keycloakHandlerConfig
	log             *zerolog.Logger
	baseDN          string
	baseDNUsers     string
	baseDNGroups    string
	baseDNBindUsers string
	restClient      *resty.Client
	sessions        *keycloakSessions
}

// keycloakSessions tracks one Keycloak session per LDAP connection; the
// handler is shared by every connection of its backend. Keyed by
// connID, as in the other handlers.
type keycloakSessions struct {
	mu       sync.Mutex
	byConnID map[string]*keycloakSession
}

type keycloakHandlerConfig struct {
	keycloakHostname string
	keycloakPort     int
	keycloakRealm    string
	keycloakDomain   string
}

type keycloakSession struct {
	clientID     string
	clientSecret string
	boundDN      *string
	token        *oauth2.Token
}

type keycloakGroup struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type keycloakUser struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	Id        string `json:"id"`
	LastName  string `json:"lastName"`
	Username  string `json:"username"`
}

// Handler (Binder)

func (h keycloakHandler) Bind(
	bindDN string,
	bindSimplePw string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("bindDN", bindDN).
		Msg("Bind request")
	if h.cfg == nil {
		return ldap.LDAPResultOperationsError,
			errors.New("misconfiguration")
	}

	pre := "cn="
	suf := "," + h.baseDNBindUsers
	// DN matching is case-insensitive (RFC 4514); the bind DN is
	// cn=<clientID>,cn=bind,<domain>.
	if len(bindDN) < len(pre)+len(suf) ||
		!strings.EqualFold(bindDN[:len(pre)], pre) ||
		!strings.EqualFold(bindDN[len(bindDN)-len(suf):], suf) {
		h.log.Error().
			Str("base", h.baseDNBindUsers).
			Msg("invalid bindDN")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	clientID := bindDN[len(pre) : len(bindDN)-len(suf)]
	clientSecret := bindSimplePw
	s, err := h.sessions.open(connID(conn), h.cfg.tokenEndpoint(),
		clientID, clientSecret, bindDN, h.log)
	if err != nil {
		h.log.Error().Err(err).Msg("Bind response")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.log.Debug().
		Time("expiry", s.token.Expiry).
		Msg("Bind response")
	return ldap.LDAPResultSuccess, nil
}

var rootDSEAttributes = []string{
	"objectClass",
	"configurationNamingContext",
	"currentTime",
	"defaultNamingContext",
	"dnsHostName",
	"domainControllerFunctionality",
	"domainFunctionality",
	"dsServiceName",
	"forestFunctionality",
	"highestCommittedUSN",
	"isGlobalCatalogReady",
	"isSynchronized",
	"ldapServiceName",
	"namingContexts",
	"rootDomainNamingContext",
	"schemaNamingContext",
	"serverName",
	"subschemaSubentry",
	"supportedCapabilities",
	"supportedControl",
	"supportedLDAPPolicies",
	"supportedLDAPVersion",
	"supportedSASLMechanisms"}

// userQueryParams maps LDAP attributes to Keycloak user query parameters.
var userQueryParams = map[string]string{
	"samaccountname":    "username",
	"cn":                "username",
	"userprincipalname": "username",
	"uid":               "username",
	"mail":              "email",
	"givenname":         "firstName",
	"sn":                "lastName",
}

// Handler (Searcher)

func (h keycloakHandler) Search(
	boundDN string,
	req ldap.SearchRequest,
	conn net.Conn,
) (ldap.ServerSearchResult, error) {
	scope := ldap.ScopeMap[req.Scope]
	deferAliases := ldap.DerefMap[req.DerefAliases]
	c := make([]string, len(req.Controls))
	for i, cc := range req.Controls {
		if s, ok := ldap.ControlTypeMap[cc.GetControlType()]; ok {
			c[i] = s
		} else {
			c[i] = cc.GetControlType()
		}
	}
	controls := strings.Join(c, " ")
	attributes := strings.Join(req.Attributes, " ")
	h.log.Debug().
		Str("boundDN", boundDN).
		Str("baseDN", req.BaseDN).
		Str("scope", scope).
		Str("derefAliases", deferAliases).
		Int("sizeLimit", req.SizeLimit).
		Int("timeLimit", req.TimeLimit).
		Bool("typesOnly", req.TypesOnly).
		Str("filter", req.Filter).
		Str("attributes", attributes).
		Str("controls", controls).
		Msg("Search request")

	session, err := h.checkSession(connID(conn), true)
	if err != nil {
		h.log.Error().Err(err).Msg("Search response")
		return searchError(ldap.LDAPResultOperationsError, "%s", err)
	}

	// TimeLimit is advisory (the client states how long it is willing to
	// wait; the server is free to ignore it, RFC 4511 4.5.1) and there
	// are no aliases to dereference, so both are accepted and ignored.
	// The LDAP server itself (EnforceLDAP) applies filter, scope,
	// attribute and size-limit enforcement to the returned entries; this
	// handler only narrows the Keycloak REST query when the filter is a
	// simple equality.
	if req.TypesOnly {
		err := unexpected("TypesOnly: true")
		h.log.Error().Err(err).Msg("Search response")
		return searchError(ldap.LDAPResultUnwillingToPerform, "%s", err)
	}

	baseDN := normalizeDN(req.BaseDN)

	// Root DSE: base-object search with an empty base DN (RFC 4512 5.1).
	if baseDN == "" && req.Scope == ldap.ScopeBaseObject {
		res := h.rootDSESearchResult()
		h.log.Debug().
			Str("BaseDN", req.BaseDN).
			Int("entries", len(res.Entries)).
			Msg("Search response")
		return res, nil
	}

	var entries []*ldap.Entry
	addUsers := func() error {
		e, err := h.usersSearchResult(session, userQuery(req.Filter))
		if err != nil {
			h.log.Error().Err(err).Msg("Search response")
			return err
		}
		entries = append(entries, e...)
		return nil
	}
	addGroups := func() error {
		e, err := h.groupsSearchResult(session, groupQuery(req.Filter))
		if err != nil {
			h.log.Error().Err(err).Msg("Search response")
			return err
		}
		entries = append(entries, e...)
		return nil
	}

	// The DIT is flat: a domain root holding the cn=users and cn=groups
	// containers, each holding leaf entries one level deep, so
	// single-level and subtree searches cover the same leaves. Subtree
	// scope includes the base object itself (RFC 4511 4.5.1).
	switch baseDN {
	case "":
		entries = append(entries, h.domainEntry())
		if req.Scope == ldap.ScopeWholeSubtree {
			entries = append(entries,
				h.rootDSESearchResult().Entries...,
			)
			entries = append(entries,
				containerEntry(h.baseDNUsers, "users"),
				containerEntry(h.baseDNGroups, "groups"))
			if err := addUsers(); err != nil {
				return searchError(ldap.LDAPResultOperationsError, "%s", err)
			}
			if err := addGroups(); err != nil {
				return searchError(ldap.LDAPResultOperationsError, "%s", err)
			}
		}
	case h.baseDN:
		switch req.Scope {
		case ldap.ScopeBaseObject:
			entries = append(entries, h.domainEntry())
		case ldap.ScopeSingleLevel:
			entries = append(entries,
				containerEntry(h.baseDNUsers, "users"),
				containerEntry(h.baseDNGroups, "groups"))
		default:
			entries = append(entries, h.domainEntry(),
				containerEntry(h.baseDNUsers, "users"),
				containerEntry(h.baseDNGroups, "groups"))
			if err := addUsers(); err != nil {
				return searchError(ldap.LDAPResultOperationsError, "%s", err)
			}
			if err := addGroups(); err != nil {
				return searchError(ldap.LDAPResultOperationsError, "%s", err)
			}
		}
	case h.baseDNUsers, h.baseDNGroups:
		users := baseDN == h.baseDNUsers
		name := "groups"
		if users {
			name = "users"
		}
		if req.Scope != ldap.ScopeSingleLevel {
			entries = append(entries, containerEntry(baseDN, name))
		}
		if req.Scope != ldap.ScopeBaseObject {
			var err error
			if users {
				err = addUsers()
			} else {
				err = addGroups()
			}
			if err != nil {
				return searchError(ldap.LDAPResultOperationsError, "%s", err)
			}
		}
	default:
		// Base-object or single-level search on a single entry:
		// cn=<name>,<container>. Narrow by the RDN value; EnforceLDAP
		// keeps only the entry whose DN equals the base (base scope) and
		// drops it for single-level scope (a leaf has no subordinates).
		head, rest := splitDN(req.BaseDN)
		attr, value, ok := parseRDN(head)
		if ok && strings.EqualFold(attr, "cn") {
			switch normalizeDN(rest) {
			case h.baseDNUsers:
				e, err := h.usersSearchResult(session,
					map[string]string{"username": value, "exact": "true"})
				if err != nil {
					h.log.Error().Err(err).Msg("Search response")
					return searchError(ldap.LDAPResultOperationsError, "%s", err)
				}
				if len(e) == 0 {
					err := fmt.Errorf("no such object: %s", req.BaseDN)
					h.log.Error().Err(err).Msg("Search response")
					return searchError(ldap.LDAPResultNoSuchObject, "%s", err)
				}
				entries = e
			case h.baseDNGroups:
				e, err := h.groupsSearchResult(session,
					map[string]string{"search": value})
				if err != nil {
					h.log.Error().Err(err).Msg("Search response")
					return searchError(ldap.LDAPResultOperationsError, "%s", err)
				}
				if len(e) == 0 {
					err := fmt.Errorf("no such object: %s", req.BaseDN)
					h.log.Error().Err(err).Msg("Search response")
					return searchError(ldap.LDAPResultNoSuchObject, "%s", err)
				}
				entries = e
			default:
				ok = false
			}
		}
		if !ok {
			err := fmt.Errorf("no such object: %s", req.BaseDN)
			h.log.Error().Err(err).Msg("Search response")
			return searchError(ldap.LDAPResultNoSuchObject, "%s", err)
		}
	}

	res := ldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
	h.log.Debug().
		Str("BaseDN", req.BaseDN).
		Str("scope", scope).
		Int("entries", len(res.Entries)).
		Msg("Search response")
	return res, nil
}

// Handler (Closer)

func (h keycloakHandler) Close(
	boundDN string,
	conn net.Conn,
) error {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("Close request")
	if _, err := h.checkSession(connID(conn), false); err != nil {
		h.log.Error().Err(err).Msg("Close response")
		return err
	}

	h.sessions.remove(connID(conn))
	h.log.Debug().Msg("Close response")
	return nil
}

// Handler (Adder)

func (h keycloakHandler) Add(
	boundDN string,
	req ldap.AddRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("Add")
	return ldap.LDAPResultOperationsError, unexpected("Add")
}

// Handler (Modifier)

func (h keycloakHandler) Modify(
	boundDN string,
	req ldap.ModifyRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("Modify")
	return ldap.LDAPResultOperationsError, unexpected("Modify")
}

// Handler (Deleter)

func (h keycloakHandler) Delete(
	boundDN string,
	deleteDN string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Str("deleteDN", deleteDN).
		Msg("Delete")
	return ldap.LDAPResultOperationsError, unexpected("Delete")
}

// Handler (HelperMaker)

func (h keycloakHandler) FindUser(
	ctx context.Context,
	userName string,
	searchByUPN bool,
) (bool, config.User, error) {
	h.log.Debug().
		Str("userName", userName).
		Bool("searchByUPN", searchByUPN).
		Msg("FindUser")
	user := config.User{}
	return false, user, unexpected("FindUser")
}

func (h keycloakHandler) FindGroup(
	ctx context.Context,
	groupName string,
) (bool, config.Group, error) {
	h.log.Debug().
		Str("groupName", groupName).
		Msg("FindGroup")
	group := config.Group{}
	return false, group, unexpected("FindGroup")
}

func (h *keycloakHandler) checkSession(
	id string,
	refresh bool,
) (*keycloakSession, error) {
	if h.sessions == nil {
		return nil, errors.New("no session")
	}
	s := h.sessions.get(id)
	if s == nil {
		return nil, fmt.Errorf("no session for connection: %s", id)
	}
	if !refresh {
		return s, nil
	}
	if err := s.refresh(h.cfg.tokenEndpoint(), h.log); err != nil {
		return nil, err
	}
	return s, nil
}

func (ss *keycloakSessions) open(
	id string,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	bindDN string,
	log *zerolog.Logger,
) (*keycloakSession, error) {
	token, err := clientCredentialsGrant(tokenEndpoint,
		clientID, clientSecret, log)
	if err != nil {
		return nil, err
	}
	s := &keycloakSession{
		clientID:     clientID,
		clientSecret: clientSecret,
		boundDN:      &bindDN,
		token:        token,
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.byConnID[id] = s
	return s, nil
}

func (ss *keycloakSessions) get(id string) *keycloakSession {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.byConnID[id]
}

func (ss *keycloakSessions) remove(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.byConnID, id)
}

// keycloakPageSize is the page size used when listing users and groups;
// Keycloak's users endpoint otherwise silently truncates at its default
// maximum of 100 results.
const keycloakPageSize = 500

// groupsSearchResult lists all realm groups, narrowed by params (a
// substring "search" for simple equality filters), and returns them as
// LDAP entries. The LDAP server refines the result with the actual
// filter, so narrowing only ever needs to be a superset.
func (h *keycloakHandler) groupsSearchResult(
	s *keycloakSession,
	params map[string]string,
) ([]*ldap.Entry, error) {
	e := []*ldap.Entry{}
	prevFirstID := ""
	for first := 0; ; first += keycloakPageSize {
		page := &[]keycloakGroup{}
		p := make(map[string]string, len(params)+2)
		for k, v := range params {
			p[k] = v
		}
		p["first"] = strconv.Itoa(first)
		p["max"] = strconv.Itoa(keycloakPageSize)
		if err := h.keycloakGet(s, "groups", p, page); err != nil {
			return nil, err
		}
		if len(*page) == 0 ||
			(first > 0 && (*page)[0].Id == prevFirstID) {
			// Empty page, or the server ignored pagination.
			break
		}
		prevFirstID = (*page)[0].Id
		for _, group := range *page {
			e = append(e, h.groupEntry(group))
		}
		if len(*page) < keycloakPageSize {
			break
		}
	}
	return e, nil
}

// groupEntry renders a Keycloak group as an LDAP group entry.
func (h *keycloakHandler) groupEntry(group keycloakGroup) *ldap.Entry {
	o := sid(group.Id, h.cfg.keycloakDomain)
	h.log.Debug().
		Str("name", group.Name).
		Str("objectSid", sidToString(o)).
		Msg("group")
	return &ldap.Entry{
		DN: fmt.Sprintf("cn=%s,%s",
			escapeDNValue(group.Name), h.baseDNGroups),
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "group"}},
			newAttribute("sAMAccountName", group.Name),
			newAttribute("cn", group.Name),
			newAttribute("description", group.Name),
			newAttribute("objectSid", string(o)),
		},
	}
}

func (h *keycloakHandler) keycloakGet(
	s *keycloakSession,
	path string,
	params map[string]string,
	result interface{},
) error {
	u := h.cfg.restAPIEndpoint(path)
	h.log.Debug().
		Str("method", "GET").
		Str("url", u).
		Interface("params", params).
		Msg("Keycloak REST API request")

	res, err := h.restClient.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(s.token.AccessToken).
		SetQueryParams(params).
		SetResult(result).
		Get(u)
	if err == nil && res.StatusCode() != http.StatusOK {
		err = errors.New(res.Status())
	}
	if err != nil {
		h.log.Error().Err(err).Msg("Keycloak REST API response")
		return err
	}
	h.log.Debug().Msg("Keycloak REST API response")
	return nil
}

// rootDSESearchResult returns the root DSE (RFC 4512 5.1). Clients read
// namingContexts from it to discover base DNs, so the discovery-critical
// attributes carry real values.
func (h *keycloakHandler) rootDSESearchResult() ldap.ServerSearchResult {
	values := map[string][]string{
		"objectClass":          {"top"},
		"currentTime":          {time.Now().UTC().Format("20060102150405Z")},
		"defaultNamingContext": {h.baseDN},
		"dnsHostName":          {h.cfg.keycloakHostname},
		"ldapServiceName":      {h.cfg.keycloakHostname},
		"namingContexts":       {h.baseDN},
		"supportedLDAPVersion": {"3"},
	}
	a := make([]*ldap.EntryAttribute, len(rootDSEAttributes))
	for i, name := range rootDSEAttributes {
		v, ok := values[name]
		if !ok {
			v = []string{""}
		}
		a[i] = &ldap.EntryAttribute{Name: name, Values: v}
	}
	e := &ldap.Entry{DN: "", Attributes: a}

	return ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{e},
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
}

// usersSearchResult lists realm users, narrowed by params for simple
// equality filters, and returns them as LDAP entries. The LDAP server
// refines the result with the actual filter, so narrowing only ever
// needs to be a superset. Results are paged: Keycloak's users endpoint
// silently truncates at its default maximum of 100 results otherwise.
func (h *keycloakHandler) usersSearchResult(
	s *keycloakSession,
	params map[string]string,
) ([]*ldap.Entry, error) {
	e := []*ldap.Entry{}
	prevFirstID := ""
	for first := 0; ; first += keycloakPageSize {
		page := &[]keycloakUser{}
		p := make(map[string]string, len(params)+2)
		for k, v := range params {
			p[k] = v
		}
		p["first"] = strconv.Itoa(first)
		p["max"] = strconv.Itoa(keycloakPageSize)
		if err := h.keycloakGet(s, "users", p, page); err != nil {
			return nil, err
		}
		if len(*page) == 0 ||
			(first > 0 && (*page)[0].Id == prevFirstID) {
			// Empty page, or the server ignored pagination.
			break
		}
		prevFirstID = (*page)[0].Id
		for _, user := range *page {
			e = append(e, h.userEntry(user))
		}
		if len(*page) < keycloakPageSize {
			break
		}
	}
	return e, nil
}

// userEntry renders a Keycloak user as an LDAP user entry. The
// attributes cover every attribute the query narrowing maps, so that
// server-side filter enforcement (EnforceLDAP) can match them.
func (h *keycloakHandler) userEntry(user keycloakUser) *ldap.Entry {
	displayName := strings.TrimSpace(user.FirstName + " " + user.LastName)
	if displayName == "" {
		displayName = user.Username
	}
	h.log.Debug().
		Str("username", user.Username).
		Msg("user")
	return &ldap.Entry{
		DN: fmt.Sprintf("cn=%s,%s",
			escapeDNValue(user.Username), h.baseDNUsers),
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{
				"top", "person", "organizationalPerson",
				"inetOrgPerson", "user"}},
			newAttribute("sAMAccountName", user.Username),
			newAttribute("cn", user.Username),
			newAttribute("uid", user.Username),
			newAttribute("givenName", user.FirstName),
			newAttribute("sn", user.LastName),
			newAttribute("displayName", displayName),
			newAttribute("userPrincipalName",
				user.Username+"@"+h.cfg.keycloakDomain),
			newAttribute("mail", user.Email),
			newAttribute("description", ""),
		},
	}
}

// domainEntry renders the naming context root.
func (h *keycloakHandler) domainEntry() *ldap.Entry {
	dc := strings.SplitN(h.cfg.keycloakDomain, ".", 2)[0]
	return &ldap.Entry{
		DN: h.baseDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "domain"}},
			newAttribute("dc", dc),
		},
	}
}

// containerEntry renders the cn=users / cn=groups containers.
func containerEntry(dn, name string) *ldap.Entry {
	return &ldap.Entry{
		DN: dn,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "container"}},
			newAttribute("cn", name),
		},
	}
}

func (c *keycloakHandlerConfig) restAPIEndpoint(path string) string {
	return fmt.Sprintf("https://%s:%d/admin/realms/%s/%s",
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm,
		path)
}

func (c *keycloakHandlerConfig) tokenEndpoint() string {
	f := "https://%s:%d/realms/%s/protocol/openid-connect/token"
	return fmt.Sprintf(f,
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm)
}

func (s *keycloakSession) refresh(
	tokenEndpoint string,
	log *zerolog.Logger,
) error {
	if s.token.Valid() {
		return nil
	}
	token, err := clientCredentialsGrant(tokenEndpoint,
		s.clientID, s.clientSecret, log)
	if err != nil {
		return err
	}
	s.token = token
	return nil
}

// NewKeycloakHandler creates a backend handler that proxies LDAP bind and
// search operations to a Keycloak realm. The backend is configured through
// the keycloak* directives of its [backend] / [[backends]] config section.
func NewKeycloakHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	h := keycloakHandler{
		log: options.Logger,
	}
	c, err := newKeycloakHandlerConfig(options.Backend)
	if err != nil {
		h.log.Error().Err(err).Msg("Keycloak backend misconfigured")
		return h
	}

	b := "dc=" + strings.Replace(c.keycloakDomain, ".", ",dc=", -1)
	h.cfg = c
	// Base DNs are stored normalized so that request base DNs can be
	// compared case-insensitively (RFC 4514).
	h.baseDN = normalizeDN(b)
	h.baseDNUsers = "cn=users," + h.baseDN
	h.baseDNGroups = "cn=groups," + h.baseDN
	h.baseDNBindUsers = "cn=bind," + h.baseDN
	h.restClient = resty.New()
	h.sessions = &keycloakSessions{
		byConnID: map[string]*keycloakSession{},
	}
	return h
}

// objectClassesUser/list the objectClass values the handler emits on user
// and group entries. An LDAP filter may anchor on any one of them
// (typically inetOrgPerson or group), so query narrowing accepts any
// and strips the objectClass equality before extracting parameters.
var (
	objectClassesUser  = []string{"top", "person", "organizationalPerson", "inetOrgPerson", "user"}
	objectClassesGroup = []string{"top", "group"}
)

// unwrapObjectClass strips any objectClass equalities from a parsed
// filter whose value is in objectClasses, returning the remaining
// children: the single remaining child when there is one, an AND
// rebuilt over several, or nil when only objectClass equalities were
// present. A non-AND filter with no objectClass equality is returned
// unchanged.
func unwrapObjectClass(f *ber.Packet, objectClasses []string) *ber.Packet {
	if f.Tag != ldap.FilterAnd {
		if v, ok := equalityValue(f, "objectclass"); ok && containsFold(objectClasses, v) {
			return nil
		}
		return f
	}
	var rest []*ber.Packet
	for _, c := range f.Children {
		if v, ok := equalityValue(c, "objectclass"); ok && containsFold(objectClasses, v) {
			continue
		}
		rest = append(rest, c)
	}
	switch len(rest) {
	case 0:
		return nil
	case 1:
		return rest[0]
	default:
		and := ber.Encode(ber.ClassContext, ber.TypeConstructed,
			ldap.FilterAnd, nil, ldap.FilterMap[ldap.FilterAnd])
		for _, c := range rest {
			and.AppendChild(c)
		}
		return and
	}
}

// containsFold reports whether list holds s, case-insensitively.
func containsFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

// equalityValue returns the value of an equality-match filter child on
// attribute (case-insensitive).
func equalityValue(f *ber.Packet, attribute string) (string, bool) {
	if f.Tag != ldap.FilterEqualityMatch || len(f.Children) != 2 {
		return "", false
	}
	attr, ok1 := f.Children[0].Value.(string)
	value, ok2 := f.Children[1].Value.(string)
	if !ok1 || !ok2 || !strings.EqualFold(attr, attribute) {
		return "", false
	}
	return value, true
}

// userQuery narrows a users search to Keycloak REST query parameters when
// the filter reduces (after stripping any objectClass equality) to one or
// more equality matches on mapped attributes. For any other filter it
// returns no narrowing; the LDAP server (EnforceLDAP) applies the filter
// to the full user list itself.
func userQuery(filter string) map[string]string {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil
	}
	f = unwrapObjectClass(f, objectClassesUser)
	if f == nil {
		return nil
	}
	children := equalityChildren(f)
	if children == nil {
		return nil
	}
	params := map[string]string{}
	for _, c := range children {
		for attr, param := range userQueryParams {
			if value, ok := equalityValue(c, attr); ok {
				params[param] = value
			}
		}
	}
	if len(params) == 0 {
		return nil
	}
	params["exact"] = "true"
	return params
}

// groupQuery narrows a groups search likewise, to Keycloak's (substring)
// search parameter for a simple equality on sAMAccountName/cn; the LDAP
// server refines the result to exact matches itself.
func groupQuery(filter string) map[string]string {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil
	}
	f = unwrapObjectClass(f, objectClassesGroup)
	if f == nil {
		return nil
	}
	children := equalityChildren(f)
	if children == nil {
		return nil
	}
	for _, c := range children {
		for _, attr := range []string{"samaccountname", "cn"} {
			if value, ok := equalityValue(c, attr); ok {
				return map[string]string{"search": value}
			}
		}
	}
	return nil
}

// equalityChildren returns the equality-match children of f: f itself
// when it is an equality match, the AND's children when f is a non-empty
// AND, or nil when f is an unsupported filter shape (OR/NOT/substring/
// present/...) or an AND holding any non-equality child.
func equalityChildren(f *ber.Packet) []*ber.Packet {
	if f.Tag == ldap.FilterEqualityMatch {
		return []*ber.Packet{f}
	}
	if f.Tag != ldap.FilterAnd {
		return nil
	}
	for _, c := range f.Children {
		if c.Tag != ldap.FilterEqualityMatch {
			return nil
		}
	}
	return f.Children
}

// normalizeDN folds case and insignificant whitespace so that DNs can be
// compared as plain strings (attribute types and the attribute values
// used here are case-insensitive per RFC 4512).
func normalizeDN(dn string) string {
	rdns := strings.Split(dn, ",")
	for i, rdn := range rdns {
		rdn = strings.TrimSpace(rdn)
		if j := strings.Index(rdn, "="); j >= 0 {
			rdn = strings.TrimSpace(rdn[:j]) + "=" +
				strings.TrimSpace(rdn[j+1:])
		}
		rdns[i] = rdn
	}
	return strings.ToLower(strings.Join(rdns, ","))
}

// splitDN splits dn at its first unescaped comma.
func splitDN(dn string) (head, rest string) {
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			return dn[:i], dn[i+1:]
		}
	}
	return dn, ""
}

// parseRDN parses a single-attribute RDN ("cn=alice"), unescaping the
// value per RFC 4514.
func parseRDN(rdn string) (attr, value string, ok bool) {
	eq := -1
	for i := 0; i < len(rdn); i++ {
		switch rdn[i] {
		case '\\':
			i++
		case '=':
			eq = i
		}
		if eq >= 0 {
			break
		}
	}
	if eq < 0 {
		return "", "", false
	}
	attr = strings.TrimSpace(rdn[:eq])
	raw := strings.TrimSpace(rdn[eq+1:])
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			if i+2 < len(raw) && isHex(raw[i+1]) && isHex(raw[i+2]) {
				b, _ := strconv.ParseUint(raw[i+1:i+3], 16, 8)
				sb.WriteByte(byte(b))
				i += 2
			} else {
				sb.WriteByte(raw[i+1])
				i++
			}
		} else {
			sb.WriteByte(raw[i])
		}
	}
	return attr, sb.String(), true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// escapeDNValue escapes a value for use in a DN per RFC 4514.
func escapeDNValue(v string) string {
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == 0:
			sb.WriteString("\\00")
			continue
		case c == ',' || c == '+' || c == '"' || c == '\\' ||
			c == '<' || c == '>' || c == ';' || c == '=' ||
			(i == 0 && (c == ' ' || c == '#')) ||
			(i == len(v)-1 && c == ' '):
			sb.WriteByte('\\')
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func clientCredentialsGrant(
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	log *zerolog.Logger,
) (*oauth2.Token, error) {
	oauth2Config := &clientcredentials.Config{
		TokenURL:       tokenEndpoint,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Scopes:         nil,
		EndpointParams: url.Values{}}

	ctx := context.Background()
	log.Debug().
		Str("endpoint", tokenEndpoint).
		Str("grant_type", "client_credentials").
		Str("client_id", clientID).
		Msg("OAuth 2.0 authorization request")

	if token, err := oauth2Config.TokenSource(ctx).Token(); err != nil {
		log.Error().Err(err).Msg("OAuth 2.0 error response")
		return nil, err
	} else if !token.Valid() {
		err := errors.New("invalid token")
		log.Error().Err(err).Msg("OAuth 2.0 error response")
		return nil, err
	} else {
		log.Debug().Msg("OAuth 2.0 access token response")
		return token, nil
	}
}

// searchError builds a failed search result with the given result code;
// the LDAP server reports that code to the client.
func searchError(
	code ldap.LDAPResultCode,
	format string,
	args ...interface{},
) (ldap.ServerSearchResult, error) {
	return ldap.ServerSearchResult{
		Entries:    make([]*ldap.Entry, 0),
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: code}, fmt.Errorf(format, args...)
}

func newAttribute(name, value string) *ldap.EntryAttribute {
	return &ldap.EntryAttribute{Name: name, Values: []string{value}}
}

func newKeycloakHandlerConfig(
	backend config.Backend,
) (*keycloakHandlerConfig, error) {
	c := &keycloakHandlerConfig{
		keycloakHostname: backend.KeycloakHostname,
		keycloakPort:     backend.KeycloakPort,
		keycloakRealm:    backend.KeycloakRealm,
		keycloakDomain:   strings.TrimSuffix(backend.KeycloakDomain, "."),
	}

	if c.keycloakHostname == "" {
		return nil, errors.New("keycloakhostname not set in backend configuration")
	}
	if c.keycloakPort == 0 {
		c.keycloakPort = 8443
	}
	if c.keycloakRealm == "" {
		return nil, errors.New("keycloakrealm not set in backend configuration")
	}
	if c.keycloakDomain == "" {
		return nil, errors.New("keycloakdomain not set in backend configuration")
	}

	return c, nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sid(id, domain string) []byte {
	d := sha1.Sum([]byte(domain))
	i := sha1.Sum([]byte(id))

	b := make([]byte, 1+1+6+5*4)
	b[0] = 1
	b[1] = 5
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], 5)
	binary.LittleEndian.PutUint32(b[8:], 21)
	for j := 0; j < 3*4; j++ {
		b[12+j] = d[j]
	}
	for j := 0; j < 1*4; j++ {
		b[24+j] = i[j]
	}
	return b
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sidToString(b []byte) string {
	r := b[0]
	n := int(b[1])
	ia := uint64(binary.BigEndian.Uint16(b[2:4]))<<32 +
		uint64(binary.BigEndian.Uint32(b[4:8]))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", r, ia))
	for i := range n {
		sa := binary.LittleEndian.Uint32(b[8+4*i : 8+4*i+4])
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}
	return sb.String()
}

func unexpected(msg string) error {
	return fmt.Errorf("unexpected call: %s", msg)
}
