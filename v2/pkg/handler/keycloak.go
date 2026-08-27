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
	"regexp"
	"strings"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
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
	baseDNUsers     string
	baseDNGroups    string
	baseDNBindUsers string
	restClient      *resty.Client
	session         *keycloakSession
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
	if !strings.HasPrefix(bindDN, pre) || !strings.HasSuffix(bindDN, suf) {
		h.log.Error().
			Str("base", h.baseDNBindUsers).
			Msg("invalid bindDN")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	clientID := strings.TrimPrefix(strings.TrimSuffix(bindDN, suf), pre)
	clientSecret := bindSimplePw
	if err := h.session.open(h.cfg.tokenEndpoint(), clientID,
		clientSecret, bindDN, h.log); err != nil {
		h.log.Error().Err(err).Msg("Bind response")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.log.Debug().
		Time("expiry", h.session.token.Expiry).
		Msg("Bind response")
	return ldap.LDAPResultSuccess, nil
}

var rootDSEAttributes = []string{
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

var filterGroupsWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=group\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(cn=(.*)\\*\\)\\)\\)$")
var filterRootDSE = regexp.MustCompile("^\\(objectclass=\\*\\)$")
var filterUsers = regexp.MustCompile("^\\(objectClass=user\\)$")
var filterUsersWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=user\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(sn=(.+)\\*\\)" +
	"\\(givenName=(.*)\\*\\)" +
	"\\(cn=(.*)\\*\\)" +
	"\\(displayname=(.*)\\*\\)" +
	"\\(userPrincipalName=(.*)\\*\\)\\)\\)$")

var attributes0 = []string{}
var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid"}
var attributes9 = []string{
	"sAMAccountName",
	"userPrincipalName",
	"description",
	"givenName",
	"sn",
	"mail",
	"userAccountControl",
	"lockoutTime",
	"objectSid"}

var controls0 = []string{}
var controls1 = []string{ldap.ControlTypePaging}

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

	if err := h.checkSession(boundDN, true); err != nil {
		h.log.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	} else if req.DerefAliases != ldap.NeverDerefAliases ||
		req.SizeLimit != 0 ||
		req.TimeLimit != 0 ||
		req.TypesOnly {

		err := unexpected(fmt.Sprintf("DeferAliases: \"%s\", "+
			"SizeLimit: %d, "+
			"TimeLimit: %d, "+
			"TypesOnly: %t",
			deferAliases,
			req.SizeLimit,
			req.TimeLimit,
			req.TypesOnly))
		h.log.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	} else if _, ok := checkSearchRequest(
		req,
		"",
		ldap.ScopeBaseObject,
		filterRootDSE,
		attributes0,
		controls0); ok {

		res := h.rootDSESearchResult()
		h.log.Debug().
			Str("BaseDN", req.BaseDN).
			Int("entries", len(res.Entries)).
			Msg("Search response")
		return res, nil
	} else if _, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsers,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(""); err != nil {
			h.log.Error().Err(err).Msg("Search response")
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsersWithPrefix,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(prefix); err != nil {
			h.log.Error().Err(err).Msg("Search response")
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(req,
		h.baseDNGroups,
		ldap.ScopeWholeSubtree,
		filterGroupsWithPrefix,
		attributes3,
		controls1); ok {

		if res, err := h.groupsSearchResult(prefix); err != nil {
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else {
		err := unexpected(fmt.Sprintf("BaseDN: \"%s\", "+
			"Scope: \"%s\", "+
			"Filter: \"%s\", "+
			"Attributes: \"%s\", "+
			"Controls: \"%s\"",
			req.BaseDN,
			scope,
			req.Filter,
			attributes,
			controls))
		h.log.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	}
}

// Handler (Closer)

func (h keycloakHandler) Close(
	boundDN string,
	conn net.Conn,
) error {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("Close request")
	if err := h.checkSession(boundDN, false); err != nil {
		h.log.Error().Err(err).Msg("Close response")
		return err
	}

	h.session.token = nil
	h.session.boundDN = nil
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

func (h *keycloakHandler) checkSession(boundDN string, refresh bool) error {
	if h.session == nil {
		return errors.New("no session")
	} else if h.session.boundDN == nil || *h.session.boundDN != boundDN {
		return fmt.Errorf("unexpected boundDN: %s", boundDN)
	} else if !refresh {
		return nil
	}
	return h.session.refresh(h.cfg.tokenEndpoint(), h.log)
}

func (h *keycloakHandler) groupsSearchResult(
	prefix string,
) (ldap.ServerSearchResult, error) {
	groups := &[]keycloakGroup{}
	err := h.keycloakGet("groups", groups)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*groups))
	for _, group := range *groups {
		if !strings.HasPrefix(group.Name, prefix) {
			continue
		}

		a := make([]*ldap.EntryAttribute, 5)
		o := sid(group.Name, h.cfg.keycloakDomain)
		a[0] = newAttribute("objectClass", "group")
		a[1] = newAttribute("sAMAccountName", group.Name)
		a[2] = newAttribute("cn", group.Name)
		a[3] = newAttribute("description", group.Name)
		a[4] = newAttribute("objectSid", string(o))
		h.log.Debug().
			Str("name", group.Name).
			Str("objectSid", sidToString(o)).
			Msg("group")

		dn := fmt.Sprintf("cn=%s,%s", group.Name, h.baseDNGroups)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h *keycloakHandler) keycloakGet(
	path string,
	result interface{},
) error {
	u := h.cfg.restAPIEndpoint(path)
	h.log.Debug().
		Str("method", "GET").
		Str("url", u).
		Msg("Keycloak REST API request")

	res, err := h.restClient.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(h.session.token.AccessToken).
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

func (h *keycloakHandler) rootDSESearchResult() ldap.ServerSearchResult {
	a := make([]*ldap.EntryAttribute, len(rootDSEAttributes))
	for i, name := range rootDSEAttributes {
		a[i] = &ldap.EntryAttribute{
			Name:   name,
			Values: []string{""}}
	}
	e := &ldap.Entry{DN: "", Attributes: a}

	return ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{e},
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
}

func (h *keycloakHandler) usersSearchResult(
	prefix string,
) (ldap.ServerSearchResult, error) {
	users := &[]keycloakUser{}
	err := h.keycloakGet("users", users)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*users))
	for _, user := range *users {
		if !strings.HasPrefix(user.Username, prefix) &&
			!strings.HasPrefix(user.LastName, prefix) {
			continue
		}

		a := make([]*ldap.EntryAttribute, 7)
		a[0] = newAttribute("objectClass", "user")
		a[1] = newAttribute("sAMAccountName", user.Username)
		a[2] = newAttribute("cn", user.Username)
		a[3] = newAttribute("givenName", user.FirstName)
		a[4] = newAttribute("sn", user.LastName)
		a[5] = newAttribute("mail", user.Email)
		a[6] = newAttribute("description", "")

		h.log.Debug().
			Str("username", user.Username).
			Msg("user")

		dn := fmt.Sprintf("cn=%s,%s", user.Username, h.baseDNUsers)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
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

func (s *keycloakSession) open(
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	bindDN string,
	log *zerolog.Logger,
) error {
	token, err := clientCredentialsGrant(tokenEndpoint,
		clientID, clientSecret, log)
	if err != nil {
		return err
	}
	s.clientID = clientID
	s.clientSecret = clientSecret
	s.boundDN = &bindDN
	s.token = token
	return nil
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
	h.baseDNUsers = "cn=users," + b
	h.baseDNGroups = "cn=groups," + b
	h.baseDNBindUsers = "cn=bind," + b
	h.restClient = resty.New()
	h.session = &keycloakSession{}
	return h
}

func checkSearchRequest(
	req ldap.SearchRequest,
	baseDN string,
	scope int,
	filterRegexp *regexp.Regexp,
	attributes []string,
	controls []string,
) (string, bool) {
	if req.BaseDN != baseDN ||
		req.Scope != scope ||
		len(req.Attributes) != len(attributes) ||
		len(req.Controls) != len(controls) {
		return "", false
	}
	for i, a := range attributes {
		if req.Attributes[i] != a {
			return "", false
		}
	}
	for i, c := range controls {
		if req.Controls[i].GetControlType() != c {
			return "", false
		}
	}

	if g := filterRegexp.FindStringSubmatch(req.Filter); g == nil {
		return "", false
	} else if len(g) == 1 {
		return "", true // no prefix
	} else {
		prefix := g[1]
		for _, gg := range g[2:] {
			if gg != prefix {
				return "", false
			}
		}
		return prefix, true
	}
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

func errorSearchResult() ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		Entries:    make([]*ldap.Entry, 0),
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultOperationsError}
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
	h := sha1.New()
	d := h.Sum([]byte(domain))

	h = sha1.New()
	i := h.Sum([]byte(id))

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
	for i := 0; i < n; i++ {
		sa := binary.LittleEndian.Uint32(b[8+4*i : 8+4*i+4])
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}
	return sb.String()
}

func unexpected(msg string) error {
	return fmt.Errorf("unexpected call: %s", msg)
}
