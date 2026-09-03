package handler

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/glauth/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/rs/zerolog"
)

func decompiled(t *testing.T, f *ber.Packet) string {
	t.Helper()
	s, err := ldap.DecompileFilter(f)
	assert.NoError(t, err)
	return s
}

func TestUnwrapObjectClass(t *testing.T) {
	// Unwrapped objectClass=user AND yields the remaining child.
	p, err := ldap.CompileFilter("(sAMAccountName=a)")
	assert.NoError(t, err)
	ps := decompiled(t, p)
	f, err := ldap.CompileFilter("(&(objectClass=user)(sAMAccountName=a))")
	assert.NoError(t, err)
	assert.Equal(t, ps, decompiled(t, unwrapObjectClass(f, objectClassesUser)))

	// Case-insensitive objectClass match.
	f, err = ldap.CompileFilter("(&(OBJECTCLASS=USER)(sAMAccountName=a))")
	assert.NoError(t, err)
	assert.Equal(t, ps, decompiled(t, unwrapObjectClass(f, objectClassesUser)))

	// Any object class in the emitted chain is accepted, so a filter
	// anchored on objectClass=inetOrgPerson (the standard SSO form)
	// unwraps just like objectClass=user.
	f, err = ldap.CompileFilter("(&(objectClass=inetOrgPerson)(sAMAccountName=a))")
	assert.NoError(t, err)
	assert.Equal(t, ps, decompiled(t, unwrapObjectClass(f, objectClassesUser)))

	// No AND wrapper: returned unchanged.
	f, err = ldap.CompileFilter("(sAMAccountName=a)")
	assert.NoError(t, err)
	assert.Equal(t, ps, decompiled(t, unwrapObjectClass(f, objectClassesUser)))

	// AND with a remaining (non-equality) child: unwrap returns that
	// child, and the query helpers correctly yield no narrowing.
	f, err = ldap.CompileFilter("(&(objectClass=user)(|(cn=a)(cn=b)))")
	assert.NoError(t, err)
	assert.NotNil(t, unwrapObjectClass(f, objectClassesUser))
	assert.Nil(t, userQuery("(&(objectClass=user)(|(cn=a)(cn=b)))"))

	// A lone objectClass equality yields no remaining child.
	f, err = ldap.CompileFilter("(objectClass=inetOrgPerson)")
	assert.NoError(t, err)
	assert.Nil(t, unwrapObjectClass(f, objectClassesUser))
}

func TestUserQueryEquality(t *testing.T) {
	assert.Equal(t, map[string]string{
		"username": "wangyuqing", "exact": "true"}, userQuery("(sAMAccountName=wangyuqing)"))

	assert.Equal(t, map[string]string{
		"email": "a@b.c", "exact": "true"}, userQuery("(&(objectClass=user)(mail=a@b.c))"))

	assert.Equal(t, "a@b.c", userQuery("(MAIL=a@b.c)")["email"])


	// objectClass=inetOrgPerson (the form Keycloak/SSO clients actually
	// send, and one of the user entry's emitted object classes) narrows
	// the same as objectClass=user.
	assert.Equal(t, map[string]string{
		"username": "wangyuqing", "exact": "true"},
		userQuery("(&(objectClass=inetOrgPerson)(sAMAccountName=wangyuqing))"))
}

func TestUserQueryAll(t *testing.T) {
	// Present, complex, and substring filters yield no narrowing; the
	// LDAP server applies them to the full user list itself.
	for _, f := range []string{
		"(objectClass=user)",
		"(|(cn=a)(cn=b))",
		"(sAMAccountName=wang*)",
	} {
		assert.Nil(t, userQuery(f))
	}
}

func TestUserQueryInetOrgPersonOrFilter(t *testing.T) {
	// A real-world Keycloak/SSO search filter: an inetOrgPerson-typed
	// user narrowed by an OR over uid and mail. assert CompileFilter
	// parses it into the expected AND(objectClass=, OR(uid=, mail=))
	// structure, and that userQuery declines to narrow: an OR is not an
	// equality shape, so the full user list is fetched and EnforceLDAP
	// applies the filter. (uid and mail are both emitted on the entry,
	// so both OR branches can match.)
	filter := "(&(objectClass=inetOrgPerson)(|(uid=jiachengkun)(mail=jiachengkun)))"
	f, err := ldap.CompileFilter(filter)
	assert.NoError(t, err)
	assert.Equal(t, ber.Tag(ldap.FilterAnd), f.Tag)
	require.Len(t, f.Children, 2)

	// child[0]: objectClass=inetOrgPerson equality.
	oc := f.Children[0]
	assert.Equal(t, ber.Tag(ldap.FilterEqualityMatch), oc.Tag)
	attr, ok := oc.Children[0].Value.(string)
	require.True(t, ok)
	assert.Equal(t, "objectClass", attr)
	val, ok := oc.Children[1].Value.(string)
	require.True(t, ok)
	assert.Equal(t, "inetOrgPerson", val)

	// child[1]: OR(uid=jiachengkun, mail=jiachengkun).
	or := f.Children[1]
	assert.Equal(t, ber.Tag(ldap.FilterOr), or.Tag)
	require.Len(t, or.Children, 2)
	for _, c := range or.Children {
		assert.Equal(t, ber.Tag(ldap.FilterEqualityMatch), c.Tag)
		require.Len(t, c.Children, 2)
		a, _ := c.Children[0].Value.(string)
		v, _ := c.Children[1].Value.(string)
		assert.Equal(t, "jiachengkun", v)
		switch a {
		case "uid", "mail":
		default:
			t.Fatalf("unexpected attribute %q", a)
		}
	}

	// The OR is not an equality shape, so narrowing must yield nil;
	// EnforceLDAP applies the filter to the full list.
	assert.Nil(t, userQuery(filter))
}

func TestUserQueryMultipleEqualities(t *testing.T) {
	// An AND over several mapped equalities narrows to all the
	// corresponding Keycloak params (Keycloak ANDs its query params).
	// The objectClass equality is stripped first.
	assert.Equal(t, map[string]string{
		"email":    "a@b.c",
		"lastName": "Wang",
		"exact":    "true",
	}, userQuery("(&(objectClass=inetOrgPerson)(mail=a@b.c)(sn=Wang))"))

	// A lone objectClass equality, or an AND holding only objectClass
	// equalities, narrows nothing.
	assert.Nil(t, userQuery("(objectClass=inetOrgPerson)"))
	assert.Nil(t, userQuery("(&(objectClass=top)(objectClass=inetOrgPerson))"))

	// uid maps to Keycloak's username param, like sAMAccountName/cn.
	assert.Equal(t, map[string]string{
		"username": "jiachengkun", "exact": "true"},
		userQuery("(uid=jiachengkun)"))
}
func TestUserQueryUid(t *testing.T) {
	// uid is the inetOrgPerson login identifier and the form Keycloak/SSO
	// clients send; it narrows to the username param under objectClass=
	// inetOrgPerson, user, or bare.
	for _, f := range []string{
		"(uid=jiachengkun)",
		"(&(objectClass=inetOrgPerson)(uid=jiachengkun))",
		"(&(objectClass=user)(uid=jiachengkun))",
	} {
		assert.Equal(t, map[string]string{
			"username": "jiachengkun", "exact": "true"},
			userQuery(f), "filter: %s", f)
	}
}

func TestUserEntryEnforceLDAP(t *testing.T) {
	// End-to-end check of the filter the Keycloak/SSO search sends
	// (objectClass=inetOrgPerson AND OR(uid, mail)) against the entry
	// the handler actually emits. query narrowing declines the OR, so
	// the whole user list is fetched and EnforceLDAP must match.
	h := &keycloakHandler{
		cfg: &keycloakHandlerConfig{keycloakDomain: "siliconflow.cn"},
		log: &zerolog.Logger{},
	}
	e := h.userEntry(keycloakUser{
		Username: "jiachengkun", Email: "jiachengkun@siliconflow.cn",
		FirstName: "J", LastName: "K",
	})

	// The uid attribute is emitted, so the uid branch of the OR matches.
	f := "(&(objectClass=inetOrgPerson)(|(uid=jiachengkun)(mail=jiachengkun)))"
	pkt, err := ldap.CompileFilter(f)
	require.NoError(t, err)
	keep, code := ldap.ServerApplyFilter(pkt, e)
	assert.EqualValues(t, ldap.LDAPResultSuccess, code)
	assert.True(t, keep, "OR(uid,mail) must match via the uid branch")

	// A non-matching uid does not keep the entry.
	pkt2, _ := ldap.CompileFilter("(uid=other)")
	keep2, _ := ldap.ServerApplyFilter(pkt2, e)
	assert.False(t, keep2)
}

func TestGroupQueryEquality(t *testing.T) {
	assert.Equal(t, map[string]string{"search": "engineering"}, groupQuery("(cn=engineering)"))

	assert.Equal(t, map[string]string{"search": "engineering"},
		groupQuery("(&(objectClass=group)(sAMAccountName=engineering))"))
}

func TestGroupQueryPrefix(t *testing.T) {
	// A prefix (substring) filter yields no narrowing; the LDAP server
	// applies it to the full group list itself.
	assert.Nil(t, groupQuery("(&(objectClass=group)(|(sAMAccountName=pre*)(cn=pre*)))"))

	assert.Nil(t, groupQuery("(objectClass=group)"))
}

func TestRestAPIEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/admin/realms/test-realm/users",
		c.restAPIEndpoint("users"))
}

func TestSid(t *testing.T) {
	assert.Equal(t,
		"S-1-5-21-2987196641-2334585625-1400046095-242709553",
		sidToString(sid("4e292dae-35db-4f1a-b40b-17e8e0a3a6b7",
			"domain.com")))
}

func TestTokenEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/realms/test-realm/protocol/"+
		"openid-connect/token", c.tokenEndpoint())
}

func TestNormalizeDN(t *testing.T) {
	assert.Equal(t, "cn=alice,dc=example,dc=com",
		normalizeDN("CN=Alice, DC=Example, DC=Com"))
	assert.Equal(t, "", normalizeDN(""))
}

func TestSplitDN(t *testing.T) {
	head, rest := splitDN("cn=alice,dc=example,dc=com")
	assert.Equal(t, "cn=alice", head)
	assert.Equal(t, "dc=example,dc=com", rest)

	// Escaped comma in the RDN value is not a separator.
	head, rest = splitDN(`cn=a\,b,dc=example,dc=com`)
	assert.Equal(t, `cn=a\,b`, head)
	assert.Equal(t, "dc=example,dc=com", rest)
}

func TestParseRDN(t *testing.T) {
	attr, value, ok := parseRDN("cn=alice")
	assert.True(t, ok)
	assert.Equal(t, "cn", attr)
	assert.Equal(t, "alice", value)

	// Escaped hex pair is decoded (RFC 4514).
	attr, value, ok = parseRDN(`cn=al\69ce`)
	assert.True(t, ok)
	assert.Equal(t, "alice", value)

	// No '=' — not an RDN.
	_, _, ok = parseRDN("notarn")
	assert.False(t, ok)
}

func TestEscapeDNValue(t *testing.T) {
	// Special characters are backslash-escaped; leading/trailing spaces
	// and leading '#' too (RFC 4514).
	assert.Equal(t, "al ice", escapeDNValue("al ice"))
	assert.Equal(t, `\ alice`, escapeDNValue(" alice"))
	assert.Equal(t, `alice\ `, escapeDNValue("alice "))
	assert.Equal(t, `\#alice`, escapeDNValue("#alice"))
	assert.Equal(t, `al\=\;ice`, escapeDNValue("al=;ice"))
	// NUL is escaped as \00.
	assert.Equal(t, "al\\00ice", escapeDNValue("al\x00ice"))
}

func TestSearchErrorNotFound(t *testing.T) {
	res, err := searchError(ldap.LDAPResultNoSuchObject, "no such object: %s", "foo")
	assert.EqualValues(t, ldap.LDAPResultNoSuchObject, res.ResultCode)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "no such object: foo"))
}
