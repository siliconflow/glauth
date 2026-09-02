package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterGroupsWithPrefix(t *testing.T) {
	s := "(&(objectClass=group)(|(sAMAccountName=pre*)(cn=pre*)))"
	g := filterGroupsWithPrefix.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 3, len(g))
	assert.Equal(t, s, g[0])
	for _, gg := range g[1:] {
		assert.Equal(t, "pre", gg)
	}
}

func TestFilterRootDSE(t *testing.T) {
	s := "(objectclass=*)"
	g := filterRootDSE.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 1, len(g))
	assert.Equal(t, s, g[0])
}

func TestUnwrapObjectClass(t *testing.T) {
	assert.Equal(t, "(sAMAccountName=a)",
		unwrapObjectClass("(&(objectClass=user)(sAMAccountName=a))", "user"))
	assert.Equal(t, "(sAMAccountName=a)",
		unwrapObjectClass("(&(OBJECTCLASS=USER)(sAMAccountName=a))", "user"))
	assert.Equal(t, "(sAMAccountName=a)",
		unwrapObjectClass("(sAMAccountName=a)", "user"))
	assert.Equal(t, "(|(cn=a)(cn=b))",
		unwrapObjectClass("(&(objectClass=user)(|(cn=a)(cn=b)))", "user"))
}

func TestUserQueryEquality(t *testing.T) {
	params, prefix := userQuery("(sAMAccountName=wangyuqing)")
	assert.Equal(t, map[string]string{
		"username": "wangyuqing", "exact": "true"}, params)
	assert.Equal(t, "", prefix)

	params, prefix = userQuery("(&(objectClass=user)(mail=a@b.c))")
	assert.Equal(t, map[string]string{
		"email": "a@b.c", "exact": "true"}, params)
	assert.Equal(t, "", prefix)

	params, _ = userQuery("(MAIL=a@b.c)")
	assert.Equal(t, "a@b.c", params["email"])

	params, _ = userQuery("(&(objectClass=user)(sn=Wang))")
	assert.Equal(t, map[string]string{
		"lastName": "Wang", "exact": "true"}, params)
}

func TestUserQueryPrefix(t *testing.T) {
	params, prefix := userQuery("(&(objectClass=user)(|(sAMAccountName=pre*)" +
		"(sn=pre*)(givenName=pre*)(cn=pre*)(displayname=pre*)" +
		"(userPrincipalName=pre*)))")
	assert.Nil(t, params)
	assert.Equal(t, "pre", prefix)
}

func TestUserQueryAll(t *testing.T) {
	for _, f := range []string{
		"(objectClass=user)",
		"(|(cn=a)(cn=b))",
		"(sAMAccountName=wang*)",
	} {
		params, prefix := userQuery(f)
		assert.Nil(t, params)
		assert.Equal(t, "", prefix)
	}
}

func TestGroupQueryEquality(t *testing.T) {
	params, prefix := groupQuery("(cn=engineering)")
	assert.Equal(t, map[string]string{"search": "engineering"}, params)
	assert.Equal(t, "", prefix)

	params, _ = groupQuery("(&(objectClass=group)(sAMAccountName=engineering))")
	assert.Equal(t, map[string]string{"search": "engineering"}, params)
}

func TestGroupQueryPrefix(t *testing.T) {
	params, prefix := groupQuery(
		"(&(objectClass=group)(|(sAMAccountName=pre*)(cn=pre*)))")
	assert.Nil(t, params)
	assert.Equal(t, "pre", prefix)

	params, prefix = groupQuery("(objectClass=group)")
	assert.Nil(t, params)
	assert.Equal(t, "", prefix)
}

func TestFilterUsersWithPrefix(t *testing.T) {
	s := "(&(objectClass=user)(|(sAMAccountName=pre*)" +
		"(sn=pre*)" +
		"(givenName=pre*)" +
		"(cn=pre*)" +
		"(displayname=pre*)" +
		"(userPrincipalName=pre*)))"
	g := filterUsersWithPrefix.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 7, len(g))
	assert.Equal(t, s, g[0])
	for _, gg := range g[1:] {
		assert.Equal(t, "pre", gg)
	}
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
		"S-1-5-21-1634561892-1663987305-970616175-959604020",
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
