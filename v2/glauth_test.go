package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/glauth/ldap"
	"github.com/pquerna/otp/totp"
)

type testEnv struct {
	checkanonymousrootDSE bool
	checkTOTP             bool
	checkbindUPN          bool
	svcdn                 string
	svcdnnogroup          string
	otpdn                 string
	expectedinfo          string
	expectedaccount       string
	scopedaccount         string
	expectedfirstaccount  string
	expectedgroup         string
	checkemployeetype     string
}

func glauthBinary() string {
	if binary := os.Getenv("GLAUTH_TEST_BINARY"); binary != "" {
		return binary
	}

	qualified := filepath.Join("bin", runtime.GOOS+runtime.GOARCH, "glauth")
	if _, err := os.Stat(qualified); err == nil {
		return qualified
	}

	distribution := filepath.Join("bin", "glauth-"+runtime.GOOS+"-"+runtime.GOARCH)
	if runtime.GOOS == "windows" {
		distribution += ".exe"
	}
	if _, err := os.Stat(distribution); err == nil {
		return distribution
	}

	return "bin/glauth"
}

func TestProperBuild(t *testing.T) {
	info, err := os.Stat(glauthBinary())
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(info.Mode())
	if mode&0b001001001 == 0 {
		t.Fatalf("bad file mode: %b", mode)
	}
}

func TestConfigBackendRejectsPasswordlessUserBinds(t *testing.T) {
	port := 3893

	configPath := filepath.Join(t.TempDir(), "passwordless.cfg")
	config := fmt.Sprintf(`debug = false

[ldap]
  enabled = true
  listen = "127.0.0.1:%d"
  tls = false

[ldaps]
  enabled = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"

[behaviors]
  LimitFailedBinds = false

[[groups]]
  name = "svc"
  gidnumber = 5501

[[users]]
  name = "nopass"
  uidnumber = 5001
  primarygroup = 5501
    [[users.capabilities]]
    action = "search"
    object = "*"
`, port)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := startSvc(t, glauthBinary(), "-c", configPath)
	defer stopSvc(svc)

	bindDN := "cn=nopass,dc=glauth,dc=com"
	for _, tc := range []struct {
		name     string
		password string
		want     string
	}{
		{name: "arbitrary password", password: "definitely-wrong", want: "exit status 49"},
		{name: "empty password", password: "", want: "exit status 53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := doRun("ldapsearch", "-LLL", "-H", fmt.Sprintf("ldap://127.0.0.1:%d", port), "-D", bindDN, "-w", tc.password, "-x", "-b", "dc=glauth,dc=com", "(cn=nopass)")
			got := getFirst(out)
			if err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("bind result = %q, want %q", got, tc.want)
			}
		})
	}
}

func ldapOnlyConfig(t *testing.T, source string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}

	contents := string(data)
	sectionMarker := "\n[ldaps]\n"
	markerStart := strings.Index(contents, sectionMarker)
	if markerStart < 0 {
		t.Fatalf("%s has no [ldaps] section", source)
	}
	start := markerStart + 1
	relEnd := strings.Index(contents[start+len("[ldaps]"):], "\n[")
	if relEnd < 0 {
		t.Fatalf("%s has no section after [ldaps]", source)
	}
	end := start + len("[ldaps]") + relEnd
	section := contents[start:end]
	sectionWithoutLDAPS := strings.Replace(section, "enabled = true", "enabled = false", 1)
	if section == sectionWithoutLDAPS {
		t.Fatalf("%s [ldaps] section does not enable LDAPS", source)
	}

	contents = contents[:start] + sectionWithoutLDAPS + contents[end:]
	path := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func batteryOfTests(t *testing.T, env *testEnv) {
	tests := []struct {
		Name  string
		Path  string
		Check func(t testing.TB)
	}{
		{
			Name: "searching for the 'hackers' user",
			Check: func(t testing.TB) {
				want := env.expectedaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hackers' user without binding with a group",
			Check: func(t testing.TB) {
				if env.svcdnnogroup == "" {
					t.SkipNow()
				}
				want := env.expectedaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdnnogroup, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hackers' user after binding using the account's UPN",
			Check: func(t testing.TB) {
				if !env.checkbindUPN {
					t.SkipNow()
				}
				want := env.expectedaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", "serviceuser@example.com", "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should find them in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "querying the root SDE",
			Check: func(t testing.TB) {
				want := env.expectedinfo
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-s", "base", "(objectclass=*)")
				got := getSecond(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get some meta information\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "querying the root SDE anonymously without authorizing in config file",
			Check: func(t testing.TB) {
				if !env.checkanonymousrootDSE {
					t.SkipNow()
				}
				want := "exit status 50"
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-x", "-s", "base", "(objectclass=*)")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get error 50\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "enumerating posix groups",
			Check: func(t testing.TB) {
				want := env.expectedgroup
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(objectclass=posixgroup)")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get a list starting with the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for members of the 'superheros' group",
			Check: func(t testing.TB) {
				want := env.expectedfirstaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com)")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get a list starting with the 'hackers' user\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "performing a complex search for members of 'superheros' group",
			Check: func(t testing.TB) {
				want := env.expectedfirstaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", "(&(objectClass=*)(memberOf=ou=superheros,ou=groups,dc=glauth,dc=com))")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Fatalf("should get a list starting with the 'hackers' user\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				// We aren't checking that "github.com/pquerna/otp/totp" creates correct values.
				// That's what their own tests are for.
				// We are checking that the totp code gets through glauth code successfully
				otpvalue, err := totp.GenerateCode("3hnvnk4ycv44glzigd6s25j4dougs3rk", time.Now())
				if err != nil {
					t.Fatal("Failed to generate totp code:", err)
				}
				want := env.scopedaccount
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.otpdn, "-w", "mysecret"+otpvalue, "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if got != want {
					if err != nil {
						got = err.Error()
					}
					t.Log(out)
					t.Fatalf("should find them in in the 'superheros' group\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account and no value",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				want := "exit status 49"
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.otpdn, "-w", "mysecret", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get 'Invalid credentials(49)'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user using a TOTP-enabled account and the wrong value",
			Check: func(t testing.TB) {
				if !env.checkTOTP {
					t.SkipNow()
				}
				want := "exit status 49"
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.otpdn, "-w", "mysecret123456", "-x", "-bou=superheros,dc=glauth,dc=com", "cn=hackers")
				got := getFirst(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("should get 'Invalid credentials(49)'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
		{
			Name: "searching for the 'hacker' user",
			Check: func(t testing.TB) {
				if env.checkemployeetype == "" {
					t.SkipNow()
				}
				want := "employeetype: Intern"
				out, err := doRun("ldapsearch", "-LLL", "-H", "ldap://127.0.0.1:3893", "-D", env.svcdn, "-w", "mysecret", "-x", "-bdc=glauth,dc=com", env.checkemployeetype, "employeetype")
				got := getSecond(out)
				if err != nil {
					got = err.Error()
				}
				if got != want {
					t.Log(out)
					t.Fatalf("type should be 'Intern'\ngot:  %s\nwant: %s", got, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Check(t)
		})
	}
}

func TestSampleSimple(t *testing.T) {
	env := testEnv{
		checkanonymousrootDSE: true,
		checkTOTP:             true,
		checkbindUPN:          true,
		expectedinfo:          "supportedLDAPVersion: 3",
		svcdn:                 "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com",
		svcdnnogroup:          "cn=serviceuser,dc=glauth,dc=com",
		otpdn:                 "cn=otpuser,ou=superheros,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,ou=superheros,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "cn=hackers",
	}

	svc := startSvc(t, glauthBinary(), "-c", ldapOnlyConfig(t, "sample-simple.cfg"))
	batteryOfTests(t, &env)
	stopSvc(svc)
}

func TestSQLitePlugin(t *testing.T) {
	_, err := os.Stat("bin/sqlite.so")
	if err != nil {
		t.Log("Unable to find sqlite plugin")
		t.SkipNow()
	}

	env := testEnv{
		checkanonymousrootDSE: true,
		checkTOTP:             false,
		checkbindUPN:          true,
		expectedinfo:          "supportedLDAPVersion: 3",
		svcdn:                 "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com",
		svcdnnogroup:          "cn=serviceuser,dc=glauth,dc=com",
		otpdn:                 "cn=otpuser,ou=superheros,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,ou=superheros,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=hackers,ou=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "",
	}

	svc := startSvc(t, glauthBinary(), "-c", "pkg/plugins/glauth-sqlite/sample-database.cfg")
	batteryOfTests(t, &env)
	stopSvc(svc)
}

func TestLdapInjection(t *testing.T) {
	out, err := doRun("sh", "-c", "docker ps | grep ldap-service | wc -l")
	if err != nil {
		t.Log("Unable to find docker container:", out)
		t.SkipNow()
	}
	matchingContainers := getFirst(out)
	if matchingContainers != "1" {
		t.Log("Unable to find docker container:", out)
		t.SkipNow()
	}

	env := testEnv{
		checkanonymousrootDSE: false,
		checkTOTP:             true,
		checkbindUPN:          false,
		expectedinfo:          "objectClass: top",
		svcdn:                 "cn=serviceuser,cn=svcaccts,ou=users,dc=glauth,dc=com",
		svcdnnogroup:          "", // ignore
		otpdn:                 "cn=otpuser,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedaccount:       "dn: cn=hackers,cn=superheros,ou=users,dc=glauth,dc=com",
		scopedaccount:         "dn: cn=hackers,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedfirstaccount:  "dn: cn=johndoe,cn=superheros,ou=users,dc=glauth,dc=com",
		expectedgroup:         "dn: ou=superheros,ou=users,dc=glauth,dc=com",
		checkemployeetype:     "",
	}

	svc := startSvc(t, glauthBinary(), "-c", "sample-ldap-injection.cfg")
	batteryOfTests(t, &env)
	stopSvc(svc)
}

// -----=============================================================================----
func WaitForPort(host string, timeout time.Duration) error {
	start := time.Now()
	for {
		conn, err := ldap.Dial("tcp", host)
		if err == nil {
			err = conn.Bind("_", "_")
			if err == nil {
				conn.Close()
				return fmt.Errorf("Successfully authenticated to glauth. This should not happen")
			}
			e := &ldap.Error{}
			if errors.As(err, &e) && e.ResultCode == 49 {
				conn.Close()
				return nil
			}
			conn.Close()
			// We have an error, it's probably a connection error or an error saying that ldap isn't setup yet
			// try again
		}
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout waiting for port %s: %w", host, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func startSvc(t *testing.T, name string, arg ...string) *exec.Cmd {

	cmd := exec.Command(name, arg...)
	cmd.Stderr = t.Output()
	cmd.Stdout = t.Output()
	cmd.Start()
	err := WaitForPort("127.0.0.1:3893", time.Second*2)
	if err != nil {
		t.Fatal("Failed to wait for glauth to start:", err)
	}
	// the port is listening but the ldap server may not be accepting connections yet
	// TODO: make glauth listen as the last part of the initialization that way as soon as it listens it can process connections
	return cmd
}

func stopSvc(svc *exec.Cmd) {
	svc.Process.Kill()
	svc.Process.Wait()
}

func getFirst(output string) string {
	out := strings.SplitN(output, "\n", 2)
	if len(out) < 1 {
		return "*fail*"
	}
	return out[0]
}

func getSecond(output string) string {
	out := strings.SplitN(output, "\n", 3)
	if len(out) < 2 {
		return "*fail*"
	}
	return out[1]
}

func doRun(name string, arg ...string) (string, error) {
	out, err := exec.Command(name, arg...).CombinedOutput()
	if err != nil {
		return string(bytes.TrimSpace(out)), err
	}

	return string(bytes.TrimSpace(out)), nil
}
