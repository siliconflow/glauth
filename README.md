
# GLAuth: LDAP authentication server for developers
[![Official GLAuth Website](https://img.shields.io/badge/Official%20GLAuth%20Website-glauth.github.io-brightgreen?style=plastic)](https://glauth.github.io/)
[![kittens dns](https://img.shields.io/badge/kittens%20dns-github-blue?style=plastic)](https://github.com/fusion/kittendns)
[![wing vpn](https://img.shields.io/badge/wing%20vpn-github-orange?style=plastic)](https://github.com/fusion/wing-vpn)

Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

![GitHub all releases](https://img.shields.io/github/downloads/glauth/glauth/total)
![Docker pulls](https://badgen.net/docker/pulls/glauth/glauth)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/glauth/glauth/master)

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory for development, or a homelab.
* Store your user directory in a file, local or in S3; SQL database; or proxy to existing LDAP servers.
* Two Factor Authentication (transparent to applications)
* Multiple backends can be chained to inject features

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### Contributing
- Please base all Pull Requests on [dev](https://github.com/glauth/glauth/tree/dev), not master.
- Format your code automatically using `gofmt -d ./` before committing

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Download a precompiled binary from the [releases](https://github.com/glauth/glauth/releases) page.
2. Download the [example config file](https://github.com/glauth/glauth/blob/master/v2/sample-simple.cfg).
3. Start the GLAuth server, referencing the path to the desired config file with `-c`.
   - `./glauth64 -c sample-simple.cfg`
4. Test with traditional LDAP tools
   - For example: `ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`

### Make Commands

Note - makefile uses git data to inject build-time variables. For best results, run in the context of the git repo.

### Documentation

<h4 align="center">:point_right: The latest version of GLauth's documentation is available at https://glauth.github.io/ :point_left:</h4>

<hr>

### Quickstart

Get started in three short [steps](https://glauth.github.io/docs/quickstart.html)

### Usage:
```
glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  --ldap <address>          Listen address for the LDAP server.
  --ldaps <address>         Listen address for the LDAPS server.
  --ldaps-cert <cert-file>  Path to cert file for the LDAPS server.
  --ldaps-key <key-file>    Path to key file for the LDAPS server.
  -h, --help                Show this screen.
  --version                 Show version.
```

### Configuration:
GLAuth can be deployed as a single server using only a local configuration file.  This is great for testing, or for production if you use a tool like Puppet/Chef/Ansible:
```unix
glauth -c glauth.cfg
```
Here's a sample config wth hardcoded users and groups:
```toml
[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
[[users]]
  name = "hackers"
  uidnumber = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a"   # dogood
  sshkeys = [ "ssh-dss AAAAB3..." ]
[[users]]
  name = "uberhackers"
  uidnumber = 5006
  primarygroup = 5501
  passbcrypt = "243261243130244B62463462656F7265504F762E794F324957746D656541326B4B46596275674A79336A476845764B616D65446169784E41384F4432"   # dogood
[[groups]]
  name = "superheros"
  gidnumber = 5501
```

More configuration options are documented [here](https://glauth.github.io/docs/file.html) and in this [sample file](https://github.com/glauth/glauth/blob/master/v2/sample-simple.cfg)

#### Keycloak backend

`datastore = "keycloak"` exposes a Keycloak realm over LDAP (read-only), so that Keycloak can act as an identity provider for services such as vSphere, even without LDAP user federation.

```toml
[backend]
  datastore = "keycloak"
  keycloakhostname = "idp.example.com"   # Keycloak server (HTTPS only)
  keycloakport = 8443                    # HTTPS port (defaults to 8443)
  keycloakrealm = "master"               # Realm whose users/groups are exposed
  keycloakdomain = "example.com"         # DNS domain deriving base DNs and objectSids
```

Users and groups of the realm appear under `cn=users,<base>` and `cn=groups,<base>`, where `<base>` is `dc=example,dc=com` for `keycloakdomain = "example.com"`.

LDAP binds authenticate as Keycloak **service accounts** (OAuth 2.0 client credentials grant, one grant per connection, token refreshed automatically): the bind DN username is the Keycloak `client_id` and the bind password is the client `client_secret`:

```
ldapsearch ... -D "cn=<client_id>,cn=bind,dc=example,dc=com" -w "<client_secret>" \
  -b "cn=users,dc=example,dc=com" "(objectClass=user)"
```

### Docker and Kubernetes:

Build an image directly from source (no pre-built binaries needed):

```sh
cd v2
docker build -f docker/Dockerfile -t glauth:local .
docker run -d -p 3893:3893 -v /path/to/config-dir:/app/config:ro glauth:local
```

The container reads `/app/config/config.cfg` (a default config is used when the file is absent). `docker/Dockerfile-standalone` and `docker/Dockerfile-plugins` remain the release images, driven by `make builddocker` with cross-compiled binaries.

A Helm chart is provided at `v2/helm/glauth`:

```sh
helm install glauth v2/helm/glauth \
  --set-file config=/path/to/config.cfg
```

The chart renders the TOML config into a ConfigMap (or use `existingConfigMap` / `existingSecret` for configs containing credentials), exposes the LDAP/LDAPS/API ports through a Service, and probes the LDAP port for liveness/readiness.

# Stargazers over time

[![Stargazers over time](https://starchart.cc/glauth/glauth.svg)](https://starchart.cc/glauth/glauth)
