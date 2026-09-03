# GLAuth 代理 Keycloak 认证流程分析

> 基于 `keycloak` 分支相对 `master` 的 diff(核心实现:`v2/pkg/handler/keycloak.go`,约 1200 行;配套:`v2/sample-keycloak.cfg`、Helm chart、Dockerfile)。

## 1. 总体架构

GLAuth 新增 `datastore = "keycloak"` 后端(`v2/pkg/server/server.go` 注册),将 Keycloak realm 以**只读 LDAP** 的形式暴露:

- LDAP **Bind / Search / Close** 被代理到 Keycloak 的 **OpenID Connect token 端点** 和 **Admin REST API**;
- **Add / Modify / Delete 一律拒绝**(`OperationsError`),后端为只读;
- 典型场景:让 Keycloak 作为 vSphere 等仅支持 LDAP 的系统的身份提供方,无需启用 Keycloak 的 LDAP user federation。

### DIT 结构(由 `keycloakdomain` 派生)

以 `keycloakdomain = "example.com"` 为例,base DN 为 `dc=example,dc=com`:

```
dc=example,dc=com                  ← naming context 根(域名条目)
├── cn=users,dc=example,dc=com     ← realm 用户(叶子条目:cn=<username>,...)
├── cn=groups,dc=example,dc=com    ← realm 组(叶子条目:cn=<group>,...)
└── cn=bind,dc=example,dc=com      ← 服务账号(客户端)bind 专用命名空间
```

Root DSE(空 base DN + base scope 查询)返回 `namingContexts`、`defaultNamingContext` 等,供 LDAP 客户端自动发现 base DN。

## 2. 认证(Bind)流程

Bind 根据 bind DN 的后缀分两类(属性类型与 base 比较均按 RFC 4514 大小写不敏感,cn 值按 RFC 4514 反转义):

### 2.1 服务账号 bind:`cn=<client-id>,cn=bind,dc=...`

```
LDAP 客户端                    GLAuth                         Keycloak
    │  bind cn=<client-id>,cn=bind,dc=...    │                              │
    │  password = client secret  │                              │
    │───────────────────────────>│                              │
    │                            │  POST token 端点             │
    │                            │  grant_type=client_credentials│
    │                            │  client_id=<client-id>       │
    │                            │  client_secret=<password>    │
    │                            │─────────────────────────────>│
    │                            │  access token                │
    │                            │<─────────────────────────────│
    │                            │  按连接 ID 保存会话           │
    │  Success /                 │  (clientID+secret+token)     │
    │  InvalidCredentials        │                              │
    │<───────────────────────────│                              │
```

- bind 密码即 **client secret**,直接用于 OAuth 2.0 **client credentials grant**;
- 成功后为该 LDAP **连接**建立一个会话(每连接独立,`keycloakSessions.byConnID`),保存 clientID/secret/token;
- 失败返回 `InvalidCredentials`。

### 2.2 用户 bind:`cn=<username>,cn=users,dc=...`

```
LDAP 客户端                    GLAuth                              Keycloak
    │  bind cn=alice,cn=users,dc=... │                                   │
    │  password = alice 的密码        │                                   │
    │───────────────────────────────>│                                   │
    │                                │ ① POST token 端点                 │
    │                                │   grant_type=password(直接授权) │
    │                                │   client_id/keycloakclientid      │
    │                                │   username=alice, password=***    │
    │                                │──────────────────────────────────>│
    │                                │   token(仅作凭据校验,丢弃)      │
    │                                │<──────────────────────────────────│
    │                                │ ② client credentials grant        │
    │                                │   (配置的 client,同 2.1)         │
    │                                │   为该连接建立服务账号会话        │
    │  Success / InvalidCredentials  │                                   │
    │<───────────────────────────────│                                   │
```

- 第一步用 **direct access grant**(OAuth 2.0 Resource Owner Password Credentials,`grant_type=password`)校验用户名/密码,**返回的用户 token 被丢弃**,仅作为凭据检查;
- 第二步用配置文件中 `keycloakclientid` / `keycloakclientsecret` 做 client credentials grant,**后续该连接的所有 Search 都以该 client 的 service account 身份执行**——即用户 bind 成功后,LDAP 连接并不以用户身份访问 Keycloak,而是统一降级为 service account;
- 未配置 `keycloakclientid` 时用户 bind 直接报 `OperationsError(misconfiguration)`;
- 其他任何形式的 bind DN 返回 `InvalidCredentials`。

## 3. 查询(Search)流程

1. **会话检查**:按连接 ID 取会话;若 token 过期(`token.Valid()` 为假),用保存的 clientID/secret 重新做 client credentials grant 刷新(未用 refresh token);
2. **base DN / scope 分发**:DIT 是扁平的(域根 → users/groups 容器 → 叶子),subtree 与 single-level 覆盖相同叶子;对 `cn=<name>,cn=users,...` 的叶子查询直接用 `username=<name>&exact=true` 缩小 REST 查询;
3. **查询收窄(narrowing)**:解析 LDAP filter,剥掉 `objectClass` 等值匹配后,若剩余为纯等值匹配(AND 组合),映射为 Keycloak REST 查询参数:

   | LDAP 属性 | Keycloak users 参数 |
   |---|---|
   | `sAMAccountName` / `cn` / `userPrincipalName` / `uid` | `username` |
   | `mail` | `email` |
   | `givenName` | `firstName` |
   | `sn` | `lastName` |

   并附加 `exact=true`;组查询的 `sAMAccountName`/`cn` 等值映射为 substring `search` 参数。其他 filter 形态(OR/NOT/子串/present 等)不收窄,拉全量后由 LDAP server 端(`EnforceLDAP`)自行按真实 filter 过滤——收窄只需是超集即可;
4. **分页**:users/groups 端点按 `first`/`max=500` 翻页(规避 Keycloak 默认 100 条静默截断),并检测服务端忽略分页(首条 ID 重复即停);
5. **条目渲染**:用户映射为 `inetOrgPerson`/`user` 等 objectClass,属性含 `sAMAccountName`、`cn`、`uid`、`givenName`、`sn`、`displayName`、`userPrincipalName`(= `username@domain`)、`mail`;组映射为 `group`,含 `objectSid`(由 Keycloak id + domain 合成 SID,供 Windows 类客户端使用);
6. Close 时移除该连接的会话。

## 4. Keycloak client 配置注意事项

GLAuth 侧配置(`[backend]`):`keycloakhostname`、`keycloakport`(默认 8443,**仅 HTTPS**)、`keycloakrealm`、`keycloakdomain`、`keycloakclientid`、`keycloakclientsecret`。对应的 Keycloak client 需满足:

### 4.1 必须开启的能力

| 配置项 | 要求 | 原因 |
|---|---|---|
| **Client authentication**(confidential client) | ON | 两种 bind 都走 client credentials / password grant,需要 client secret;public client 无 secret 可用 |
| **Service Accounts Enabled** | ON | bind 成功后所有 Search 都以该 client 的 service account 调 Admin REST API |
| **Direct Access Grants Enabled** | ON | 用户密码 bind(2.2 第一步)依赖 `grant_type=password` |
| Standard Flow / Implicit Flow | 不需要 | 流程中不使用浏览器重定向 |

### 4.2 Service account 授权

给该 client 的 service account(Clients → `<client>` → Service Account Roles)分配 `realm-management` client 的角色:

- **`view-users`** — 读取 realm 用户列表/详情;
- **`query-users`** — 调用 users 查询端点;
- **`query-groups`** — 调用 groups 查询端点。

### 4.3 其他注意事项

- **协议**:GLAuth 只拼 `https://` URL(REST 与 token 端点均是),Keycloak 必须提供有效 HTTPS;`keycloakport` 默认为 8443;
- **端点**:token 端点为 `https://<host>:<port>/realms/<realm>/protocol/openid-connect/token`,REST 为 `https://<host>:<port>/admin/realms/<realm>/...`——如果 Keycloak 部署带非根 context path(如 `/auth`),当前实现无法配置,需反代到根路径;
- **token 有效期**:会话刷新靠 `token.Valid()` 判断过期后重新 client credentials grant;realm 的 **Access Token Lifespan** 不宜过短(每次 Search 前都会检查,过短会增加 token 请求频率);
- **暴力破解保护**:realm 若开启 Brute Force Detection,频繁失败的用户 bind(每次都打一次 password grant)可能触发账号临时锁定,评估 Max Login Failures 阈值;
- **用户前提**:direct grant 要求用户已设置密码(非仅 federated/social 登录),且无未完成的 required actions(如 Update Password、Verify Email、Terms and Conditions)——存在 pending required action 时 password grant 会失败,bind 表现为 `InvalidCredentials`;
- **服务账号 bind 的 client 与配置 client 可不同**:`cn=bind` 命名空间下任何 confidential client(开了 service account 且具备上述角色)都可直接 bind;用户 bind 则固定使用配置文件中的 `keycloakclientid`;
- **只读语义**:不要指望通过 GLAuth 写入 Keycloak,所有写操作被拒绝;用户/组管理仍在 Keycloak 侧进行。
