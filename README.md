# AuthProxyServer

AuthProxyServer (APS) provides authentication/authorization reverse proxy
for CHESS backend services. It relies on CHESS authentication scheme via
LDAP provider and verifies CHESS user credentials along with BTRs groups.

### Configuration
Here is basic configuration file

```
Services:
  AuthzUrl: http://localhost:8380
Kerberos:
  Realm: CLASSE.CORNELL.EDU
  Krb5Conf:  /etc/krb5.conf
LDAP:
  URL: "ldaps://xxx.yyy.cornell.edu:port"
  baseDN: "DC=xxx,DC=cornell,DC=edu"
  Login: "login credential"
  Password: "password"
  Expire: 3600
Authz:
  CheckLDAP: true
  ClientId: "client-id-string"
  ClientSecret: "client-secret-string"
  WebServer:
    Name: foxden-authz-service
    Port: 8380
    Verbose: 1
    LogFile: /path/FOXDEN/logs/Authz.log
    LogLongFile: true
    GinOptions:
      DisableConsoleColor: true
AuthProxyServer:
  CheckBtrs: true
  CheckAdmins: true
  MainPageTemplate: id4b.tmpl
  Backends:
    -
      url: http://localhost:8888
      endpoint: /id4b/submit
      btrs: ["test-demo"]
    -
      url: http://localhost:8888
      endpoint: /id4b/analysis
      btrs: ["test-demo"]
  WebServer:
    Name: auth-proxy-server
    Port: 8345
    StaticDir: /path/FOXDEN/AuthProxyServer/static
    Verbose: 1
    LogFile: /path/FOXDEN/logs/AuthProxyServer.log
    LogLongFile: true
    GinOptions:
      DisableConsoleColor: true
      Production: true
  OAuth:
    -
      Provider: github
      ClientID: client-id-string
      ClientSecret: client-secret
    -
      Provider: google
      ClientID: client-id-string
      ClientSecret: client-secret
      RedirectURL: http://localhost:8345/google/callback
    -
      Provider: facebook
      ClientID: client-id-string
      ClientSecret: client-secret
      RedirectURL: http://localhost:8345/facebook/callback

```
