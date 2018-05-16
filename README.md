# README

## Update 1

I did some debugging and noticed that `org.wildfly.extension.undertow.security.jaspi.JASPICAuthenticationMechanism.authenticate(HttpServerExchange, SecurityContext)` is reading the context which was set by the `KeycloakAdapter`;

```java
if (isValid) {
  // The CBH filled in the JBOSS SecurityContext, we need to create an Undertow account based on that
  org.jboss.security.SecurityContext jbossSct = SecurityActions.getSecurityContext();
  authenticatedAccount = createAccount(cachedAccount, jbossSct);
  updateSubjectRoles(jbossSct);
}
```

At this point the roles cannot be read, because the `SecurityContext` which was previously set by `org.keycloak.adapters.wildfly.WildflyRequestAuthenticator` does not contain any roles. The request authenticator tries to add roles into the context which were discovered by the keycloak adapter. For this a `SubjectInfo` is created and the subject is passed which was filled with role information. During `createSubjectInfo` the roles are ommited (see comment in code below).

If the roles are re-added to the new `SubjectInfo` the call of the secured endpoint works. The method `mapGroupMembersOfAuthenticatedSubjectIntoSubjectInfo` is a proof-of-concept - not to be considered as a final patch, as I'm not very deep into the security handling.

*Question* Is this the root cause and can be fixed by the keycload wildfly adapter-team or the defect located elsewhere in the flow?

```java
@Override
protected void propagateKeycloakContext(KeycloakUndertowAccount account)
{
    super.propagateKeycloakContext(account);
    SecurityInfoHelper.propagateSessionInfo(account);
    log.debug("propagate security context to wildfly");
    Subject subject = new Subject();
    Set<Principal> principals = subject.getPrincipals();
    principals.add(account.getPrincipal());
    Group[] roleSets = getRoleSets(account.getRoles());
    for (int g = 0; g < roleSets.length; g++)
    {
        Group group = roleSets[g];
        String name = group.getName();
        Group subjectGroup = createGroup(name, principals);
        if (subjectGroup instanceof NestableGroup)
        {
            /* A NestableGroup only allows Groups to be added to it so we
            need to add a SimpleGroup to subjectRoles to contain the roles
            */
            SimpleGroup tmp = new SimpleGroup("Roles");
            subjectGroup.addMember(tmp);
            subjectGroup = tmp;
        }
        // Copy the group members to the Subject group
        Enumeration<? extends Principal> members = group.members();
        while (members.hasMoreElements())
        {
            Principal role = members.nextElement();
            subjectGroup.addMember(role);
        }
    }
    // add the CallerPrincipal group if none has been added in getRoleSets
    Group callerGroup = new SimpleGroup(SecurityConstants.CALLER_PRINCIPAL_GROUP);
    callerGroup.addMember(account.getPrincipal());
    principals.add(callerGroup);
    org.jboss.security.SecurityContext sc = SecurityContextAssociation.getSecurityContext();
    Principal userPrincipal = getPrincipal(subject);
    sc.getUtil().createSubjectInfo(userPrincipal, account, subject);

    // Roles of subjectInfo are null, because is was constructed by
    // org.jboss.security.identity.extensions.CredentialIdentityFactory
    //   .createIdentity(Principal [=userPrincipal], Object [=account], Role [=null]).
    // Therefore the roles are only contained in the authenticatedSubject (member of subjectInfo)
    // and subsequent logics do only access subjecctInfo#roles instead of authenticatedSubject#roles.
    mapGroupMembersOfAuthenticatedSubjectIntoSubjectInfo(sc.getSubjectInfo());
}

private void mapGroupMembersOfAuthenticatedSubjectIntoSubjectInfo(SubjectInfo subjectInfo)
{
    if (subjectInfo == null)
    {
        return;
    }

    Subject authenticatedSubject = subjectInfo.getAuthenticatedSubject();
    if (authenticatedSubject == null)
    {
        return;
    }

    // Get role group of subjectInfo in order to add roles of authenticatedSubject.
    RoleGroup scRoles = subjectInfo.getRoles();
    if (scRoles == null)
    {
        scRoles = new SimpleRoleGroup("Roles");
        subjectInfo.setRoles(scRoles);
    }

    // Get group roles of authenticatedSubject and add them into subjectInfo
    Iterator<Principal> principalItr = authenticatedSubject.getPrincipals().iterator();
    while (principalItr.hasNext())
    {
        Principal principal = principalItr.next();
        if (principal instanceof Group)
        {
            Enumeration<? extends Principal> members = ((Group) principal).members();
            while (members.hasMoreElements())
            {
                Principal role = members.nextElement();
                scRoles.addRole(new SimpleRole(role.getName()));
            }
        }
    }
}
```

## Abstract

* Requesting a secured rest resource fails with a _403 Forbidden_ using the setup described in the following. I expected to gain access to the resource just as to the unsecured one, once the jwt bearer token was added to the request. At some point the role infomation are lost (see logging snippet below for details).

## Preface

* Configuration file for keycloak are provided in `export/keycloak`
* Request samples can be imported in postman and are provided in `export/postman`
* This example was mostly built using the examples provided by
  * <https://www.eclipse.org/community/eclipse_newsletter/2017/september/article2.php>
  * <https://github.com/MicroProfileJWT/eclipse-newsletter-sep-2017>
  * <https://github.com/wildfly-swarm/wildfly-swarm-examples/tree/master/security/keycloak>

## Instructions

### Install Keycloak

* Download "demo edition" <https://www.keycloak.org/archive/downloads-3.4.3.html> (here zip-file was used).
* Start with `\keycloak-demo-3.4.3.Final\keycloak\bin>standalone.bat`.
* Open url <http://localhost:8080/auth>.
* Create initial admin (username `admin`, password `password`) and login to administration console.

### Configure Keycloak

* Add realm <http://localhost:8080/auth/admin/master/console/#/create/realm> (name `playground`).
* Add client <http://localhost:8080/auth/admin/master/console/#/create/client/playground> (client id `playground-client`, client protocol `openid-connect`).
  * Edit settings of client and set access type to `bearer-only`.
* Add client <http://localhost:8080/auth/admin/master/console/#/create/client/playground> (client id `playground-auth`, client protocol `openid-connect`).
  * Add protocol mapper `user-realm-role-mapper`(Mapper Type `User Realm Role`, Multivalued `On`, Token Claim Name `groups`, Claim JSON Type `String`).
  * Add protocol mapper `user-property-email-mapper` (Mapper Type `User Property`, Property `email`, Token Claim Name `upn`, Claim JSON Type `String`).
* Add role <http://localhost:8080/auth/admin/master/console/#/realms/playground/roles> (name `user-role`)
* Add role <http://localhost:8080/auth/admin/master/console/#/realms/playground/roles> (name `group-role`)
* Add group <http://localhost:8080/auth/admin/master/console/#/create/group/playground/parent/realm> (name `user-group`)
  * Assign role mapping `group-role`
* Add user <http://localhost:8080/auth/admin/master/console/#/create/user/playground> (username `John Doe`, email `john.doe@example.org`)
  * Set password to `password` (disable temporary)
  * Assign user to group `user-group`

### Obtain token

```bash
curl -X POST \
  http://localhost:8080/auth/realms/playground/protocol/openid-connect/token \
  -H 'Cache-Control: no-cache' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Postman-Token: f04a9ae6-1207-4677-b775-2ef0520127be' \
  -d 'grant_type=password&client_id=playground-auth&username=john%20doe&password=password'
```

#### Example

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "Fb1VGOeFsd13K5p-lF_ccsBpuLvtYNXgUaAMxED-pzc"
}
{
  "jti": "14fc002c-9b08-443d-8a40-587498ca513c",
  "exp": 1524573754,
  "nbf": 0,
  "iat": 1524555754,
  "iss": "http://localhost:8080/auth/realms/playground",
  "aud": "playground-auth",
  "sub": "c7375973-7b28-4e37-bc90-d0dbb72b2102",
  "typ": "Bearer",
  "azp": "playground-auth",
  "auth_time": 0,
  "session_state": "2de9932b-e1ac-4f7c-a5db-1ee3fca656ab",
  "acr": "1",
  "allowed-origins": [],
  "realm_access": {
    "roles": [
      "user-role",
      "group-role",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "upn": "john.doe@example.org",
  "name": "John Doe",
  "groups": [
    "uma_authorization",
    "user-role",
    "offline_access",
    "group-role"
  ],
  "preferred_username": "john doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.org"
}
```

### Build and start example project

```posh
PS playground-mp-jwt-auth> mvn package
PS playground-mp-jwt-auth> java -jar target\playground-mp-jwt-auth-swarm.jar

or debug via

PS playground-mp-jwt-auth>java -agentlib:jdwp=transport=dt_socket,server=y,address=5005,suspend=n -jar target\playground-mp-jwt-auth-swarm.jar
```

### Call /playground/unsecured

```bash
curl -X GET \
  http://localhost:8100/playground/unsecure \
  -H 'Cache-Control: no-cache' \
  -H 'Postman-Token: 011959e0-26f8-4f8e-96ef-9ecc4488f78b'
```

#### Output for /playground/unsecure

```json
{
    "resource": "/unsecure",
    "raw_token": null,
    "iss": null,
    "preferred_username": null,
    "realm_access": "ClaimValueWrapper[@14a73c4], name=realm_access, value[class java.util.Optional]=Optional.empty",
    "securityContext": "No security principal.",
    "jsonWebToken": "No jwt."
}
```

### Call /playground/secured

```bash
curl -X GET \
  http://localhost:8100/playground/secure \
  -H 'Authorization: Bearer eyJhb-snip-n16TwZA' \
  -H 'Cache-Control: no-cache' \
  -H 'Postman-Token: 7143caec-b79b-44de-bb40-e4d88bc9d9de'
```

#### Output for /playground/secured

```html
<html>
    <head>
        <title>Error</title>
    </head>
    <body>Forbidden</body>
</html>
```

```log
DEBUG [org.wildfly.extension.undertow] (default I/O-14) Creating http handler org.wildfly.swarm.microprofile.metrics.runtime.MetricsHttpHandler from module org.wildfly.swarm.microprofile.metrics:runtime with parameters {}
DEBUG [org.wildfly.extension.undertow] (default I/O-14) Creating http handler org.wildfly.swarm.microprofile.health.runtime.SecureHttpContexts from module org.wildfly.swarm.microprofile.health:runtime with parameters {}
DEBUG [io.undertow.request] (default I/O-14) Matched default handler path /playground/secure
DEBUG [org.keycloak.adapters.PreAuthActionsHandler] (default task-1) adminRequest http://localhost:8100/playground/secure
DEBUG [io.undertow.request.security] (default task-1) Security constraints for request /playground/secure are [SingleConstraintMatch{emptyRoleSemantic=PERMIT, requiredRoles=[user-role, mapped-user-role, group-role]}]
DEBUG [io.undertow.request.security] (default task-1) Authenticating required for request HttpServerExchange{ GET /playground/secure request {Postman-Token=[611189ee-a826-41c9-b5bb-9ca9324f44fe], Accept=[*/*], Connection=[keep-alive], Authorization=[Bearer eyJh-snip-TwZA], cache-control=[no-cache], accept-encoding=[gzip, deflate], User-Agent=[PostmanRuntime/7.1.1], Host=[localhost:8100]} response {}}
DEBUG [io.undertow.request.security] (default task-1) Setting authentication required for exchange HttpServerExchange{ GET /playground/secure request {Postman-Token=[611189ee-a826-41c9-b5bb-9ca9324f44fe], Accept=[*/*], Connection=[keep-alive], Authorization=[Bearer eyJh-snip-TwZA], cache-control=[no-cache], accept-encoding=[gzip, deflate], User-Agent=[PostmanRuntime/7.1.1], Host=[localhost:8100]} response {}}
DEBUG [io.undertow.request.security] (default task-1) Attempting to authenticate HttpServerExchange{ GET /playground/secure request {Postman-Token=[611189ee-a826-41c9-b5bb-9ca9324f44fe], Accept=[*/*], Connection=[keep-alive], Authorization=[Bearer eyJh-snip-TwZA], cache-control=[no-cache], accept-encoding=[gzip, deflate], User-Agent=[PostmanRuntime/7.1.1], Host=[localhost:8100]} response {Expires=[0], Cache-Control=[no-cache, no-store, must-revalidate], Pragma=[no-cache]}}, authentication required: true
DEBUG [org.wildfly.extension.undertow] (default task-1) validateRequest for layer [HttpServlet] and applicationContextIdentifier [default-host ]
DEBUG [org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager] (default task-1) Get connection: {}->http://localhost:8080, timeout = 0
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) [{}->http://localhost:8080] total kept alive: 0, total issued: 0, total allocated: 0 out of 20
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) No free connections [{}->http://localhost:8080][null]
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) Available capacity: 20 out of 20 [{}->http://localhost:8080][null]
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) Creating new connection [{}->http://localhost:8080]
DEBUG [org.apache.http.impl.conn.DefaultClientConnectionOperator] (default task-1) Connecting to localhost:8080
DEBUG [org.apache.http.client.protocol.RequestAddCookies] (default task-1) CookieSpec selected: default
DEBUG [org.apache.http.client.protocol.RequestAuthCache] (default task-1) Auth cache not set in the context
DEBUG [org.apache.http.client.protocol.RequestTargetAuthentication] (default task-1) Target auth state: UNCHALLENGED
DEBUG [org.apache.http.client.protocol.RequestProxyAuthentication] (default task-1) Proxy auth state: UNCHALLENGED
DEBUG [org.apache.http.impl.client.DefaultHttpClient] (default task-1) Attempt 1 to execute request
DEBUG [org.apache.http.impl.conn.DefaultClientConnection] (default task-1) Sending request: GET /auth/realms/playground/protocol/openid-connect/certs HTTP/1.1
DEBUG [org.apache.http.wire] (default task-1)  >> "GET /auth/realms/playground/protocol/openid-connect/certs HTTP/1.1[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  >> "Host: localhost:8080[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  >> "Connection: Keep-Alive[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  >> "[\r][\n]"
DEBUG [org.apache.http.headers] (default task-1) >> GET /auth/realms/playground/protocol/openid-connect/certs HTTP/1.1
DEBUG [org.apache.http.headers] (default task-1) >> Host: localhost:8080
DEBUG [org.apache.http.headers] (default task-1) >> Connection: Keep-Alive
DEBUG [org.apache.http.wire] (default task-1)  << "HTTP/1.1 200 OK[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Connection: keep-alive[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Cache-Control: no-cache[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "X-Powered-By: Undertow/1[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Server: WildFly/11[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Content-Type: application/json[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Content-Length: 462[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "Date: Tue, 24 Apr 2018 07:54:02 GMT[\r][\n]"
DEBUG [org.apache.http.wire] (default task-1)  << "[\r][\n]"
DEBUG [org.apache.http.impl.conn.DefaultClientConnection] (default task-1) Receiving response: HTTP/1.1 200 OK
DEBUG [org.apache.http.headers] (default task-1) << HTTP/1.1 200 OK
DEBUG [org.apache.http.headers] (default task-1) << Connection: keep-alive
DEBUG [org.apache.http.headers] (default task-1) << Cache-Control: no-cache
DEBUG [org.apache.http.headers] (default task-1) << X-Powered-By: Undertow/1
DEBUG [org.apache.http.headers] (default task-1) << Server: WildFly/11
DEBUG [org.apache.http.headers] (default task-1) << Content-Type: application/json
DEBUG [org.apache.http.headers] (default task-1) << Content-Length: 462
DEBUG [org.apache.http.headers] (default task-1) << Date: Tue, 24 Apr 2018 07:54:02 GMT
DEBUG [org.apache.http.impl.client.DefaultHttpClient] (default task-1) Connection can be kept alive indefinitely
DEBUG [org.apache.http.wire] (default task-1)  << "{"keys":[{"kid":"Fb1VGOeFsd13K5p-lF_ccsBpuLvtYNXgUaAMxED-pzc","kty":"RSA","alg":"RS256","use":"sig","n":"hWSgnHgKgolEX8dMeC1681GoNdfo9A8IGCrPogOTKvKC9I31nskqBgkfxdcl0ahup1QQMnBCegd4Wwy_3YIZlYtl1HY5mplzc4SertJAtHRPc76_63QffzOg3QRv6F2cnBL_hQDx6HyV-PMeY0r1Jn-2DzK89TJKs7_o-vEbgXyTU12BHC_wT98-zdVCInRnImN9OI1B4yHnLRig9-Qsz0hSZ3duRoeLDg5aFzZximaYhvYd4DuvagLGd-MdGIvXFVT5w9H9YkI4v3_b2VaTO-Glrgo9iEFOq3h2OM0KoQygbL8r0E__91b5ePdI-Xdfl06O77EjhUbUdKcx4LfELQ","e":"AQAB"}]}"
DEBUG [org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager] (default task-1) Released connection is reusable.
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) Releasing connection [{}->http://localhost:8080][null]
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) Pooling connection [{}->http://localhost:8080][null]; keep alive indefinitely
DEBUG [org.apache.http.impl.conn.tsccm.ConnPoolByRoute] (default task-1) Notifying no-one, there are no waiting threads
DEBUG [org.keycloak.adapters.rotation.JWKPublicKeyLocator] (default task-1) Realm public keys successfully retrieved for client playground-client. New kids: [Fb1VGOeFsd13K5p-lF_ccsBpuLvtYNXgUaAMxED-pzc]
DEBUG [io.undertow.request.security] (default task-1) Authenticated as c7375973-7b28-4e37-bc90-d0dbb72b2102, roles [user-role, group-role, uma_authorization]
DEBUG [org.keycloak.adapters.wildfly.WildflyRequestAuthenticator] (default task-1) propagate security context to wildfly
DEBUG [org.keycloak.adapters.RequestAuthenticator] (default task-1) User 'c7375973-7b28-4e37-bc90-d0dbb72b2102' invoking 'http://localhost:8100/playground/secure' on client 'playground-client'
DEBUG [org.keycloak.adapters.RequestAuthenticator] (default task-1) Bearer AUTHENTICATED
DEBUG [io.undertow.request.security] (default task-1) Authenticated as c7375973-7b28-4e37-bc90-d0dbb72b2102, roles []
DEBUG [io.undertow.request.security] (default task-1) Authentication outcome was AUTHENTICATED with method org.wildfly.extension.undertow.security.jaspi.JASPICAuthenticationMechanism@c2a8eb for HttpServerExchange{ GET /playground/secure request {Postman-Token=[611189ee-a826-41c9-b5bb-9ca9324f44fe], Accept=[*/*], Connection=[keep-alive], Authorization=[Bearer eyJh-snip-TwZA], cache-control=[no-cache], accept-encoding=[gzip, deflate], User-Agent=[PostmanRuntime/7.1.1], Host=[localhost:8100]} response {Expires=[0], Cache-Control=[no-cache, no-store, must-revalidate], Pragma=[no-cache]}}
DEBUG [io.undertow.request.security] (default task-1) Authentication result was AUTHENTICATED for HttpServerExchange{ GET /playground/secure request {Postman-Token=[611189ee-a826-41c9-b5bb-9ca9324f44fe], Accept=[*/*], Connection=[keep-alive], Authorization=[Bearer eyJh-snip-TwZA], cache-control=[no-cache], accept-encoding=[gzip, deflate], User-Agent=[PostmanRuntime/7.1.1], Host=[localhost:8100]} response {Expires=[0], Cache-Control=[no-cache, no-store, must-revalidate], Pragma=[no-cache]}}
DEBUG [io.undertow.request] (default task-1) Matched default handler path /playground/secure
DEBUG [org.keycloak.adapters.AuthenticatedActionsHandler] (default task-1) AuthenticatedActionsValve.invoke http://localhost:8100/playground/secure
DEBUG [org.keycloak.adapters.AuthenticatedActionsHandler] (default task-1) Policy enforcement is disabled.
DEBUG [org.wildfly.extension.undertow] (default task-1) secureResponse for layer [HttpServlet] and applicationContextIdentifier [default-host ].
```

This part is interesting - the roles are set at some time, but after passing the security context they're gone.

```posh
DEBUG [io.undertow.request.security] (default task-1) Authenticated as c7375973-7b28-4e37-bc90-d0dbb72b2102, roles [user-role, group-role, uma_authorization]
DEBUG [org.keycloak.adapters.wildfly.WildflyRequestAuthenticator] (default task-1) propagate security context to wildfly
DEBUG [org.keycloak.adapters.RequestAuthenticator] (default task-1) User 'c7375973-7b28-4e37-bc90-d0dbb72b2102' invoking 'http://localhost:8100/playground/secure' on client 'playground-client'
DEBUG [org.keycloak.adapters.RequestAuthenticator] (default task-1) Bearer AUTHENTICATED
DEBUG [io.undertow.request.security] (default task-1) Authenticated as c7375973-7b28-4e37-bc90-d0dbb72b2102, roles []
```

The eclipse newsletter example outputs:

```posh
DEBUG [io.undertow.request.security] (default task-1) Authenticated as jdoe@example.com, roles [Debtor, ViewBalance, BigSpender, Creditor]
DEBUG [io.undertow.request.security] (default task-1) Authenticated caller(jdoe@example.com) for path(/wallet/balance) with roles: [Debtor, ViewBalance, BigSpender, Creditor]
DEBUG [io.undertow.request.security] (default task-1) Authenticated as jdoe@example.com, roles [Debtor, ViewBalance, BigSpender, Creditor]
```

## Observations

* Neither declaring the security constraints in the `web.xml` nor in `project-default.yml` changes anything. Should be covered by the annotations anyway?
* Setting `@DenyAll` within the endpoint permits the call of `/playground/unsecured` as expected.

## Questions

1) Am I doing something completely wrong?
2) Can you spot a faulty configuration?
3) What exactly does `microprofile: jwtauth: token:` do?
