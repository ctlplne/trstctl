# OIDC runbooks

These runbooks wire browser sign-on to the served trstctl OIDC path:
`/auth/login` starts the flow, `/auth/callback` completes it, `/auth/me` reads the
session, `/auth/logout` clears the session, and `/auth/oidc/back-channel-logout`
accepts logout tokens from providers that support back-channel logout.

OIDC logout matches the verified issuer and client, then the IdP subject and
`sid` when present. The `sid` is the IdP's identifier; it is not the trstctl
browser-cookie identifier. SAML and LDAP browser sessions sharing a username
are outside that match. A subject-only assertion revokes sessions whose ID
token was issued no later than the logout assertion; a `sid` assertion revokes
that exact IdP session. When both claims exist, both must match. The receiver
finds matching sessions through an indexed, provider-bound locator even when
the user's tenant came from an ID-token claim. It commits revocation and an
exact signed-assertion receipt together, so an identical retry after a lost
response succeeds while a changed assertion reusing the JTI is refused. A
callback carrying an ID token issued before the logout is refused. These
receipts are included in PostgreSQL backup and restore. The locator contains
only digests and is removed with the tenant or subject; it is rebuilt by a
new login, not restored from backup.

The locator migration makes already-issued OIDC cookies reauthenticate once.
Those cookies have no recoverable global subject binding, so the new server
rejects them instead of claiming an IdP logout reached them. SAML and LDAP
cookies remain in their own auth-method scope.

The local evaluation IdP can issue a signed logout assertion for its own
authenticated browser session at `/backchannel/logout-token`. Its HTML form
binds a single-use challenge to that IdP session; a stock client can POST the
returned `logout_token` to trstctl's `/auth/oidc/back-channel-logout` endpoint.
Keep the assertion in a private file during testing and omit it from screenshots
and reports. The same challenge returns the same signed assertion after a lost
response, and cannot be changed to a broader scope. This fixture is local QA
support; production IdPs send their own signed logout assertions.

Every provider page uses the same hardened shape:

- trstctl is a **confidential client**. Store the client secret in the encrypted
  tenant-scoped credential store and point the server at that secret with
  `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT` plus
  `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF`.
- The authorization request uses **PKCE S256**, random `state`, and a random
  `nonce`. PKCE is not optional.
- If the IdP advertises RFC 9207, turn on the authorization response `iss` check
  with `TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true`.
- The ID token must verify against the configured issuer, audience, nonce, time
  window, and JWKS.
- A user must map to exactly one tenant through a tenant claim, group mapping, or
  explicit single-tenant fallback. Missing mapping fails the login closed.

## Pick The Provider

| Provider | Issuer shape | Group claim shape | Runbook |
| --- | --- | --- | --- |
| Keycloak | `https://<host>/realms/<realm>` | `groups` string array | [keycloak.md](keycloak.md) |
| Authentik | `https://<host>/application/o/<slug>/` | `groups` string array from a property mapping | [authentik.md](authentik.md) |
| Okta | `https://<org>.okta.com/oauth2/default` or org issuer | `groups` string array from an authorization-server claim | [okta.md](okta.md) |
| Auth0 | `https://<tenant>.auth0.com/` | namespaced URL claim, for example `https://trstctl.example.com/auth/groups` | [auth0.md](auth0.md) |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | `groups` string array of object IDs | [entra-id.md](entra-id.md) |
| Google Workspace | broker through Keycloak or Authentik | direct Google tokens do not carry groups | [google-workspace.md](google-workspace.md) |

## Common trstctl Settings

Each provider page repeats a concrete block with the real
`TRSTCTL_AUTH_OIDC_*` settings. The exact URLs change per IdP, but the knobs are the
same:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://idp.example.com/issuer
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=primary-oidc
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://idp.example.com/oauth2/v1/authorize
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://idp.example.com/oauth2/v1/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/idp-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

Use `TRSTCTL_AUTH_OIDC_JWKS_JSON` only when your deployment mechanism can safely
inject the JWKS document without shell history or process-list leakage. File-based
JWKS is easier to rotate and audit.

See [Configuration](../../configuration.md) for the complete browser SSO variable
table and [Platform & API](../../features/platform-and-api.md) for the served auth
surface.
