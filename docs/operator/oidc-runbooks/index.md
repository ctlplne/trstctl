# OIDC runbooks

These runbooks wire browser sign-on to the served trstctl OIDC path:
`/auth/login` starts the flow, `/auth/callback` completes it, `/auth/me` reads the
session, `/auth/logout` clears the session, and `/auth/oidc/back-channel-logout`
accepts logout tokens from providers that support back-channel logout.

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
