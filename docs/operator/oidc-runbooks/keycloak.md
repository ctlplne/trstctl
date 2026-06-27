# Keycloak OIDC Runbook

Keycloak is the reference self-hosted IdP for trstctl. Use a dedicated realm and a
confidential client registered as OpenID Connect. Do not share the Keycloak `master`
realm with production trstctl login.

## IdP Setup

1. Create or choose a realm, for example `platform-prod`.
2. Create an OpenID Connect client named `trstctl-web`.
3. Enable **Client authentication** so the client is confidential.
4. Enable **Standard flow**. Leave implicit flow and direct access grants off.
5. Set **Valid redirect URIs** to exactly
   `https://trstctl.example.com/auth/callback`.
6. Set the PKCE policy to **S256** when your Keycloak version exposes that knob.
   trstctl always sends PKCE S256.
7. Add the back-channel logout URL:
   `https://trstctl.example.com/auth/oidc/back-channel-logout`.
8. Add a group-membership mapper on the client scope:
   - Token claim name: `groups`
   - Full group path: off
   - Add to ID token: on
9. Create groups such as `trstctl-admins`, `trstctl-operators`, and
   `trstctl-viewers`, then assign users to those groups.

The issuer is the realm URL:

```text
https://keycloak.example.com/realms/platform-prod
```

The authorization and token endpoints are the realm protocol endpoints:

```text
https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/auth
https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/token
```

## trstctl Settings

First store the Keycloak client secret in the encrypted tenant-scoped credential store
under `(tenant-prod, auth.oidc, keycloak-prod, client_secret)`. Then configure
the control plane:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/platform-prod
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=keycloak-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/auth
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/keycloak-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

Download the JWKS from:

```text
https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/certs
```

Set `TRSTCTL_AUTH_OIDC_TENANT_CLAIM` only if Keycloak stamps the real trstctl
tenant id into the token. Otherwise map Keycloak subjects or groups in the auth
tenant mapping table. Group-based mapping is the usual production shape.

## Verification

Open `/auth/login`. The browser should redirect to Keycloak with `response_type=code`,
`code_challenge_method=S256`, `state`, `nonce`, and the configured redirect URI. After
login, Keycloak redirects to `/auth/callback`; trstctl verifies the token, checks the
authorization response `iss`, maps the user to one tenant, and mints the normal secure
browser session.

For logout, clear the trstctl session with `/auth/logout`. When Keycloak is configured
for back-channel logout, it can also post a logout token to
`/auth/oidc/back-channel-logout`; trstctl verifies that token against the same issuer,
audience, and JWKS.

## Troubleshooting

- If login fails before the token exchange, compare the redirect URI in Keycloak with
  `TRSTCTL_AUTH_OIDC_REDIRECT_URI` byte for byte.
- If every user lands in a no-tenant or no-role failure, decode the ID token and check
  the `groups` claim. The mapper must emit simple group names, not `/full/path`.
- If key rotation breaks login, refresh the file pointed at by
  `TRSTCTL_AUTH_OIDC_JWKS_FILE` from the Keycloak certs endpoint and restart or reload
  the deployment according to your operations runbook.

See the shared [OIDC runbook index](index.md) for the common hardening model.
