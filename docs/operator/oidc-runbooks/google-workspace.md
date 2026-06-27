# Google Workspace OIDC Runbook

Google Workspace can authenticate the user, but direct Google OIDC does not emit a
groups claim. For trstctl, the recommended production pattern is to broker Google
through Keycloak or Authentik. Google performs the human login; the broker emits the
tenant and group claims that trstctl needs.

## IdP Setup

1. Complete the [Keycloak](keycloak.md) or [Authentik](authentik.md) runbook first
   with a local test user.
2. In Google Cloud, create an OAuth web client for the broker.
3. Set the Google redirect URI to the broker callback, for example:
   `https://keycloak.example.com/realms/platform-prod/broker/google/endpoint`.
4. In the broker, add Google as an upstream identity provider.
5. Restrict the Google OAuth consent screen to your Workspace domain.
6. In the broker, assign Google-federated users to groups such as
   `trstctl-operators`.
7. In the broker's trstctl client, keep the redirect URI as
   `https://trstctl.example.com/auth/callback`.
8. Configure the broker, not Google, to send back-channel logout tokens to
   `https://trstctl.example.com/auth/oidc/back-channel-logout` when supported.

From trstctl's view, the issuer is the broker issuer. For Keycloak:

```text
https://keycloak.example.com/realms/platform-prod
```

## trstctl Settings

Store the broker client secret in the encrypted tenant-scoped credential store under
`(tenant-prod, auth.oidc, google-broker-prod, client_secret)`. Then configure
trstctl against the broker:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/platform-prod
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=google-broker-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/auth
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://keycloak.example.com/realms/platform-prod/protocol/openid-connect/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/google-broker-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

This keeps trstctl's OIDC implementation simple and fail-closed: it sees a normal
confidential client, PKCE S256, a broker issuer, a broker JWKS, and a groups claim
from the broker. It never needs a privileged Google Directory API call during login.

## Verification

Start `/auth/login`. trstctl redirects to the broker with PKCE S256, state, nonce,
and the configured callback. The broker redirects the user to Google, receives the
Google callback, resolves broker-side groups, and returns to `/auth/callback`.
trstctl checks the authorization response `iss` from the broker and maps the broker
`groups` claim to one trstctl tenant.

Back-channel logout depends on the broker. If Keycloak or Authentik can post logout
tokens, configure `/auth/oidc/back-channel-logout`; Google direct sign-out does not
clear the trstctl session by itself.

## Troubleshooting

- If a user logs in at Google but has no trstctl role, check group assignment in the
  broker, not Google Workspace.
- If Google returns `redirect_uri_mismatch`, fix the broker callback URL in the
  Google OAuth client.
- If trstctl issuer verification fails, remember that
  `TRSTCTL_AUTH_OIDC_ISSUER` must be the broker issuer, not
  `https://accounts.google.com`.

See the shared [OIDC runbook index](index.md) for the common hardening model.
