# Okta OIDC Runbook

Okta can serve trstctl from either the org authorization server or a custom
authorization server. Use a custom authorization server such as
`/oauth2/default` when you need a `groups` claim, because that is where Okta exposes
claim rules.

## IdP Setup

1. Create an **OIDC - OpenID Connect** app integration.
2. Choose **Web Application** so the app is a confidential client.
3. Enable the **Authorization Code** grant. Do not use implicit flow.
4. Set **Sign-in redirect URIs** to
   `https://trstctl.example.com/auth/callback`.
5. Copy the Client ID and Client secret.
6. Assign the app to the Okta groups allowed to use trstctl.
7. In **Security -> API -> Authorization Servers -> default -> Claims**, add a
   `groups` claim:
   - Token type: ID token
   - Value type: Groups
   - Filter: `trstctl-.*`
   - Include in: Any scope
8. Add a back-channel logout URI when your Okta tenant exposes the feature:
   `https://trstctl.example.com/auth/oidc/back-channel-logout`.

The default custom authorization server issuer is:

```text
https://your-org.okta.com/oauth2/default
```

## trstctl Settings

Store the Okta client secret in the encrypted tenant-scoped credential store under
`(tenant-prod, auth.oidc, okta-prod, client_secret)`. Then configure:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://your-org.okta.com/oauth2/default
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=0oaexampleclientid
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=okta-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://your-org.okta.com/oauth2/default/v1/authorize
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://your-org.okta.com/oauth2/default/v1/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/okta-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

For the org authorization server, remove `/oauth2/default` from the issuer and use
the org server's authorize, token, and JWKS endpoints. Keep every value byte-for-byte
aligned with Okta discovery metadata.

## Verification

Start `/auth/login`. Okta should receive an authorization-code request with PKCE S256.
After `/auth/callback`, trstctl checks the authorization response `iss`, verifies the
ID token against the Okta JWKS, and maps one Okta group to one trstctl tenant role.

Back-channel logout, when enabled in Okta, targets
`/auth/oidc/back-channel-logout`. trstctl validates the logout token before clearing
matching sessions.

## Troubleshooting

- If Okta says the user is not assigned to the application, assign the user or the
  user's `trstctl-*` group to the app integration.
- If the ID token has no groups, check the authorization-server claim rule. The app
  assignment and the claim filter are separate controls.
- If issuer validation fails, compare `TRSTCTL_AUTH_OIDC_ISSUER` with the discovery
  document's `issuer` value. Do not add or remove a trailing slash.

See the shared [OIDC runbook index](index.md) for the common hardening model.
