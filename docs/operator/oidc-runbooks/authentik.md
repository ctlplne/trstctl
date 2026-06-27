# Authentik OIDC Runbook

Authentik works well with trstctl because it can emit a simple `groups` claim through
OAuth2/OpenID property mappings. Treat Authentik as the IdP and trstctl as a
confidential client.

## IdP Setup

1. In Authentik, create an **OAuth2/OpenID Provider** named `trstctl-web`.
2. Set **Client type** to **Confidential** and save the generated client secret.
3. Set the redirect URI to exactly `https://trstctl.example.com/auth/callback`.
4. Set the signing key to an RSA or ECDSA key that appears in Authentik's JWKS.
5. Create an Application with slug `trstctl` and attach the provider.
6. Add or verify a property mapping that emits groups:

   ```python
   return [group.name for group in user.ak_groups.all()]
   ```

7. Include the `groups` scope in the provider so the mapping reaches the ID token.
8. Add the back-channel logout URL when your Authentik version exposes it:
   `https://trstctl.example.com/auth/oidc/back-channel-logout`.

The usual issuer for application slug `trstctl` is:

```text
https://authentik.example.com/application/o/trstctl/
```

## trstctl Settings

Store the Authentik client secret in the encrypted tenant-scoped credential store
under `(tenant-prod, auth.oidc, authentik-prod, client_secret)`. Then set:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://authentik.example.com/application/o/trstctl/
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=authentik-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://authentik.example.com/application/o/authorize/
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://authentik.example.com/application/o/token/
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/authentik-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

Fetch the JWKS document from Authentik's discovery metadata and write it to
`TRSTCTL_AUTH_OIDC_JWKS_FILE`. Keep the file owned by the trstctl service account and
rotate it whenever the Authentik signing key changes.

## Verification

Open `/auth/login` and confirm the Authentik authorize URL contains PKCE S256, a
nonce, and state. After callback, trstctl validates the ID token, checks the
authorization response `iss`, resolves the `groups` claim, and creates one
tenant-scoped session.

Back-channel logout uses the same `/auth/oidc/back-channel-logout` endpoint as every
other provider. If Authentik cannot send logout tokens in your version, keep the
session TTL short and rely on `/auth/logout` for user-initiated logout.

## Troubleshooting

- Authentik issuer URLs are sensitive to the trailing slash. Match
  `TRSTCTL_AUTH_OIDC_ISSUER` to the `issuer` value in discovery metadata.
- If `groups` is missing, the property mapping exists but is not included in the
  provider scopes. Add the `groups` scope and try a fresh login.
- If token verification fails after a signing-key change, refresh the JWKS file named
  by `TRSTCTL_AUTH_OIDC_JWKS_FILE`.

See the shared [OIDC runbook index](index.md) for the common hardening model.
