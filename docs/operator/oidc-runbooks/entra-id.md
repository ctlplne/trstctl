# Microsoft Entra ID OIDC Runbook

Microsoft Entra ID works with trstctl through the v2.0 OIDC endpoint. Register
trstctl as a confidential client. The important operator detail is that Entra's
`groups` claim usually carries group object IDs, not human names. Map those object IDs
to trstctl roles.

## IdP Setup

1. In the Entra admin center, create an **App registration** named `trstctl-web`.
2. Choose a single-tenant app unless you intentionally serve multiple Entra tenants.
3. Add a **Web** redirect URI:
   `https://trstctl.example.com/auth/callback`.
4. Create a client secret and record it in your secret intake process.
5. In **Token configuration**, add a groups claim:
   - Group type: Security groups or groups assigned to the application
   - Token type: ID token
   - Format: Group ID
6. Optionally add `email` as an ID-token optional claim.
7. Under the Enterprise Application, require assignment and assign the allowed
   operator groups.
8. Add the back-channel logout URL if your tenant exposes back-channel logout:
   `https://trstctl.example.com/auth/oidc/back-channel-logout`.

The issuer is:

```text
https://login.microsoftonline.com/<tenant-id>/v2.0
```

## trstctl Settings

Store the Entra client secret in the encrypted tenant-scoped credential store under
`(tenant-prod, auth.oidc, entra-prod, client_secret)`. Then configure:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=11111111-1111-1111-1111-111111111111
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=entra-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/authorize
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/entra-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tid
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=groups
```

Use `TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tid` only when the Entra tenant ID is mapped to
the correct trstctl tenant. Otherwise use explicit subject or group mappings.

## Verification

Start `/auth/login`. Entra receives an authorization-code request with PKCE S256,
state, and nonce. After `/auth/callback`, trstctl validates the ID token, checks the
authorization response `iss`, and maps the `groups` object IDs to tenant roles.

For back-channel logout, Entra posts to `/auth/oidc/back-channel-logout` when the
feature is enabled. trstctl verifies the logout token using the same issuer, client
ID, and JWKS used for ID tokens.

## Troubleshooting

- If the token contains `hasgroups` instead of `groups`, the user has too many group
  memberships for the ID token. Prefer "Groups assigned to the application" to bound
  the claim.
- If role mapping fails, confirm the mapping uses Entra object IDs, not display names.
- If issuer validation fails, ensure `TRSTCTL_AUTH_OIDC_ISSUER` ends in `/v2.0` and
  has no trailing slash after it.

See the shared [OIDC runbook index](index.md) for the common hardening model.
