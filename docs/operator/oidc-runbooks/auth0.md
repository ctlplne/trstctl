# Auth0 OIDC Runbook

Auth0 requires custom claims to use a URL-shaped namespace. Register trstctl as a
confidential client, then make the group claim look like
`https://trstctl.example.com/auth/groups`, not bare `groups`. The values inside the
claim are still normal group names.

## IdP Setup

1. Create an Auth0 **Regular Web Application** named `trstctl-web`.
2. Keep **Token Endpoint Authentication Method** on a confidential-client method.
3. Set **Allowed Callback URLs** to exactly
   `https://trstctl.example.com/auth/callback`.
4. Set **Allowed Web Origins** to `https://trstctl.example.com`.
5. Add the back-channel logout URL if your Auth0 plan and tenant settings expose it:
   `https://trstctl.example.com/auth/oidc/back-channel-logout`.
6. Pick a namespace, for example `https://trstctl.example.com/auth/`.
7. Create a Login Action that reads your chosen group source and writes a namespaced
   ID-token claim:

   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const groups = (event.user.app_metadata && event.user.app_metadata.groups) || [];
     api.idToken.setCustomClaim("https://trstctl.example.com/auth/groups", groups);
   };
   ```

8. Attach the Action to the Login flow and test that the ID token contains the claim.

The issuer includes the trailing slash:

```text
https://example-tenant.us.auth0.com/
```

## trstctl Settings

Store the Auth0 client secret in the encrypted tenant-scoped credential store under
`(tenant-prod, auth.oidc, auth0-prod, client_secret)`. Then configure:

```sh
export TRSTCTL_AUTH_OIDC_ENABLED=true
export TRSTCTL_AUTH_OIDC_ISSUER=https://example-tenant.us.auth0.com/
export TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED=true
export TRSTCTL_AUTH_OIDC_CLIENT_ID=auth0-client-id
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT=tenant-prod
export TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF=auth0-prod
export TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT=https://example-tenant.us.auth0.com/authorize
export TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT=https://example-tenant.us.auth0.com/oauth/token
export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
export TRSTCTL_AUTH_OIDC_JWKS_FILE=/etc/trstctl/oidc/auth0-jwks.json
export TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE=/var/lib/trstctl/oidc-session.key
export TRSTCTL_AUTH_OIDC_TENANT_CLAIM=tenant
export TRSTCTL_AUTH_OIDC_GROUPS_CLAIM=https://trstctl.example.com/auth/groups
```

The namespaced group claim is configured through
`TRSTCTL_AUTH_OIDC_GROUPS_CLAIM`. Leave `TRSTCTL_AUTH_OIDC_TENANT_CLAIM` unset unless
you also emit a real tenant claim from an Action.

## Verification

Start `/auth/login` and inspect the Auth0 authorize URL. It must carry PKCE S256,
state, nonce, and `redirect_uri=https://trstctl.example.com/auth/callback`. After the
callback, trstctl verifies the ID token, checks the authorization response `iss`, and
reads the namespaced groups claim as one literal claim key.

If back-channel logout is enabled, Auth0 sends logout tokens to
`/auth/oidc/back-channel-logout`; trstctl verifies those tokens before session
revocation. If your Auth0 tenant does not support back-channel logout, rely on
`/auth/logout` plus short browser-session TTLs.

## Troubleshooting

- If groups are visible at jwt.io but trstctl maps no roles, check that
  `TRSTCTL_AUTH_OIDC_GROUPS_CLAIM` is the full namespaced URL.
- If Auth0 strips the claim, the Action used a non-namespaced key. Auth0 requires URL
  shape for custom claims.
- If issuer validation fails, keep the trailing slash in
  `TRSTCTL_AUTH_OIDC_ISSUER`; Auth0 emits it in the `iss` claim.

See the shared [OIDC runbook index](index.md) for the common hardening model.
