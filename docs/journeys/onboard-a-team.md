# Onboard a team as a tenant

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `tenant_rls`, `oidc`, `rbac`, `policy`, `audit_export`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

You will give a team its own isolated slice of trstctl: a tenant whose data no other
team can read, browser sign-in through your existing identity provider, roles that
decide who can do what, a default-deny policy on the dangerous actions, and a
tamper-evident record of everything that happens. The outcome is a team that logs in
with its own accounts, holds exactly the permissions it should, and leaves an audit
trail you can hand to a security reviewer. This is for an operator setting up a new
group on a shared trstctl deployment.

## Before you start

- A running control plane and an admin API token from
  [Getting started](../getting-started.md) (`trstctl token create` mints the first
  one; it deliberately cannot self-issue certificates).
- The CLI pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
- An OpenID Connect, SAML 2.0, or LDAP / Active Directory provider (Entra ID, Okta,
  Ping, Google, Keycloak, OpenLDAP, AD, and the like) if you want browser sign-in. See
  [Platform & API](../features/platform-and-api.md).
- A SCIM-capable identity provider if you want automatic user provisioning and
  deprovisioning. The same providers that handle SSO commonly expose SCIM 2.0.

## Steps

1. Pick a tenant id for the team and mint a tenant-scoped token. Isolation between
   tenants is enforced by the database itself, so one team can never read another's
   data — see [Platform & API](../features/platform-and-api.md).

   ```sh
   trstctl token create --tenant 22222222-2222-2222-2222-222222222222 --subject payments-team
   # -> prints a trst_... token once. Store it now.
   ```

   -> you have a credential confined to the new tenant; every CLI/API call with it acts
   only on that team's data.

2. Wire browser sign-in to your identity provider. For OIDC, set the issuer, client
   id, and redirect URI. For SAML, set the SP entity ID, metadata URL, ACS URL, and
   IdP metadata file. For LDAP / Active Directory, set the directory URL, user lookup
   or direct-bind template, group search, and session-secret file. The callback
   verifies the OIDC id_token, SAML signature, or LDAP bind before minting an
   `HttpOnly` session cookie. See [Platform & API](../features/platform-and-api.md).

   ```yaml
   auth:
     oidc:
       enabled: true
     saml:
       enabled: false
     ldap:
       enabled: false
   ```

   ```sh
   export TRSTCTL_AUTH_OIDC_ISSUER=https://login.example.com/
   export TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web
   export TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback
   ```

   -> a user visiting the UI is redirected to your provider, signs in, and returns with
   a session that authorizes API calls under the same roles as a token. An enabled but
   incomplete OIDC, SAML, or LDAP block fails closed at startup.

3. Map each signed-in user to the right tenant so two users in different teams see only
   their own data. Use a configurable id_token/SAML claim, an LDAP group mapping, or an
   explicit subject/claim/group mapping; a user who maps to no tenant is rejected. See
   [Platform & API](../features/platform-and-api.md).

   ```yaml
   auth:
     oidc:
       tenant_claim: "tenant"
   ```

   -> each browser session is confined to its mapped tenant; cross-team leakage is
   denied at the database layer.

4. Turn on SCIM provisioning if the IdP should manage team membership. Create one
   high-entropy bearer token per tenant, store it in a root-readable secret file, and
   point the IdP at `/scim/v2`. The token is tenant-bound in trstctl config; SCIM
   payloads do not choose the tenant.

   ```yaml
   auth:
     scim:
       enabled: true
       tokens:
         - name: okta-payments
           tenant_id: 22222222-2222-2222-2222-222222222222
           token_file: /etc/trstctl/scim/okta-payments.token
   ```

   Configure IdP groups to match trstctl role names (`admin`, `operator`, `viewer`,
   `auditor`, `ra-officer`). When the IdP adds Alice to the `viewer` group, SCIM writes
   that role into Alice's tenant membership; when the IdP sends `active:false` or
   DELETE, Alice is offboarded and her session loses access on the next request.

   -> membership changes in the IdP become live trstctl RBAC changes without a manual
   role edit.

5. Decide who can do what with roles. trstctl ships `admin`, `operator`, `viewer`,
   `auditor`, and `ra-officer` (which can request but not self-issue certificates).
   The required permission is checked on every route and returns `403` on failure. See
   [Policy & governance](../features/policy-and-governance.md).

   -> a `viewer` can read inventory but not mint; an `ra-officer` can request a
   certificate but cannot issue it — the registration-authority separation, enforced,
   not assumed.

6. Turn on default-deny policy for the dangerous actions and require a second approver.
   With the policy gate enabled, every issue, deploy, and revoke is denied unless your
   Rego explicitly allows it, and a privileged action needs a *distinct* approver
   (self-approval is rejected). See [Policy & governance](../features/policy-and-governance.md).

   ```yaml
   ca:
     policy:
       enabled: true
       require_approval: true
   ```

   A minimal default-deny policy:

   ```text
   package trstctl.policy
   default allow = false
   allow { input.action == "revoke" }
   allow { input.action == "issue"; input.profile != "" }
   ```

   -> issuance now requires both a bound profile and a second person, and an approval is
   recorded via `POST /api/v1/identities/{id}/approvals`.

7. Add an ABAC deny overlay for runtime guardrails. RBAC says who may issue; ABAC says
   whether this exact request is allowed right now. Use it for attributes such as
   environment, identity tags, current UTC hour, or an operator-set change-window flag.

   ```yaml
   auth:
     abac:
       enabled: true
       environment:
         change_window: "false"
       module: |
         package trstctl.abac
         default deny := false
         default reason := ""
         deny if {
           input.permission == "certs:issue"
           input.resource.env == "prod"
           input.env.change_window != "true"
         }
         reason := "prod certificates may issue only during a change window" if {
           deny
         }
   ```

   -> a caller with `certs:issue` can still issue staging credentials, but a prod
   identity tagged `env=prod` is denied until `change_window=true` is set in
   `auth.abac.environment`. The ABAC module is deny-only and fail-closed.

8. Confirm the trail. Every action is recorded as an immutable, hash-chained event, and
   you can export a signed evidence bundle for a reviewer. See
   [Policy & governance](../features/policy-and-governance.md).

   ```sh
   trstctl-cli audit events --type policy.abac.decision --since 2026-01-01T00:00:00Z --limit 100
   trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z
   ```

   -> you can show exactly who did what, when, and that the record was not altered
   (any tampering breaks the chain).

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — bring the team's
  existing certificates under trstctl.
- [manage-secrets.md](manage-secrets.md) — give the team's apps managed secrets.

**Journey:** J6
**Steps through:** F40, F8, F13, SCIM 2.0, F28, F29, F9, F58
