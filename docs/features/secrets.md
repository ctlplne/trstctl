# Secrets — store, issue, rotate, and encrypt the credentials machines use

## What it is

A [secret](../glossary.md) is any sensitive value software needs but shouldn't expose:
a database password, an API token, an encryption key. trstctl is a full secrets
platform alongside its certificate work: it stores secrets encrypted, hands out
short-lived ones on demand, rotates them safely, encrypts data on behalf of apps,
syncs secrets to other platforms, and governs who can read or change them.

The mental model: think of a bank. The **vault** stores valuables encrypted (the secret
store). The **safe-deposit clerk** issues a temporary key that self-destructs after an
hour (dynamic secrets). The **armored-car service** moves valuables to other branches
(secret sync). The **teller window** encrypts your deposit without you ever seeing the
master key (encryption-as-a-service). And every action needs ID and is logged
(auth + approvals + audit).

> **One honest note up front.** Most of the _secrets_ domain is now **served** on the
> running control plane: the secret store (CRUD + rotation), dynamic secret leases,
> one-time secret sharing, the dynamic PKI secret, machine login, secret-sync, secret
> scanning, workload injection, ephemeral API keys, and the Vault/OpenBao common
> compatibility paths are all mounted. The `/api/v1/secrets/*` surface is off by default
> (`secrets.enable_api`) and fail-closed when off; ephemeral API keys live under
> `/api/v1/ephemeral/api-keys` since they mint tenant credentials, not stored secret
> values. Transit encryption-as-a-service is served separately at `/api/v1/transit/*`
> (`transit` CLI group, `keys:*` RBAC scopes). KMIP is served as an opt-in mTLS
> listener (`protocols.kmip.*`) for AES-256 SymmetricKey Create/Get/Locate/Revoke/Destroy
> and for RSA and ECDSA key pairs that are activated, sign and verify on the server,
> with client attributes; remaining gaps are in [Current limitations](../limitations.md).

## Why it exists

Leaked secrets are one of the most common breach causes: the traditional approach —
long-lived secrets copied into config files, environment variables, images, and CI —
spreads them everywhere and never expires them. trstctl attacks the problem from every
angle: encrypt at rest, prefer short-lived/dynamic secrets that can't be hoarded, rotate
long-lived ones automatically, never let a secret value touch a log or disk it
shouldn't, and wrap access in approvals and a tamper-evident audit trail. Secret
material lives in wipeable `[]byte` buffers zeroed after use, never a Go `string` — Go
copies strings freely, so a value placed in one can linger in memory beyond your
control.

## How it works

### How every secret is encrypted at rest

trstctl uses **[envelope encryption](../glossary.md)** through the single isolated
cryptography path. Each secret gets a fresh per-secret data key (DEK, AES-256-GCM),
itself encrypted under a master key-encryption key (KEK), bound to the secret's tenant
and path so a sealed blob can't be moved elsewhere. The KEK loads at startup from
`TRSTCTL_SECRETS_KEK_FILE` (0600), stays transient, and is zeroized. Rotating
protection means re-wrapping small DEKs, not all your data.

A tenant can also move off the deployment KEK into its own **tenant key
domain**: a domain KEK kept under an operator wrapper (a local wrapper file, or
an HSM key the isolated signer holds), so sealing one tenant never touches
another. The console's tenant custody panel and `trstctl-cli platform
tenant-key-domain` serve its lifecycle: migrate (create the domain KEK and
re-wrap the tenant's data), seal and unseal (a reversible revoke), and rotate (a
new generation of the domain KEK, under the same or another wrapper, with every
stored DEK and the tenant's event history re-wrapped and both generations
readable until the switch). Rotation re-wraps DEKs, not payloads, so backups,
archives, and exports taken before it still open with the previous generation
through its wrapper. See [configuration](../configuration.md#rotating-a-tenant-domain-key).

The deployment KEK itself rotates as well. The operator tenant
(`secrets.kek_operator_tenant_id`) moves it from the local key file to a key under
an operator wrapper file or an HSM key the signer holds, from the console's
deployment key panel or with `trstctl-cli platform deployment-kek rotate`. New
data is wrapped under the new generation at once; a background pass re-wraps every
stored data key, the history of tenants that have not moved to their own domain,
and the deployment's sealed files, then reads them all back before the previous
generation is retired. Credentials stay readable throughout, and afterwards only
through the wrapper. See [configuration](../configuration.md#rotating-the-deployment-kek).

### The native secret store (F63)

A served, tenant-isolated key-value store for application secrets: `POST
/api/v1/secrets/store/preview` checks an exact create request without changing
anything, `POST /api/v1/secrets/store` creates version 1, `PUT
/api/v1/secrets/store/{name}` writes the next version, and `GET
/api/v1/secrets/store/{name}` reveals only the latest value to a `secrets:read`
caller. Metadata responses list names, versions, and timestamps only, never values.

The console's create flow has two clear steps: enter the name, owner, and value;
then review the server's plan. Preview applies the same tenant-owner and duplicate
name checks as create, but writes no row, event, audit record, idempotency record,
outbox intent, or external effect. It never returns the value. Instead it returns a
server-keyed fingerprint that changes if the tenant, caller, name, owner, or value
changes. Editing any input throws away the reviewed plan. Only a current, ready plan
reveals **Create reviewed secret**; creation remains a separate idempotent mutation.

Headless operators use the same oracle with `trstctl-cli secrets store preview -f
secret-create.json`, then pass that exact JSON body to `secrets store put`. Keep the
body in a permission-restricted file or pipe it with `-f -`; do not place plaintext
on a shared command line or in QA evidence. A ready preview is evidence about the
request, not a reservation: the create call rechecks authority and current state.

Every create, rotation, and recovery stores a row in `secret_store_versions` under
PostgreSQL RLS and emits `secret.version.written` without plaintext.
`GET /api/v1/secrets/store/history/{name}?version=N` reads a prior version, and
`POST /api/v1/secrets/store/recover/{name}` with body `{"at":"2026-06-25T12:00:00Z"}`
recovers whichever version was current then as the next monotonic version, keeping
rollbacks auditable. `DELETE /api/v1/secrets/store/{name}` purges the current row and
sealed history for that tenant; another tenant gets a 404 — both tables are
RLS-scoped.

Values may contain `${secret.path}` placeholders: a normal read returns the literal
value, while `GET /api/v1/secrets/store/{name}?resolve=true` expands references within
tenant/permission scope instead. Cycles like `a -> b -> a` return a structured `409`
with the cycle path; missing references return a normal `404`.

`POST /api/v1/secrets/store/import` accepts `{"prefix":"optional/path","values":
{"name":"value"}}` for 1–100 new secrets. Its one event holds tenant/name-bound
sealed values, not plaintext. Per-name fences serialize concurrent single-secret
and batch mutations; projection commits every version-1 row and one metadata-only
batch receipt in one PostgreSQL transaction. An exact `Idempotency-Key` retry
returns the same receipt. Any existing or reserved name returns `409` before
publishing a partial batch. The CLI command is `trstctl-cli secrets store import
-f import.json`; the console reviews names before execution and never displays
values. Keep the input file private and remove it after use.

The served store seals through a versioned binary container, its KEK loaded into
locked, zeroizable memory at startup, never a raw byte slice on the heap. An older
store core, kept for legacy event replay and compatibility, holds its KEK the same way
and still replays both the binary container and earlier JSON-envelope history; new
writes go through the path above.

### Projects, environments and restricted access (A235)

A **project** groups an application's secrets by environment over the same native
store: a secret belongs to project `payments`, environment `stage` when its name starts
with `payments/stage/` (the rest is its folder path and key), so references, history,
recovery, sync and `trstctl run` work unchanged and nothing is copied to a second store.
Set one up with slugs only:

```
trstctl secrets projects create -f payments.json   # {"slug":"payments","environments":[{"slug":"dev"},{"slug":"stage","restricted":true}]}
trstctl secrets projects members grant payments team-a-ci -f grant.json   # {"role":"developer","environments":["stage"]}
trstctl secrets projects show payments
```

An unrestricted environment behaves like any tenant secret. A **restricted** environment
is open only to the project's members granted it: `viewer` reads, and `developer` and
`admin` read and write; a member with no `environments` list is granted every environment.
The rule holds on every surface that reads or writes by name. That covers the native
read, list, history, preview, create, rotate, delete, recover, import, sync and rotation
routes, every hop of a `${secret.…}` reference, and the Vault-compatible KV routes. A
read the rule denies answers exactly as a missing secret, so names don't reveal what
exists, and a denied write is 403.

A `secret://` reference is a read too (A235-L2). trstctl redeems one later by name
with no caller present: a network relay per attempt, a connector run, a notification
send or a verifier. So only a member granted a restricted environment can set up a
reference into it. That covers a connector target's credentials (and an inline endpoint
destination's), a notification channel's or an observer's credential, a ticket intake's or
an MDM poll's token, a DNS-01 provider's credentials, an MDM SCEP challenge key, an ACME
EAB key, a discovery source's bind password or SSH key, and a secret sync's workload
proof. The rule holds whichever way the reference is spelled, and is checked again on
every update. So a non-member can't repoint a channel or a target that keeps one at an
endpoint of its own. The refusal (403) doesn't say whether the secret exists, and a
leaked-secret move naming a restricted secret answers as for a missing one. A
reference outside every restricted environment stays governed by the route's own
permission.

Dynamic secrets follow the same rule. An operator can place a provider in an environment
with `secret_environment` in its configuration. In a restricted environment only its
members see the provider and its leases, and only its developers and admins issue, renew
and revoke them, on the native, Vault-compatible and rotation paths alike. A machine
session or the SDK agent therefore gets a prod credential only when its principal is
granted prod.

Projects and environments change under
`access:write`, and either can be renamed there (A235-L3): the display name changes, and
the slug, which every secret name in it begins with, stays. Membership changes under `access:write`, or under `secrets:write` by a
member holding the project's `admin` role, within its own grant (A235-L1): an admin
restricted to some environments grants only those, can't grant every environment, and
can't change or revoke a member whose grant reaches past its own. So a `secrets:write`
token still can't grant itself an environment. The member routes admit the computed
`secrets:members.manage` predicate (`access:write` or `secrets:write`; no role or token
can be granted it), and the tenant's ABAC policy is evaluated against the permission the
caller acts under. A tenant
administrator who needs a restricted value grants themselves membership, which is
recorded. `projects show` lists each environment's secrets with their owner, or
`unknown` when none is set, and shows a restricted environment the caller isn't granted
as `restricted` without its names. Tenant RLS stays the boundary: an environment is not
a tenant.

In the console, **Secrets → Projects and environments** (`/secrets/projects`) lists the
projects with their owners. "Unknown owner" is shown plainly, never guessed. A project
opens to its environments, each marked open, restricted and granted to you, or
restricted. A restricted environment you aren't granted shows no names. Each secret
shows its key, version and owner, and the page lists the members, with grant and revoke
for `access:write` holders and for the project's admins within their own grant. When the project has an owner, the **application view** also
shows how many certificates and identities that owner holds. It lists the soonest-expiring
of each with its health (ok, expiring within 30 days, expired), so an application's
certificates, workload identities and secrets read as one inventory. With no owner,
the page says to set one instead of guessing.

### Promoting between environments (A236)

A **promotion** copies one environment's secrets, or one folder of them, into another
environment of the same project as new versions, all in one batch. Preview first: the
plan is value-free and lists each key's source and target versions and its action
(`create`, `update`, `unchanged` or `blocked`), the target secrets the promotion leaves
alone (`kept`), and a `plan_digest`. A secret the promotion creates takes its source's
owner (A236-L2): the plan names it (`owner_id`, `owner_name`) and the console's plan
shows it, a source with no owner gives none, and an update keeps the target's own owner.
Apply the plan by that digest:

```
trstctl secrets projects promote preview payments -f promote.json   # {"from":"dev","to":"stage","folder":"db"}
trstctl secrets projects promote apply payments -f apply.json       # the same body plus "plan_digest"
```

A reference into the source environment (`${secret.payments/dev/db/password}`) is
pointed at the same key in the target (`${secret.payments/stage/db/password}`); any
other reference is kept as written. Every reference of a changed secret must resolve in
the target as you may read it, hop by hop and without a cycle. An item whose reference
cycles, reaches a restricted environment you aren't granted, names a secret that exists
only in another tenant, or doesn't resolve is `blocked`, with the reason. A source
version whose credential a rotation retired, revoked or let expire is blocked too. A
blocked item blocks the whole promotion (`409`, code `plan_blocked`), and nothing is
written. The apply recomputes the plan, so a secret changed since the preview answers
`409` with code `plan_stale` and the new plan. The batch then reserves every name at its
planned version, so no other write can land between that check and the write. Target
secrets with no source are never touched or deleted. A plan with nothing to change answers
`200` without a batch, and an exact retry with the same `Idempotency-Key` returns the
first receipt. You need read access to the source environment and write access to the
target. Every new version is audited like a single write.

A promotion into a **restricted** environment needs four-eyes approval (A236-L1). The
first apply writes nothing and answers `403` naming the approval request
(`dual control: approval_required:<project>/<environment> request_id=…`). Other members
who hold write in that environment approve that exact plan in Approvals: the tenant's
required number of distinct approvers, two by default. The requester can't approve its
own promotion, and a member not granted the environment neither sees nor decides the
request. The requester then applies again with the same body and `Idempotency-Key`. The
versions and the approval are recorded together, so the approval is used once, and the
next plan needs its own. A promotion into an open environment needs no approval. A secret
change's approval in a restricted environment is likewise listed to, and decided by, only
the members who hold write there, on the generic Approvals route as on the secret's own.

### Restoring a folder to a point in time (A236)

A **restore** puts an environment, or one folder of it, back to how it stood at a point in
time. Each secret that changed since then gets a new version holding the value it had,
and the new version names the version it restored. Secrets created since are listed as
`created_since` and kept; nothing is deleted, and no secret outside the folder changes.
Like a promotion, the plan is value-free and applied by its digest, the whole folder
changes in one batch or not at all, and a change after the preview makes the plan stale:

```
trstctl secrets projects restore preview payments -f restore.json   # {"environment":"stage","folder":"db","at":"2026-11-01T10:00:00Z"}
trstctl secrets projects restore apply payments -f apply.json       # the same body plus "plan_digest"
```

A restore never brings back a dead credential silently. A version whose credential a
rotation retired at its provider, is retiring, revoked by rolling back, or whose lease
has expired is `blocked` with the rotation named, and a blocked item blocks the restore.
Every restored value's references must still resolve, as for a promotion. A deleted
secret can't be restored, because deleting a secret removes its history. The console
offers both on a project's page (**Promote or restore**) for `secrets:write` holders.

### Migrating from another system (A243)

A migration run moves an export into a project and lets the old system keep
writing those secrets until their consumers have moved. It reads common formats,
not products: dotenv, JSON and YAML, one file per environment (and, optionally,
folder).

- **dotenv**: `KEY=VALUE` and `export KEY=VALUE`; a double-quoted value may span
  lines and takes `\n`, `\t`, `\"` and `\\`; a single-quoted one is literal.
  Comment lines above a key are its metadata: plain text is the description,
  `@tags: a, b`, `@owner: team`, and `@exportable: false` for a value the export
  could not carry.
- **JSON and YAML**: a map of folders down to values; a record with `$value`,
  `$description`, `$tags`, `$owner` and `$exportable`; or a top-level list of
  records (`key`, `value`, `folder`, …). A null value is a credential the export
  could not carry. YAML block scalars carry multiline values.

Each secret becomes `<project>/<environment>/<folder…>/<key>`. References become
the store's own: `${NAME}` (same folder), `${folder/NAME}` (same environment) and
`${environment:folder/NAME}` turn into `${secret.<name>}`, so a chain stays a
chain and resolves on read.

1. **Assess** (`trstctl-cli secrets migrate assess -f bundle.json`, or Secrets →
   Projects → *Migrate an export*). The bundle names the project, the sources,
   and optionally the export's permissions and the consumers expected to read
   the result. The answer is a plan with no values: per secret, import, reissue
   (the export could not carry it) or blocked (a missing environment, an
   unresolved reference — its name is not echoed — or a cycle, an environment
   you may not write, or a secret another run's export still writes), plus what
   could not be read, and a digest over the plan and every value.
2. **Permissions** translate only where nothing widens: an environment-wide read
   becomes a viewer and write a developer, for those environments. A folder
   grant, admin, a wildcard, one subject with different access in different
   environments, or a subject that already has a different membership is held
   for review. An environment the export restricted that is open in the project
   blocks its secrets unless you accept that explicitly
   (`accept_open_environments`). `secrets migrate permissions <id>` applies the
   translated grants and needs `access:write`.
3. **Stage** (`secrets migrate stage <id> -f bundle.json` with `plan_digest`)
   imports by the digest as new versions; a stale digest is refused. From now
   until cutover the export's system is each secret's one writer: a write,
   promotion or restore through the store answers 409 `migration_source_writer`.
   Re-assess and stage again to bring its later changes over.
4. **Verify consumers.** Each consumer's first read of each of its secrets, as its
   own subject, is recorded on the run.
5. **Cut over** (`secrets migrate cutover <id>`) once every consumer has read its
   secrets (or with `no_consumers` when the export named none). Writing moves to
   the store.
6. **Reissue** (`secrets migrate reissue <id>`) issues new random values for the
   credentials the export could not carry; the run records them as reissued,
   never as migrated, and the old system's credential is yours to revoke.
7. **Roll back** (`secrets migrate rollback <id>`) uses the manifest: each secret
   gets back the version the run found, each one the run created is deleted, and
   one written since the run wrote it is kept. A retried rollback returns the
   same evidence.

`secrets migrate show <id>` lists every object with its version before and
after, its writer, its rollback outcome, and each consumer's read and pending
secrets. No value appears in a plan, an event, a log or a receipt.

### Vault/OpenBao-compatible common API

Teams migrating from Vault or OpenBao can point a stock `vault` CLI at trstctl — a
compatibility shim over the served secret store and dynamic PKI secret. Enable the same
surface (`secrets.enable_api`) and use a tenant API token (`secrets:read`/`secrets:write`)
as `X-Vault-Token`, which is what the Vault CLI sends:

```sh
export VAULT_ADDR=https://trstctl.example.com
export VAULT_TOKEN=trst_...

vault login -no-store "$VAULT_TOKEN"
vault kv put secret/payments/db username=payments password='correct horse battery staple'
vault kv get -format=json secret/payments/db
vault write -format=json pki/sign/default csr=@payments.csr ttl=1h
vault read -format=json database/creds/readonly
vault lease revoke -sync database/creds/readonly/lease-...
```

Supported paths are intentionally small:

| Vault path                                 | trstctl behavior                                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------------------- |
| `GET /v1/auth/token/lookup-self`           | Validates the `trst_...` token; returns Vault-shaped metadata, never the token.        |
| KV mount-discovery preflight for `secret/` | Lets `vault kv` discover `secret/` is KV v2.                                           |
| `POST`/`PUT /v1/secret/data/{path}`        | Upserts a KV v2 object into `/api/v1/secrets/store/{path}` as the next sealed version. |
| `GET /v1/secret/data/{path}`               | Reads the latest value as Vault KV v2 `data.data` plus version metadata.               |
| `POST`/`PUT /v1/pki/issue/{role}`          | Issues a short-lived certificate and key via the signer-backed dynamic PKI secret.     |
| `POST`/`PUT /v1/pki/sign/{role}`           | Signs a requester-generated CSR and returns no private key.                            |
| `GET /v1/secret/metadata/{path}`           | KV v2 metadata: the retained versions with their write times, current and oldest version. |
| `LIST /v1/secret/metadata/{folder}` (or `GET ?list=true`) | Direct children of a folder, sub-folders suffixed `/`; an empty folder is `404` as in Vault. |
| `DELETE /v1/secret/data/{path}`, `DELETE /v1/secret/metadata/{path}` | The native delete: the object leaves reads and listings; history stays under native retention (no soft-delete state). |
| `POST /v1/sys/capabilities-self`           | Capabilities per path from the token's trstctl permissions and the tenant's Vault ACL policies; `deny` when none. |
| `POST /v1/auth/token/renew-self`           | `400`: trstctl API tokens are not renewable leases; mint a new token instead.           |
| `POST /v1/sys/wrapping/wrap`, `unwrap`, `lookup` | Response wrapping over the native one-time share rows: a single-use `trstw_` wrapping token (`X-Vault-Wrap-TTL`, default 5m, max 24h), lookup without consuming, unwrap exactly once. |
| `GET`/`POST`/`PUT`/`DELETE`/`LIST /v1/cubbyhole/{path}` | A per-token scratch space keyed by the presented token; another token sees nothing; entries expire with the token when it has an expiry. |
| `GET /v1/database/creds/{role}`            | Opens a native lease on the tenant's PostgreSQL, MySQL, MongoDB or Redis provider offering the role; returns `username` and `password`. |
| `GET`/`POST /v1/aws/creds/{role}`, `/v1/aws/sts/{role}` | Opens an AWS STS lease: `access_key`, `secret_key`, `session_token` and the assumed-role `arn`; accepts `ttl` and the role's own `role_arn`. |
| `POST`/`PUT /v1/kubernetes/creds/{role}`   | Opens a Kubernetes lease: a ServiceAccount token for the role's binding, with `service_account_name` and `service_account_namespace`; `kubernetes_namespace` and `audiences` must be the provider's. |
| `/v1/{provider}/creds/{role}`              | The same lease, naming the provider when several offer the role. |
| `LIST`/`GET /v1/{engine}/roles`, `GET /v1/{engine}/roles/{role}` | The roles a database, AWS or Kubernetes engine (or one provider's mount) offers, and one role's provider and lifetimes (A203-L2); no credential. |
| `LIST`/`GET /v1/database/config`, `GET /v1/database/config/{name}` | The database engine's connections: each provider's plugin, allowed roles and readiness, never its DSN (A203-L2). |
| `POST`/`PUT`/`DELETE` on those roles and config paths | `405`: providers and roles are configured in trstctl's configuration file, not through Vault paths. |
| `PUT /v1/sys/leases/lookup`, `renew`, `revoke` | Lookup reports a lease's issue and expiry; renew extends a database lease, never past the provider's maximum TTL; revoke with `-sync` returns once the provider confirms removal. An STS session stays valid until its native expiry; a Kubernetes API server may accept a recently used token for its 10-second authentication cache. |

The served compatibility contract also includes tenant-authored KV v2, PKI, and
transit mounts, Vault ACL policy management, common transit operations, the
cubbyhole, response wrapping, and the native dynamic leases at the Vault
database, AWS and Kubernetes engine paths, with the engines' roles and database
connections readable (not writable: providers are operator-configured); the
native trstctl API remains the full surface. The machine-readable contract is
pinned separately as
[`docs/contracts/vault-openbao-compat.openapi.json`](../contracts/vault-openbao-compat.openapi.json),
since `/v1` paths preserve Vault/OpenBao wire shapes. Mutating calls accept
`Idempotency-Key`. For the stock CLI's KV put and PKI issue/sign commands,
trstctl derives a token-keyed digest of method, path, and body when the header is
absent, so an exact retry cannot mint a duplicate certificate or secret version.
A dynamic-credential read without the header opens a new lease each time, as
Vault does; `sys/leases` renew targets an absolute expiry and revoke is a state
transition, so a retry cannot extend or revoke twice.
For transit writes, pass the CLI's `-header` option explicitly. Use a fresh key
for each distinct mutation and reuse that key when retrying the same request:

```bash
idem="$(openssl rand -hex 16)"
vault write -header="Idempotency-Key=$idem" transit/keys/payments type=aes256-gcm96
```

The same header option applies to transit encrypt, decrypt, rewrap, HMAC, sign,
and verify. The stock CLI sends these `vault write` calls with HTTP `PUT`; the
compatibility API serves both `POST` and `PUT` for the listed transit paths.
Vault transit `verify/{name}` accepts a signature only when its public key belongs
to a retained version of that named key in the current tenant. Rotation keeps
older signatures verifiable under the same name, while another name or tenant
returns `valid: false`.
The stock CLI's `vault secrets enable/disable` and `vault policy write/delete`
commands also work without a custom header: the fallback is bound to the last
event for that exact mount or policy, so a retry does not append twice and a
later delete/recreate cycle is a fresh operation.
Disabling a tenant-authored KV mount closes that namespace. Re-enabling the
same path starts an empty namespace, so previously written values cannot
reappear through the Vault-compatible route. The sealed predecessor remains
subject to the native secret store's retention and erasure policy; mount disable
is not a physical-erasure receipt.
An identical request from the same token replays its original result; force a fresh
issue with a different explicit `Idempotency-Key`, or use the native
`/api/v1/secrets/pki` route. Transit mutations require an explicit
`Idempotency-Key` so intentional repeated rotations stay distinguishable.

### The developer secrets experience (F64)

The **Use secrets in apps** workspace at `/secrets/developer` turns one secret name
into an exact, value-free access plan. Choose the secret, environment variable, and
whether references should resolve; then select **Review access plan**. The served
`POST /api/v1/secrets/access/preview` route proves the caller can open the current
tenant-scoped version, immediately wipes those bytes, and returns only metadata:
the required `secrets:read` permission, current version, CLI arguments, HTTP path,
TypeScript example, recovery steps, verification steps, and a server-keyed plan
fingerprint. It writes no event or audit row and makes no external call.

Only a ready, unchanged plan enables **Run reviewed access test**. That test performs
the real served read, checks that the returned name and version still match the
review, and renders a value-free receipt. A denied read can be retried with the same
review. Changed inputs or a changed secret version invalidate the plan and require a
new review. Missing references, cycles, wrong-tenant names, and invalid environment
variables fail closed with a specific recovery step. Copyable CLI, HTTP, and
TypeScript examples come from the server response, so the portal cannot drift from
the API contract or invent a secret value.

The CLI exposes the same plan before the process boundary:

```sh
printf '%s\n' '{"name":"db/password","env_var":"DB_PASSWORD","resolve":false}' > access-plan.json
trstctl-cli secrets access preview -f access-plan.json
```

After review, `trstctl-cli run` fetches named secrets from the served store and runs
your program with them in the child environment, never writing the value to disk,
via the normal `GET /api/v1/secrets/store/{name}` RBAC path:

```sh
trstctl-cli run --secret DB_PASSWORD=db/password -- env
trstctl-cli run --resolve --secret DATABASE_URL=app/db/dsn -- ./payments-api
```

The `--resolve` flag maps to `?resolve=true`; without it, a value like
`${secret.app/db/password}` passes through literally instead of expanding further.
After the child exits, trstctl wipes the byte-backed copies fetched — the OS
environment remains an edge string API, so use `run` for trusted processes and skip
debug commands printing the full environment.

Developers can read with `trstctl-cli secrets store get NAME --resolve=true` for the
same opt-in resolve/cycle-detect behavior, scoped to the caller's tenant and RBAC.
For multiple new names, `trstctl-cli secrets store import -f import.json` sends one
atomic request and prints the metadata receipt. The file contains secret values;
use a private file, or `-f -` for standard input, and do not log its content.

### Dynamic secrets (F65) and PKI-as-a-secrets-engine (F67)

Instead of a long-lived secret to steal, dynamic secrets are minted on demand, scoped,
and time-limited by a [lease](../glossary.md); on expiry trstctl revokes the credential
automatically where the provider supports native revocation, even across a restart, since the revocation intent is journaled first to
a durable [outbox](../glossary.md) and delivered at-least-once. Thirty-nine backend families ship
behind one interface, each backed by real infrastructure, not a stub: PostgreSQL,
MySQL, MongoDB, AWS STS, GCP IAM, Azure Entra, Kubernetes ServiceAccount tokens,
Redis ACL users, LDAP directory accounts, TOTP codes, OAuth 2.0 access tokens, ClickHouse
users, Elasticsearch API keys, RabbitMQ users, Tailscale auth keys, MongoDB Atlas
database users, Kafka SCRAM users, Couchbase users, Milvus users, GitHub App installation
tokens, Snowflake service users, ElastiCache and MemoryDB RBAC users, IBM API Connect app
credentials, SQL Server logins, Azure SQL contained database users, Cassandra login
roles, Oracle Database users and SAP HANA users (A239), and Datadog and OpenAI keys,
OpenRouter, Fireworks AI and LiteLLM proxy keys, Supabase secret API keys, Convex deploy
keys, dbt platform service tokens, Cloudflare API tokens and R2 access keys (A240). SSH user
certificates are issued natively by the SSH CA (`/api/v1/ssh/certificates`, revoked
through the served KRL), not as dynamic-secret leases.

The control plane mounts the lease lifecycle when `secrets.enable_api` is on and
`secret_integrations.dynamic_providers` supplies tenant-bound endpoints, allowed roles,
maximum TTLs, egress policy, and `file:`/`secret://` credential references
(`buildRunDeps` wires the registry). A `postgresql`, `mysql` or `aws-iam` provider with
`allow_static_rotation: true` also serves the static-rotation worker (F37): it mints
credentials with no native expiry for the roles in `allowed_roles`, and trstctl
retires them explicitly after their successor is verified. Issuance commits a pending lease and sealed
outbox command first, so only the outbox worker calls the provider. Providers
with a native lookup or replay identity recover the same identity after a crash;
AWS STS instead fences an uncertain AssumeRole call and never blindly retries it.
Cloud/Kubernetes endpoints require HTTPS; `allow_insecure_loopback` is a
same-host-emulator exception limited to `localhost`, `127.0.0.0/8`, or `::1`.

The LDAP backend creates one directory entry per lease under the configured
container, with a password the directory sets and hashes itself, in the group its
role is bound to, and deletes it at revocation; the directory then refuses its bind.
It speaks LDAPS verified against the configured server name (plain LDAP only to a
private address with an explicit opt-in), and a retry after an uncertain issue
replaces the same entry. See [configuration](../configuration.md) for its fields.

The TOTP backend hands out the current RFC 6238 code of a seed the control plane
holds (the base32 secret an authenticator app enrolls) with `valid_until`, the end
of its time step. Nothing else leaves the control plane, and a code can't be
withdrawn or renewed: revocation only closes the lease, and the code lapses at
`valid_until` (or after any skew window the verifier allows), so the catalog marks
it `ttl_only`. `max_ttl` is required and no longer than the period, so a lease
never outlasts its code by more than one period.

The OAuth 2.0 backend (`oauth-client-credentials`) asks an authorization server's
token endpoint for a new access token per lease (client credentials grant, with the
scopes the lease's role is bound to). It refuses a token that carries any other
scope, isn't a Bearer token, or lives longer than `max_ttl` or shorter than the
lease, and revokes such a token first when it can. A token can't be extended, so a
renewal is refused. With `revocation_endpoint`, revoking the lease presents the
token at that endpoint (RFC 7009): the lease keeps its sealed token only until that
revocation completes, and the catalog marks the provider `confirmed`. Without it
the token is accepted until its own expiry, which the lease shows as
`native_expires_at`, and the revocation stays pending until then (`ttl_only`). A
token request has no idempotency key, so an uncertain one is never retried: the
lease fails and states that a token may exist for at most `max_ttl`.

The ClickHouse backend creates one ClickHouse user per lease through the HTTP
interface, as `admin_user`, with a generated password, `VALID UNTIL` the provider's
maximum lifetime, and the ClickHouse role its lease role is bound to as its only
(default) role, so the lease carries exactly that role's grants. Revocation drops
the user and ClickHouse then refuses its login. The user's name derives from the
lease, so a retry after an uncertain attempt replaces the same user, and revocation
only ever drops users with the provider's issued-name shape (its prefix, the role, and the lease digest suffix). Server errors are reported by
their ClickHouse error code only, since their text can echo the statement.

The Elasticsearch backend creates one API key per lease through the security API,
as `admin_user`: it expires with the provider's maximum lifetime and its role
descriptor grants only the index privileges the lease role is bound to
(`"read on logs-*"`), so it never exceeds that grant (nor the administrator's own
privileges). Revocation invalidates the key and Elasticsearch then refuses it. The
key's name derives from the lease, and a retry first invalidates any key an
uncertain earlier attempt left under it, so a lease never has two live keys.

The RabbitMQ backend creates one RabbitMQ user per lease through the management
API, as `admin_user`, with a generated password and only its role's permissions in
one virtual host: the binding `"read on orders in /"` grants read on exactly the
named queues or exchanges (configure and write match nothing). Revocation deletes
the user and closes its open connections, since RabbitMQ keeps established
connections of a deleted user open; RabbitMQ then refuses its login. A retry after
an uncertain attempt replaces the same user's password.

The Tailscale backend creates one auth key per lease through Tailscale's API, with
`bearer_token_ref` as the API token: single-use, ephemeral, preauthorized, carrying
the ACL tags its role is bound to, and expiring with the provider's maximum lifetime.
Revocation deletes the key, so Tailscale refuses it for any further registration;
a device it already registered stays in the tailnet until removed (an ephemeral one
when it goes offline). The key request has no idempotency key, so an uncertain one
is never retried. It is built against a stand-in of Tailscale's API made from its
documentation; there is no proof against a real tailnet yet.

The MongoDB Atlas backend creates one database user per lease in the configured
Atlas project, through the Admin API with a service account's token
(`client_id`, `client_secret_ref`): a generated password, the built-in roles its
role is bound to (`"read on orders"`), and a `deleteAfterDate` the provider's maximum
lifetime away, so Atlas itself removes the user if nothing else does (at most seven
days). Revocation deletes the user. A retry after an uncertain attempt finds the
lease's user and updates it instead of adding one. It is built against a stand-in
of the Atlas Admin API made from its documentation; there is no Atlas proof yet.

The Kafka backend creates one SCRAM-SHA-512 user per lease with a generated password
and only its role's ACLs (`"read,describe on topic:orders; read on group:orders-app"`),
as a SCRAM administrator over verified TLS (SASL_SSL), or SASL_PLAINTEXT to a literal
loopback or private IP. Revocation deletes the user's ACLs first: the broker authorizes
every request, so a client still connected is refused from its next request (Kafka does
not end an authenticated connection when its credential goes). Then it deletes the
credential, so the next login fails. A retry after an uncertain attempt replaces the
same user's password and leaves its ACLs as they are, and if the ACLs fail the new user
is deleted again. Only users with the provider's issued-name shape (its prefix, the role, and the lease digest suffix) are ever revoked.

The Cassandra backend creates one login role per lease with a generated password,
granted only its role's existing Cassandra roles (`"orders_reader"`), as an
administrator role over verified TLS to one configured node, or plaintext to a literal
loopback or private IP. Only the password's bcrypt hash travels in CQL (`HASHED
PASSWORD`), so the password never appears in a CQL statement or a log or trace of one,
and the administrator's password goes only to Cassandra's PasswordAuthenticator. Revocation
drops the role: the next login fails, and a connection already open is refused from
its next query once the node's role and permission caches expire (`roles_validity`
and `permissions_validity`, 2 s by default; Cassandra does not end the connection). A
retry after an uncertain attempt finds the same role, sets the new password and keeps
the grants it already has, and if a grant fails the new role is dropped again. Only
roles with the provider's issued-name shape are ever dropped.

The SAP HANA backend creates one user per lease with a generated password and no
password lifetime, granted only its role's existing HANA roles, through go-hdb. Like the
Oracle backend, it sends the password and every name only as parameters of an anonymous
SQLScript block, which quotes them into the DDL it runs (`ESCAPE_DOUBLE_QUOTES`).
Revocation deactivates the user, disconnects its sessions and drops it with what it owns;
a retry after an uncertain attempt finds the same user, sets the new password and
reactivates it. Its lab test runs only on the x86 CI runner (the express edition's image is
x86 only).

The Oracle Database backend creates one user per lease with a generated password,
granted only its role's existing Oracle roles (`"ORDERS_READER"`, carrying `CREATE
SESSION`), as an administrator through go-ora. The password and every name travel only as
bind variables: the database quotes them itself (`DBMS_ASSERT.ENQUOTE_NAME`) into the DDL it
runs, so no statement text carries them. Revocation locks the user, kills its open sessions
(`ALTER SYSTEM KILL SESSION`) and drops it, waiting out a session that is still going, so
the next login fails. A retry after an uncertain attempt finds the same user, sets the new
password and unlocks it, and if a grant fails the new user is dropped again. Only users with
the provider's issued-name shape are ever dropped.

The Couchbase backend creates one local user per lease through the cluster's
management REST API, with a generated password and only its role's roles on the named
buckets (`"bucket_full_access on orders"`). Couchbase's user PUT replaces an existing
user, so a retry after an uncertain attempt replaces the same user's password instead
of adding one. Revocation deletes the user, and Couchbase refuses its next request.
The Community Edition has one data role, full access to a bucket, so a Community lease
is scoped by bucket; the Enterprise Edition's roles narrow it further.

The Milvus backend creates one user per lease through the RESTful API and grants it
the Milvus roles its role is bound to (`"orders_reader"`); the roles carry the
privileges. Milvus refuses to create a user that exists and lets no one reset a
password without the old one, so the lease's user is dropped before it is created: a
retry after an uncertain attempt replaces the user instead of adding one. If a grant
fails, the new user is dropped again. Revocation drops the user with its grants, and
Milvus refuses its next request.

The GitHub App backend mints one installation access token per lease, narrowed to the
role's permissions and the repositories it names; the token request is authenticated
with a short RS256 JWT signed with the app's private key inside the crypto boundary.
A token GitHub returns with broader permissions or other repositories, or without a
future expiry, is revoked and refused. GitHub has no idempotency key for the request,
so issuance is at-most-once: an uncertain request is not retried, and the lease states
that a token may exist until an hour after the request. GitHub ends every token an hour
after minting; revocation ends it at once by presenting it, so the lease keeps its sealed
token until the revocation completes, and a lease can't be extended (a new lease mints
a new token). It is built against a stand-in of GitHub's API made from its
documentation; there is no proof against GitHub yet.

The Snowflake backend creates one service user (`TYPE = SERVICE`) per lease that
authenticates with a key pair the provider generates; the lease returns the private key,
so no password exists to reach SQL text or query history. The user is granted only the
role's roles and set to expire in Snowflake after the provider's maximum lifetime rounded
up to whole days (`DAYS_TO_EXPIRY`), a backstop if trstctl is down when the lease ends.
The administrator calls the SQL API with a key-pair JWT signed inside the crypto
boundary. A retry after an uncertain attempt finds the lease's user and installs the new
key on it. Revocation disables the user, which aborts its running queries and refuses
its logins, then drops it. It is built against a stand-in of the SQL API made from its
documentation; there is no Snowflake proof yet.

The ElastiCache and MemoryDB backends create one RBAC user per lease with a generated
password and the role's access string, compiled from literal key prefixes and explicit
safe commands as for the Redis provider (`on ~orders:* -@all +get +ping`), and add it to
the configured user group (ElastiCache) or ACL (MemoryDB) once AWS reports the user
settled; AWS creates users asynchronously, so the provider retries the group change
while the user or group is still modifying, and deletes the user if it never joins. A
retry after an uncertain attempt finds the lease's user and replaces its password and
access string. Revocation deletes the user, which AWS removes from every group and
cluster. Requests are SigV4-signed with the configured access key. They are built
against stand-ins of the ElastiCache Query API and the MemoryDB JSON API made from their
documentation; there is no AWS proof yet.

The IBM API Connect backend creates one credential per lease on the consumer app the
role is bound to, through the platform API with the api_key grant; the app's
subscriptions are its authority. API Connect generates the secret and never shows it
again, so a retry that finds the lease's credential name taken deletes it and creates it
anew. Revocation deletes the credential, and the gateway refuses its client ID. It is
built against a stand-in of the platform API made from its documentation; there is no
API Connect proof yet.

The SQL Server backend (`mssql`) creates one login per lease with a generated password
that meets SQL Server's password policy, a user for it in the configured database, and
that user's membership of the role's database roles; the Azure SQL backend
(`azure-sql`) creates a contained database user instead, with no server login. The
password reaches SQL Server only as a parameter, which SQL Server quotes into the
statement it runs itself, and a failure reports only SQL Server's error number. Every
step finds what an earlier attempt left (the login or user gets the new password, a
membership already held stays), so a retry after an uncertain attempt converges on one
principal; a failed membership removes the new principal again. Revocation disables the
login so no session starts, ends the principal's open sessions (SQL Server keeps a
dropped principal's sessions and refuses to drop a login that is logged in), then drops
the user and the login. Their lab tests run against SQL Server 2022 Developer Edition on
an x86 CI runner, since the image is x86 only; Azure SQL is exercised through SQL
Server's contained database users, the same T-SQL Azure SQL Database runs, with no
Azure proof yet.

The MySQL backend requires an explicit `account_host` for every generated
account. Wildcard host patterns need the separate
`allow_wildcard_account_host` operator opt-in; omitting the host never creates a
global `user@'%'` login. The provider catalog shows both settings before issue.

- `GET /api/v1/secrets/leases/providers` returns fifty-six safe setup recipes (including the
  `aws-iam` compatibility name for `aws-sts`, and `auth0`, `unix`, `windows`, `iosxe`,
  `junos`, `eos`, `fortigate`, `bigip`, `redfish`, `esxi`, `vcenter-sso`, `okta-user`,
  `entra-user`, `google-workspace-user`, `okta` and `databricks`, which only rotate). Each states its `authority` (what a
  leased credential may do) and its `revocation`: `confirmed` when the provider ends
  the credential before its native expiry (the lease's `revocation_status` reaches
  `completed` only once it has), or `ttl_only` when the credential lapses only at that
  expiry, as an AWS STS session or a TOTP code does. Each configured provider also
  states its own `revocation` (an OAuth provider is confirmed only with a revocation
  endpoint; an AWS STS provider with `revoke_with_deny_policy` is `deny_policy`), and the
  console says it beside the connected provider ("When a lease is revoked"). The
  response also returns
  this tenant's real configured provider IDs, allowed roles, maximum TTLs, and
  runtime configuration revisions. It never returns endpoints, native bindings,
  credential references, or provider credential values. Configuration remains a
  startup-admin operation: edit the server configuration or mounted secret reference
  and restart the control plane; the console does not turn infrastructure credentials
  into browser form fields.
- `POST /api/v1/secrets/leases/preview` validates the exact configured ID, role, TTL,
  caller, tenant, and running configuration revision. It opens no credential
  reference, calls no provider, writes no event/audit/idempotency/outbox state, and
  returns the exact execution effects, recovery steps, verification steps, CLI
  command, and a server-keyed `request_fingerprint`.
- `POST /api/v1/secrets/leases` issues one credential copy for a provider, role, and
  TTL, guarded by `secrets:write` plus `Idempotency-Key`. The console always supplies
  the current preview fingerprint; changed inputs or a restarted/reconfigured
  provider return `409` before a provider call. API clients may omit the fingerprint
  for backward compatibility.
- `GET /api/v1/secrets/leases/{lease_id}` returns lease metadata only, never replaying
  the credential after first issue. `expires_at` is the lease deadline: the expiry
  worker queues revocation on its next pass (normally every 30 seconds), and provider
  access can continue during delivery or retries. `hard_expires_at` is the original
  renewal ceiling, not proof of native credential expiry. `revocation_status` is
  `none`, `pending`, `completed`, or `failed`; only `completed` with
  `revocation_completed_at` confirms the provider removal operation, or for AWS
  STS, that its session is denied through its role or its native session expiration
  has passed — `revocation_method` (`deny_policy` or `native_expiry`) says which. `revoked_at`
  records when the control plane queued the request. Older immutable operation
  receipts may omit these additional fields; GET returns current durable evidence.
  If provider creation finishes after `expires_at`, `issued_at` records the real
  late completion time, the API withholds the expired credential, and the expiry
  worker queues native revocation. A retry that starts after `expires_at` fails
  before provider contact. Check `revocation_status=completed` before assuming the
  backend identity is gone. A one-line PostgreSQL `file:` DSN may end in CR/LF;
  the PostgreSQL adapter removes only that terminal line ending before parsing it.
- AWS dynamic leases use STS `AssumeRole`, with an explicit role ARN binding and a
  15-minute to 12-hour maximum TTL. The `aws-iam` provider name remains a compatibility
  spelling for this issuer; it does not create IAM users or long-lived access keys.
  Configure the caller's signing key through a mode-0600 `file:` or tenant-scoped
  `secret://` reference. A short-lived caller also needs `session_token_ref`. The
  issued credential contains an access key ID, secret access key, session token, and
  expiration; `native_expires_at` on metadata is the AWS session expiry. STS has no
  per-session delete call: by default early revoke closes the trstctl lease and leaves
  `revocation_status=pending` until native expiry. AWS can still accept the old
  session during that window. Set the shortest workable TTL and replace dependent
  workload credentials promptly. With `revoke_with_deny_policy: true` on the provider,
  revoking a lease ends its session early instead (N3): trstctl writes an inline
  policy on the session's role named `trstctl-revoked-<expiry>-<digest>`, holding one
  statement that denies every action on every resource when `aws:userid` equals that
  session's assumed-role ID, so no other session of the role is touched. It reads the
  policy back before the revocation reaches `completed` with `revocation_method`
  `deny_policy`; AWS enforces the denial once IAM has propagated the policy, usually
  within seconds. Each revoked
  session has its own policy, so two revocations never rewrite one document, and
  every revocation first deletes the role's denials of sessions more than five
  minutes past expiry. The provider's credentials then also need
  `iam:PutRolePolicy`, `iam:GetRolePolicy`, `iam:ListRolePolicies` and
  `iam:DeleteRolePolicy` on the bound roles; a refused write or a readback without
  the statement is a retried, then failed, revocation, never a completed one. A
  role's inline policies share a 10,240-character quota, which bounds how many of its
  sessions can be denied at once. Sessions the revoked session started by assuming
  another role are not covered. A saved AssumeRole result can be recovered with
  the original idempotency key. If AWS may have accepted the request but its response
  was lost, trstctl fences that operation as indeterminate and does not submit it
  again; reconcile it with CloudTrail before starting a new lease.
- `POST /api/v1/secrets/leases/{lease_id}/renew` extends a lease without returning the
  credential again for renewable backends. Kubernetes TokenRequest tokens are
  immutable: renewal issues a new bound token and lease, confirms provider-side
  revocation of the predecessor, and returns the replacement credential once with
  a new lease ID. Store that token only in the workload's protected credential
  location, update the lease ID used for later renew/revoke calls, and verify the
  previous token is rejected with `kubectl`. A Kubernetes replacement must have
  at least 600 seconds remaining and fit within the predecessor's renewal limit.
  AWS STS renewal likewise issues a replacement lease and reveals one new session;
  the predecessor remains usable in AWS until its own `native_expires_at`. A
  replacement needs at least 900 seconds of requested validity and must fit within
  the original renewal limit.
- `POST /api/v1/secrets/leases/{lease_id}/revoke` closes the lease and queues backend
  revocation through the outbox worker. If GET later reports
  `revocation_status=failed`, correct the provider outage and POST the same revoke
  path with a **new** `Idempotency-Key`. That creates a separate audited outbox
  attempt, preserves the failed predecessor, and returns `pending`; use GET until
  `completed`, then test the old credential with the native client. Replaying an
  earlier key returns that earlier immutable receipt and never queues another
  provider call. The Workloads console can load an existing lease ID after a
  restart, show failed removal, and retry it. A revoked lease is unusable in
  trstctl while provider cleanup is pending, but native access can persist.

The console presents the same contract as three small steps: **Choose connection →
Review exact plan → Use and retire**. It selects only a real configured provider ID
and an allowlisted role; the old free-text provider/role form is gone. The first step
shows the selected backend's safe prerequisites and a disclosure containing all eight
built-in recipes. Review must prove zero writes and zero calls before **Create reviewed
credential** appears. The issued credential lives only in the reveal-once panel;
dismissing it, navigating away, reaching the lease deadline, losing the metadata read,
or revoking the lease removes the browser copy, while
durable metadata remains available for renewal, revocation, and verification. The
visible receipt refreshes every five seconds and on return to the tab. A revoke
response acknowledges queuing; its idempotent replay retains that original result
even after the provider finishes. Read current metadata and test the same login
against the provider to confirm that access has ended.

**PKI-as-a-secrets-engine** plugs certificate issuance into the same operator
workspace. The recommended `csr_pem` mode accepts one self-signed PKCS#10 request,
signs it through the isolated signer, and returns only the short-lived certificate.
The mutually exclusive `common_name` compatibility mode generates and returns the
leaf key from wipeable memory. That mode is deprecated: its
`issuance.server_side_keygen` receipt must be durable before key generation begins,
and its idempotent replay returns the original sealed response without generating a
second key. The console defaults to CSR mode; Vault/OpenBao uses `pki/sign` for the
same custody model and retains `pki/issue` only as the legacy equivalent. Both
key-returning routes run only while the tenant allows control-plane key generation
(`PUT /api/v1/tenant/key-generation`, off for tenants registered since that switch);
with it off they are refused before anything is recorded, naming the CSR route.
Native issuance returns `certificate_id` alongside the serial and public PEM.
The event projects that exact leaf into tenant certificate inventory, records its
subject-key origin, and queues its initial signed CRL publication. Use
`POST /api/v1/certificates/bulk-revoke` with `certificate_ids: [certificate_id]`
and a named RFC 5280 reason; then check the certificate row and signed CRL or
OCSP response. That mutation requires `certs:issue` and `identities:write` in
addition to `secrets:write` used for issuance. The console keeps a link to the
exact revocation selection after its one-time certificate reveal is dismissed.

The console does not jump from those inputs straight to signing. Its three-step
journey is **Configure certificate → Review exact plan → Verify result**. The review
calls `POST /api/v1/secrets/pki/preview`, which uses the same profile validator as
execution but does not sign, append events, write audit, create an idempotency row,
enqueue work, or contact anything. It explains, in plain language:

- whether the secrets API, issuing CA, selected custody input, revocation tracking,
  and—only for the deprecated mode—durable deprecation evidence are ready;
- the exact common name and every DNS SAN, the effective lifetime after the
  `secrets-api` profile cap, public-key algorithm and size, issuing-CA and CSR
  SHA-256 fingerprints, and matching Vault/OpenBao path;
- exactly what issuance writes and calls, how to revoke/recover, how to verify, and
  the equivalent `trstctl-cli secrets pki` invocation.

The response includes a server-keyed `request_fingerprint` bound to the tenant,
authenticated principal, CA, custody input, profile, and requested/effective TTL.
The console supplies it as `preview_fingerprint` when issuing; changed input or CA
state therefore fails closed with `409` and requires a fresh review. API clients may
omit it for backward compatibility, but automation can use
`trstctl-cli secrets pki preview -f REQUEST.json` before the idempotent mutation.
Neither preview nor its evidence contains CSR bytes, certificate bytes, or a private
key. Richer live OCSP/CRL state and revoke diagnostics remain a documented roadmap
residual; the existing serial/revocation pipeline is not represented as richer UI
than it is.

### Secret rotation (F37)

Provider rotation runs through durable commands: the request commits the command
and returns queued, non-secret evidence; a bounded worker performs every provider
effect and a restart resumes from the last persisted phase. Before execution,
`POST /api/v1/secrets/rotations/preview` returns an exact,
effect-free F37 plan. It reads only tenant-scoped secret metadata and configuration:
it generates no successor value, decrypts no secret, writes no event or outbox row,
and contacts no connector. The plan reports current/next versions, the resolved
connector destination, required permission, a tenant-bound request fingerprint,
execution effects, recovery steps, and explicit blockers. The console and
`trstctl-cli secrets rotations preview` use this plan without an Idempotency-Key;
changing console inputs invalidates the review. Only a ready, still-current review
reveals the separate execution action.

`POST /api/v1/secrets/rotations` accepts three provider modes. `connector:<target>`
commits one application-secret event plus its sealed outbox intent before returning
queued, non-secret evidence. Any other `provider` names a configured dynamic-secret
provider (`secret_integrations.dynamic_providers`, type `postgresql`, `mysql` or
`aws-iam`) with `allow_static_rotation: true` whose `allowed_roles` lists the secret
name: the request commits one durable static-rotation command (an immutable
`secret.static_rotation.queued` event, its projected row and one outbox intent) and
returns `queued:true` with a `command_id`. The secret-integrations outbox worker then
runs the phases, each recorded as an immutable `secret.static_rotation.advanced`
event: **stage** mints a long-lived credential for role `key` at the provider, pinned
to the command id so a retry after a crash replaces the same principal instead of
leaking one; **cutover** publishes it as the next secret version through the same
fenced `secret.rotated` mutation every write uses and keeps the predecessor value
sealed; **verify** opens a session with the staged credential (PostgreSQL, MySQL;
AWS IAM has no side-effect-free proof and records `verify_mode: not_available`);
**retire** revokes `old_ref` at the provider, or skips when `old_ref` is `none`; a
provider deletes only principals it issued, so an `old_ref` naming an account someone
else provisioned is refused and the command ends `retire_pending` with the successor
live (use `rotation_accounts` to rotate accounts you provision).
The staged credential and the predecessor value stay sealed under the tenant key
domain between phases (AN-8). A verification that still fails on its third worker
attempt rolls back: the predecessor is restored as a new version and the successor
revoked (`rolled_back`); a restore that fails ends in `rollback_failed`; a retirement
that exhausts the outbox budget leaves the successor live as `retire_pending`.
`GET /api/v1/secrets/rotations/{id}` and `GET /api/v1/secrets/rotations?key=<name>`
(CLI `secrets rotations get` / `list`) follow a command to its terminal phase; no
response carries the credential.

A PostgreSQL role can instead rotate between two accounts its database owner
provisioned with the role's grants (A240): set `rotation_accounts`
(`{"<role>": ["<account a>", "<account b>"]}`, each role in `allowed_roles`, no
account in two roles) on the provider. **Stage** then sets a new password on the
account `old_ref` does not name, **retire** replaces the `old_ref` account's password
with one nobody holds and ends its sessions, and nothing is ever created or dropped,
so both accounts keep every grant, default privilege and object they own; until
retirement both credentials work. `old_ref` must name the account consumers use now
(`400` otherwise, including `none`), and the preview names the account it will set
and the one it will retire. A rollback replaces the refused successor's password the
same way, leaving the predecessor live. The served proof runs scheduled cycles
against a real PostgreSQL target while an application keeps writing with the
credential it last read, through a target that blocks retirement past the delivery
deadline, a server restart mid-cycle and a successor the target refuses.

An LDAP role rotates the same way between two existing entries under `users_dn` that
the directory's owner placed in the role's group (A240): `rotation_accounts` names
their DNs, **stage** sets a new password on the entry `old_ref` does not name (the
directory hashes it, RFC 3062) and verifies it by binding, and **retire** sets a
password nobody holds on the other; group memberships never change, and nothing is
created or removed. LDAP has no session to end, so a bind already open lasts until it
binds again. The served proof runs on OpenLDAP over verified LDAPS: three unattended
cycles while an application binds with the credential it last read and reports each
version it used, then a retirement against a paused directory that times out and
leaves the predecessor binding until the directory resumes.

A MongoDB role rotates the same way between two existing users of the provider's
`database` that hold the role's roles (A240): `rotation_accounts` names them,
**stage** sets a new password on the user `old_ref` does not name (`updateUser`) and
verifies it by connecting, and **retire** sets a password nobody holds on the other;
roles never change, and nothing is created or dropped. A connection that already
authenticated lasts until it reconnects. The served proof runs on MongoDB 7.0 with
authorization on: three unattended scheduled cycles while an application connects with
the credential it last read and reports each version it used, then a retirement against
a paused database that times out and leaves the predecessor connecting until the
database resumes.

A SQL Server role rotates the same way between two existing logins whose users in
`database` hold its role memberships (A240; for Azure SQL, two contained users there):
**stage** sets a new password on the login `old_ref` does not name (`ALTER LOGIN … WITH
PASSWORD`, the password a parameter the server quotes itself) and verifies it by
connecting, and **retire** sets a password nobody holds on the other and ends its
sessions; nothing is disabled, created or dropped, so memberships stay. Its served proof
runs in the x86 CI lab against SQL Server 2022 Developer Edition: three unattended
scheduled cycles while an application connects with the credential it last read, then a
retirement against a paused server that times out and leaves the predecessor connecting
until the server resumes.

An Oracle role rotates the same way between two existing users that hold its grants
(A240): `rotation_accounts` names them, **stage** sets a new password on the user `old_ref`
does not name and verifies it by connecting, and **retire** sets a password nobody holds on
the other and kills its sessions; the user is not locked or dropped, so its grants and
objects stay. The served proof runs on Oracle Database Free (26ai): three unattended
scheduled cycles while an application connects with the credential it last read and reports
each version it used, then a retirement against a paused database that times out and leaves
the predecessor connecting until the database resumes.

`unix` (A240) rotates local account passwords on a Unix/Linux host over SSH: the
control plane authenticates as an administrator with a key (`admin_user`,
`private_key_ref`), pins the host key (`host_key_fingerprint`, any of the host's keys:
the client tries one host-key algorithm at a time until the pinned key is presented,
before sending any credential), and runs only `chpasswd` with the change on stdin
(`sudo -n` when `sudo` is set). A role with `rotation_accounts` alternates between two
local accounts its owner provisioned (two-phase: the predecessor works until
retirement sets a password nobody holds; its groups and files stay; sessions already
open last until they end). A role bound to one account changes that password in
place, so it is single-phase and runs only with `acknowledge_single_phase: true`.
The new password is verified by logging in (`verify_mode: authenticated`). It rotates
only; it issues no leases. The served proof runs on a Debian OpenSSH host: three
unattended two-user cycles while an application logs in with the credential it last
read and reports each version it used, a retirement against a paused host that times
out and leaves the predecessor working until the host resumes, and an acknowledged
in-place rotation after which only the new password logs in.

`windows` (A240) rotates local account passwords on a Windows host serving OpenSSH, the
same way: an administrator in Administrators authenticating with a key (its public key in
`administrators_authorized_keys`), the host key pinned, and one command, Windows
PowerShell's `Set-LocalUser`, its script passed encoded and naming only the account, the
password on stdin. Passwords mix upper and lower case letters and digits, which Windows'
complexity rule needs, and account names have at most 20 characters. Two-user pairs and
single in-place accounts work as for `unix` (`sudo` does not apply). The proof runs on a
windows-latest CI runner serving OpenSSH to itself: two two-user cycles in which the
predecessor logs in until its retirement and only the successor after, and an in-place
change after which only the new password logs in. The served rotation around those calls
is the one the Unix proof exercises; the runner has no embedded PostgreSQL for the served
harness.

`iosxe` and `junos` (A270) change local account passwords on network devices through the
device's own command line over SSH, as an administrator signing in with a password, the
host key pinned. On IOS-XE the change is `username <account> privilege <level> secret 0
<password>` under `configure terminal`, then `write memory`: the account's current
privilege level is read first and kept, because IOS replaces the whole username line. A
role bound to `enable` rotates the privileged-mode secret and is proved by entering
privileged mode with it. On Junos the password is typed at `plain-text-password`'s
prompts, never on the command line, and committed with `commit and-quit`. Each role's
one account changes in place, so a rotation runs only when acknowledged
(`acknowledge_single_phase`); the worker proves the new password signs in, and a change
the device does not prove is put back to the predecessor, which must sign in again.
Discovery (A260) reads a device's local accounts with their privilege level or login
class and never their password hashes. The served proof runs against stand-ins of both
CLIs: an account and the enable secret rotate with the privilege kept and the
configuration saved, the old password stops, a device that reports the change but keeps
the old password is rolled back, and discovery stages each account with its level.

`eos`, `fortigate` and `bigip` (A270) do the same through each device's HTTPS management
API, its certificate pinned and egress limited to its address. EOS runs the CLI commands
through eAPI (`runCmds`): the account's privilege and role are read from the running
configuration and restated, because omitting them resets them, the change is copied to
the startup configuration, and a role bound to `enable` rotates the enable password,
proved by entering privileged mode with it. FortiGate's REST API administrator changes an
administrator with `PUT /api/v2/cmdb/system/admin/<name>`, and the new password is proved
at `/logincheck`, whose session is logged out at once. BIG-IP changes a user with
`PATCH /mgmt/tm/auth/user/<name>` and saves the configuration; every call signs in for a
token at `/mgmt/shared/authn/login` and deletes it after. A password always travels in a
request body, never a URL, and a device's error text, which can echo the command, is
never kept. The served proof runs against stand-ins of all three APIs: each account
rotates with its level kept and the configuration saved, the old password stops, EOS's
enable password rotates, a FortiGate that reports the change but keeps the old password
is rolled back, and discovery stages every account with its level.

`redfish` (A271) rotates server management controller accounts through Redfish's
AccountService (HPE iLO first, then any conforming controller): the administrator
opens a Redfish session, finds the bound account's `ManagerAccount` by `UserName`,
PATCHes its `Password` (sending the account's ETag as `If-Match` when the controller
gives one) and logs the session out. The change is proved by opening a new session
with the new password; a change the controller does not prove is put back to the
predecessor. Discovery lists every account with its `RoleId`; Redfish never returns a
password. The served proof runs against a Redfish stand-in: the account moves to the
published password alone, a controller that answers but keeps the old password is
rolled back, discovery stages each account's role, and no session is left open.

`esxi` (A271) rotates VMware ESXi local accounts through the vSphere Web Services API
(SOAP at `/sdk`): an administrator signs in (`SessionManager.Login`), changes the bound
account with `HostLocalAccountManager.UpdateUser` and signs out; the password travels as
escaped XML in the request body only. The change is proved by signing in as the account
with the new password, and a change the host does not prove is put back. `vpxuser` and
`dcui` are refused: vCenter and the console manage them. Discovery reads the local users
(`RetrieveUserGroups`) and the roles their permissions grant (`RetrieveAllPermissions`),
marking `vpxuser` and `dcui` as system accounts. The served proof runs against a stand-in
of the API with the same checks as the Redfish proof.

`vcenter-sso` (A271) resets vCenter's local single sign-on users' passwords: vCenter
offers no public API that sets another SSO user's password, so the provider runs the
documented `dir-cli password reset --account <user> --new '<password>' --login
<administrator@domain>` in the appliance's root shell over SSH (a key, the host key
pinned, shell history off), typing the SSO administrator's password at `dir-cli`'s prompt
so it never appears on a command line. The new password is `--new`'s argument, as
`dir-cli` documents it. The change is proved by opening a vSphere Automation API session
(`POST /api/session`) as the user, and a reset the appliance does not prove is put back.
Discovery lists the SSO `Administrators` group. The served proof runs against a stand-in
of the appliance's shell and REST API.

`okta-user`, `entra-user` and `google-workspace-user` (A272) rotate identity provider
administrator passwords — the break-glass super administrators — through each provider's
own administration API: Okta's partial user update with an API token, a Microsoft Graph
`passwordProfile` PATCH with an application's token, and an Admin SDK Directory PATCH as a
service account impersonating another super administrator. Okta and Entra prove a change
with one non-interactive sign-in (Okta's Authentication API, where an MFA step after the
right password counts and the pending transaction is cancelled; an Entra resource-owner
sign-in read by its error code); a proof is never retried, so a wrong password costs one
lockout attempt. Google has no such check, so its verification reports not available.
The served proof runs against stand-ins of all three with a lockout counter, which never
reaches its threshold.

A static rotation (or its schedule) can hold the predecessor until its consumers have
moved (A240): `consumers` names the labels whose delivery reports
(`POST /api/v1/secrets/deliveries` with `state: verified`, the version the consumer's
application proved it uses) must reach the new version, and `retire_after_seconds`
is the approved deadline after verification (up to 30 days; required with
`consumers`) at which the predecessor retires even if a consumer never reports.
Retirement waits without spending the worker's retry budget, looks again as soon as a
named consumer reports, and is recorded with `retire_not_before` and
`retire_approved_by` (the requester, or `secret-rotation-schedule:<id>`). The command
view keeps `credential_valid` (the successor passed its own verification) apart from
`consumer_adoption` (`not_requested`, `pending` or `adopted`, with each consumer's
verified version), so a rotation that retired at its deadline still shows which
consumers never adopted. The preview names the consumers and the deadline. The served
proof runs the PostgreSQL two-user cycles with the application reporting each version
it writes with: no session ends at retirement, and a consumer that stays silent is
retired past at the deadline with adoption still pending.

A provider rotates in one of two phase models (A240), and the command view shows
which as `rotation_phase`. Two-phase providers (the database providers, AWS IAM) keep
the predecessor working until retirement. A single-phase provider invalidates the
current credential the moment it issues the next, so consumers fail until they read
the new version: the preview says so and stays blocked, and a rotation or schedule is
refused (`400`), until the request sets `acknowledge_single_phase: true`; the command
and schedule then record `single_phase_acknowledged`. The first single-phase provider
is `auth0`, which rotates an application's client secret through the Management API's
`rotate-secret` (each role is bound to the application's client ID; it rotates only
and issues no leases) and verifies the new secret at the tenant's token endpoint
(`verify_mode: authenticated`). It is built against a stand-in of the Auth0 API, with
no Auth0 proof yet.

`datadog` (A240) issues and rotates Datadog keys. A role bound to `api_key` gets an
organization API key; one bound to `application_key <service-account-id>
<scope>,<scope>` gets an application key of that service account restricted to those
scopes. Revocation deletes a lease's key. A static rotation is two-phase: the
successor is created next to the predecessor, both work until retirement (or the
consumers' deadline), and retirement deletes only keys the provider named. An API key
is verified at the site's `/api/v1/validate` (`verify_mode: authenticated`); a scoped
application key has no side-effect-free proof, so its rotation records
`not_available`. A retried creation first deletes the key its earlier attempt named,
so an uncertain attempt leaves one key. It is built against a stand-in of the Datadog
API, with no Datadog proof yet.

`openai` (A240) issues and rotates OpenAI service-account keys. Each role is bound to a
project; a lease, or a rotation's successor, is a new service account in that project,
whose API key OpenAI returns once at creation, and revocation (or retirement) deletes
the service account and its key with it, after checking the provider named it. The
rotation is two-phase, and a key is verified by listing models with it
(`verify_mode: authenticated`). It is built against a stand-in of the admin API, with
no OpenAI proof yet.

`azure-entra` also rotates a stored client secret (A240): the successor is a second
password of the bound application, added through Microsoft Graph and named for the
rotation, and the predecessor keeps working until retirement removes it. Removal first
checks the password's display name, so the application's own secrets, which the
provider did not add, are never removed. A secret is verified with a client-credentials
token request (`verify_mode: authenticated`); a new secret can take a moment to reach
every Entra region, and the rotation's verify retries. Rotation is built against a
stand-in of Graph and the identity platform, with no Entra proof yet.

`okta` and `databricks` (A240) rotate an existing client's secret: an Okta app's client
secret (two per app) or a Databricks service principal's OAuth secret (five per principal).
A rotation adds a secret beside the one consumers use, and retirement removes the old one:
Okta deactivates and then deletes it, as Okta requires. These secrets carry no name, so the
bound client is the boundary: a reference to a secret of any other client is refused, and
every secret of the bound client is a version of the credential being rotated. Okta proves a
secret by authenticating the app at the org's introspection endpoint, Databricks by getting
an account-level OAuth token with it (`verify_mode: authenticated`). Both rotate only and
are built against stand-ins of their APIs, with no live proof yet.

`gcp-iam` also rotates a stored service-account key (A240): the successor is a new key
of the bound service account (an account holds ten), and retirement deletes the
predecessor. Revocation deletes only keys of the bound service account: the reference
names the key and becomes the request path, so any other is refused. A new key can take a
minute to work and Google offers no side-effect-free check of one, so verification
reports `not_available` and retirement waits for consumer evidence or the approved
deadline. It is built against a stand-in of the IAM API, with no Google Cloud proof yet.

`snowflake` also rotates an existing user's key pair (A240): a role bound to
`user <NAME>` (with `allow_static_rotation`) rotates that user's key through its two key
slots, `RSA_PUBLIC_KEY` and `RSA_PUBLIC_KEY_2`. The successor goes in the slot the
predecessor is not in, both keys sign in until retirement unsets the predecessor's slot,
and only while that slot still holds the predecessor's key; the reference is
`<NAME>/<slot>/<fingerprint>`. A key pair is proven by running `SELECT 1` as its user
through the SQL API (`verify_mode: authenticated`). When both slots hold keys, the first
rotation names the one consumers use in `old_ref`. Built against a stand-in of the SQL
API, with no Snowflake proof yet.

The hosted API key providers (A240) share one engine: a lease, or a rotation's
successor, is a new key created with the administrator's credential under the target
the role is bound to, named for the lease or command, and revocation (or retirement)
deletes it after checking the provider named it, so a key someone else created is never
deleted. A retried creation first deletes the key its earlier attempt named. Every
rotation is two-phase: both keys work until the predecessor is retired.

| `type` | A lease is | Scoped by | Verified by |
|---|---|---|---|
| `openrouter` | an API key | the role's credit limit | reading its own details (`authenticated`) |
| `fireworks` | an API key of the bound user | that user's permissions | listing accounts (`authenticated`) |
| `litellm` | a proxy virtual key | the role's models | reading its own details (`authenticated`) |
| `supabase` | a secret API key of the bound project | the project (secret keys bypass row-level security) | nothing: Supabase documents no key check (`not_available`) |
| `convex` | a deploy key of the bound deployment | the role's actions, when listed | nothing: only the deployment checks a deploy key (`not_available`) |
| `dbt` | a service token | one permission set, on one project or all | listing the accounts it reaches (`authenticated`) |
| `cloudflare` | an API token copying a template token | the template's policies and condition | Cloudflare's token verification route (`authenticated`) |
| `cloudflare-r2` | an S3 key pair: the new token's ID and the SHA-256 of its value | the template's R2 policies | nothing: the pair carries no token and S3 is the account's host (`not_available`) |

Where verification is `not_available`, retirement waits for the named consumers'
adoption reports or the approved deadline. Cloudflare keys are new tokens beside the
predecessor, not Cloudflare's roll, which would end the old value at once. All eight are
built against stand-ins of their
vendors' APIs, made from the vendors' API references, with no live vendor proof yet.

`dynamic-lease:<provider>` rotates the lease an application secret publishes, on a
configured `postgresql`, `mysql`, `redis` or `aws-sts` provider. The secret's name is the
provider role, `old_ref` is the lease id the secret publishes now (or `none`), and
`ttl_seconds` (required, at most the provider's `max_ttl`) is the new lease's
lifetime. It runs as the same durable command: **stage** issues the new lease
through the durable lease lifecycle under an idempotency key derived from the
command, so a crash resumes the same lease; **cutover** publishes its credential as
the next secret version; **verify** opens a database session, or authenticates to
Redis as the lease user and runs `PING`, or signs STS `GetCallerIdentity` with the
new temporary session and matches an allowed configured role; **retire** revokes the `old_ref` lease and
completes only once the provider confirms the removal (until then the outbox
retries, and a removal that never completes ends as `retire_pending`). A failed
verification restores the predecessor and revokes the new lease. The command view
reports `ttl_seconds` and the new lease's `new_expires_at`, and the console's
rotation form takes the lease TTL. Rotating a MongoDB, other cloud IAM or Kubernetes
lease remains unavailable (`503`); issue, renew and revoke those leases through
the lease endpoints. Native-store value rotation remains a separate event-sourced
operation.

The scheduled path records connector cadences at
`POST /api/v1/secrets/rotation-schedules`, lists them with
`GET /api/v1/secrets/rotation-schedules`, and runs due ones with
`POST /api/v1/secrets/rotation-schedules/run-due`. Schedule names are distinct per
tenant: one under a name another schedule holds answers 409 (`code: name_held`) and
records nothing. A schedule may name a
connector target, a static provider that allows static rotation for the secret,
or `dynamic-lease:<provider>` with `ttl_seconds` (A201-L1). A dynamic-lease
schedule is checked like an on-demand dynamic-lease rotation before it is stored:
the TTL is required and at most the provider's `max_ttl` (`400`, `422`), the
provider must issue and verify leases for the role (`503`), and `old_ref` must be
`none` or the role's active lease (`409`); `ttl_seconds` on any other schedule is
`400`. A static or dynamic-lease due edge queues one durable
command, chains its predecessor from the credential the last terminal command left
live (the successor after `completed`, the preserved predecessor after
`rolled_back` or `failed`), defers with `command_in_flight` while a command is
still running, and fails the edge after an unresolved `rollback_failed` until an
operator resolves that command. Each dynamic-lease command issues a new lease of
the schedule's TTL, publishes it as the secret's next version and revokes the lease
before, so the next cadence starts from the newest lease. A schedule whose provider
no longer allows static rotation, or a dynamic-lease schedule whose provider is no
longer configured to issue and verify its leases, is terminalized as
`unsupported`, disabled, and makes zero provider calls. A queued connector run
advances `old_ref`; a connector whose local version committed before terminal
delivery failure also advances to that committed version so later cadences cannot
stale-loop.

An operator can read one schedule at `GET /api/v1/secrets/rotation-schedules/{id}`
and use `POST .../{id}/pause`, `.../{id}/resume`, or `.../{id}/retire` with a fresh
`Idempotency-Key` and `secrets:write`. The console exposes these actions in the
schedule table; the CLI has matching `secrets rotation-schedules` commands. Pause
stops future due-run claims but retains the exact next due time, predecessor
reference, and run history. Resume checks that the connector still exists and
the predecessor matches the current native secret version, then starts from that
retained due time; if it is past due, the next scheduler tick can run it. Retirement
is permanent, keeps the schedule and its receipts visible, and reserves its name.
The immutable `secret.rotation_schedule.paused`, `.resumed`, and `.retired`
events each carry a matching closed action and operator-request reason code, so
audit filters for one action cannot silently include the others. Their
current events also retain the authenticated request binding and exact first
public response, including a successful no-op. If the HTTP result is lost, retry
the **same** key, caller, route, and body: the original response is returned
without applying the old decision over a newer operator action. A changed request
under that key is rejected. If a control event is durable but its SQL projection
has not caught up, a different-key control or a brand-new due child fails closed.
The due tick records a terminal `503` with the affected schedule ID and creates
no child command or provider effect; after projection recovery, run a new tick
with a fresh key. The tenant-scoped projection changes only future eligibility.
A run already claimed when an operator pauses or retires can finish and record
its exact successor and delivery receipt. The console shows a
separate retired state and reviews this effect before retirement.

The terminal `error` field is a closed, status-specific evidence class, never a
provider response or wrapped error string. Empty-success statuses carry no error;
delivery and rollback failures use their exact fixed classes; unavailable and
other terminal statuses accept only their documented finite classes. Startup also
sanitizes retained schema-v1 events written by older binaries. That rewrite is
fleet-gated by `TRSTCTL_SECRET_ROTATION_HISTORY_FLEET_READY`, signed, sequence
preserving, and limited to the one JSON error token. Until it is safe to stop old
writers, projection catch-up, audit/search, retention, and backup export fail
closed without returning any legacy payload bytes.

The console revalidates that same closed vocabulary before rendering a successful
or partial tick. An otherwise well-formed response with an unknown run, rollback,
deferred, or system error is treated as a malformed scheduler failure; neither its
error nor its problem detail is displayed. This keeps a stale cache or damaged
proxy from turning rejected provider text back into operator-visible copy.

The manual connector form is review-first. A blocked preview explains why a provider
or reference cannot run; a ready preview states what the mutation will write, which
external connector it will contact, how secret material is handled, and how to retry
or recover. Preview and execute remain separate server calls so viewing a plan can
never become an accidental rotation.

Each `run-due` idempotency key owns one durable PostgreSQL tick. The tick freezes
`due_through` from the outer idempotency row's database `created_at`, the UUID-ring
cursor where scanning began, the current row snapshot, the ordered non-secret
receipt, and the exact 50-run/500-scan budgets. One tenant has one live tick owner:
every progress or terminal compare-and-swap checks its fresh lease token,
generation, and PostgreSQL-clock lease. A simultaneous same-key caller receives a
non-cached `503` in-progress error; a different live key receives a busy `503`.
After expiry, the same key resumes the same cutoff, cursor, receipt, and budgets. A
different key first freezes the abandoned tick as an exact indeterminate `503`,
without moving its cursor, then begins from that cursor; replaying the abandoned
key returns those retained bytes.

Before a scheduled connector effect can start, the tick saves the row it is about
to run and PostgreSQL records one immutable child command for the exact
`(tenant, schedule, due_at)` edge. Run, command, and terminal-event IDs are
deterministic, while each live claimant receives a fresh lease token. Overlap,
runner replacement, restart, and projection rebuild therefore resume or reconcile
the same command instead of minting another secret version. The version-3 terminal
event carries the exact due time, provider, key, old reference, command key, and
request binding. Cadence replay advances from `due_at`, not a producer's wall
clock; an unmatched schedule compare-and-swap rolls back terminalization instead
of manufacturing a completed command. Tick progress, receipt, cursor movement,
and an optional deferred child-lease release commit in one transaction, so a crash
exposes either all of a row's progress or none of it.

There are exactly four nonterminal deferral reasons: `approval_pending`,
`command_in_flight`, `command_claimed`, and `config_revision_unanchored`. The last
one means a schedule created before immutable configuration evidence existed must
be saved again; that scan creates no child command and calls no provider. Every
deferral keeps the same due edge and is returned with schedule ID, reason, due time,
and optional error; later due rows are still scanned. The stable UUID ring wraps at
most once per tick. One tick executes at most 50 rotations and scans at most 500
rows. Landing exactly on either bound is reported conservatively as
`run_limit_reached` or `scan_limit_reached`, with
`complete:false`, because only an under-budget empty or short ring proves that no
due row remains. The console names the consumed bound and tells the operator to run
the next tick from the durable cursor.

If shared store, event, custody, or integrity state fails after earlier rows finish,
the endpoint returns a truthful `503` envelope with `complete:false`,
`partial:true`, the failed schedule ID, and the system error. The outer idempotency
record caches that whole envelope: replaying the same key is byte-identical and
executes no child command; a new key reconciles any retained terminal event and
continues later rows. A tick's composite foreign key keeps its bound outer
idempotency row out of normal garbage collection. The indeterminate takeover
receipt stays until its original key returns and completes the outer row; deleting
that completed outer row then cascades to the tick. Terminal child-command
receivers are garbage collected only after their exact immutable version-3
terminal event is still retained, the schedule has advanced past that due edge,
and a newer command exists. The newest command remains as a finite
one-row-per-schedule lineage fence; claimed or ambiguous commands are never purged.

Scheduled runs execute two provider classes:

- `connector:<target>` atomically commits a native-store version and one sealed
  secret-sync outbox command. The response sets `queued:true` and `completed:false`;
  only the bounded outbox worker calls the connector. Delivery failure stays on the
  durable job for retry and does not perform a compensating direct write.
- A static provider queues one durable static-rotation command per due edge, as
  described above.

Scheduled `dynamic-lease:<provider>` rotation is what comes next: creating such a
schedule returns `503`, and a historical one is terminalized as `unsupported`. Run
a dynamic-lease rotation on request through `POST /api/v1/secrets/rotations`.

The rotation package's library rotators (stage/cutover/verify/retire-and-rollback
for PostgreSQL, MySQL and AWS IAM) are not what the served commands run: those run
the durable phases above and use the package's PostgreSQL and MySQL credential
checks.

### Ephemeral API keys (F38)

For high-churn automation, trstctl issues short-lived API keys through the served
control plane:

- `POST /api/v1/ephemeral/api-keys/preview` validates and normalizes the exact
  tenant/caller/subject/scopes/TTL plan without creating a bearer, event,
  idempotency row, projection, or external effect. It returns a server-keyed
  `request_fingerprint` and complete recovery/verification instructions.
- `POST /api/v1/ephemeral/api-keys` mints a tenant API token with `subject`, `scopes`,
  `ttl_seconds`, and an optional reviewed `preview_fingerprint`. A stale fingerprint
  returns `409` before issuance.
- `trstctl-cli ephemeral api-keys preview -f body.json` and `ephemeral api-keys
  issue -f reviewed.json` drive the same two-step contract.
- Both review and issue require `access:write`; both also attenuate authority by
  refusing any requested scope the caller does not already possess.
- Execution is guarded by `Idempotency-Key`, so a byte-identical retry with the same
  key returns the original response instead of minting twice. Reusing that key with
  changed input returns `409`.
- The response returns the raw `trst_...` token once; the event log stores only the
  token hash in `api_token.created` — the raw token is never persisted or emitted.
- The served leaseworker sweeps expired keys and emits `api_token.revoked`, so the read
  model shows `revoked_at` evidence and authentication rejects the key after TTL.
- The console makes the whole lifecycle executable: configure, effect-free review,
  reviewed issue, metadata-ledger observation, same-key recovery after uncertainty,
  bearer-only verification, immediate revocation, and post-revoke cleanup. The raw
  bearer lives only in React memory and is removed on dismiss or revoke.

```json
{
  "subject": "ci-preview-deploy",
  "scopes": ["access:read"],
  "ttl_seconds": 900,
  "preview_fingerprint": "sha256:<value returned by preview>"
}
```

Use it for short CI jobs, deploy previews, partner imports, and similar workflows
needing a narrow bearer credential for minutes, not a reusable key.

### Encryption-as-a-service & KMIP (F66)

Transit encrypts, decrypts, HMACs, signs, verifies, and rewraps data using tenant-scoped
named keys the application _never sees_, mounted at `/api/v1/transit/*` with a
one-for-one CLI: `GET /api/v1/transit/keys` / `transit keys list` reads only
tenant-scoped name, purpose, and current-version metadata;
`GET /api/v1/transit/keys/{name}/versions` / `transit keys versions <name>` reads
the complete retained version history without key material; `GET
/api/v1/transit/status` / `transit status` reads effect-free sealed-restore and
KMIP runtime posture;
`POST /api/v1/transit/keys` / `transit keys create` mints a key,
`.../keys/rotate` / `transit keys rotate` rotates it, and the same
`POST /api/v1/transit/<op>` / `trstctl-cli transit <op>` pairing covers `encrypt`,
`decrypt`, `rewrap`, `hmac`, `sign`, and `verify`.

Ciphertexts are versioned (`trv:<version>:...`) so rotation can rewrap old data to the
newest version. Requests are tenant-bound and idempotent, auth-gated by `keys:write`
for creation/rotation/encrypt/decrypt/rewrap/HMAC/sign and `keys:read` for verify.
Plaintext and associated data live in wipeable `[]byte` buffers zeroized after the
response is written. With the deployment KEK configured, each tenant's keyring is one
sealed row in PostgreSQL that every replica shares: every create/rotate is saved before
it is reported, a replica that lacks a key or version reloads the row, and a key
created or rotated on one replica works on all of them and after a restart. A keyring
an earlier version checkpointed to `transit.keyring_dir` is imported once at startup;
a row or file the original KEK cannot open fails the operation or the start instead of
silently replacing the keys. There is deliberately no browser upload/import path for
key material.
Events —
`transit.key.created`, `transit.key.rotated`, `transit.encrypt`, `transit.rewrap`,
`transit.hmac`, `transit.sign` — give audit evidence without logging key bytes or
plaintext.

The console's **Encryption and signing** task at `/secrets/engines` reads back safe
key metadata, creates AEAD/HMAC/signing keys, selects only a compatible key for each
operation, rotates the selected key of each type, and operates encrypt, decrypt,
rewrap, HMAC, sign, and verify. It also shows the full retained version history,
Transit-only immutable audit receipts, automatic sealed-restore state, an explicit
proof-first failed-operation recovery journey, and the real tenant-bound KMIP
listener/profile status. Transit is a separate encryption service, so those controls
remain available when the optional native secret store is disabled. No key bytes
enter the browser. The raw plaintext returned by decrypt is shown in a reveal-once
panel and removed from the page when dismissed.

```bash
cat > transit-key.json <<'JSON'
{"name":"payments","kind":"aead"}
JSON
trstctl-cli --idempotency-key transit-payments-create transit keys create -f transit-key.json
trstctl-cli transit keys list
trstctl-cli transit keys versions payments
trstctl-cli transit status

cat > transit-encrypt.json <<'JSON'
{"key":"payments","plaintext":"Y2FyZC10b2tlbi0xMjM=","aad":"dGVuYW50PXBheW1lbnRz"}
JSON
trstctl-cli --idempotency-key transit-payments-encrypt transit encrypt -f transit-encrypt.json
```

If a create, rotate, encrypt, rewrap, HMAC, or sign response is uncertain, do not
invent a replacement key or changed request. Keep the original inputs and
`Idempotency-Key`, read `transit status`, the key's version history, and the filtered
`transit.*` audit receipts, then replay the byte-identical request with the same key.
For a restore failure, repair the original KEK, tenant key domain or database and
restart; never delete or overwrite the sealed keyring row or file just to make the
process start.

For legacy gear, the binary can also mount an opt-in KMIP listener:

- `TRSTCTL_PROTOCOLS_KMIP_ENABLED=true`
- `TRSTCTL_PROTOCOLS_KMIP_TENANT_ID=<tenant-uuid>`
- `TRSTCTL_PROTOCOLS_KMIP_ADDR=:5696`
- `TRSTCTL_PROTOCOLS_KMIP_CERT_FILE=/path/server.crt`
- `TRSTCTL_PROTOCOLS_KMIP_KEY_FILE=/path/server.key`
- `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE=/path/client-ca.crt`
- `TRSTCTL_PROTOCOLS_KMIP_CLIENT_REGISTRATIONS=true` (optional: every tenant's own clients)

The listener is raw KMIP over mutual TLS 1.3; the TLS layer verifies the client cert
chain before the KMIP handler sees a frame. The service stores objects under the
configured tenant, emits immutable `kmip.object.created`, `kmip.object.revoke`, and
`kmip.object.destroyed` audit events, and zeroizes in-memory key material on destroy,
rekey, and shutdown. The served OASIS 1.4 profile is stock-client-tested: Query,
DiscoverVersions, Create/Register an AES-256 `SymmetricKey`, Get it plain or
AES-GCM-wrapped (and register the wrapped value back), Locate, Revoke, and Destroy over
TTLV. Unsupported operations get a KMIP failure response, not an unframed TCP close.

The listener also serves key pairs. Create Key Pair generates an RSA (2048, 3072 or
4096 bits) or ECDSA (P-256 or P-384) pair inside the server; each half links to the
other and starts Pre-Active, so it neither signs nor verifies until Activate. Sign
runs with the private key (RSA PKCS#1 v1.5 or PSS, or ECDSA, over SHA-256, -384 or
-512, single-part Data) and Signature Verify with the public key, which Get returns as
an X.509 SubjectPublicKeyInfo. The private key is sealed like every key the server
holds and Get refuses it (Not Extractable) unless the client set Extractable when it
created the pair, so by default it never leaves the server; a key a client makes
unextractable stays unextractable. Get Attributes, Get Attribute List, Add, Modify
and Delete Attribute serve names, contact information and `x-` custom attributes with
text values; the server's own attributes (state, dates, links, usage mask) are
read-only. A revocation for key or CA compromise leaves the object Compromised, and
it signs and verifies nothing after that. Locate narrows by object type, algorithm and
name. A stock client drives all of this in an opt-in proof that builds PyKMIP 0.10:
`TRSTCTL_PYKMIP_PROOF=1 go test ./internal/kmip -run PyKMIP -v`.

With `TRSTCTL_PROTOCOLS_KMIP_CLIENT_REGISTRATIONS=true` one listener serves every
tenant's own clients. A tenant registers a client on the Transit page, with
`trstctl-cli kmip clients register`, or at `POST /api/v1/kmip/clients` (`keys:write`),
and gets a one-time enrollment: a username (the registration's ID) and a password
shown once, valid for 24 hours, of which the server keeps only the SHA-256. Configure
the client with the listener's server CA, its own TLS certificate and that username
and password; its first KMIP request binds the certificate it presents to the tenant,
and from then on the certificate alone selects the tenant. The handshake proves the
client holds the certificate's key and the secret proves the tenant issued the
enrollment, so a tenant cannot claim another tenant's client by registering a
certificate it has only seen, and a certificate binds to one registration at a time.
Each tenant sees only its own objects. When the client moves to a new certificate,
issue a new enrollment (`trstctl-cli kmip clients enroll <id>`); the old certificate
keeps working until the new one enrolls. Removing a registration
(`trstctl-cli kmip clients remove <id>`) refuses its certificate from its next request.
`TRSTCTL_PROTOCOLS_KMIP_TENANT_ID` and `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE` become
optional; set together, they keep serving the clients the deployment's CA issued for
that tenant.
The Transit status endpoint and console report `not_configured`, `starting`, or
`listening` from the assembled tenant binding and live listener state. That status is
not a conformance claim: use a stock KMIP client to prove the complete mTLS wire path.

### Secret sync (F68)

trstctl pushes secrets _outward_ via the durable outbox (journaled first, at-least-once,
no half-writes). Operators first call `POST /api/v1/secrets/syncs/preview`. Preview
checks only the tenant-scoped secret metadata and configured target catalog. It does
not open the secret value, emit an event, write an outbox row, or contact the target.
For a ready plan it returns the exact secret version, destination, effects, recovery
steps, verification steps, and a caller-bound request fingerprint.

`POST /api/v1/secrets/syncs` reads the stored secret only after the operator submits
that reviewed fingerprint, writes a sealed
outbox row in the same tenant-scoped transaction, delivers through the configured
pusher, and returns metadata only (`job_id`, `name`, `target`, `remote_key`,
enqueued/delivered flags). `GET /api/v1/secrets/syncs/{id}` reads the exact job's
tenant-scoped pending, delivered, or failed projection; `delivered` records the
worker's target receipt, so independently read the target to verify its value.
`GET /api/v1/secrets/syncs/targets` lists the catalog and marks which targets
are configured. Shipped concrete pushers: AWS Secrets Manager, AWS Systems Manager
Parameter Store, GCP Secret Manager, Azure Key Vault, GitHub Actions, GitLab CI,
Vercel, Netlify, Kubernetes, Terraform Cloud/OpenTofu, HashiCorp Vault/OpenBao KV v2,
a signed webhook (templated JSON with an HMAC-SHA256 signature over a timestamp and
the body; see [configuration](../configuration.md#signed-webhook-parameter-store-and-netlify-targets)),
a generic CI/JSON endpoint with no payload signature, and the hosted targets of
A241 (Heroku, Render, Railway, Fly.io, DigitalOcean App Platform, Northflank, Qovery,
Cloud 66, Laravel Forge, CircleCI, Travis CI, Bitbucket Pipelines, TeamCity, Spacelift,
Humanitec, Rundeck, Checkly, Windmill, Zabbix, Portainer, Devin, Daytona, Ona,
Trigger.dev, Cloudflare Workers, Cloudflare Pages, Cloudflare Secrets Store, Azure App
Configuration, OCI Vault, OVHcloud Secret Manager, Databricks, Supabase, Camunda and Chef
Infra Server; see
[configuration](../configuration.md#hosted-sync-targets-a241)). Each catalog row says
whether a scoped sync can target it, its `qualification` on the A242 ladder (`served`,
or `locally-proven` for KV v2; the integration catalog's unbuilt targets are listed as
`discovered`, each with a `note` on what it waits for), whether it is `generic` (the
signed webhook and generic CI JSON take any receiver of their format and are never
counted as native support), what it reads back (`readback`: `value`, `digest`
or `receipt-only`) and how far it is proven (`proof`: `locally-proven` against the
vendor's own software, or `stand-in-only` against a stand-in built from the vendor's
API documentation).
The console's **Check a previous delivery** field accepts a job ID from any
receipt or CLI run. It reads the same durable status and keeps the ID in the
page URL, including when the target is no longer configured. A pending status
does not prove the external value changed; read the destination independently.

Every redelivery reuses the same sync-operation ID — AWS Secrets Manager sends it as
both `ClientRequestToken` and `Idempotency-Key`; GCP Secret Manager and Azure Key Vault
compare the current version before creating another, forwarding the ID too — so a
crash between commit and acknowledgment reconciles to the existing value instead of
duplicating, rejecting any changed replay outright.

Commands are FIFO across the whole tenant+target, not merely one spelling of a
remote key: receivers commonly normalize `/TOKEN/` and `TOKEN` to the same object.
Each new command copies its positive immutable event sequence into the projected job
and outbox row; a retry/backoff therefore blocks later same-target commands while a
different target can progress. Terminal delivery evidence is itself a deterministic
event receipt, and startup compares retained history with SQL before workers run.
Immediately before receiver I/O, the worker records a monotonic command-global
start token under the same tenant+job terminal-choice lock. A failed event is safe
only when durable authority proves no generation could have changed the receiver;
configured HTTP targets now place that token after a successful TCP dial but before
any request bytes. A refused dial therefore leaves zero possible receiver starts,
so a later successful retry can release the next command in target order. A TLS
failure after connect, a request timeout, or a lost response still counts as a
possible effect; the worker cannot infer that the receiver made no change.
An ordinary timeout or expired worker remains `effect_possible`, keeps its FIFO
barrier, and is retried with the same receiver idempotency key until delivery is
proved. The one exception is a typed local no-network result owned by the first and
still-only start token. Its closed error and event attempt count are frozen before
append so crash recovery reproduces the same canonical evidence bytes.

A lost result is proved by reading the receiver back, never by sending the value
again. Targets whose receiver exposes its state (Vault KV v2, Terraform Cloud and
OpenTofu through the operation marker, GCP Secret Manager, Azure Key Vault and
Kubernetes; the catalog lists `receiver-reconcile`) are read back under the same
operation ID right after an ambiguous error, again when the retry budget is spent,
and once more after any delivery that needed more than one receiver start. A match
delivers, or settles the delivered command with one retained
`secret.sync.receiver_settled` receipt that releases the lane; a provable absence
fails the command with reconciled authority so the next version proceeds. Targets
with no readable state (GitHub, GitLab, Vercel, Netlify, the signed webhook and the
generic CI JSON receiver) keep the lane closed after a multi-start delivery until an operator reconciles the
job: `POST /api/v1/secrets/syncs/{id}/reconcile`, `trstctl-cli secrets syncs
reconcile`, or the Secrets console, with `operator_verified` and what they saw at
the destination (`value_present` or `value_absent`). The attestation is recorded with
the operator's name; a blind call on such a target is refused with `409 unknown`,
and `GET /api/v1/secrets/syncs/{id}` names the blocking predecessor
(`blocked_by_job_id`), the receiver authority (`receiver_effect_state`,
`receiver_io_starts`) and whether the target is `reconcilable`.
The command ID also includes the tenant's secret lifecycle epoch, so offboarding and
re-registering the same tenant UUID cannot reactivate old ciphertext or outcomes.

Worker capacity and fairness use the tenant plus that effective target lane. Two
tenants may both call a target `ci`, but one tenant's slow `ci` receiver does not
consume the other tenant's `ci` lane or circuit allowance. Within either tenant,
the whole target remains serial and FIFO, including remote-key aliases. The bounded
secret-sync family worker pool and queue still cap aggregate work across tenants and
reject promptly when that global provider-plane budget is full.

Targets are configured under `secret_integrations.sync_targets`, one tenant/credential
reference each, resolved for a single outbox attempt before the locked buffer is
destroyed. GitHub values use its X25519/XSalsa20-Poly1305 sealed-box format — sealed
locally with the repo's public key, decryptable only by the matching private key's
holder, never sent as plaintext. Sync endpoints follow the dynamic-provider transport
rule: HTTPS by default, `allow_private_endpoint` is only an address grant, plaintext
needs the explicit loopback-only switch.

#### AWS, GCP, and Azure workload identity for secret sync

Each cloud is configured independently on its matching sync target:
`aws_workload_identity`, `gcp_workload_identity`, or
`azure_workload_identity`. Every switch is false by default. Enabling one forbids
that target's static credential fields, so a missing workload-identity source fails
closed instead of falling back to a long-lived token or access key. The three
provider exchanges are thin, hand-written REST encoders over one shared
`internal/cloudauth` cache and refresh-before-expiry seam; there is no cloud vendor
SDK or parallel authentication stack.

AWS Secrets Manager targets can replace long-lived access keys with an explicitly
configured workload identity. Set `aws_workload_identity: true` on that target and
leave `access_key_id`, `secret_access_key_ref`, and `session_token_ref` empty.
`workload_identity_endpoint` is optional and defaults to the AWS STS endpoint; it is
primarily useful for an approved private endpoint or test substrate. The default is
still off, so existing static-credential targets do not change and a fresh install
makes no token-exchange egress.

An operator then creates a tenant source at
`/api/v1/secrets/syncs/workload-identity-sources` (or with
`trstctl-cli secrets syncs workload-identities create --body-file ...`). The source
binds exactly one configured AWS target to an IAM role ARN, expected OIDC issuer
trust source, audience, subject, allowed remote-key prefixes, and a `file:` or
`secret://` proof reference. The API stores only this configuration and honest
`ready`, `active`, `disabled`, `offline_disabled`, or `exchange_failed` status; it
never accepts or stores an inline proof or AWS token. The console under **Secrets**
serves create, list, edit, delete, expiry, and failure-state workflows.
The target ID is an operator-chosen name, not a provider type. The target catalog
reports its configured protocol separately and offers it for this workflow only
when that target's workload-identity switch is enabled. Source creation refuses
an unconfigured target, a static-credential target, or a target for another cloud.
The cloud-manager coverage and unvaulted-secret posture also count configured
targets by their provider type. A custom target ID appears as the actual sync
target in the coverage response; the built-in ID remains the example when that
provider has no configured target.

Only the bounded secret-sync outbox worker resolves the proof, validates its signature
and exact issuer/audience/subject/expiry against the tenant's JWT/JWKS trust source,
and performs `AssumeRoleWithWebIdentity`. The shared `internal/cloudauth` minter
caches the short-lived result until its refresh window, keeps secret bytes locked and
wipeable, and passes them into the existing hand-written AWS SigV4 pusher. No vendor
SDK or parallel AWS integration is involved. When air-gap policy is enabled, the
worker records `offline_disabled` before opening a connection, marks that delivery
failed once with a stable reason, and does not retry forever.

GCP Secret Manager targets use the same boundary with
`gcp_workload_identity: true` and no `token_ref`.
`workload_identity_endpoint` defaults to the RFC 8693 endpoint at
`sts.googleapis.com`. A GCP source leaves `role_arn` empty and may set
`service_account`: when it is blank, the worker passes the short-lived STS bearer
to the existing GCP pusher; when it is present, the worker performs the optional
IAM Credentials `generateAccessToken` step at the configured
`workload_identity_impersonation_endpoint`. Both paths resolve and validate the
OIDC proof, exchange it, cache it, and refresh it through the same
`internal/cloudauth` minter used by AWS. The API, CLI, generated clients, and
console expose the same tenant-scoped source and honest runtime status.

Azure Key Vault targets use that same boundary with
`azure_workload_identity: true` and no `token_ref`.
`workload_identity_endpoint` is optional; when absent, the source's
`azure_tenant_id` selects
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`. The Azure source
sets `provider: "azure"`, the Entra application `client_id`, and a Key Vault
`target_scope`, normally `https://vault.azure.net/.default`, in addition to the
same trust source, exact audience/subject, target, allowed remote-key prefixes, and
proof reference used by the other clouds.

After the outbox worker validates the referenced OIDC proof, the thin Entra
exchange sends `grant_type=client_credentials`, the application client ID, target
scope, and that existing proof unchanged in the JWT-bearer `client_assertion`
field. This is the Entra federated-credential flow: trstctl does not mint a second
JWT, sign an assertion with a certificate, or hold an Entra certificate/private
key. The returned short-lived bearer goes through the existing hand-written
`internal/secretsync` Azure Key Vault pusher. It replaces this sync target's
static `token_ref`; the similarly named
`TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN(_FILE)` settings and
`internal/kms/azurekv` are a separate managed-key child-signer path.

Like the other two providers, Azure exchanges only during a bounded secret-sync
outbox delivery. The request handler merely journals the work. Air-gapped mode records
`offline_disabled` before any Entra or Key Vault network request, fails the queued
delivery once with a stable reason, and does not retry forever. The served Azure
proofs also verify tenant isolation and that neither the OIDC proof nor minted bearer
reaches the API response, event log, outbox payload, job error, or source status.
See [Secrets configuration](../configuration.md#secrets-credentials-at-rest) for
the complete target and source fields.

`GET /api/v1/secrets/cloud-secret-managers` / `trstctl-cli secrets
cloud-secret-managers`: read-only `cloud_secret` discovery for AWS Secrets Manager, GCP
Secret Manager, Azure Key Vault, and HashiCorp Vault KV, plus sealed-outbox sync
coverage for AWS/GCP/Azure — counts, operations, evidence, residuals only, never
values, credentials, or tokens.

`GET /api/v1/secrets/kubernetes-operator` / `trstctl-cli secrets kubernetes-operator`:
the `TrstctlSecretSync` CRD declares the target Kubernetes Secret, the trstctl
references to resolve, and which `Deployment`/`StatefulSet`/`DaemonSet` workloads
reload via a pod-template hash annotation; the operator writes `Secret.data` and
records `status.phase`, `status.contentHash`, and `status.reloadedWorkloads` —
metadata only.

`GET /api/v1/secrets/workload-injection` / `trstctl-cli secrets workload-injection`:
the `TrstctlSecretInjection` CRD consumes a namespace-local Kubernetes Secret and
patches `Deployment`/`StatefulSet`/`DaemonSet` pod templates with a memory-backed
shared volume, app-container mounts, optional `valueFrom.secretKeyRef` env entries,
and the `trstctl-agent --secret-inject` sidecar; the operator checks source
Secret key names before patching, reads its metadata/content hash, and discards
the Kubernetes response bytes. The sidecar copies volume files as byte slices
and wipes buffers. A missing requested key sets the CR to `Error` before a
workload rollout. `Ready` reports a successful template patch; check workload
pod readiness separately for sidecar runtime failures.

#### Rendering secrets into files for an application (A238)

`trstctl-agent --secret-render-config render.yaml` keeps files current for an
application on the host, with no Kubernetes Secret in the path. It reads secrets with an
API token (`secrets:read`) and needs no enrollment:

```yaml
server: https://trstctl.example:8443
ca_file: /etc/trstctl/ca.pem
token_file: /etc/trstctl/render.token
consumer: web-1/nginx          # the name its delivery reports use
interval: 30s
freshness: 1h                  # serve the last values at most this long without the control plane
state_dir: /var/lib/trstctl/render
templates:
  - name: htpasswd
    destination: /etc/nginx/auth/htpasswd
    mode: "0440"
    owner: nginx               # optional, with group: names or numeric IDs; needs a root agent
    group: nginx
    template: |
      app:{PLAIN}{{ secret "web/prod/password" }}
    reload: { command: ["nginx", "-s", "reload"] }   # or { signal: HUP, pid_file: /run/nginx.pid }
    verify: { url: "http://127.0.0.1/", username: app, password_secret: web/prod/password }
    on_stale: remove           # or keep
```

A template is literal text with `{{ secret "name" }}` placeholders and nothing else, so it
can't run code. It's rendered over bytes: a value is never turned into a string, never
logged, and wiped once written. A changed version is written atomically: a private
temporary file in the same directory is written, flushed and given its mode (never
readable by others), then renamed over the old file, so a reader sees the old file or the
new one, never part of either. Then the reload hook runs (an argv with no shell, or a
signal to the process in a pid file), and the verify probe asks the application to prove it
uses the new value (on Windows a mode sets the file's read-only attribute and an explicit DACL that
inherits nothing from the directory: the agent's user and SYSTEM, plus the agent's primary group for the
group bits and Authenticated Users for the other bits; a file an application holds open is replaced once it
lets go, within two seconds, or on the next render). The control plane hears `injected` when the file is written and
`verified` only when the probe passes. `trstctl-cli secrets deliveries list --name
web/prod/password` shows each consumer as `verified` on the current version, `injected`
only, or `behind`. A consumer can report only secrets it may read, at versions that
exist (`trstctl-cli secrets deliveries report`). When the control plane can't be reached
the last file keeps serving until `freshness` runs out. Then it's removed and the
application reloaded, or kept if the template says `on_stale: keep`. The fetch time lives
in a state file with no values, so the bound holds across an agent restart.

An agent running as root can give the file to the application's user: `owner` and `group`
(names or numeric IDs, either or both) are given to the private temporary file before it is
renamed into place, so the destination never appears with another owner, and every new
version keeps them (A238-L2). Only root can give a file away, so an agent that isn't root
refuses a template naming an owner or a group rather than leaving the file as its own. On
Windows they're refused too: there the file's DACL already names who reads it.

A template can also use a dynamic lease:
`{{ lease "payments-db/readonly" "username" }}` and `{{ lease "payments-db/readonly" "password" }}`
pick JSON fields of the lease's credential, and `{{ lease "provider/role" }}` takes all
of it (`lease_ttl` sets the lifetime asked for; the token then needs `secrets:write`). A
lease is renewed in place while it can be. When it can't be renewed far enough, or when
the file must be written again for another reason (a credential is returned only at
issue), a new lease is issued. The new credential is written and verified by the
application, and only then is the replaced lease revoked: replacement before revocation.
If the application doesn't verify, the old lease stays valid until it does. Each issue
uses a key saved before the call, so a retry after a lost answer gets the same lease back
instead of leaving an untracked one. Without the control plane, a file holding a lease
credential goes at the lease's own expiry if that comes before the freshness bound.

For an approved AWS permanent-key replacement, a template can first adopt the
exact session published by that change, then use the ordinary lease loop:

```yaml
consumer: orders-worker
# Other connection and state settings are the same as above.
templates:
  - name: orders
    destination: /run/orders/aws.json
    template: '{{ lease "workload-sts/orders" }}'
    lease_ttl: 15m
    replacement:
      change_id: 11111111-1111-4111-8111-111111111111
      provider: workload-sts
      role: orders
    verify:
      url: http://127.0.0.1:9080/credential-check
      expect_status: 200
```

Use the actual change ID and configured provider/role. This token needs
`access:read`, name-scoped `secrets:read`, and `secrets:write` for lease refresh.
Its authenticated subject and the configured consumer must match the approved
change. The probe must perform a fresh resource request with the currently loaded
credential; a generic liveness response cannot prove credential adoption.
The renderer waits for approved publication, checks its exact name/version and
native expiry, writes that session, and reports its version only after the probe
passes. The control plane then rechecks the role/session and deletes the captured
old key. A missing initial file is recovered from that same published version.
At the refresh threshold the renderer issues a new allowed role session, verifies
it, and retires its predecessor. Later sessions do not report themselves as the
original published secret version. Only public lease/change metadata is saved in
the state directory; keep that directory across restarts. STS retirement can stay
pending until native expiry. Local emulation proves API flow and resource readback;
AWS authorization and revoked-signature rejection require live cloud proof.

#### Secret volumes for pods, with no Kubernetes Secret (A238)

`deploy/kubernetes/csi-secrets.yaml` installs a node plugin (CSI driver
`secrets.csi.trstctl.com`) that hands a pod its secrets as an inline volume. Nothing is
stored in a Kubernetes Secret object, etcd or the node's disk:

```yaml
spec:
  serviceAccountName: api
  securityContext:
    fsGroup: 2000                  # the files are 0440, owned by root and this group
  volumes:
    - name: secrets
      csi:
        driver: secrets.csi.trstctl.com
        readOnly: true
        volumeAttributes:
          secrets: "password=payments/prod/db-password,api-key=payments/prod/api-key"
          freshness: 1h            # optional: serve the last values at most this long without the control plane
          onStale: remove          # optional: remove (the default) or keep
```

Each `file=secret-name` pair becomes one file. When the kubelet publishes the volume, the
plugin gets the pod's own service-account token, minted for the `trstctl` audience and
passed in the request's secrets (`serviceAccountTokenInSecrets`), which keeps it out of the
kubelet's logs. The plugin exchanges the token at `POST /api/v1/secrets/login` through the
`kubernetes` machine-login method, so the volume holds only what that pod's service account
may read. That method needs `allow_token_reuse: true`: machine-login tokens are single-use
by default, and the plugin presents the kubelet's token again until the kubelet rotates it. A restricted environment is open only to the members granted it (the member
subject is `system:serviceaccount:<namespace>:<name>`). A pod that may not read a secret
gets no volume, and the file of a secret the pod loses access to is removed at the next
republish. The values go into a memory filesystem (tmpfs: no devices, no set-id, nothing
executable, 8 MiB) the plugin mounts at the volume, and they leave the node when the pod
does. The kubelet republishes every volume periodically (`requiresRepublish`). A
republish writes a changed version atomically and reports it as `injected` for the
consumer `pod:<namespace>/<name>` (`secrets deliveries list`). An application can't
report `verified` through the volume; the agent's render templates can. When the control
plane can't be reached, the last files keep serving until `freshness` runs out. Then
they're removed, unless the volume says `onStale: keep`. The fetch time is kept in a
value-free state file, so the bound holds across a plugin restart.

Trust boundary. The plugin holds no credential of its own and no Kubernetes API access:
its service account mounts no token and has no RBAC. A pod's token is used only for the
login, and the session it buys lives in the plugin's memory until it nears expiry or the
volume goes. Mounting needs `CAP_SYS_ADMIN` and bidirectional mount propagation, so the
plugin's container is privileged. Whoever controls that container, or the node, can read
the volumes of the pods on that node, as with any node-local secret delivery. The kubelet
reaches the plugin over a node-local Unix socket, as with every CSI driver. The control
plane needs a `kubernetes` machine-login method that trusts the cluster's service-account
issuer, with the `trstctl` audience; the plugin pins the control plane's CA (`ca_file`).

`GET /api/v1/secrets/unvaulted` / `trstctl-cli secrets unvaulted`: repository and
third-party scanning sources, redacted `leaked_secret` finding counts, cloud-secret
discovery across AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and
HashiCorp Vault KV, and configured AWS/GCP/Azure sync targets — read-only and
metadata-only.

#### Scoped sync (A237)

A **scoped sync** keeps a whole scope in step with a destination: every secret under a
source prefix (a project environment such as `payments/prod/`, a folder, any name
prefix) goes to a configured KV v2 or hosted target under a destination prefix. A
hosted target holds variable names, so its destination prefix is a name prefix
(`APP_`) and `key_transform: env` names nested secrets (`db/password` becomes
`DB_PASSWORD`); a key the target can't hold is blocked in the plan. Define it once,
then preview and apply:

```
trstctl secrets scoped-syncs define -f sync.json   # {"name":"payments-prod","source_prefix":"payments/prod/","target":"vault","destination_prefix":"payments","delete_scope":"managed"}
trstctl secrets scoped-syncs preview <id>
trstctl secrets scoped-syncs apply <id> -f apply.json   # {"plan_digest":"…"}
```

The plan is value-free and lists every destination key with its action: `create`,
`update` (named drift when the destination changed outside the sync), `unchanged`
(on a receipt-only target, when this source version's delivery job succeeded: the
target can't show a change made outside the sync, and the plan says so),
`delete`, `orphaned`, `unmanaged` or `blocked`. A key the sync didn't write is never
touched: it's listed as `unmanaged`, and if a source maps onto it the item is blocked
until the definition sets `adopt_existing`. Deletes follow the reviewed delete scope:
`none` keeps a managed key whose source is gone (`orphaned`), `managed` deletes it,
and `prefix` deletes every key under the destination prefix, including keys the sync
didn't write. Two secrets on one key (`key_transform: env` maps `db-password` and
`db_password` both to `DB_PASSWORD`), and a key that would also be a folder (`db` beside
`db/password`), are blocked. Applying by the plan's digest fixes the plan in one event.
It then queues the durable per-secret sync jobs for the writes and one outbox command
per delete. A source or destination that changed since the preview makes the plan
stale (`409`, code `plan_stale`). A crash after a remote write is settled on retry by
reading the destination back, so the value isn't written twice. `scoped-syncs show`
lists the keys a sync manages with each delivery's status. A write or delete of a
managed key that fails for good also raises a warning on the notification surface
(`secret.scoped_sync.delivery_failed`, routed like other trust-operations alerts): it
names the sync, the destination key, the target and the reason, never a value, and a
failed delete keeps the key managed so the next plan proposes deleting it again.
Removing a definition leaves its destination keys where they are.

A definition is `manual` (it waits for a reviewed apply) or `auto`
(`trstctl secrets scoped-syncs mode <id> -f mode.json` with `{"mode":"auto"}`, or
`"mode":"auto"` at definition). On the leader, the control plane checks auto syncs every
30 seconds. When a sync's source names or versions changed, or every 15 minutes for
drift, it plans the sync again. A plan with changes and nothing blocked is applied exactly
as a reviewed apply would be, and the receipt names the reconciler. A blocked or failed
plan is recorded on the definition (`reconcile_status`, `reconcile_reason`) and writes
nothing until someone reviews it.

A third mode, `approved`, is approval-gated convergence (A237-L1). The control plane
plans an approved sync like an auto one. A plan with changes is applied only once the
tenant's required number of distinct approvers approve that exact plan; two are required
by default. The approvers are members who hold write in the source's environment, and the
requester never approves its own request. Until then the definition reads
`awaiting_approval`, naming the request (asked for by the sync's author). The next pass
after the approval applies the plan, and the approval is used once. A manual apply of an
approved sync waits for the same kind of approval, asked for by its caller. A changed plan
asks again. Leaving the `approved` mode, or removing an approved sync, needs
`access:write`, so the members it gates can't lift the gate themselves.

A definition is replaced in place, under the same ID and history (A237-L3), with `PUT
/api/v1/secrets/scoped-syncs/{id}` (`trstctl secrets scoped-syncs replace <id> -f def.json`).
It takes the same body and checks as a new definition. A replacement that keeps the
destination keeps the keys the sync manages there. One that moves it (another target,
destination prefix or key transform) releases them: they stay where they are, as on
removal, and the next plan writes the new place. A mode left out stays as it is. Taking a
definition out of `approved` this way needs `access:write`, as switching does. The replacer
becomes the definition's author, and a replacement that changes nothing records nothing.

In the console, **Secrets → Sync** lists the scoped syncs. `secrets:write` holders can
define new ones, preview and apply plans, edit a definition, and set a sync's mode:
manual, auto or approval-gated. An approval-gated sync names the request its plan waits
for and links Approvals.

### The auth-method framework (F58)

Before reading a secret, a workload must authenticate _to_ trstctl via the auth-method
framework: it presents a credential (a token, an OIDC JWT, a Kubernetes SA token, cloud
IAM, etc.), trstctl verifies it through the single isolated cryptography path
(timing-safe), and issues a scoped, time-bounded **session bearer**. Credential bytes
are never logged (wipeable memory, never a copyable string). The raw bearer is shown
once; only its one-way hash enters the event-sourced API-token projection. Successful
sessions and operator revocations become tenant-scoped evidence in the durable
session ledger, and revocation atomically disables the linked bearer. Authentication
failures return only a generic denial.

`POST /api/v1/secrets/login` serves seven machine methods — `token`, `kubernetes`,
`aws-iam`, `gcp`, `azure`, `oidc`, `jwt`. JWT-family methods verify against an
operator-supplied JWKS, check issuer/audience/expiry, and bind a tenant claim or pin the
method to one tenant. Each configured method must grant non-empty static `scopes`,
or OIDC/generic JWT may name one signed `scopes_claim`; setting both or neither
fails startup. A token's ordinary `scope`/`scopes` claim never overrides static
operator policy. AWS IAM uses the Vault-style signed `sts:GetCallerIdentity`
request, verifying the caller via STS without ever receiving the AWS secret access key.
The request trstctl sends to STS is rebuilt from the configured endpoint, the root path
and the signed STS parameters alone (`Action`, `Version` and the SigV4 `X-Amz-*` query
parameters, each in the shape AWS signs); a submitted request with any other parameter,
a repeated or malformed one, or another path is refused before anything is sent.

```yaml
secrets:
  enable_api: true
  # Optional builtin HMAC token method. Its deployment-wide verifier is usable
  # only for this tenant and grants exactly these scopes.
  auth_secret_file: /etc/trstctl/machine-auth.bin
  auth_token_tenant_id: 11111111-1111-1111-1111-111111111111
  auth_token_scopes: ["secrets:read"]
  machine_auth:
    - name: kubernetes
      tenant_claim: trstctl.io/tenant
      issuer: https://kubernetes.default.svc
      audience: trstctl
      jwks_file: /etc/trstctl/k8s-sa-jwks.json
      allowed_namespaces: ["payments"]
      allowed_service_accounts: ["payments/api"]
      scopes: ["secrets:read"]
    - name: aws-iam
      tenant_id: 11111111-1111-1111-1111-111111111111
      allowed_accounts: ["123456789012"]
      scopes: ["secrets:read"]
```

The `/secrets/access` console turns that backend framework into one complete,
review-first journey:

1. **Choose method.** Select one method from the server's secret-free method
   inventory. The console shows its real type, source, issuer/audience rules, tenant
   restrictions, and enabled/disabled overlay. Method definitions remain
   deployment-owned configuration; the browser cannot invent or silently edit an
   authentication authority.
2. **Review login.** `POST /api/v1/secrets/login/preview` receives only the method
   name. It reads configuration and returns the exact tenant binding, credential
   shape, whether the credential is single-use (`single_use`, with `credential_reuse`
   in plain words: OIDC, JWT, Kubernetes, GCP and Azure tokens log in once unless the
   method sets `allow_token_reuse`; a machine token or an AWS IAM request logs in again
   until it expires), session lifetime, prerequisites, blockers, writes, outside
   calls, recovery steps, verification steps, and CLI command. It does not receive a credential,
   call the verifier, create a session/event/idempotency row, or contact AWS STS.
3. **Test reviewed login.** Only a ready plan reveals the password-style credential
   field. `POST /api/v1/secrets/login` consumes the credential once and requires an
   `Idempotency-Key`; the request is bound with a server-keyed digest of the tenant,
   method, credential, and review fingerprint. An exact retry returns the original
   response—including the same one-time bearer—instead of issuing a second session.
   Reusing the key for different input returns `409`. The presented credential and
   raw session bearer never enter an event or read model.
4. **Verify and recover.** The result shows session id, principal, method, scopes,
   expiry, and a one-time reveal panel for the `trst_…` bearer. Copy it directly into
   the workload, then dismiss it; trstctl cannot recover it from the stored hash. The
   page refreshes **Issued sessions** so the durable row can be checked and revoked.
   Revocation immediately makes the linked bearer fail authentication. The browser
   clears the presented credential after both success and failure. A normal
   authentication failure keeps the reviewed plan for a corrected retry; a `409`
   configuration/fingerprint change discards it and requires a fresh review. A
   disabled method shows blockers and never accepts a credential.

   Disabling a method commits a tenant-and-method denial before publishing its
   event, so a projection delay cannot admit a new login. A login already
   verifying a credential must pass the same final admission lock before its
   session event is appended; disable and that final check have one clear order
   across replicas. Pending enable stays denied until its event projects. The exact
   pending command and denial state survive backup and restore; retry the same
   operation after recovery, then confirm the method status in the console.

   For a machine session with an issued bearer, revocation commits a tenant- and
   session-bound denial before publishing its revocation event. If event delivery
   or projection is interrupted, the bearer remains refused while the exact
   command is recovered. Retry with the same idempotency key and read the issued
   session ledger to confirm completion. Older ledger-only sessions have no
   linked bearer; they remain revocable as historical records.

Headless users get the same contract. Keep credential JSON in a permission-restricted
file or provide it through a protected pipe; do not put credentials in shell history:

```bash
trstctl-cli secrets login preview -f machine-login.json
trstctl-cli --idempotency-key workload-login-20260902 secrets login -f machine-login.json
trstctl-cli secrets sessions list
trstctl-cli --idempotency-key revoke-synthetic-session-1 secrets sessions revoke SESSION_ID
```

Preview requires `secrets:read` because method configuration is operator metadata.
The login exchange itself is intentionally public: the presented machine credential
authenticates the workload, while `X-Tenant-ID` remains only a lookup hint and never
grants access. The session list/revoke and method enable/disable operations remain
RBAC-protected. This preserves CA/provider agnosticism: the framework validates the
credential against the configured authority but does not require trstctl to have
issued it.

### Secret scanning bridge (F39) and sharing & approvals (F60)

#### Decoy API credentials

The console's **Secrets → Automatic secret sources → Plant a decoy credential**
workflow, `trstctl-cli secrets honeytokens`, and `/api/v1/secrets/honeytokens`
serve the same tenant-scoped decoy lifecycle. A caller with `secrets:write` plants
a name and intended placement. The create response reveals one ordinary-looking
`trst_` bearer; an identical idempotency replay to the same authenticated caller
returns that original response. Subsequent list/get responses contain only
metadata. Put that value in a
controlled location where a real trstctl API bearer would not belong. Do not
put a production credential there. The decoy is stored in `honey_tokens`, never
`api_tokens`, and has no permission or authentication path. Even a public API
route refuses it.

The first bearer use appends `honeytoken.triggered`, changes the decoy to
`triggered`, and queues one `notification.honeytoken` critical alert in the same
tenant transaction. The event and detail view retain the matched route pattern
and method, not the raw URL, query, or bearer. Configure an operator notification
channel and routing policy before planting so the alert has a receiver; the
notification inbox and delivery receipts show retry or failure. Refresh the
decoy list to investigate, then retire it. A retired value remains unusable.
To replace exposed bait, retire the old record and plant a new one.

#### Decoy secrets

A decoy secret is an ordinary stored secret registered as bait. trstctl is in the
read path, so every read of its value names the reader. In the console,
**Secrets → Automatic secret sources → Plant a decoy credential → Decoy secrets**
takes a path that looks real (for example `prod/payments/db-password`), a value
shape (password, API key or database connection string), a label and where you
advertise the path. It writes a generated value through the normal create path, so
the stored secret is indistinguishable from any other, and then registers it. From
the CLI, create the secret yourself and register it:

```bash
trstctl-cli secrets store create -f bait.json
trstctl-cli secrets honeytokens secrets register -f decoy.json
```

where `decoy.json` is `{"secret_name": "prod/payments/db-password", "name":
"payments db password bait", "placement": "payments repo .env.example"}`. Registering
needs `secrets:write`; a path with no stored secret is refused (404) and a path that
is already a decoy returns 409. The registry (`GET /api/v1/secrets/honeytokens/secrets`) also needs `secrets:write`: a caller who can only
read secrets is exactly who must not learn which secrets are bait, and the bearer
decoy list never shows secret decoys.

Every value read served to a caller is observed: the native read
(`GET /api/v1/secrets/store/{name}`), a historical version, a `${secret.path}`
reference resolved with `?resolve=true`, and the Vault-compatible
`GET /v1/secret/data/{path}`. The reader gets the value, and the read appends
`honeytoken.triggered` with the authenticated reader. The first read moves the decoy
to `triggered` and keeps that reader, method and route; every distinct reader queues
exactly one critical `notification.honeytoken` alert naming them, so a second reader is
not hidden behind the first. The decoy keeps its readers, each as a tenant-bound one-way
reference (never its name) with its first and last read and how many reads it made, so a
reader repeating the read is not re-alerted however long after, even once the delivered
alert has left the outbox. The decoy reports how many readers read it, how many reads they
made and when it was last read (`readers`, `reads`, `last_read_at`), and the console's
decoy list says so. Listing
names, reading metadata (native or Vault), the access preview, a template read without
`resolve`, the NHI inventory, the credential graph, secret sync and trstctl's other
internal reads never serve the value to a caller and never alert. A full read-model
rebuild keeps the decoy's state and its readers, and adds no alert while the readers'
alerts are still in the outbox (see the limitations). `retire` stops watching; the
secret stays in place until you delete it.

A decoy's value planted on purpose, in a repository as a lure for example, is found
by trstctl's secret scans like any other secret. A scan finding whose line (or a line
beside it) holds a live decoy's value is the known decoy, not a leak: the finding
carries `known_decoy` (the decoy's ID and label) and a risk of 10, and the console's
discovery findings name it. The repository scans, third-party scans and on-demand
scans compare the scanned lines with the tenant's live decoy values in memory, wipe
both, and keep nothing about the scanned value; that comparison is trstctl's own
work and raises no read alert. A decoy value shorter than 8 bytes is never matched,
and a retired decoy's value found again is an ordinary leaked secret.

#### Decoy database logins

A decoy login is a PostgreSQL login that reaches only its own empty database.
trstctl never uses it, so any login with it raises one critical
`notification.honeytoken` alert. A tenant PostgreSQL dynamic-secret provider opts in
by listing the role `decoy` in its `allowed_roles`; the ordinary lease routes, the
Vault-compatible dynamic API and the provider catalog never offer that role, and an
ordinary lease asking for it is refused (422). Only PostgreSQL providers can mint
decoys: any other backend would read the unknown role as read-write, so it refuses.

Mint one in the console (**Secrets → Automatic secret sources → Plant a decoy
credential → Decoy database logins**), with `trstctl-cli secrets honeytokens databases
plant -f decoy.json` (`{"provider": "warehouse-pg", "name": "warehouse db bait",
"placement": "ops wiki runbook", "ttl_seconds": 2592000}`), or
`POST /api/v1/secrets/honeytokens/databases` (`secrets:write`). The issue runs through
the durable dynamic-secret lease, so a retried request replays the same connection
string; the response shows it once. The provider creates a database named after the
login (`<login>_db`), closes it to `PUBLIC`, creates the login valid for the lease and
grants it `CONNECT` on that database only. Nothing in the connection string says
"decoy": the login is named like any other generated application login of the
provider. The decoy's lease is hidden from the ordinary lease routes.

The leader reads each untriggered decoy database's session counter
(`pg_stat_database.sessions`, PostgreSQL 14 and later) through the provider's admin
connection every 30 seconds. The provider's own administration, a port or TLS probe
and the watcher itself never establish a session on the decoy database, so they never
alert. The first session marks the decoy `triggered` (method `LOGIN`, path
`postgres/<database>`) and queues one critical alert; later logins do not re-alert.
The counter persists in PostgreSQL, so a login while trstctl is down is seen at the
next check; a statistics reset reads zero and alerts nothing. A failed login with a
wrong password creates no session and is not detected. `retire` revokes the lease,
which drops the login and its database, and stops watching.

#### AWS IAM decoy keys

**Secrets → Automatic secret sources → Plant a decoy credential** also has an
AWS IAM decoy workflow. An operator first attaches one AWS account to one tenant
with `secret_integrations.honey_aws_accounts`. The browser lists only the account
ID, configured Regions, polling interval, and key lifetime limit. IAM writer and
CloudTrail reader authority are separate `file:` or tenant `secret://` references;
neither credential is sent to the browser. Each referenced file must be mode 0600
and contain JSON fields `access_key_id`, `secret_access_key`, `session_token`, and
`expires_at`. These are **short-lived operator caller sessions**, refreshed in
place before expiry. The bait key itself is an IAM access key and remains stable
until its lease expires or the operator retires it; an STS session would expire
before it could serve as durable bait.

Example attachment (substitute owned values and private file paths):

```json
{
  "secret_integrations": {
    "honey_aws_accounts": [{
      "tenant_id": "11111111-1111-1111-1111-111111111111",
      "id": "security-decoys",
      "account_id": "123456789012",
      "regions": ["us-east-1"],
      "iam_credentials_ref": "file:/var/lib/trstctl/private/iam-decoy-writer.json",
      "cloudtrail_credentials_ref": "file:/var/lib/trstctl/private/cloudtrail-decoy-reader.json",
      "max_ttl": "720h",
      "poll_interval": "5m"
    }]
  }
}
```

The IAM writer needs narrowly scoped create/get/tag/policy/key/delete permissions
under `/trstctl/honeytokens/`; the reader needs `cloudtrail:LookupEvents` in each
listed Region. Grant those through independently assumed roles. trstctl checks
the account, IAM path, and ownership tag; installs an explicit deny-all inline
user policy; reads that policy back; **then** creates the bait access key. The
create response reveals the secret access key once, with an idempotent same-caller
recovery path. The normal dynamic-secret issue endpoint cannot issue these keys.
For an owned local IAM/CloudTrail fixture, set explicit loopback endpoints and
`allow_private_endpoint`, `allow_insecure_loopback`, and a narrow
`private_egress_cidrs` entry. Private overrides are operator-only; tenant webhooks
retain their public HTTPS rule.

`trstctl-cli secrets honeytokens aws accounts` lists attachments. Run
`trstctl-cli secrets honeytokens aws preview -f request.json` to review the
exact account, Regions, TTL, IAM sequence, detection limit, recovery, and
verification without an IAM or CloudTrail call. It validates local account
configuration; remote IAM permission is checked only by the creation attempt.
Plant with
`trstctl-cli secrets honeytokens aws plant -f request.json` where the JSON has
`account_id` (the configured attachment ID), `name`, `placement`, and
`ttl_seconds`. Supplying the returned `preview_fingerprint` binds the plant
request to the reviewed caller, account attachment, and fields; a changed
request is rejected before IAM effects. The console requires this review step.
`list`, `get <id>`, `rearm <id>`, and `retire <id>` match the console and the
`/api/v1/secrets/honeytokens/aws` API. Retirement queues IAM key/user removal;
`lease.revocation_status=completed` means a subsequent IAM `GetUser` confirmed
the user absent. A queued `retiring` state does not claim deletion. Monitoring
continues for 72 hours after confirmed removal to catch delayed CloudTrail
delivery.

The monitor calls CloudTrail `LookupEvents` through a durable outbox. Each page
becomes an immutable event before the next page is queued; account/Region calls
share a PostgreSQL rate slot across replicas. Duplicate event IDs yield one
incident. The first observed use enters the existing critical honeytoken alert
route; the investigation view shows Region watermarks, gaps, AWS event IDs,
operation names, source addresses, and detection times. Coverage is limited to
management events in the configured account and Regions. CloudTrail delivery can
lag; after triage, `rearm` makes the same live bait alert on its next
distinct observed use while preserving earlier incident records. An already seen
CloudTrail event does not trigger another alert. Without a trail, data events,
other accounts/Regions, and gaps older than CloudTrail's 90-day
lookup window are not covered. A failed/dead-lettered scan is a monitoring outage,
not evidence that the bait was untouched. No real AWS account was available for
the local QA campaign, so the AWS adapter has local contract evidence only.

**Trail log files: data events and every account (N4).** An attachment may also
name the CloudTrail trail whose log files its decoys are looked for in, with a
`trail` object: `bucket`, `bucket_region`, the trail's `key_prefix` if it has one,
`organization_id` (`o-…`) for an organization trail, optional `accounts` (empty
reads every account the bucket holds), optional `s3_endpoint` and `path_style` for
an S3-compatible store, and `credentials_ref` — a session file like the others,
whose role needs only `s3:ListBucket` and `s3:GetObject` on the trail's prefix. An
organization trail holds every account in the organization, and a trail that logs
data events holds them too, so a decoy key used against an S3 object in another
account, or logged by an account other than its own, is found; LookupEvents finds
neither. The leader reads the day folders (UTC) of every account and Region at the
attachment's poll interval, from the day the oldest watched decoy was created (at
most 90 days back) through today, so files delivered while the control plane was
down are read when it is back, and records each log file once
by its key as an immutable event (`honeytoken.aws.trail_object_scanned`, with the
decoy records in it), and the first new use triggers the decoy through the same
alert route. A use shows the account whose key made the call, the account whose
trail logged it, CloudTrail's `event_category` (`Management` or `Data`) and
`found_in` (`lookup` or `trail`); the same event found both ways is recorded once.
A file larger than 64 MiB compressed, or one that is not a CloudTrail log file,
is recorded as refused with the reason and never read in part; a file the store
cannot return is left for the next pass. The account catalog's `trail.read`
shows the files read, decoy records found and files refused in the last four days.
Records of keys that are not decoys are read and dropped; nothing from them is
kept.

The scanning bridge runs the pinned Gitleaks scanner from the served control plane,
recording redacted findings into [discovery](discovery-and-inventory.md), the
[credential graph](graph-query-ai.md), and the risk view. `TRSTCTL_SECRETS_GITLEAKS_BIN`
points at the Gitleaks `v8.27.2` binary from `tools/gitleaks/install.sh`, which
checksums the release tarball before installing. `secrets.scan_roots` (or
`TRSTCTL_SECRETS_SCAN_ROOTS`, a comma-separated list) is the closed set of mounted
filesystem trees the served scanner may read; an empty setting confines scans to the
control-plane working directory. This prevents a caller with `secrets:write` from
turning the scanner into a general host-file reader. `POST
/api/v1/secrets/scans/preview` first validates the exact confined path, scan mode,
installed scanner, and additive rules without starting Git or Gitleaks, creating a
file, appending an event, or recording idempotency. Its keyed fingerprint is bound to
the tenant, caller, normalized target, mode, rules path, and capabilities. `POST
/api/v1/secrets/scans` may require that fingerprint and fails with `409` before the
scanner starts if the reviewed command changed. Execution scans a repo or workspace
with the pinned `213`-rule default set (above the 140-rule floor);
the response and stored finding carry only rule id, file, line, scanner version, and
fingerprint — Gitleaks redacts the value, never reaching the API, event log, graph, or
audit output.

```bash
cat > secret-scan.json <<'JSON'
{"path":".","mode":"git_history","custom_rules_path":"./gitleaks-custom-rules.toml"}
JSON
trstctl-cli secrets scans preview -f secret-scan.json
# Copy request_fingerprint from the review into preview_fingerprint, then run.
trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f reviewed-secret-scan.json
```

A bare `{"path":"."}` scans the working tree by default; `mode`/`custom_rules_path`
above switch on full Git-history scanning (`--log-opts --all`) plus an additive
`[[rules]]` TOML fragment wrapped with `[extend] useDefault = true` — never an
allowlist or disabled-rule override. The response's `mode`, `custom_rules`, and
`capabilities` fields prove full-history, entropy, pattern, 100+ default-rule, and
custom-rule coverage without storing a secret value; `run_id` can be replayed against
`GET /api/v1/discovery/findings?run_id=...` or the graph view. TruffleHog JSON
ingestion still exists for offline import/contract tests, but Gitleaks is the served
engine. If a scanner or network failure interrupts execution, retry the identical
reviewed body with the same `Idempotency-Key`: a pre-recording failure can try again,
while a completed request returns its original run instead of scanning twice. The
console preserves that recovery key only in memory, keeps the original failure
visible, and labels the action **Retry reviewed scan**.

Locally, the same runner works without a server: `secrets scans staged-diff` and
`secrets scans pre-commit install` scan only staged Git blobs, or an explicit
base/head CI diff, into a temporary tree, dropping raw values from stdout, stderr, and
JSON output. Findings block commits and pipeline steps by default; `--advisory` keeps
the report but exits zero for non-blocking rollout:

```bash
trstctl-cli secrets scans staged-diff --repo . --base origin/main --head HEAD --advisory
```

For realtime repo ingress, `GET /api/v1/secrets/scans/repositories` reports provider
posture for GitHub, GitLab, and Bitbucket; `POST
/api/v1/secrets/scans/repositories/{provider}/webhook` takes a normalized event —
`repository`, `checkout_path`, `ref`, `commit_sha`, `event`, `credential_ref` — and
upserts a tenant-scoped `secret_repo` discovery source plus a `discovery.run` outbox
row. The outbox worker scans `checkout_path` directly, or clones a public/local
`clone_url`; credential-bearing URLs are rejected, and private credentials must stay
secret references, never payload values.

GitHub can also call trstctl directly (P6): configure a hook under
`secrets.scan_webhooks` (an `id`, the `tenant_id`, `provider: github` and a
`secret_ref` holding the webhook's secret) and point the repository's webhook at
`POST /api/v1/secrets/scans/hooks/{id}`. trstctl checks `X-Hub-Signature-256`
(HMAC-SHA256 of the exact body under that secret) in constant time before reading
anything else and refuses a missing or wrong signature with 401, recording a
`secret.scan_hook.refused` audit event with the hook, the delivery ID and whether the
signature was missing or wrong (never the body or the signature); `ping` answers
`{"pong": true}`; a `push` queues the same scan as the normalized route for the
pushed repository's `clone_url` at the pushed commit. `X-GitHub-Delivery` is the
idempotency key, so a redelivery returns the recorded answer and queues nothing new.
The normalized route and scheduled polling stay for installs that cannot accept
webhooks. Native GitLab and Bitbucket signatures and private `credential_ref` clone
resolution remain shortfalls, not served.

A leaked secret a scan found moves into the native store from the CLI (P6):

```
trstctl secrets scans move <finding-id> --repo ./payments --name payments/slack-bot-token
```

The served finding is redacted — it names the rule, the file and the line, never the
value. The CLI reads the finding, re-finds that one value in your own checkout with the
pinned gitleaks (its unredacted report read from a pipe, never written to disk; every
other value it held is wiped), stores it with `POST /api/v1/secrets/store` and links the
finding with `POST /api/v1/discovery/findings/{id}/secret-move` by the secret's name and
version only. The same local run lists every history commit that still holds the value;
those locations (commit, file, line, rule — no value) are kept on the finding as
`secret_move.history_residue`. The CLI prints the reference to use instead
(`${secret.payments/slack-bot-token}`, or `trstctl run --secret ENV=payments/slack-bot-token`).
The value appears in no finding, event or log.

Moving does not close the finding: the leaked value still works until it is rotated. The
leader closes a moved finding as `remediated` (actor `system:leaked-secret-closure`) only
when all three hold: the secret was rotated (a version newer than the moved one exists),
a consumer read a rotated version through the store (recorded once as
`secret_move.consumer_read_*`), and a scan of the finding's source completed after the
rotation without seeing the leak. A scan that fails — a clone or provider error — is no
evidence, and a scan that still sees the leak (the value still in the file) keeps the
finding open. The evidence reference names the rotated version, the read and the scan
run; after it closes, the history commits stay listed on the finding, because cleaning
the latest file does not remove the value from history (rotation is what ends the
exposure). A finding seen again after it closed shows as regressed.

Reads through the native store's own routes and through the KV-compatible `/v1` surface
count as consumer reads, recorded with the reader's subject. A secret-sync delivery of a
rotated version counts too: the target's consumers read the secret there, so the delivery
is recorded as the read of `secret-sync:<target>`.

Third-party artifacts use the same shape: `GET /api/v1/secrets/scans/third-party` and
`POST /api/v1/secrets/scans/third-party/{provider}/ingest` cover `cicd_log`,
`container_registry`, `slack`, and `jira` — a source plus operator-owned
`artifact_path` queues a `secret_third_party` discovery run against the same Gitleaks
runner. Raw CI logs, registry exports, chat transcripts, and issue exports stay outside
trstctl storage; events record only provider, artifact kind, rule id, file, line,
scanner version, and credential-ref. When the provider signs its export, add
`signature_path` (a detached RSA or ECDSA signature over the artifact bytes, raw or
base64) and `signer_public_key_pem`. Raw signature bytes are read exactly as supplied;
only base64 text may have surrounding whitespace. trstctl verifies the signature before the scanner
opens the artifact, fails the run without scanning when it does not verify, and stamps
every finding with `signature_verified` and the signer key's SHA-256. Set
`require_signature` on sources that must never scan an unsigned export; the ingest is
refused with 400 when the signature inputs are missing. Add
`delete_artifact_after_scan` when the export must not outlive its scan: trstctl removes
that one file once the run is terminal and the run message records the removal. The
redacted findings themselves age out through the privacy retention worker after
`TRSTCTL_PRIVACY_RETENTION_THIRD_PARTY_SCANS` (default 90 days); the discovery run
record stays as evidence that the scan happened.

**Is the leaked secret still live? (P14).** With `secrets.validity_checks.enabled`,
a scan checks each AWS access key it finds where it found it, while the scanned tree
still exists: it reads the 40-character secret access key beside the key ID (a
credentials file, an environment file or a chat message), signs one STS
`GetCallerIdentity` call with the pair (SigV4, so only a signature leaves the host,
never the secret) and records the finding's `validity` as `valid` (with the account
and ARN), `invalid` (AWS refused the key: deactivated, deleted or a wrong secret),
`unknown` (AWS could not be reached or answered otherwise) or `unchecked` (no secret
beside the key ID, the endpoint not declared, or the check budget spent). The
endpoint each check calls (`endpoints`, the public STS endpoint by default) must be in
the checks' declared outbound destinations (`allowlist`), or the check is refused
before anything is sent, and `rates` bounds checks per second (5 by default) so a
large scan stays within the provider's limits. The value is never kept: the next scan
of the source rechecks. A secret found in a collected Slack channel also names its
poster and, from the poster's profile email (`users.info`, which needs the bot's
`users:read.email` scope), the tenant owner with that address as the finding's
`owner_id`.

**Native collection (N6).** Instead of `artifact_path`, a source may carry `collect`
and trstctl reads the content from the provider itself, in the layout of that
provider's own export, so the scan and the finding-to-object mapping are the same as
for an export. `container_registry` reads one image (`repository` and `reference`, a
tag or `sha256:` digest) over the OCI distribution API — anonymously, with a static
bearer token, or through the registry's token service with `username_ref` and
`token_ref` — every platform of an index (up to sixteen), each platform's config (its
environment and build history) and the regular files of each layer, each blob checked
against its digest before it counts; findings name the image's repository and
digest. `slack` reads `channels` (IDs) through `conversations.history` with a bot
token; findings name the channel and message. `jira` reads the issues `jql` selects
(summary, description and comments) with a personal access token, or with
`username_ref` and an API token; findings name the issue. `since` bounds Slack and
Jira to a lookback (`720h`), and `max_items` and `max_bytes` bound what one run
reads. The content goes to a private temporary directory that the run removes when it
ends; it never enters an event, the database or a log line, and findings carry the
item and byte counts and whether a limit stopped the collection. Credentials are
operator-approved references resolved by the worker for that one call; a private
endpoint needs `allow_private_endpoint`, `private_egress_cidrs` and the private-egress
permission, as an annotation connection does. A refused credential or endpoint fails
the run with the reason and records nothing. `cicd_log` reads CI logs: with
`system: github` and `repo` (`owner/name`), the newest GitHub Actions runs' log
archives; with `system: gitlab` and `repo` (a project ID or path), the newest jobs'
traces (a `PRIVATE-TOKEN` reference). Each run or job lands in a folder named by its
repository and commit, so its findings name the system, repository, commit and run or
job; an annotation on a collected CI log or image names only its connection (and a CI
log's `system`), because the object comes from the collection.

```json
{"source":"team-app","collect":{"base_url":"https://registry.example.com","repository":"team/app","reference":"v1",
 "username_ref":"env:REGISTRY_USER","token_ref":"env:REGISTRY_TOKEN"}}
```

```bash
cat > third-party-scan.json <<'JSON'
{"source":"acme/slack","artifact_path":"/var/lib/trstctl/exports/slack.jsonl","event":"message_export"}
JSON
trstctl-cli --idempotency-key third-party-scan-1 \
  secrets scans third-party ingest slack -f third-party-scan.json
```

In the console, open **Find leaked secrets in code**, expand **Scanner setup and
exact evidence**, and queue the same provider, source reference, artifact path, and
optional event. The receipt includes a discovery run ID. The page opens that run
automatically; after a restart, paste its ID into **Third-party scan result** or
open `/secrets/scanning?third_party_run=<run-id>`. Refresh until the outbox run is
terminal. The page shows the run status and the first 50 redacted findings, then
links to **Discovery** filtered to that exact run for the full finding list and
triage. Neither the artifact contents nor scanner matches appear in the console.
The artifact path must be readable by the running control plane, inside an
operator-configured scan root, and the pinned Gitleaks binary must be installed.

**Secret sharing** is a review-first, one-time delivery journey. `POST
/api/v1/secrets/shares/preview` accepts only `ttl_seconds`: the value never enters the
preview request. It returns the normalized lifetime, permission, exact execution
writes, recovery and verification steps, empty preview/external-effect lists, and a
tenant-and-principal-bound fingerprint. The preview creates no share, event, audit
row, idempotency record, signer request, outbox work, or external call. Zero selects
the 24-hour default; explicit lifetimes must be between 60 seconds and 7 days.

`POST /api/v1/secrets/shares` accepts the value only at execution and may bind it to
the reviewed lifetime with `preview_fingerprint`. A changed lifetime then fails with
`409` before any state change. PostgreSQL stores only `SHA-256(token)` plus the
envelope-encrypted value in `secret_shares`; the raw bearer token is returned once. A
valid share survives a restart, while a stolen database or backup holds neither the
token nor plaintext. If the response is interrupted, retry the identical request with
the same `Idempotency-Key`: trstctl returns the exact original token instead of
creating a duplicate. Reusing that key for changed input fails closed.

`POST /api/v1/secrets/shares/redeem` requires the share token plus an authenticated
principal with `secrets:read` in the same tenant. It atomically deletes the row and
returns the value for one redemption; another new request, expired token, or wrong
tenant gets a normal `404`. A retry of the identical authenticated request with its
original `Idempotency-Key` recovers the original response. The console retains that
key only in memory after an ambiguous network/server error and offers **Retry same
redemption**. Changing the token or leaving the page discards this recovery key.
This is authenticated token delivery, not an anonymous share URL. Individual share
cancellation before consumption or expiry is not currently served.
The `/secrets/sharing` console exposes the same configure → review → create → reveal →
redeem/verify path, keeps the value out of the preview, and preserves each recovery key
only in memory while an ambiguous request is retried. Neither value nor token is
written to browser storage or product evidence.

**Change approvals** appear beside sharing and reuse the same dual-control
[approval](incident-and-jit.md) store
as privileged issuance: with `ca.policy.require_approval` enabled, `rotate`/`recover`/
`delete` mutations open a tenant-scoped approval request and fail with `403` until
enough distinct approvers approve it, and a requester can't approve their own change.
Approvers call `POST /api/v1/secrets/store/approvals/{name}` with `{"action":"rotate"}`,
`{"action":"recover"}`, or `{"action":"delete"}`; the response holds only `resource`,
`action`, `approver`, and the approval count.

### In the console

The console renders the native store at `/secrets` and separate task-focused workspaces
for machine access, one-time sharing, engines, scanning, and delivery. Transit lives in
the **Encryption and signing** task at `/secrets/engines`; the exact console/API
boundary is listed above. **Bulk secret import** reviews the selected JSON file's
names, executes one batch, and displays its metadata receipt. See
[The web console](../web-console.md).

## Use it

Served workflows run through the API/CLI; embedders can use the same lower-level Go
interfaces directly, shown here in byte-oriented shape:

```go
store.Put(ctx, "db/password", []byte("s3cr3t"), "idem-key") // -> version 1
val, _ := store.Get(ctx, "db/password")                     // latest live version
lease, _ := dyn.Issue(ctx, "postgresql", "readonly", time.Hour, "req-1") // auto-revoked
ct, _ := keyring.Encrypt(ctx, "app-key", []byte("hello"), nil) // -> "trv:1:..."
```

The `secretstore.APIServer` exposes the store over HTTP (`PUT/GET /secrets/<path>`, with
`Idempotency-Key` and tenant headers) once mounted.

```bash
cat > secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
JSON

# Effect-free: reads metadata only and contacts no target.
trstctl-cli secrets syncs preview -f secret-sync.json

# Copy request_fingerprint from preview into preview_fingerprint, without adding a
# secret value. Execution rejects a stale fingerprint if the secret version,
# destination, caller, or remote key changed after review.
cat > reviewed-secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD","preview_fingerprint":"sha256:<copy-from-preview>"}
JSON
trstctl-cli --idempotency-key sync-db-password-1 secrets syncs run -f reviewed-secret-sync.json

# Use the job_id returned by run; repeat this read after reconnecting to see the
# durable worker outcome. A delivered receipt still needs target readback.
trstctl-cli secrets syncs status <job_id>

curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_URL/api/v1/secrets/syncs/targets"
```

## Pitfalls & limits

- **Serving status:** rotation serves worker-queued connector-backed manual and
  scheduled variants and durable static-provider commands for PostgreSQL, MySQL and
  AWS IAM providers that opt in with `allow_static_rotation` (AWS IAM verification
  is recorded as not available). Dynamic-lease rotation still fails closed before
  provider effects. An unconfigured
  secret-sync target fails closed with `503` instead of dropping the write; a missing
  Gitleaks binary fails scanning closed with `503` too.
- **Machine login tenant binding:** token credentials MAC-bind the tenant, the
  `machine-login` audience, principal, and expiry. `X-Tenant-ID` is a lookup hint on
  the public login route; a token for tenant A is rejected if presented with tenant B.
  The builtin HMAC verifier itself must also name exactly one
  `auth_token_tenant_id` and one or more `auth_token_scopes`; startup rejects an
  unpinned or unscoped authority.
- **Protect the KEK.** Everything at rest is only as safe as `TRSTCTL_SECRETS_KEK_FILE`;
  in production back it with an [HSM/KMS](issuance-and-cas.md).
- **Dynamic beats static.** Prefer dynamic/ephemeral secrets over long-lived ones; if
  you must store one, put it on a rotation schedule.
- **Transit/KMIP boundaries:** appliance-specific templates are not shipped; tenants
  manage their own KMIP clients with client registrations — see
  [Current limitations](../limitations.md).
- **Sync is push + drift-detect**, not a two-way merge — trstctl is the source of truth.

## Reference

- **At rest:** envelope encryption (AES-256-GCM DEK wrapped by KEK); config
  `TRSTCTL_SECRETS_KEK_FILE`.
- **Store:** `Put/Get/GetVersion/Versions/Rollback/Delete/Purge`; `APIServer`
  (`PUT/GET /secrets/<path>`, `Idempotency-Key`).
- **Developer run wrapper:** `trstctl-cli run --secret ENV=secret/path -- <cmd>`
  fetches via `/api/v1/secrets/store/{name}` and injects only into the child env.
- **Dynamic backends:** `postgresql`, `mysql`, `mongodb`, `aws-sts` (`aws-iam` alias), `gcp-iam`,
  `azure-entra`, `kubernetes`, `redis`, plus `pki`.
- **Transit:** `/api/v1/transit/{keys,encrypt,decrypt,rewrap,hmac,sign,verify}`,
  `trstctl-cli transit ...`, versioned `trv:<n>:` ciphertext.
- **KMIP:** opt-in mTLS listener (`TRSTCTL_PROTOCOLS_KMIP_ENABLED=true`) for AES-256
  SymmetricKey Create/Register/Get/Locate/Revoke/Destroy and RSA/ECDSA Create Key Pair,
  Activate, Sign, Signature Verify and the attribute operations, default address
  `:5696`, tenant bound by `TRSTCTL_PROTOCOLS_KMIP_TENANT_ID`.
- **Sync targets:** AWS Secrets Manager, AWS Systems Manager Parameter Store, GCP
  Secret Manager, Azure Key Vault, GitHub Actions, GitLab CI, Vercel, Netlify,
  Kubernetes, Terraform Cloud/OpenTofu, HashiCorp Vault/OpenBao KV v2, signed webhook,
  generic CI/JSON, and the hosted targets (Heroku, Render, Railway, Fly.io,
  DigitalOcean App Platform, Northflank, Qovery, Cloud 66, Laravel Forge, CircleCI,
  Travis CI, Bitbucket Pipelines, TeamCity, Spacelift, Humanitec, Rundeck, Checkly,
  Windmill, Zabbix, Portainer, Devin, Daytona, Ona, Trigger.dev, Cloudflare Workers,
  Cloudflare Pages, Cloudflare Secrets Store, Azure App Configuration, OCI Vault,
  OVHcloud Secret Manager, Databricks, Supabase, Camunda, Chef Infra Server).
- **Scanning:** `GET /api/v1/secrets/scans/repositories`,
  `POST /api/v1/secrets/scans/repositories/{provider}/webhook`,
  `GET /api/v1/secrets/scans/third-party`,
  `POST /api/v1/secrets/scans/third-party/{provider}/ingest`, `POST /api/v1/secrets/scans`;
  `trstctl-cli secrets scans` subcommands `repositories`, `repositories webhook`,
  `third-party`, `third-party ingest`, `run`, `staged-diff`, `pre-commit install`;
  Gitleaks `v8.27.2`, `213` default rules active, workspace and full-Git-history modes,
  additive custom `[[rules]]` fragments, CI-log/container-registry/Slack/Jira artifact
  ingress, redacted findings only.
- **Events:** `secret.version.written`, `rotation.*`, `rotation.rollback_failed`,
  `secret.rotation.connector_cutover`, `secret.rotation.connector_rolled_back`,
  `secret.rotation_schedule.upserted`, `secret.rotation_schedule.ran`,
  `auth.session.issued`, `discovery.finding.recorded`, `discovery.run.completed`.

## See also

[Workload identity](workload-identity.md) (attestation behind ephemeral secrets) ·
[Issuance & certificate authorities](issuance-and-cas.md) (HSM-backed KEK; PKI engine) ·
[Incident response & JIT](incident-and-jit.md) (compromise + approvals) ·
[Discovery & inventory](discovery-and-inventory.md) (finding existing secrets) ·
[Current limitations](../limitations.md) ·
glossary: [secret](../glossary.md), [envelope encryption](../glossary.md),
[KEK/DEK](../glossary.md), [dynamic secret](../glossary.md), [lease](../glossary.md),
[transit](../glossary.md), [KMIP](../glossary.md)

**Covers:** F37, F38, F39, F63, F64, F65, F66, F67, F68, F58, F60, F80


For AWS STS, the credential proof uses locked byte-backed signing headers, a fixed
STS origin, verified TLS and dial-time private-network controls. A caller from an
unconfigured role, a mismatched native session, an expired credential, a redirect,
or an air-gap refusal cannot become an authenticated result. It proves the STS
identity, not authorization to every resource. Without explicit native session
deny policy, predecessor revocation remains pending until AWS expiry; it does not
finish merely because trstctl revoked the lease. Native LocalStack wire/readback
proof does not qualify live AWS enforcement. The reviewed replacement and workload
adoption path must separately retire an existing long-lived IAM key.


#### Native recovery for a vaulted AD account

The explicit `ldap` provider profile with `directory_mode: active_directory`
can restore a single configured account after verification of its replacement
fails. Recovery reserves the existing application-secret publication fence, uses
the configured directory administrator to restore the exact predecessor password,
and proves that password authenticates over pinned LDAPS before publishing it as
a recovered vault version. An undisclosed intermediate reset prevents the rejected
successor from remaining valid during AD's preceding-password grace period.
Neither the password nor the intermediate appears in events or command output.

An upstream reset or sign-in failure produces `rollback_failed`; it does not
publish an old vault value while claiming the directory recovered. Inspect that
command and resolve its native account/fenced publication before another scheduled
rotation. Existing lockout checks still refuse unsafe authentication attempts.
This inverse is specific to the configured AD single-account profile. Paired
accounts retain their existing two-phase lifecycle. The native recovery proof uses
Samba AD; Windows service/task/IIS dependent coordination and directory drift
reconciliation have separate execution and verification requirements.

New in-place AD rotations retain a version2 encrypted preparation before the
first reset. It holds the final password and both forward and inverse
intermediates. All three remain byte-backed, locked and wiped after use. The
preparation binds the operation, provider, account GUID/SID/name, exact DC
invocation, verified TLS peer address and the directory's password-change count.
The old vault value is encrypted alongside it before any native write.

The fixed sequence is original → forward intermediate → new password → inverse
intermediate → restored predecessor. A restarted worker reads the native version
and proves only that version's retained credential. It never guesses several
passwords. If recovery starts after the first forward write, it completes the
retained new generation before running the inverse; this gives every intermediate
one unambiguous position. A completed operation replays without another reset.
Existing version1 preparations stay readable, but an intermediate they did not
retain cannot acquire this recovery guarantee retroactively.

The reset principal must read rootDSE/DC invocation and Directory Service
`dSHeuristics` metadata as well as the account's native state. Key-version
emulation (`fKVNOEmuW2K`, character17) is refused because its constant version1
cannot identify progress. Keep the configured DC and original verified TLS trust
available while an operation is pending. A changed DC, account, provider or
unexplained native progress stops further resets.

The administrative reset API has no atomic expected-version condition. These
checks refuse observed serial changes; another directory administrator can still
race the last read and the write. Keep external password automation and manual
resets out of the operation's maintenance window. Failed attribution or an unsafe
lockout state requires investigation before deliberate recovery.

Imported predecessors can contain bounded UTF-8 without NUL. Native rollback
encodes quoted UTF-16LE directly into locked LDAPS buffers and proves a sign-in
before publishing recovery. Generated passwords keep their printable-ASCII
contract. Directory policy can refuse a predecessor; that remains
`rollback_failed`, with no claim of recovery. The owned Samba proof exits an
actual worker after each of four native writes, reloads the same encrypted
preparation, checks the exact native version and uses stock `ldapsearch` to prove
current acceptance and explicit retired-password refusal. This is worker-process
recovery evidence; it does not qualify host power loss, a multi-DC forest or the
Windows dependent workflow.

The Windows service dependent adapter reads the enrolled host's local Service
Control Manager. It selects the exact account SID, captures service names and
start dependencies, and hashes private configuration inside the crypto boundary.
Updates change only the stored logon password and recheck the frozen native
configuration on the same service handle. Restarts preserve stopped services and
verify a fresh running process's account SID. This identity result alone is not
functional completion: the host workflow must also pass its configured service
health check. The task and IIS adapters and the full host workflow have separate
execution and verification requirements. The Windows runner fixture uses a real SCM service and a local SAM account;
it is not an AD forest qualification.

Windows Automation arguments use a separate native memory boundary: credential
BSTRs are locked before filling and wiped before their native allocator frees
them. Private task XML stays byte-backed inside that boundary, and native
exception descriptions are wiped without entering logs. The native Windows
memory/Automation proof is separate from task-dependent rotation and full host
orchestration; those parts are still in progress.

Scheduled-task discovery selects the exact native principal SID, including tasks
whose logon mode does not store a password. Credential updates currently require
password logon mode: S4U, interactive, group, service-account and legacy mixed
modes remain explicitly identified in inventory and are refused by the password
writer. Private task XML and the existing ACL contribute only to the frozen
configuration hash. Updates preserve the definition and ACL and suppress
registration triggers.

Starting a task for verification requires an exact local allowlist entry and an
enabled task that permits demand start. A running instance is left alone. The
Task Scheduler Operational log must already be enabled by the host operator;
product verification never changes that policy. A fresh instance is verified
against its native start account, each action result and task completion records,
with an independent functional probe still required by the host workflow. A
previous global last-result value cannot establish this proof. Lost start replies
remain explicit uncertainty: retain the attempt fence and observe the known
instance instead of starting it again. Native Windows execution and the complete
host workflow remain separate qualification steps.

IIS application-pool discovery selects the exact custom account SID. The adapter
freezes the pool configuration and its existing encryption provider without reading
the saved password. Password writes keep that provider and require a fresh native
readback that confirms encrypted storage. A changed SID, provider or configuration
stops the write. Native IIS recycling settings remain in force: writing the logon
password can itself recycle the pool, so the host workflow must approve and order
that effect.

Restarting one selected pool preserves its previous stopped state. A started pool
needs an independent functional request to create and exercise its worker. Native
worker metadata and process tokens must then agree on the exact pool, fresh PID
and account SID; process identity alone is not a functional result. The Windows
fixture performs nonce-bound HTTP work and predecessor recovery using an owned
local SAM account, pool and site. Its native execution remains a separate required
qualification; cross-compilation does not establish that result. The full enrolled
host workflow, durable task-attempt journal and directory reconciliation remain
in progress.

The host's task-start journal records a durable fence before calling Task
Scheduler, then retains the exact native instance before waiting for completion.
After restart, a known instance is observed without another start. If the start
reply was lost before an instance could be retained, execution stays uncertain;
an operator must reconcile it without blindly running the task again. Failed
native or functional reports keep these fences, including after the server
acknowledges the failure. Unrelated host work can continue.

Journal events are sealed under the agent registration and server trust binding.
Missing keys, a different registration, malformed frames and incomplete writes
are refused without discarding retained evidence. A successful report retires
only its own fully completed journal after acknowledgement. Windows process
restart is covered by the native fixture; machine power-loss durability remains
a filesystem qualification. This journal primitive and the native task adapter
are separate from the full enrolled-host dependent workflow still being built.

When a native start reply is lost, the agent pauses further dependent-rotation
claims and continues explicitly selected unrelated host work. It never sends an
empty filtered kind list as an unrestricted claim. Stop the agent before
inspecting or reconciling its private task state:

```sh
trstctl-agent --task-execution inspect --name HOST --server-name CONTROL_PLANE \
  --ca-bundle ca.pem --key agent.key --cert agent.crt
trstctl-agent --task-execution reconcile --name HOST --server-name CONTROL_PLANE \
  --ca-bundle ca.pem --key agent.key --cert agent.crt \
  --task-job JOB_ID --task-step STEP_ID --task-instance EXISTING_GUID \
  --task-recovery-reason 'Observe the exact terminal instance before inverse work'
```

These one-shot modes use the existing registration and server trust. They do not
enroll, connect to the control plane, read a vault credential or replace a sealing
key. The report store's process lock refuses them while the agent runs. Inspection
returns public task identity, fence time and retained native evidence. Choose an
existing instance from the host's Task Scheduler operational history; supplying a
GUID does not authorize starting that instance or the task.

Reconciliation reads that exact instance's dated start, action and completion
records, checks the frozen path, account SID and definition, and requires no running
instances under a fully elevated administrator view. [A filtered ordinary-user view](https://learn.microsoft.com/windows/win32/taskschd/registeredtask-getinstances)
cannot establish quiescence. Nonzero native action results remain failures. Running,
foreign, incomplete, changed or historical evidence refuses without clearing state.
New version-two fences retain the original fence time; older undated unknown-start
journals remain readable but cannot gain an invented recovery timestamp.

The host appends a separate sealed observation with the local actor and reason.
It preserves the original unknown instance and outcome, and original execution can
never be retried or reported successful through this operation. Fully settled
history is archived with the existing fsync and collision checks; an unacknowledged
original report still blocks new work. After acknowledgement, separately authorized
work can use the active slot. Restarting the agent does not revive an expired job
or change an already failed or uncertain server step. Use the separate explicit
inverse recovery review below after resolving local uncertainty. Windows runtime qualification of this
terminal-observation path and final-image recovery remain unverified; portable
journal/CLI contracts and Windows cross-compilation are separate evidence.

AD account discovery in an explicit `active_directory` provider now includes
SPN-bearing user accounts and the accounts named by its rotation bindings under
`users_dn`. They use the `directory_service_account` kind, with `service_account: "true"`
and public `native_sid` / `native_guid` details. SPNs are public identity metadata;
selection as a service account does not add administrator privileges. Existing
group and protected-user evidence remains separate in `privileges`.

The provider reads these identities through its pinned LDAPS byte-backed bind.
It never requests a password attribute, follows a referral, or changes the native
account. Missing or ambiguous identity/state, an escaped search scope or an
exceeded result bound fails the scan. SID/GUID metadata survives the existing
tenant-isolated discovery projection and replay. Accounts with neither an SPN nor
a configured rotation binding are outside this directory selection; enrolled-host
dependent inventory and matching are the next workflow step. This does not
qualify gMSA password rotation or a real multi-DC forest.

### Review and run an AD dependent rotation

In **Account access → Discovery**, select the discovered AD account and open its
host dependents. Enable each enrolled Windows host, then request a complete native
inventory from every enabled host. Inventory-only permission authorizes reads;
it does not authorize password changes or task execution.

The host operator separately grants `windows_dependent_writes` entries containing
one `account_sid`, `family`, native `name` and `probe_id`. Each ID resolves through
`windows_dependent_probes` to a fixed literal-loopback HTTP URL with an explicit
port. The probe implements the nonce-bound useful-work contract. Tenant job data
cannot supply executable commands, widen those grants, redirect the request or
select another URL. Enable `host.windows_dependents.rotation` in the enrolled
host's claimable job kinds and configure its private durable report-state store.

Choose **Rotate account and dependents**, select the stored password reference,
review every selected service, task and pool, set the startup order and choose its
local useful-work probe. Services must follow their native dependencies; stop
operations use the reverse order. Review the served preview and its exact digest,
then acknowledge the single-phase outage risk before queuing. The reviewed native
identity, complete host set, source scans, provider configuration, secret version,
order and probe bindings are frozen together. Changed inventory or host membership
requires another review; ordinary static rotation refuses this selected account.

The worker completes all host preflights before changing the directory. It then
stops previously running services and pools, updates password-bearing dependents,
starts the objects that were running, and collects fresh process/account evidence
plus useful-work proof. Previously stopped objects stay stopped. Task verification
retains the exact native instance and its start/completion event times; a historical
last-result value cannot qualify this operation. The vault publishes its new value
only after all required native results succeed. A dependent failure selects a
durable inverse: restore the directory, restore every dependent, then verify
recovery before publishing the predecessor. If another writer changed the vault,
that unrelated version is preserved and the unresolved conflict stays visible.

`access discovery rotation preview ACCOUNT -f review.json` returns the effect-free
intent and digest. Submit them with `acknowledge_single_phase: true` using
`access discovery rotation queue ACCOUNT -f approved.json`; retain the same
Idempotency-Key after a lost response. Use `access discovery rotation get ID` and
`access discovery rotation steps ID --limit 50` to inspect retained progress.
Follow `next_cursor` with `--after`. Delivery status is separate from native proof.
The console can reopen the same operation with read permission. Changed projected
proof is refused until the read model is rebuilt from its canonical sources.

A task start without a retained native instance remains uncertain and blocks a
blind repeat. Keep the encrypted host journal and its key. A known completed
failed task can retain its original evidence while a separate inverse proceeds;
this does not clear an unknown start. Native AD worker-exit recovery is qualified
separately with Samba. The served coordinator also runs real Samba directory
changes and recovery with signed host boundary fixtures; stock LDAP independently
accepts the final generation and refuses the retired value. Portable coordinator
fixtures cover publication, source refusal and vault-conflict paths. The Windows
SCM/task/IIS receiver fixture uses local SAM accounts; its native hosted execution,
the complete Samba/Windows combination and final-image replay remain separate
proof obligations. Approved drift reconciliation has the separate directory and
signed-host-fixture proof described below. These results do not qualify an AD forest or host power loss.

The local useful-work endpoint receives `GET /configured-path?phase=verify&challenge=UUID`.
It returns HTTP 200 and one bounded JSON object with `probe_id`, the same
`challenge`, `account_sid`, `evidence_sha256`, and the actual `process_id` for a
service or pool. `evidence_sha256` is the digest of the independent work result.
For a password-bearing task, the host first sends POST with `phase=prepare` and
the challenge; the endpoint retains that challenge and returns HTTP 204. The task
must produce work bound to it. The later GET also carries `task_instance_id`; its
response must return that exact instance instead of a process ID. Responses are
limited to 16 KiB and ten seconds, with no proxy or redirect. Implement this
endpoint against actual application work; echoing a nonce alone is insufficient.
The endpoint and native process/task identity checks establish different facts,
and both must pass.


### Designated directory reset identity

A separate reset identity can repair a password changed outside the vault. The
native adapter checks that identity before every prepared reset or recovery,
using its directory SID and object GUID rather than trusting a reused name.

An explicit `active_directory` provider may define `ad_reconcile` with
`bind_dn`, protected `password_ref`, `sid`, raw 16-byte `guid` encoded as 32 hex
characters, and explicit `allowed_roles`. Its DN and credential reference must
differ from the ordinary writer; each role names one existing target account.
Grant only the target's [Reset Password extended right](https://learn.microsoft.com/windows/win32/adschema/r-user-force-change-password)
(`00299570-246d-11d0-a768-00aa006e0529`). The adapter reads public identity and
DC progress metadata over verified LDAPS. It refuses missing permissions,
changed identity pins and unprepared writes; it never falls back to the ordinary
writer. The credential reference remains in the control plane.

Choose **Reconcile external drift** in the account's dependent rotation wizard
and give a reason. Review the exact target and designated writer DN, SID and GUID,
retained vault version, complete host inventory, restart order, useful-work probes
and deadline. Request independent approval. The Approvals page opens that same
frozen manifest; it refuses approval while the manifest is missing or differs.
The requester cannot approve their own operation. Refresh the approval in the
wizard, acknowledge the single-phase interruption, then queue the frozen intent.
The saved URL reopens that exact review or its already queued operation.

The CLI follows the same contract:

```sh
trstctl access discovery rotation preview ACCOUNT -f reconcile-preview.json
trstctl access discovery rotation approval ACCOUNT -f reconcile-approval.json
trstctl access discovery rotation review PLAN_ID
trstctl access discovery rotation pending ACCOUNT PLAN_ID --approval-request-id APPROVAL_ID
trstctl access discovery rotation queue ACCOUNT -f approved-reconcile.json
```

The preview input sets `mode: "reconcile"` alongside `secret_name`, `order` and
`probes`. The approval input contains the returned `intent`, `intent_digest` and
a reason of at most 4096 characters. The queue input adds the returned
`approval_request_id`, `approval_intent_digest` and
`acknowledge_single_phase: true`. All mutations require an `Idempotency-Key`.
Request, preview and queue require `access:targets.write`, `secrets:write` and
write access to the stored reference. Independent review and approval require
`access:approve`. The requester-only pending read needs the write permissions,
not approval permission. Approval requires one independent reviewer and expires
no later than the original 15-minute inventory deadline.

Approval and the exact first command are durably claimed before broker append.
If publication or SQL projection is interrupted, `queue_pending: true` means the
same claimed command needs recovery; it does not claim that the operation was
projected. Retrying its exact queue request or restarting the control plane
recovers the original event and transactionally creates the parent, native child
and outbox work. A different approval or intent cannot replace that first command.
This command state is included in backup and privacy erasure. Recovery never
needs another password or fresh consent for the same already spent capability.

Before native effects, the worker checks locally that the retained vault value
contains a valid recovery password for the exact account. It does not authenticate
that possibly stale password. Expiry or changed inventory before any recorded
native apply ends the command without resetting AD or probing the old value.
After apply begins, only the sealed prepared generations may resume or recover.
Before vault publication and retirement, native identity and the exact final
prepared generation must still verify. A dependent failure restores the retained
stored generation; it cannot reconstruct the unknown drifted password.

Samba proof covers a separate writer with the target-only reset right, independent
public approval, drift repair, audit and vault state, dependent failure recovery,
stock LDAP acceptance and retired-password refusal. The signed host reports in
that coordinator proof are fixtures. Separate adapter proof also refuses a foreign
target without the grant. Native Windows dependent execution, the combined domain
journey, final-image replay and forest replication remain unverified. Existing
lockout checks remain in force; this workflow does not unlock an account.


### Recovering an inverse dependent step

When directory restoration has been canonically recorded and the next inverse
step has failed, is uncertain, or has passed its immutable execution deadline plus
one minute of receipt grace, progress exposes `recovery_step_id`. An operator with
`access:targets.write` and write access to the exact vault key can choose **Review
inverse recovery** in the account's rotation progress. Read the complete effect,
enter a reason, and acknowledge that the original result stays in the record.

The review freezes the original native action, host, SID, service/task/pool
configuration, useful-work probe, predecessor PIDs, original report digest, and
current vault version. Queueing creates a separate step with a fresh challenge
and two-minute lease. An update uses the already retained predecessor credential.
It does not repeat the AD reset, create a new password, or reuse the original
reconciliation approval. Changed provider identity, source evidence, review digest
or vault version requires opening a new review. A successful original step and
forward work cannot be replaced this way.

Headless operators use the same review and queue:

```sh
trstctl access discovery rotation get ROTATION_ID
trstctl access discovery rotation recovery-preview ROTATION_ID --step-id STEP_ID
trstctl access discovery rotation recovery-queue ROTATION_ID --force -f recovery.json
```

`recovery.json` contains `step_id`, `intent_digest`, `recovery_digest`, a bounded
`reason`, and `acknowledge_original_outcome: true`, copied from the exact review.
Keep the same idempotency key when retrying a lost response. The first immutable
recovery command also binds the actor and reason; a different request cannot
replace it after an append acknowledgement or a lost projection transaction.

The old row keeps its original failed/uncertain report. An expired unobserved row
remains queued with cancelled delivery. Replacement rows carry `intent.recovery`
with root and previous IDs and a depth. Paging retains both histories. At most
127 replacements can follow one original step; reaching that retained-history
bound refuses further work without deleting evidence. Exact late signed receipts
are retained for audit without applying the old step to current state. Removing
SQL lineage cannot revive an old host grant. Only separate successful replacement
evidence can let the existing inverse coordinator continue toward vault recovery.

A new server lease cannot clear an agent's unknown-start fence. Stop the agent,
complete the exact native terminal observation described above, acknowledge its
original report, then restart it. This is a distributed recovery: a queued response
is not native completion. Portable served tests cover uncertainty, actual lease
expiry, late signed receipts, lost projection, tamper refusal and privacy/rebuild.
Native Windows execution and the combined final-image journey remain unverified.


### Bounded pages for a complete account review

A headless operator can record an entire selected account's public native scope
in immutable pages. Each page is at most 64 KiB; the account has one header and
one final seal. Header, page and seal creation do not reset a directory password
or send a credential to a host. Once sealed, the review's GET response includes
an `intent` and `intent_digest` computed by the server. Queue those exact values
through the existing dependent rotation endpoint, with
`acknowledge_single_phase: true`; the CLI's `rotation queue` also requires
`--force`. The whole account keeps one operation and one directory generation.
The console authors this same paged review. It keeps every enabled host,
including hosts with no dependents, and packs pages by UTF-8 wire size. Edit
restart order in bounded row pages; a configured useful-work probe can fill empty
entries without overwriting per-dependent overrides. Review pages show the exact
native reference, global position, enrolled host and probe. All pages must load
before acknowledgement or independent approval is available. This is a review
aid; loading pages does not prove that a person inspected every entry.

Use **Save this sealed review for reopening** to retain its URL before requesting
approval. Reopening reads the frozen server intent without rescanning or rewriting
its scope. A reconciliation requester must supply a reason and obtain the separate
approval. Reviewers use the approval page reader with `access:approve`; they do
not need secret-read access. A failed, changed or expired page blocks the console
control. Existing operations expose the same frozen pages to read-only operators.
The server rechecks authority when the exact sealed intent is queued.

```sh
trstctl access discovery reviews open ACCOUNT_ID -f review.json
trstctl access discovery reviews append REVIEW_ID 0 -f page-0.json
trstctl access discovery reviews page REVIEW_ID 0
trstctl access discovery reviews get REVIEW_ID
trstctl access discovery reviews seal REVIEW_ID -f seal.json
```

A reconciliation uses the same sealed intent with `mode: "reconcile"`. Request
its independent approval before queuing. An approver with `access:approve` can
read each proposed page using `access discovery reviews approval-page REVIEW_ID
PAGE`; the page must belong to an actual frozen reconciliation review. The
approver does not need a vault credential. Read all pages and the final seal
before approving the complete account.

Execution keeps the global order: preflight every reference, stop active services
and pools in reverse order, update password-bearing dependents, start what was
active, then collect useful-work probes. Each step names its exact page and
position. Advancing that position requires the original event record and a
successful signed report, or a frozen snapshot proving the stage has no effect.
A pending event whose SQL projection was lost blocks the old host grant until
that exact metadata is restored; it never grants permission to rerun native work.

`review.json` contains the `secret_name` and optional `mode: "reconcile"`. The
server freezes the exact AD account, provider configuration, current vault version,
designated writer where applicable, and original fifteen-minute review window.
Writes need `access:targets.write` and write access to the exact vault key; only
the opening author can append or seal that review. Reads need account access and
read access to its key. No credential value or designated-writer credential
reference belongs in these public files.

A page contains `header_digest`, `previous_digest`, `hosts`, and ordered `entries`.
The first `previous_digest` is the header digest; later pages use the previous
page's returned digest. Each host supplies the exact enabled binding, signed
inventory run ID, inventory digest and observation time. An entry supplies that
host reference, its native `ref`, and the host's configured `probe_id`. Services,
tasks and pools retain their native selectors. A complete selected host with no
matching objects still needs a host declaration; it does not acquire a fabricated
entry. Use page numbers starting at zero and split files before the per-page limit.

`seal.json` contains `header_digest` and the final page's `tail_digest`. Sealing
requires every native reference from every enabled selected host exactly once,
consistent scan references, a fresh unchanged provider/vault binding, and native
service dependency order across pages. The final digest binds the whole account,
its exact counts, last page, and earliest scan expiry. A partial page set, duplicate,
wrong host, changed scan, unsafe order or expired review is refused. Pages cannot
be appended after sealing. These checks preserve one account scope; pages are
not independently rotated password groups.

Keep the same idempotency key when retrying a lost response. The first immutable
page/seal source also prevents a changed request from replacing it after an append
acknowledgement but before SQL projection. A pending or changed cache returns a
conflict with retry/rebuild guidance. Canonical sources preserve ordered scope
through snapshots, rebuilds, and author erasure. Native selectors remain exact;
the human author becomes a pseudonym. A seal is a reviewed-data commitment,
not evidence of a native password change or completed rotation.
