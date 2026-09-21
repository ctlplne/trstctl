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
> interop; remaining gaps are in [Current limitations](../limitations.md).

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

Bulk application-secret import is deliberately unavailable. The compatibility route
`POST /api/v1/secrets/store/import` returns `501 Not Implemented` and writes nothing;
its OpenAPI operation is deprecated and marked `x-trstctl-availability: unavailable`.
An atomic batch command must fence, append, project, and receipt every name together
before this can be enabled without bypassing the immutable event log. Until then,
preview and then create each secret through the two native-store routes, using a
distinct idempotency key for each create mutation.

The served store seals through a versioned binary container, its KEK loaded into
locked, zeroizable memory at startup, never a raw byte slice on the heap. An older
store core, kept for legacy event replay and compatibility, holds its KEK the same way
and still replays both the binary container and earlier JSON-envelope history; new
writes go through the path above.

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

It skips Vault mount management, ACL policies, cubbyhole, response wrapping, transit
paths, and every dynamic secret engine — the native trstctl API remains the full
surface. The machine-readable contract is pinned separately as
[`docs/contracts/vault-openbao-compat.openapi.json`](../contracts/vault-openbao-compat.openapi.json),
since `/v1` paths preserve Vault/OpenBao wire shapes. Mutating calls accept
`Idempotency-Key`; since the stock CLI sends none, trstctl derives one from method,
path, and body so a retry can't mint a duplicate certificate — force a fresh one with a
different `Idempotency-Key`, or use the native `/api/v1/secrets/pki` route.

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
There is no bulk-import CLI command while the compatibility route is safely
unavailable: OpenAPI exposes only its `501` response and the portal shows a disabled
**Import unavailable** control with the safe alternative. Scripts must create each
secret as its own event-sourced request and use a separate idempotency key.

### Dynamic secrets (F65) and PKI-as-a-secrets-engine (F67)

Instead of a long-lived secret to steal, dynamic secrets are minted on demand, scoped,
and time-limited by a [lease](../glossary.md); on expiry trstctl revokes the credential
automatically, even across a restart, since the revocation intent is journaled first to
a durable [outbox](../glossary.md) and delivered at-least-once. Eight backends ship
behind one interface, each backed by real infrastructure, not a stub: PostgreSQL,
MySQL, MongoDB, AWS IAM, GCP IAM, Azure Entra, Kubernetes ServiceAccount tokens, and
Redis ACL users.

The control plane mounts the lease lifecycle when `secrets.enable_api` is on and
`secret_integrations.dynamic_providers` supplies tenant-bound endpoints, allowed roles,
maximum TTLs, egress policy, and `file:`/`secret://` credential references
(`buildRunDeps` wires the registry). Issuance commits a pending lease and sealed
outbox command first, so only the outbox worker calls the provider and a crash retry
reuses the same identity. Cloud/Kubernetes endpoints require HTTPS; `allow_insecure_loopback` is a
same-host-emulator exception limited to `localhost`, `127.0.0.0/8`, or `::1`.

- `GET /api/v1/secrets/leases/providers` returns the eight safe setup recipes plus
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
  `revocation_completed_at` confirms the provider removal operation. `revoked_at`
  records when the control plane queued the request. Older immutable operation
  receipts may omit these additional fields; GET returns current durable evidence.
- `POST /api/v1/secrets/leases/{lease_id}/renew` extends a lease without returning the
  credential again.
- `POST /api/v1/secrets/leases/{lease_id}/revoke` closes the lease and queues backend
  revocation through the outbox worker.

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
same custody model and retains `pki/issue` only as the legacy equivalent.

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

The repository contains a four-phase static-provider engine (stage, cutover, verify,
retire), but that engine keeps staged authority in process memory and cannot recover
an ACK-loss crash between provider effects. The served API therefore does not invoke
it. Before execution, `POST /api/v1/secrets/rotations/preview` returns an exact,
effect-free F37 plan. It reads only tenant-scoped secret metadata and configuration:
it generates no successor value, decrypts no secret, writes no event or outbox row,
and contacts no connector. The plan reports current/next versions, the resolved
connector destination, required permission, a tenant-bound request fingerprint,
execution effects, recovery steps, and explicit blockers. The console and
`trstctl-cli secrets rotations preview` use this plan without an Idempotency-Key;
changing console inputs invalidates the review. Only a ready, still-current review
reveals the separate execution action.

`POST /api/v1/secrets/rotations` currently accepts only `connector:<target>` and
commits one application-secret event plus its sealed outbox intent before returning
queued, non-secret evidence. Manual static-provider and dynamic-lease requests return
`503` before stage, issue, cutover, delivery, verification, rollback, revoke, or
retirement. Native-store value rotation remains a separate event-sourced operation.

The scheduled path records connector cadences at
`POST /api/v1/secrets/rotation-schedules`, lists them with
`GET /api/v1/secrets/rotation-schedules`, and runs due ones with
`POST /api/v1/secrets/rotation-schedules/run-due`. New static and dynamic-lease
schedules fail closed with `503`. A historical static or dynamic schedule is terminalized as
`unsupported`, disabled, and makes zero provider calls instead of pretending that
its phase chain is crash-safe. A queued connector run advances `old_ref`; a
connector whose local version committed before terminal delivery failure also
advances to that committed version so later cadences cannot stale-loop.

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

The endpoint currently accepts one provider class:

- `connector:<target>` atomically commits a native-store version and one sealed
  secret-sync outbox command. The response sets `queued:true` and `completed:false`;
  only the bounded outbox worker calls the connector. Delivery failure stays on the
  durable job for retry and does not perform a compensating direct write.

Static providers such as `postgresql`, `mysql`, and `aws-iam`, plus
`dynamic-lease:<provider>`, fail closed with a stable `503` before any provider,
connector, event, or outbox effect. Issuing, renewing, and revoking dynamic leases
remain supported through the lease endpoints. Provider rotation stays unavailable
until one durable worker command can autonomously own every effect and compensation
across every crash boundary.

PostgreSQL, MySQL, and AWS IAM rotators ship as concrete, infrastructure-verified
library backends covering stage/cutover/verify/retire-and-rollback; the served
request path deliberately does not invoke them yet.

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
response is written. When `transit.keyring_dir` and the deployment KEK are configured,
every create/rotate atomically checkpoints an opaque sealed keyring and startup restores
it before serving; a missing or unreadable original KEK fails startup instead of silently
replacing the keys. There is deliberately no browser upload/import path for key material.
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
For a restore failure, repair the original KEK or sealed-keyring mount and restart;
never delete or overwrite the sealed file just to make the process start.

For legacy gear, the binary can also mount an opt-in KMIP listener:

- `TRSTCTL_PROTOCOLS_KMIP_ENABLED=true`
- `TRSTCTL_PROTOCOLS_KMIP_TENANT_ID=<tenant-uuid>`
- `TRSTCTL_PROTOCOLS_KMIP_ADDR=:5696`
- `TRSTCTL_PROTOCOLS_KMIP_CERT_FILE=/path/server.crt`
- `TRSTCTL_PROTOCOLS_KMIP_KEY_FILE=/path/server.key`
- `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE=/path/client-ca.crt`

The listener is raw KMIP over mutual TLS 1.3; the TLS layer verifies the client cert
chain before the KMIP handler sees a frame. The service stores objects under the
configured tenant, emits immutable `kmip.object.created`, `kmip.object.revoke`, and
`kmip.object.destroyed` audit events, and zeroizes in-memory key material on destroy,
rekey, and shutdown. The served OASIS 1.4 profile is stock-client-tested: Query,
DiscoverVersions, Create/Register an AES-256 `SymmetricKey`, Get it plain or
AES-GCM-wrapped (and register the wrapped value back), Locate, Revoke, and Destroy over
TTLV. Unsupported operations get a KMIP failure response, not an unframed TCP close.
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
pusher, and returns metadata only (`name`, `target`, `remote_key`, enqueued/delivered
flags). `GET /api/v1/secrets/syncs/targets` lists the catalog and marks which targets
are configured. Shipped concrete pushers: AWS Secrets Manager, GCP Secret Manager,
Azure Key Vault, GitHub Actions, GitLab CI, Vercel, Kubernetes, Terraform Cloud/OpenTofu,
HashiCorp Vault/OpenBao KV v2, and a generic CI/JSON endpoint.

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
an ordinary timeout or expired worker remains `effect_possible`, keeps its FIFO
barrier, and is retried with the same receiver idempotency key until delivery is
proved. The one exception is a typed local no-network result owned by the first and
still-only start token. Its closed error and event attempt count are frozen before
append so crash recovery reproduces the same canonical evidence bytes.
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
and the `trstctl-agent --secret-inject` sidecar; the operator reads only
metadata/content hash, and the sidecar copies volume files as byte slices and wipes
buffers.

`GET /api/v1/secrets/unvaulted` / `trstctl-cli secrets unvaulted`: repository and
third-party scanning sources, redacted `leaked_secret` finding counts, cloud-secret
discovery across AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and
HashiCorp Vault KV, and configured AWS/GCP/Azure sync targets — read-only and
metadata-only.

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
   shape, session lifetime, prerequisites, blockers, writes, outside calls, recovery
   steps, verification steps, and CLI command. It does not receive a credential,
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
secret references, never payload values. Native GitHub/GitLab/Bitbucket signature
verification and private `credential_ref` clone resolution remain shortfalls, not
served.

Third-party artifacts use the same shape: `GET /api/v1/secrets/scans/third-party` and
`POST /api/v1/secrets/scans/third-party/{provider}/ingest` cover `cicd_log`,
`container_registry`, `slack`, and `jira` — a source plus operator-owned
`artifact_path` queues a `secret_third_party` discovery run against the same Gitleaks
runner. Raw CI logs, registry exports, chat transcripts, and issue exports stay outside
trstctl storage; events record only provider, artifact kind, rule id, file, line,
scanner version, and credential-ref. Native Slack/Jira/container-registry API polling,
signature validation, and provider-native annotations remain shortfalls, not served.

```bash
cat > third-party-scan.json <<'JSON'
{"source":"acme/slack","artifact_path":"/var/lib/trstctl/exports/slack.jsonl","event":"message_export"}
JSON
trstctl-cli --idempotency-key third-party-scan-1 \
  secrets scans third-party ingest slack -f third-party-scan.json
```

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
boundary is listed above. Import stays disabled because its compatibility route returns
`501` without writing. See [The web console](../web-console.md).

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

curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_URL/api/v1/secrets/syncs/targets"
```

## Pitfalls & limits

- **Serving status:** rotation serves worker-queued connector-backed manual and
  scheduled variants. Static-provider and dynamic-lease rotation fail closed before
  provider effects pending a durable multi-phase worker command. An unconfigured
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
- **Transit/KMIP boundaries:** appliance-specific templates and tenant self-service
  KMIP listener management remain deliberate boundaries — see
  [Current limitations](../limitations.md).
- **Sync is push + drift-detect**, not a two-way merge — trstctl is the source of truth.

## Reference

- **At rest:** envelope encryption (AES-256-GCM DEK wrapped by KEK); config
  `TRSTCTL_SECRETS_KEK_FILE`.
- **Store:** `Put/Get/GetVersion/Versions/Rollback/Delete/Purge`; `APIServer`
  (`PUT/GET /secrets/<path>`, `Idempotency-Key`).
- **Developer run wrapper:** `trstctl-cli run --secret ENV=secret/path -- <cmd>`
  fetches via `/api/v1/secrets/store/{name}` and injects only into the child env.
- **Dynamic backends:** `postgresql`, `mysql`, `mongodb`, `aws-iam`, `gcp-iam`,
  `azure-entra`, `kubernetes`, `redis`, plus `pki`.
- **Transit:** `/api/v1/transit/{keys,encrypt,decrypt,rewrap,hmac,sign,verify}`,
  `trstctl-cli transit ...`, versioned `trv:<n>:` ciphertext.
- **KMIP:** opt-in mTLS listener (`TRSTCTL_PROTOCOLS_KMIP_ENABLED=true`) for AES-256
  SymmetricKey Create/Get/Locate/Revoke/Destroy, default address `:5696`, tenant bound by
  `TRSTCTL_PROTOCOLS_KMIP_TENANT_ID`.
- **Sync targets:** AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, GitHub
  Actions, GitLab CI, Vercel, Kubernetes, Terraform Cloud/OpenTofu, HashiCorp
  Vault/OpenBao KV v2, generic CI/JSON.
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

**Covers:** F37, F38, F39, F63, F64, F65, F66, F67, F68, F58, F60
