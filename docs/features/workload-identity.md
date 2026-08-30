# Workload identity — give software a verifiable, short-lived identity

## What it is

A [workload](../glossary.md) is a running piece of software — a service, a container,
a CI job, an AI agent — that *proves what it is* to other services without a
long-lived password or API key planted inside it, by combining
[attestation](../glossary.md) (cryptographic proof of what and where a workload is)
with short-lived credentials issued only to workloads that pass it.

The mental model: replace a permanent shared badge with a temporary badge issued
after checking the workload's proof. The workload still protects its private key
and any sensitive proof; the resulting pass expires in minutes. This page
covers the [SPIFFE](../glossary.md) standard, trstctl's attestation chain, ephemeral
issuance, the non-human identity lifecycle, and a purpose-built AI-agent broker.

## Why it exists

The classic way to give a service access — bake an API key or certificate into it — is
also the classic way to get breached: those secrets get copied into logs, images, git
history, and laptops, and rarely expire. Attestation-based, short-lived identity
reduces the exposure window: a stolen private key and certificate can still be
abused before expiry, but a short lifetime limits how long that access lasts.
Attestation and rotation do not replace key protection. This is a foundation of "zero-trust"
service-to-service security, and it matters even more for AI agents, which spin up
fast, act with real privileges, and need tight, revocable scopes.

## How it works

### The attestation chain (F30) — proof before trust

Everything here rests on attestation: before issuing anything, trstctl demands and
verifies proof of the workload's identity. The framework is pluggable — an `Attestor`
verifies one kind of proof — and trstctl ships six:

- **TPM 2.0 quote** — verifies a hardware TPM's endorsement chain back to the
  manufacturer root, plus a signed quote bound to a fresh nonce.
- **AWS IMDSv2** — verifies the PKCS#7-signed EC2 instance identity document against the
  AWS root.
- **GCP metadata** — verifies the Google-signed instance-identity JWT against Google's
  JWKS.
- **Azure metadata** — verifies the PKCS#7-signed IMDS attested document against a
  trusted Azure root.
- **Kubernetes projected SAT** — verifies a pod's projected service-account token
  against the cluster's JWKS.
- **GitHub OIDC + Fulcio** — verifies a GitHub Actions OIDC token and can produce a
  Sigstore/Fulcio binding for keyless code signing.

The verifier dispatches by method, computes a stable attestation ID through the single
crypto path, adds an attestation node to the [credential graph](graph-query-ai.md), and
emits an immutable `attestation.verified` event — or, on failure, `attestation.rejected`
and nothing else (fail-closed). Every attester must pass a conformance harness proving
it accepts a genuine proof and rejects a forgery.

Served at `/api/v1/workloads/attester-trust-sources` and
`POST /api/v1/workloads/attested-issuance`: workload owners with `certs:issue` manage
(create/replace/rotate/revoke/delete) tenant trust sources for `tpm`, `aws_iid`,
`gcp_iit`, `azure_imds`, `k8s_sat`, and `github_oidc`, and the binary builds the
verifier from those records plus any configured process defaults. It verifies the
proof, signs an X.509-SVID through the isolated signer, records the certificate as
`certificate.recorded`, and binds the attestation with `attestation.bound` — or fails
closed if no enabled trust source matches the method.

#### Review before issuing

On **Workloads & Machines**, open **Issue attested SVID**. An SVID is the workload's
short-lived identity certificate. The workflow has three steps:

1. **Describe the request.** Choose the proof method, paste the base64 proof and
   one public-key PEM block, and request a lifetime in seconds. The matching
   private key stays on the workload.
2. **Review what will happen.** `POST /api/v1/workloads/attested-issuance/preview`
   returns the exact request's SHA-256 digests, trust domain, enabled methods,
   effective lifetime, required permission, execution effects, and safe recovery.
   It reads tenant and operator-managed trust configuration but makes no event,
   outbox, idempotency, or certificate writes and calls neither verifier nor signer.
3. **Collect and prove.** Explicit issuance rechecks `certs:issue` and current
   trust, verifies the proof, derives the workload subject, and signs through the
   isolated signer. Copy the public certificate deliberately, then inspect the
   certificate inventory and audit evidence.

**Ready is not verified.** Some proofs contain one-time nonces. Preview must not
consume those proofs or emit verification events, so proof verification happens
only during issuance. A ready preview can still be refused if proof is invalid,
expired, or its trust source is revoked before execution. Missing trust produces
a visible blocker; it never falls back to trusting the browser.

The lifetime uses the server default for a nonpositive value and is capped at the
server maximum before conversion to a Go duration, including very large integer
inputs. The console accepts nonnegative whole seconds and shows any adjustment.
Changing an input invalidates the previous review. Within the open workflow, an
unchanged issuance retry keeps the same `Idempotency-Key`; a lost response must not
mint a second certificate. Inputs and the retry key are not persisted across a
page reload. If you lose the page, inspect inventory and audit before starting a
new issuance.

The API keeps both the base64-encoded proof and its decoded payload in wipeable
byte buffers, not immutable Go strings. It clears the application-owned encoded
buffer after conversion and on rejected or partially decoded requests, and clears
the decoded proof when handling finishes. This does not make request logs safe:
never log the proof or capture it in screenshots. The browser clears its proof
input after successful issuance; a failed attempt retains it for an unchanged retry.

The CLI supports the same no-effect review:

```sh
trstctl workloads attested-issuance preview -f attested-request.json
```

The JSON uses the same `method`, `payload_base64`, `public_key_pem`, and optional
`ttl_seconds` fields as issuance. Preview requires `certs:issue` but sends no
`Idempotency-Key`. Protect the request file as sensitive short-lived proof; do not
commit it or include it in screenshots, logs, or QA reports.

### The SPIFFE Workload API (F24) — the standard interface

[SPIFFE](../glossary.md) is the open standard for workload identity; its document is the
**SVID**, delivered as an X.509 certificate or a JWT. trstctl implements a
SPIRE-compatible Workload API server: a workload presents *selectors* (e.g.
`k8s:ns:default`, `k8s:sa:web`), the server matches them against registration entries
by set-subset (every required selector must be present), and issues the SVID. Signing
goes through the single crypto path to keys in the separate, isolated signing
service — private-key operations never run in the API process. A `NeedsRotation`
helper flags an SVID for renewal once half-expired (SPIRE's policy); issuance runs in
its own bounded lane, each step recorded as an immutable event.

Served as a gRPC service on a Unix domain socket (`protocols.spiffe.enabled`, default
off): a `spiffe-helper`/go-spiffe/Envoy-SDS workload dials the socket and can call
`FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID`, `FetchJWTBundles`, and
`ValidateJWTSVID`. X.509-SVIDs are signed through the isolated signing service;
JWT-SVIDs use the signer-backed JWT handle and validate against the served JWT bundle.
The Workload-API gRPC/protobuf contract is vendored verbatim from go-spiffe, so the
wire format is byte-identical.

#### Check the running path before connecting a workload

Open **How machines request credentials** and find **SPIFFE workload identity
readiness**. The console automatically asks the running control plane for a safe,
tenant-scoped review of the exact trust domain, Unix socket, owner-only socket mode,
registration-rule count, isolated issuing path, activation gate, and bounded worker
capacity. It does not dial the socket, request an SVID, call the signer, or write
state. Each failed gate names the repair that keeps the system fail-closed.

Headless operators can run the same check:

```sh
trstctl protocols spiffe qualify
```

That command calls `POST /api/v1/protocols/spiffe/qualification` as an authenticated
read-only request. A green result proves the running server is ready for a workload
client; it does not claim that a workload has fetched an identity. Final wire proof
still uses a stock go-spiffe or spiffe-helper client against the reported
`unix://...` path.

The control-plane-local socket is a compatibility path. For normal deployments,
run `trstctl-agent` on each host, bind registration entries to that node, and mount
only the host-local Workload API socket into workloads. This limits a compromised
host to identities assigned to that host instead of widening it to the trust domain.

### SPIRE upstream authority — keep SPIRE, anchor it in trstctl

If you already run [SPIRE](../glossary.md), trstctl can sit above it as the upstream
private CA: the `trstctl-spire-upstream-authority` plugin implements SPIRE's
UpstreamAuthority interface, so SPIRE keeps its local CA private key, sends only a CSR
to trstctl, and gets a signed intermediate CA chain back. SPIRE keeps minting locally
while trstctl becomes the governed root of trust — tenant-scoped API auth,
idempotency, audit, and signer-backed CA custody.

The plugin calls the served route `POST /api/v1/ca/authorities/{id}/intermediates/csr`
with `csr_pem` and a CA profile (`common_name`, `ttl_seconds`, `max_path_len`, optional
DNS constraints), reading its token from a mounted file rather than a command-line
argument. A stable `Idempotency-Key` on the CSR stops SPIRE retries from minting
duplicate intermediates; the response is the SPIRE intermediate plus the trstctl
upstream root.

```hcl
UpstreamAuthority "trstctl" {
  plugin_cmd = "/opt/spire/plugins/trstctl-spire-upstream-authority"
  plugin_data {
    endpoint = "https://trstctl.example.com:8443"
    ca_bundle_file = "/run/secrets/trstctl-server-ca.pem"
    allow_private_cidrs = ["10.96.42.15/32"]
    ca_authority_id = "11111111-1111-1111-1111-111111111111"
    token_file = "/run/secrets/trstctl-spire-token"
    common_name = "SPIRE Server CA"
    ttl_seconds = 3600
    max_path_len = 0
  }
}
```

For trstctl's default private/internal TLS, mount its published certificate-only
trust file at `ca_bundle_file`. The plugin pins that bundle for this upstream HTTPS
connection only; it does not disable verification or modify SPIRE's process-wide
trust store. Omit the field when the endpoint chains to a CA already trusted by the
host.

The plugin also applies resolved-address SSRF protection and locks requests to the
configured scheme and host. If a private trstctl name resolves to RFC 1918 space,
list only its expected address or smallest practical range in
`allow_private_cidrs`; private destinations are refused by default.

This is container-proven end to end: CI runs a real SPIRE server, loads the plugin,
mints an X.509-SVID, and verifies the chain as workload leaf -> SPIRE intermediate ->
trstctl root. SPIRE's optional JWT upstream method isn't claimed by this plugin —
X.509-SVID trust anchoring only.

### Ephemeral issuance (F25) — attestation in, short-lived cert out

The ephemeral issuer ties it together: it verifies an attestation (refusing to sign on
failure), mints a short-lived certificate (default TTL 15 minutes, clamped to a
per-method maximum), and binds the attestation to the credential in the graph and
audit trail. Every request takes an `Idempotency-Key`, so a retry never mints a second
credential — it returns the original.

The direct X.509-SVID flavor is served when attested issuance is configured, at
`POST /api/v1/workloads/attested-issuance`; the approval-gated JIT flavor is served
when ephemeral issuance is configured. Start with
`POST /api/v1/ephemeral/preview`. This POST-shaped read returns the exact request and
public-key SHA-256 digests, accepted proof methods, policy-normalized TTL, approval
rule, durable writes, outside effects, one eventual signer call, blockers, and safe
recovery steps. It does not verify the proof, write to PostgreSQL or the event log,
enqueue outbox work, or contact the signer. Proof verification remains execution-only
because some attestation evidence can be consumed once.

After review, `POST /api/v1/ephemeral` executes the same request. The first call
verifies the proof, opens a dual-control approval, and enqueues the notification
intent in the same tenant transaction. Its response keeps the caller's workflow
`request_id` separate from the genuine queue `approval_request_id` and returns the
queue record's `intent_digest`. A distinct approver calls
`POST /api/v1/ephemeral/{id}/approvals`, where `{id}` is that
`approval_request_id`, with `action: issue`, the same UUID in body `request_id`, and
the matching `intent_digest`. A fresh `Idempotency-Key` on
`POST /api/v1/ephemeral` then mints the short-TTL credential. The response also
carries `certificate_pem`, `credential_id`, `certificate_id`, `subject`,
`not_after`, approval counts, and verified attestation metadata.

The Workloads page exposes this as a three-step ELI5 workflow. It collects the proof
and public key, binds the submit button to the exact server preview, sends the request
for a different approver, links to the approval queue, and recovers the same request
after approval. Review and retained browser state show digests and public metadata,
not the proof. The matching private key always stays with the workload.

### Non-human identity lifecycle (F59)

Beyond a single credential, the identity itself has a lifecycle: requested, issued,
deployed, renewing, revoked, retired (terminal). trstctl models this as a guarded
state machine — every transition goes through one served path enforcing the legal
moves, updating PostgreSQL-backed identity rows and the credential graph projection,
and emitting immutable lifecycle events (`identity.created`, `identity.issued`,
`identity.deployed`, `identity.revoked`, `identity.renewed`, `identity.retired`).

The served REST routes `POST /api/v1/identities` and
`POST /api/v1/identities/{id}/transitions` (both take an `Idempotency-Key`, so a retry
never double-creates or double-applies) are the canonical identity lifecycle surface:
there's no parallel in-memory NHI manager — the PostgreSQL-backed identity rows,
orchestrator events, audit trail, graph projection, and OpenAPI/CLI paths are the
product path operators run.

The console now makes that state machine reviewable before it runs. It first calls
`POST /api/v1/identities/{id}/transitions/preview`, a POST-shaped **read** that accepts
the proposed target, reason, and optional public CSR. The server returns the current
owner, lifecycle version, legal event, exact outbox destination, prerequisites,
durable writes, external effects, warnings, and verification steps. Preview writes no
event, changes no projection, enqueues no outbox item, and contacts no signer or
external system. The response says this plainly so an operator can tell the
difference between “look” and “do.”

The same safe review is available to headless operators. Pass the intended
transition body to `trstctl-cli identities transition-preview <id> -f -`; the CLI
sends it to the effect-free preview route without adding an `Idempotency-Key`. After
reviewing that response, add its `expected_version` to the body and run
`identities transition` with a stable idempotency key.

Execution echoes the preview's server-owned `expected_version` to
`POST /api/v1/identities/{id}/transitions`. The orchestrator checks that version while
holding the identity row lock in the same tenant transaction that appends the event
and outbox intent. If anything changed after review, execution returns `409 Conflict`,
makes no lifecycle change, and requires a fresh preview. A matching
`Idempotency-Key` still returns the original result instead of applying the action
twice.

After execution, the console checks that the returned identity reached the requested
state, reloads the inventory and evidence panels, and only then says **Verified**.
For transitions with an asynchronous effect, “state accepted” is deliberately not
presented as “deployment finished”: the plan tells the operator to follow the
matching delivery or rotation receipt. Revocation uses the backend's closed RFC 5280
reason set instead of accepting free text that the API would reject. Revoke and
retire also retain typed-name confirmation and served credential-graph blast radius.

### The AI-agent identity broker (F61)

AI agents are a sharp case: they appear fast, act with real privileges, and chain
tools together, so an over-scoped or un-revocable credential is dangerous. The
AI-agent identity broker is a dedicated issuance surface that (1) evaluates a
[policy](policy-and-governance.md) decision *before* issuing — a deny records
`agent.identity.refused` and signs nothing; (2) issues an attested, short-lived
credential via the ephemeral issuer; (3) records the agent and its credential in the
graph so you can ask **blast radius** ("everything this agent can reach") *before*
trusting it. A tenant-wide broker history and one-call revocation console remain a
roadmap residual, not part of the served GA claim.

Served when the agent broker is configured, at `POST /api/v1/broker/agent-identities`:
the operator supplies the trust domain, attestors, Rego policy module, and
signer-backed issuing CA. A request carries the agent id, attestation method, proof
payload, public key, requested scopes, and optional TTL; trstctl verifies the proof,
evaluates policy before signing, mints a short-lived X.509-SVID through the isolated
signer, records `certificate.recorded`, and projects the agent-to-credential edge into
the graph. Denies emit `agent.identity.refused` and return no credential.

### In the console

The console adds a governance lens over non-human identities: a unified NHI inventory
by kind (`GET /api/v1/nhi/inventory`), a risk-posture summary, orphan-governance for
credentials whose custodian is gone or inactive, and a blast-radius explorer at
`/graph`. The identity grid at `/identities` carries issue / deploy / revoke actions
behind the same confirm and dual-control guards as the API. See
[The web console](../web-console.md).

## Use it

Create and transition a managed identity:

```sh
trstctl-cli identities create -f service-account.json
trstctl-cli identities transition <id> \
  -f '{"to":"revoked","reason":"cessationOfOperation"}'
```

Both map to `POST /api/v1/identities` and `POST /api/v1/identities/{id}/transitions`
(mutations require an `Idempotency-Key`). Automated decommissioning from owner
departure, vendor termination, or inactivity signals is governance, not an
identity-lifecycle primitive: `POST /api/v1/nhi/decommission`
(`trstctl-cli nhi decommission`) resolves those signals against managed NHIs and
revokes or retires them via these same transitions. Canonical home:
[Policy & governance](policy-and-governance.md#automated-nhi-decommissioning).

Deploying against an existing SPIRE cluster requires installing the plugin binary (or
mounting it read-only) and adding the `UpstreamAuthority "trstctl"` block above with a
`token_file` scoped to `certs:issue` on the owning tenant.

Attested X.509-SVID issuance needs an enabled trust source first
(`POST /api/v1/workloads/attester-trust-sources`; name, method, issuer, audience,
JWKS), then:

```sh
TRSTCTL_ATTESTED_ISSUANCE_ENABLED=true
TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN=example.org
TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL=10m
TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL=1h
```

These environment variables are the container equivalent of the
`attested_issuance` JSON/YAML block. Turning the mint on does not trust any
platform by itself: issuance remains disabled for a method until that tenant
adds an enabled public trust source. Never put an attestation token or private
key in an environment variable; send the proof and public key only in the
preview and issuance request bodies. Preview does not verify or consume proof.

```sh
curl -sS -X POST https://localhost:8443/api/v1/workloads/attested-issuance \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: k8s-web-1" -H "Content-Type: application/json" \
  -d '{"method":"k8s_sat","payload_base64":"...","public_key_pem":"...",
      "ttl_seconds":600}'
```

The response is the certificate the workload should load, plus the verified subject
that became the SPIFFE path (e.g. `spiffe://example.org/ns/default/sa/web`). Trust
material rotates, revokes, and offboards via `.../rotate`, `.../revoke`, and
`DELETE .../{id}`, each idempotent and recorded as an immutable event.

Approval-gated ephemeral/JIT issuance is off by default. Enable the
`ephemeral_issuance` block with a trust domain, credential TTL bounds, approval TTL,
and approval threshold. Verification material is not global process config: each
tenant enables its own public workload attester trust source through the Workloads
page or `/api/v1/workloads/attester-trust-sources`. A tenant without a valid enabled
source sees an exact preview blocker and cannot submit. The requester opens the
approval, a distinct approver records it (never themselves), then the requester mints
with a fresh idempotency key:

```json
{
  "ephemeral_issuance": {
    "enabled": true,
    "trust_domain": "workloads.example.com",
    "default_ttl": "5m",
    "max_ttl": "30m",
    "approval_ttl": "15m",
    "required_approvals": 2
  }
}
```

```sh
trstctl-cli ephemeral preview -f jit-request.json
trstctl-cli --idempotency-key jit-1-request ephemeral issue -f jit-request.json
# approval.json contains action, the returned approval_request_id as request_id,
# and the returned intent_digest. The path argument is that same approval_request_id.
trstctl-cli --idempotency-key jit-1-approve ephemeral approve <approval_request_id> -f approval.json
trstctl-cli --idempotency-key jit-1-issue ephemeral issue -f jit-request.json
```

The first call returns `state: "awaiting_approval"` and no certificate; the approved
call returns `state: "issued"` with a certificate whose `not_after` is clamped by the
TTL policy. Replaying either key returns the same response without opening another
approval or minting again.

The AI-agent broker works the same way once configured:

```sh
curl -sS -X POST https://localhost:8443/api/v1/broker/agent-identities \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: agent-7-issue" -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-7","method":"k8s_sat","payload_base64":"...",
      "public_key_pem":"...","scopes":["mcp:graph.read","tool:inventory.read"],
      "ttl_seconds":600}'
```

The response includes the issued certificate, `credential_id`, `certificate_id`,
verified attestation metadata, expiry, and the graph `node_id` for the agent workload.
Replaying the same key returns the same response without minting twice.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| NHI lifecycle routes (F59) | Served — `/api/v1/identities`, `/transitions` |
| SPIFFE Workload API (F24) | Served — gRPC over a UDS (`protocols.spiffe.enabled`); `FetchX509SVID`, `FetchJWTSVID`, bundle fetches, and `ValidateJWTSVID` wired to the signer-backed path |
| SPIRE upstream authority | Served and container-proven for X.509 — SPIRE loads `trstctl-spire-upstream-authority`, trstctl signs its intermediate CA CSR via `/api/v1/ca/authorities/{id}/intermediates/csr`, and the e2e verifies a minted SVID chain to the trstctl root |
| Ephemeral issuance (F25) | Served — direct attested X.509-SVID mint at `POST /api/v1/workloads/attested-issuance`; effect-free exact JIT review at `POST /api/v1/ephemeral/preview`; approval-gated mint at `POST /api/v1/ephemeral` plus `/api/v1/ephemeral/{id}/approvals`; and a dedicated review/approval/recovery workflow on Workloads |
| Attestation chain (F30) | Served — tenant trust-source lifecycle at `/api/v1/workloads/attester-trust-sources`; exact effect-free review at `/api/v1/workloads/attested-issuance/preview`; the six-attester verifier gates `POST /api/v1/workloads/attested-issuance`; the console separates request, review, and result with unchanged-key retries; conformance covers each attester |
| AI-agent broker (F61) | Served when configured — `POST /api/v1/broker/agent-identities` verifies proof, gates policy, mints a short-lived credential, and projects the graph grant |

Operationally: each attestation method needs public trust material configured first
(cloud roots, cluster JWKS, TPM manufacturer roots), and short TTLs mean frequent
renewal for workloads and agents — the point, but plan for it.

## Reference

- **Served routes:** `POST /api/v1/identities`,
  `POST /api/v1/identities/{id}/transitions`,
  `GET /api/v1/workloads/attester-trust-sources`,
  `POST /api/v1/workloads/attester-trust-sources`,
  `PUT /api/v1/workloads/attester-trust-sources/{id}`,
  `POST /api/v1/workloads/attester-trust-sources/{id}/rotate`,
  `POST /api/v1/workloads/attester-trust-sources/{id}/revoke`,
  `DELETE /api/v1/workloads/attester-trust-sources/{id}`,
  `POST /api/v1/workloads/attested-issuance`,
  `POST /api/v1/ephemeral`,
  `POST /api/v1/ephemeral/{id}/approvals` (`{id}` is the genuine
  `approval_request_id`; body `request_id` and `intent_digest` must match it),
  `POST /api/v1/broker/agent-identities`,
  `POST /api/v1/ca/authorities/{id}/intermediates/csr`.
- **Attestation methods:** `tpm`, `aws_iid`, `gcp_iit`, `azure_imds`, `k8s_sat`,
  `github_oidc`.
- **SPIFFE:** `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID`,
  `FetchJWTBundles`, `ValidateJWTSVID`; selector match is set-subset.
- **Events:** `attestation.verified/rejected/bound`,
  `ephemeral.approval.requested`, `ephemeral.approval.granted`, `ephemeral.issued`,
  `spiffe.svid.issued`, `certificate.recorded`, `identity.created`,
  `identity.{issued,deployed,revoked,renewed,retired}`,
  `agent.identity.{issued,refused,revoked}`.

## See also

[SSH](ssh.md) (attestation-gated SSH certs use the same chain) ·
[Issuance & certificate authorities](issuance-and-cas.md) ·
[Graph, query & AI](graph-query-ai.md) (blast radius) ·
[Policy & governance](policy-and-governance.md) (the broker's policy gate and NHI
decommissioning) ·
glossary: [workload](../glossary.md), [attestation](../glossary.md),
[SPIFFE/SVID](../glossary.md)

**Covers:** F24, F25, F30, F59, F61
