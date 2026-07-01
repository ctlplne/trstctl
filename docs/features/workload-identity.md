# Workload identity — give software a verifiable identity, no secrets to steal

## What it is

A [workload](../glossary.md) is a running piece of software — a service, a container, a
CI job, an AI agent. Workload identity is how that software *proves what it is* to other
services, without anyone planting a long-lived password or API key inside it. trstctl
does this by combining two ideas: [attestation](../glossary.md) (cryptographic proof of
what and where a workload is) and short-lived credentials issued only to workloads that
pass attestation.

The mental model: instead of giving every employee a permanent badge they might lose,
you install a fingerprint scanner at each door. The workload doesn't carry a secret — it
*proves what it is* at the moment it needs access, and gets a pass that expires in
minutes. This page covers the [SPIFFE](../glossary.md) standard for workload identity,
trstctl's attestation chain, ephemeral issuance, lifecycle management for non-human
identities, and a purpose-built broker for AI agents.

## Why it exists

The classic way to give a service access — bake an API key or certificate into it — is
also the classic way to get breached: those secrets get copied into logs, images, git
history, and laptops, and they rarely expire. Attestation-based, short-lived identity
removes the thing attackers steal. There's nothing long-lived in the workload to leak,
and even a captured credential is useless within minutes. This is the foundation of
"zero-trust" service-to-service security, and it matters even more for AI agents, which
spin up fast, act with real privileges, and need tight, revocable scopes.

## How it works

### The attestation chain (F30) — proof before trust

Everything here rests on attestation: before issuing anything, trstctl demands proof of
the workload's identity and verifies it. The framework is pluggable — an `Attestor`
knows how to verify one kind of proof — and trstctl ships six:

- **TPM 2.0 quote** — verifies a hardware TPM's endorsement chain back to the
  manufacturer root, plus a signed quote bound to a fresh nonce.
- **AWS IMDSv2** — verifies the PKCS#7-signed EC2 instance identity document against the
  AWS root.
- **GCP / Azure metadata** — verifies the signed identity document the cloud's metadata
  service hands a VM.
- **Kubernetes projected SAT** — verifies a pod's projected service-account token against
  the cluster's JWKS.
- **GitHub OIDC + Fulcio** — verifies a GitHub Actions OIDC token and can produce a
  Sigstore/Fulcio binding for keyless code signing.

The verifier dispatches by method, computes a stable attestation ID inside the single
crypto path, adds an attestation node to the [credential graph](graph-query-ai.md),
and emits an immutable `attestation.verified` event — or `attestation.rejected` and
**nothing else** on failure (fail-closed). Every attester must pass a conformance harness
that proves it *accepts the genuine proof and rejects a forgery*. All signature/JWT/CMS
verification runs through the single crypto path.

**Status:** **served** at `/api/v1/workloads/attester-trust-sources` and
`POST /api/v1/workloads/attested-issuance`. Workload owners with `certs:issue` can create,
replace, rotate, revoke, and delete tenant trust sources for `tpm`, `aws_iid`, `gcp_iit`,
`azure_imds`, `k8s_sat`, and `github_oidc`; the running binary builds the verifier from
those tenant records plus any configured process defaults. It verifies the presented
proof, signs an X.509-SVID through the isolated signing service, records the certificate
through `certificate.recorded`, and binds the attestation with `attestation.bound`. If no
enabled trust source matches the method, the route fails closed.

### The SPIFFE Workload API (F24) — the standard interface

[SPIFFE](../glossary.md) is the open standard for workload identity; its document is the
**SVID**, delivered as an X.509 certificate or a JWT. trstctl implements a
SPIRE-compatible Workload API server: a workload presents *selectors* (e.g.
`k8s:ns:default`, `k8s:sa:web`), the server matches them against registration entries
using set-subset semantics (you must present every selector an entry requires), and
issues the SVID. Signing goes through the single crypto path to keys held in the separate,
isolated signing service — private-key operations never run in the API process; a
`NeedsRotation` helper flags an SVID for renewal once it's half-expired (SPIRE's policy);
issuance runs in its own bounded lane and every step is recorded as an immutable event.

**Status:** **served** as a gRPC service on a Unix domain socket
(`protocols.spiffe.enabled`, default off): a `spiffe-helper`/go-spiffe/Envoy-SDS workload
dials the socket and can call `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID`,
`FetchJWTBundles`, and `ValidateJWTSVID`. X.509-SVIDs are signed through the isolated
signing service; JWT-SVIDs use the signer-backed JWT handle and are validated against
the served JWT bundle. The Workload-API gRPC/protobuf contract is vendored verbatim
from go-spiffe so the wire format is byte-identical.

### SPIRE upstream authority — keep SPIRE, anchor it in trstctl

If you already run [SPIRE](../glossary.md), trstctl can sit above it as the upstream
private CA. The `trstctl-spire-upstream-authority` plugin implements SPIRE's
UpstreamAuthority interface: SPIRE generates and keeps its local CA private key,
sends only a CSR to trstctl, and receives a signed intermediate CA chain back. In
plain terms, SPIRE keeps doing the local workload minting it is good at, while trstctl
becomes the governed root of trust with tenant-scoped API auth, idempotency, audit,
and signer-backed CA custody.

The plugin calls the served route
`POST /api/v1/ca/authorities/{id}/intermediates/csr`. The request contains
`csr_pem` and a CA profile (`common_name`, `ttl_seconds`, `max_path_len`, and optional
DNS constraints). The token comes from a file mounted into the SPIRE server container,
not from command-line arguments, and the plugin sends a stable `Idempotency-Key` for
the CSR so SPIRE retries do not mint duplicate intermediates. The response is the
SPIRE intermediate plus the trstctl upstream root.

```hcl
UpstreamAuthority "trstctl" {
  plugin_cmd = "/opt/spire/plugins/trstctl-spire-upstream-authority"
  plugin_data {
    endpoint = "https://trstctl.example.com:8443"
    ca_authority_id = "11111111-1111-1111-1111-111111111111"
    token_file = "/run/secrets/trstctl-spire-token"
    common_name = "SPIRE Server CA"
    ttl_seconds = 3600
    max_path_len = 0
    permitted_dns_domains = ["example.org"]
  }
}
```

**Status:** **served and container-proven for X.509.** CI starts a real SPIRE server
container, loads the trstctl upstream-authority plugin, has SPIRE mint an X.509-SVID,
and verifies the chain as workload leaf -> SPIRE intermediate -> trstctl root.
SPIRE's optional JWT upstream publication method is not claimed by this plugin; use it
for X.509-SVID trust anchoring.

### Ephemeral issuance (F25) — attestation in, short-lived cert out

The ephemeral issuer ties it together: it takes an attestation, verifies it (refusing to
sign if verification fails), mints a short-lived certificate (default TTL 15 minutes,
clamped to a per-method maximum), and **binds** the attestation to the credential in the
graph and audit trail. Every request takes an `Idempotency-Key`, so a retry never mints a
second credential — it returns the original.

**Status:** the direct X.509-SVID flavor is **served when attested issuance is
configured** at `POST /api/v1/workloads/attested-issuance`. The approval-gated JIT
flavor is also **served when ephemeral issuance is configured** at `POST
/api/v1/ephemeral`: the first call verifies the proof, opens a dual-control approval
request, and enqueues the approval notification intent in the same tenant transaction.
After a distinct approver calls `POST /api/v1/ephemeral/{request_id}/approvals`, a
fresh `Idempotency-Key` on `POST /api/v1/ephemeral` mints the short-TTL credential. The
response carries `certificate_pem`, `credential_id`, `certificate_id`, `subject`,
`not_after`, approval counts, and verified attestation metadata.

### Non-human identity lifecycle (F59)

Beyond a single credential, the *identity itself* has a lifecycle: requested, issued,
deployed, renewing, revoked, and retired (a terminal state). trstctl models this as a
guarded state machine — every transition goes through one served path that enforces the
legal moves, updates PostgreSQL-backed identity rows and the credential graph projection,
and emits immutable lifecycle events (`identity.created`, `identity.issued`,
`identity.deployed`, `identity.revoked`, `identity.renewed`, `identity.retired`).

**Status:** the served REST routes `POST /api/v1/identities` and
`POST /api/v1/identities/{id}/transitions` (both take an `Idempotency-Key`, so a retry
never creates the same identity twice or applies a transition twice) are the canonical
identity lifecycle surface. There is no parallel in-memory NHI manager; the
PostgreSQL-backed identity rows, orchestrator events, audit trail, graph projection, and
OpenAPI/CLI paths are the product path operators run.

### The AI-agent identity broker (F61)

AI agents are a sharp case: they appear quickly, act with real privileges, and chain
tools together, so an over-scoped or un-revocable agent credential is dangerous. The
broker is a dedicated issuance surface that (1) evaluates a [policy](policy-and-governance.md)
decision *before* issuing — a deny records `agent.identity.refused` and signs nothing;
(2) issues an attested, short-lived credential via the ephemeral issuer; (3) records the
agent and its credential in the graph so you can ask **blast radius** ("everything this
agent can reach") *before* trusting it; and (4) supports **one-call revocation** of every
credential an agent owns.

**Status:** **served when the agent broker is configured** at
`POST /api/v1/broker/agent-identities`. The operator supplies the trust domain,
attestors, Rego policy module, and signer-backed issuing CA. A request carries the
agent id, attestation method, proof payload, public key PEM, requested scopes, and
optional TTL; trstctl verifies the proof, evaluates policy before signing, mints a
short-lived X.509-SVID through the isolated signer, records `certificate.recorded`, and
projects the agent-to-credential ownership edge into the graph. Denies emit
`agent.identity.refused` and return no credential.

### In the console

The console adds the governance lens over non-human identities: a unified **NHI inventory**
by kind backed by `GET /api/v1/nhi/inventory`, a **risk-posture** summary,
**orphan-governance** for credentials whose human custodian is gone or inactive, and a
credential-graph **blast-radius explorer** at `/graph`.
The identity grid at `/identities` carries the issue / deploy / revoke lifecycle actions
behind the same confirm and dual-control guards as the API. See
[The web console](../web-console.md).

## Use it

The non-human-identity lifecycle is served today:

```sh
# create a managed non-human identity (idempotent)
trstctl-cli identities create -f service-account.json

# transition its state (e.g. disable on decommission)
trstctl-cli identities transition <id> -f '{"to":"revoked","reason":"cessationOfOperation"}'

# run automated NHI decommissioning from governance signals
trstctl-cli nhi decommission -f nhi-decommission.json --force
```

Those map to `POST /api/v1/identities`,
`POST /api/v1/identities/{id}/transitions`, and `POST
/api/v1/nhi/decommission` (mutations require an `Idempotency-Key`). The
decommission route resolves departure, vendor-term, and inactivity signals to
tenant-local managed NHIs, then uses the same event-sourced lifecycle transitions
to revoke active credentials or retire already-revoked identities. The **SPIFFE
Workload API is now served** over a UDS (`protocols.spiffe.enabled`): workloads
fetch X.509-SVIDs and JWT-SVIDs from the same socket, fetch both bundle types,
and validate JWT-SVIDs through the served `ValidateJWTSVID` RPC.

If SPIRE already runs in the cluster, install the plugin binary into the SPIRE server
container image or mount it from a read-only volume, then configure the
`UpstreamAuthority "trstctl"` block shown above. The API token in `token_file` needs
`certs:issue` on the tenant that owns the CA authority. On startup, SPIRE sends a CSR
for its local CA key; trstctl signs that CSR through
`/api/v1/ca/authorities/{id}/intermediates/csr`; and workloads continue using normal
SPIRE Workload API clients.

Attested X.509-SVID issuance is also served after a workload owner configures an enabled
trust source:

```sh
trust_source=$(
  jq -n \
    --arg name "prod-k8s" \
    --arg method "k8s_sat" \
    --arg issuer "https://kubernetes.default.svc" \
    --arg audience "trstctl" \
    --slurpfile jwks cluster-jwks.json \
    '{name: $name, method: $method, issuer: $issuer, audience: $audience, jwks: $jwks[0], enabled: true}'
)

curl -sS -X POST https://localhost:8443/api/v1/workloads/attester-trust-sources \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: k8s-trust-$(date +%s)" \
  -H "Content-Type: application/json" \
  -d "$trust_source"

body=$(
  jq -n \
    --arg method "k8s_sat" \
    --arg payload "$PROJECTED_SAT_B64" \
    --rawfile public_key workload.pub \
    '{method: $method, payload_base64: $payload, public_key_pem: $public_key, ttl_seconds: 600}'
)

curl -sS -X POST https://localhost:8443/api/v1/workloads/attested-issuance \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: k8s-web-$(date +%s)" \
  -H "Content-Type: application/json" \
  -d "$body"

printf '%s' "$body" \
  | trstctl-cli --idempotency-key k8s-web-$(date +%s) workloads attested-issuance -f -
```

The response is the certificate the workload should load, plus the verified subject
that became the SPIFFE path (for example `spiffe://example.org/ns/default/sa/web`).
Rotate trust material with
`POST /api/v1/workloads/attester-trust-sources/{id}/rotate`, revoke it with
`POST /api/v1/workloads/attester-trust-sources/{id}/revoke`, and offboard it with
`DELETE /api/v1/workloads/attester-trust-sources/{id}`; each mutation is idempotent and
recorded as an immutable trust-source event.

Approval-gated ephemeral/JIT issuance is served when `EphemeralIssuanceConfig` supplies
attestors, trust domain, signer-backed issuing CA, approval TTL, and approval threshold:

```sh
jit_body=$(
  jq -n \
    --arg request "jit-agent-7" \
    --arg method "k8s_sat" \
    --arg payload "$PROJECTED_SAT_B64" \
    --rawfile public_key workload.pub \
    '{request_id: $request, method: $method, payload_base64: $payload, public_key_pem: $public_key, ttl_seconds: 120}'
)

# Requester: verifies attestation, opens approval, enqueues notification intent.
printf '%s' "$jit_body" \
  | trstctl-cli --idempotency-key jit-agent-7-request-1 ephemeral issue -f -

# Distinct approver: records approval. The requester cannot approve their own request.
printf '{"action":"issue"}' \
  | trstctl-cli --idempotency-key jit-agent-7-approve-1 ephemeral approve jit-agent-7 -f -

# Requester: use a fresh idempotency key after approval to mint the credential.
printf '%s' "$jit_body" \
  | trstctl-cli --idempotency-key jit-agent-7-issue-1 ephemeral issue -f -
```

The first call returns `state: "awaiting_approval"` and no certificate. The approved
call returns `state: "issued"` with a signer-issued certificate whose `not_after` is
clamped by the configured TTL policy. Replaying either idempotency key returns the same
pending or issued response without opening another approval request or minting another
credential.

The AI-agent broker is also served when configured:

```sh
broker_body=$(
  jq -n \
    --arg agent "agent-7" \
    --arg method "k8s_sat" \
    --arg payload "$PROJECTED_SAT_B64" \
    --rawfile public_key agent.pub \
    '{agent_id: $agent, method: $method, payload_base64: $payload, public_key_pem: $public_key, scopes: ["mcp:graph.read", "tool:inventory.read"], ttl_seconds: 600}'
)

curl -sS -X POST https://localhost:8443/api/v1/broker/agent-identities \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: agent-7-$(date +%s)" \
  -H "Content-Type: application/json" \
  -d "$broker_body"

printf '%s' "$broker_body" \
  | trstctl-cli --idempotency-key agent-7-$(date +%s) broker agent-identities issue -f -
```

The broker response includes the issued certificate, `credential_id`,
`certificate_id`, verified attestation metadata, expiry, and the graph `node_id` for the
agent workload. Replay the same `Idempotency-Key` to get the same credential response
without minting twice.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| NHI lifecycle routes (F59) | **Served** — `/api/v1/identities`, `/transitions` |
| SPIFFE Workload API (F24) | **Served** — gRPC over a UDS (`protocols.spiffe.enabled`); `FetchX509SVID`, `FetchJWTSVID`, bundle fetches, and `ValidateJWTSVID` are wired to the signer-backed served path |
| SPIRE upstream authority | **Served and container-proven for X.509** — SPIRE loads `trstctl-spire-upstream-authority`, trstctl signs SPIRE's intermediate CA CSR through `/api/v1/ca/authorities/{id}/intermediates/csr`, and the e2e verifies a minted SVID chain to the trstctl root |
| Ephemeral issuance (F25) | **Served** — direct attested X.509-SVID mint is `POST /api/v1/workloads/attested-issuance` after a tenant trust source is enabled; approval-gated JIT mint is `POST /api/v1/ephemeral` plus `/api/v1/ephemeral/{request_id}/approvals` |
| Attestation chain (F30) | **Served** — tenant trust-source lifecycle is `/api/v1/workloads/attester-trust-sources`; the six-attester verifier gates `POST /api/v1/workloads/attested-issuance`; conformance still covers each attester |
| AI-agent broker (F61) | **Served when configured** — `POST /api/v1/broker/agent-identities` and `trstctl-cli broker agent-identities issue` verify proof, gate policy, mint a short-lived credential, and project the graph grant |

The **SPIFFE Workload API is served** (gRPC/UDS), and the attested X.509-SVID endpoint
is served once a tenant enables a matching trust source or an operator supplies a
process default. The ephemeral/JIT and broker endpoints are served when their attestors,
approval/policy controls, trust domain, and signer-backed issuing CA are configured.
Operationally: each attestation method needs public trust material (cloud roots, cluster
JWKS, TPM manufacturer roots), and short TTLs mean workloads and agents must renew —
which is the point, but plan for it.

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
  `POST /api/v1/ephemeral/{request_id}/approvals`,
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
[Policy & governance](policy-and-governance.md) (the broker's policy gate) ·
glossary: [workload](../glossary.md), [attestation](../glossary.md),
[SPIFFE/SVID](../glossary.md)

**Covers:** F24, F25, F30, F59, F61
