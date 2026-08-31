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
expired, not yet valid, or its trust source is revoked before execution. Missing trust produces
a visible blocker; it never falls back to trusting the browser.

Kubernetes, GitHub and GCP JWT proofs must contain an integer-second `exp`
(expiry). A signed proof is refused at or after that deadline. If `nbf` (not
before) or `iat` (issued at) is present, it must be an integer-second timestamp
that is not in the future. Missing expiry, null values and malformed times are
refused. There is no implicit clock-skew allowance: keep the issuer and trstctl
clocks synchronized. Legacy non-expiring Kubernetes tokens are not supported by
this projected-token proof path. These are proof checks, not certificate renewal.

#### Exact identity names and upgrade safety

A SPIFFE name is an authorization input, not a display label. trstctl now requires
canonical lowercase `spiffe://` and trust-domain text, preserves path case, and
rejects ports, queries, fragments, percent escapes and empty or relative path
segments. Its limits are 255 bytes for the trust domain and 2,048 bytes for the
complete identity. The signer and certificate identity reader use the same grammar;
the reader also refuses a certificate with more than one URI SAN. This is strict
canonical-input behavior, not automatic normalization of URI aliases. See the
[SPIFFE identity specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md).

Automatic identities start with `/_trstctl/v1/tenant/<tenant UUID>/`. The tenant
comes from the authenticated server context, never from a proof's tenant claim.
That matters even when two tenants use the same CA: a separate service must be able
to distinguish their signed identity names, not just their database records.

After that prefix, the issuance route and verified method are explicit:

| Route | Path after the tenant prefix |
| --- | --- |
| Attested issuance | `attested/method/<method>/subject/<mapped subject>` |
| Approval-gated ephemeral issuance | `ephemeral/method/<method>/subject/<mapped subject>` |
| Broker issuance | `broker/agent/<authorized agent ID>/method/<method>/subject/<mapped subject>` |

For example, a Kubernetes subject `ns/qa/sa/web` in tenant
`11111111-1111-4111-8111-111111111111` receives:

```text
spiffe://example.org/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/attested/method/k8s_sat/subject/ns/qa/sa/web
```

Valid subject path segments stay readable. Punctuation outside the SPIFFE alphabet
is encoded as `trstctl-hex-` followed by lowercase hexadecimal bytes: `a:b` becomes
`trstctl-hex-613a62`. Literal segments already starting with `trstctl-hex-` are encoded
too, preventing encoded-looking names from impersonating another subject. Empty,
`.` and `..` segments are rejected rather than stripped or cleaned. Agent IDs and
methods are whole segments, so a slash in one cannot escape into another field.

Ordinary CSR profiles cannot mint the reserved `/_trstctl` namespace, even with a
permissive URI allow-list. Manual SPIFFE registration entries cannot claim it
either. Those paths continue to support nonreserved identities. The reservation
does not silently change the issuer, replace an external CA or rotate a trust root.
The profile's custom-extension seam also refuses core identity and policy OIDs;
an extra SAN extension cannot replace the identities checked before signing.
Non-core extensions remain supported.

Ephemeral approval checks the exact signed URI, public key, approved CA and
lifetime, then checks that the URI's tenant and method match the retained event.
Its versioned subject decoder reverses only canonical mappings: it rejects unknown
versions, a different issuance route and alternate spellings. Historical unreserved
subjects remain literal. This check preserves old command meaning; it does not
turn an old approval into permission for a new tenant-bound credential.

The verified original subject stays unchanged in responses, audit and durable
history; encoding is not encryption. Never put secrets in an identity subject.
These names do not add permissions or replace tenant-scoped attestor trust and
broker policy. Operators must still allocate identities deliberately across multiple
trusted proof sources within one tenant and method; this is not automatic
per-cluster identity policy. Manually registered Workload API entries use their own
nonreserved namespace and operator-managed authorization.

**Upgrading an exact-name consumer:** earlier broker certificates could contain
`ns%2Fqa%2Fsa%2Fweb`; standard SPIFFE clients reject that name. Older automatic
identities also omitted tenant scope. All new automatic names use the tenant-bound
prefix above; old certificates do not become tenant-isolated by upgrading software.
Inspect existing pins before rollout. Issue a new credential with a new issuance
idempotency key, verify its chain and exact URI using the intended consumer, and
replace the old exact-name pin deliberately. Do not wildcard the path, disable
verification or alias the old identity automatically. Existing history and old
certificate bytes are not rewritten. An old completed command can only return its
original credential, never a renamed one; current authorization or a changed
approval binding can refuse recovery. Approval-gated cutovers require a new exact
approval for the new tenant-bound URI. Rotate or revoke the old certificate and
prove the new connection before retiring the old deployment. No automatic
relying-party policy migration is performed.

**A reused CA needs a separate migration proof.** An older, permissive issuance
path may already have signed a URI that looks like the newly reserved namespace.
Reserving names now does not invalidate those older signatures. Before accepting
the new names under an existing CA, inspect its prior issuance and registration
inventory for conflicting claims and retire them, then prove that every intended
consumer enforces the revocation. If that history or revocation enforcement cannot
be established, use an explicitly approved new issuing authority and trust-policy
cutover. Do not silently rotate the CA or call an in-place upgrade isolated based
only on the new naming tests. Fresh-stack qualification does not prove this upgrade
boundary.

The lifetime uses the server default for a nonpositive value and is capped at the
server maximum before conversion to a Go duration, including very large integer
inputs. The console accepts nonnegative whole seconds and shows any adjustment.
Changing an input invalidates the previous review. Within the open workflow, an
unchanged issuance retry keeps the same `Idempotency-Key`; a lost response must not
mint a second certificate. Inputs and the retry key are not persisted across a
page reload. If you lose the page, inspect inventory and audit before starting a
new issuance.

The outcome table counts unsuccessful attempts retained in the current browser
session, not attestation refusals across the server. A signer or database outage
can happen after proof verification. A server error keeps the unchanged retry
available; consult **Change history** for the actual verification and issuance
events. The registered-identity count covers workload and SSH identity records,
not the number of certificates issued.

Broker and attested REST issuance also complete the issuing CA's initial
certificate revocation list (CRL) before returning success. A CRL is a signed
list of certificate serial numbers that should no longer be trusted. The list
starts empty and is published through the existing event-sourced revocation
service; an anonymous CRL download never triggers a signature or state change.
If publication fails after the leaf certificate was recorded, the API returns a
server error. Restore the dependency and retry the identical request with the
same `Idempotency-Key`: current proof and permission are checked again, the
recorded certificate is recovered, and publication is retried without signing
another leaf. Inspect inventory if proof expires before recovery; do not disable
verification or assume the failed response means nothing was recorded.

A published CRL does not force every consumer to check it. The receiving service
must enforce certificate-chain trust, workload identity, validity, revocation
and its own authorization policy. Prove those decisions with fresh connections
on the actual receiving platform before claiming end-to-end revocation.

An X.509-SVID can have an empty X.509 subject: its SPIFFE URI in the Subject
Alternative Name (SAN) identifies the workload. Inventory uses that URI rather
than showing a blank name, and short deadlines use minutes or hours. Certificate
details include timestamped validity. **Replace with fresh workload proof** opens
a blank attestation workflow; it never reuses old proof or submits automatically.

New attested issuances record requester key origin in the immutable certificate
event and its inventory projection. trstctl received only the public key. The
private key's storage and exportability remain unrecorded because this path has
no evidence for them. Existing unrecorded custody is not backfilled by assumption.

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
trusting it. The source now includes tenant-wide durable broker history and guided
preview, issuance and retry. Installed-product qualification remains pending as
described below. Revocation uses the shared certificate control plane; there is no
separate broker-specific one-call revocation action.

Served when the agent broker is configured, at `POST /api/v1/broker/agent-identities`:
the operator supplies the trust domain, Rego policy module, and signer-backed
issuing CA. Public attestation trust is configured for each tenant through
`/api/v1/workloads/attester-trust-sources`; normal configuration does not require
in-process attestors. Enabling the broker without tenant trust is allowed, but
issuance remains blocked until matching enabled trust exists. A request carries the agent id, attestation method, proof
payload, public key, requested scopes, and optional TTL; trstctl verifies the proof,
evaluates policy before signing, mints a short-lived X.509-SVID through the isolated
signer, records `certificate.recorded`, and projects the agent-to-credential edge into
the graph. Denies emit `agent.identity.refused` and return no credential.

#### Broker review and safety boundaries

`POST /api/v1/broker/agent-identities/preview` and
`trstctl-cli broker agent-identities preview -f broker-request.json` review the same
request before issuance. Both require `certs:issue`; the read-only preview does
not send or reserve an `Idempotency-Key`. It returns the agent, scopes, trust
domain, enabled methods, effective lifetime, safe input digests, and recovery
steps. It never calls policy, the proof verifier, the licensed task gate, or the
signer, and does not append events or write mutation state.

**Ready means configured, not authorized.** Issuance still verifies fresh proof,
checks current tenant trust and scope policy, and refuses invalid, expired or
not-yet-valid proof and revoked trust. JWT proof uses the same required expiry
and optional start/issued-at checks described above. A supplied
`task_envelope_base64` requires the licensed task gate;
a deployment without that gate refuses it instead of silently dropping its task
restriction. Preview exposes this as a blocker without consuming task proof.
Requested scopes are issuance-policy inputs: the certificate proves identity,
while each receiving service must enforce its own access policy.

The default lifetime is ten minutes and the default maximum is one hour unless
the operator configures tighter or different bounds. A nonpositive request uses
the configured default; an over-maximum request is capped before integer-to-duration
conversion. The effective lifetime reaches the actual signer. Review the returned
deadline, not only the requested number. Input must contain exactly one valid,
header-free PKIX `PUBLIC KEY` PEM block; duplicate keys, leading or trailing junk,
and private-key blocks are rejected.

New broker issuances record requester key origin through `certificate.recorded`.
The workload supplied only a public key, so storage and exportability remain
unrecorded. Existing custody records are not backfilled by guessing. The API keeps
encoded and decoded proof/task bytes in wipeable buffers and clears them on
success, refusal, and partial decoding errors. Request files and browser inputs
still need protection: never log them or commit them to source control.

#### Broker retries after cache retention

New issuances keep their original agent ID, verified subject and method, scope
list, original owner ID, requested/effective lifetime, and optional verified task
digest in the same `certificate.recorded` event as the public certificate. They
remain one certificate in the shared inventory. Rediscovery may update where that
certificate was observed or who owns it now; it cannot rewrite these issuance facts.
Raw attestation proof, task-envelope contents, and private keys are not added to
this record.

The event also keeps a one-way fingerprint of the authenticated requester and
command. After the short-lived HTTP result cache expires, a retry must still
match that original command. A changed requester, agent, method, scopes, lifetime,
public key, proof, or task envelope returns `409`, not a relabeled old certificate.
The matching retry rechecks current trust, policy, proof, and any task gate before
returning the original certificate; it does not sign again. Changed verification
results are refused. A missing database projection can be recovered from the event.

Legacy certificates without these facts, or records whose facts were removed by
privacy policy, cannot safely be reconstructed from a new request. Once their
cached response is gone, recovery refuses them. Inspect the existing certificate
and its expiry before deciding whether a genuinely new issuance is needed. Never
change recovery keys repeatedly just to make an uncertain operation appear green.
Subject export/erasure includes broker metadata, retention clears it, and snapshot
restore/event replay preserve the recorded state. An old snapshot without the new
fields must replay history rather than claim that history is complete.

#### Durable broker history and the guided console

`GET /api/v1/broker/agent-identities` and `GET /api/v1/broker/agent-identities/{id}`
read the shared certificate inventory with `certs:read`. They remain available
when new broker issuance is disabled. These reads do not consume proof, sign,
revoke, or reserve recovery keys. They never return certificate bodies, raw proof,
task contents, or internal command bindings.

```sh
trstctl-cli broker agent-identities list --limit 20 --state expired
trstctl-cli broker agent-identities list --q agent-7 --method k8s_sat
trstctl-cli broker agent-identities get <certificate_id>
```

Pages are newest first, with an opaque `next_cursor`; pass it as `--cursor` to
continue. Limits are 1–100, search is literal and at most 200 characters, and a
method filter matches the recorded original method, not a later discovery label.
The server calculates one state vocabulary for display and filtering: `valid`,
`not_yet_valid`, `expired`, `revoked`, `superseded`, or `unknown`. `NotAfter` is an
exclusive deadline: exactly at that time the certificate is expired. Revoked and
replaced records keep those states even after expiry. `valid` means the projected
lifecycle is active and the validity window contains the server's check time;
it does not grant access at a receiving service.

Every response gives `generated_at` and coarse `projection_state`: `current`,
`catching_up`, `blocked`, or `unknown`. A projection is the database view built
from immutable events. A lagging or blocked view may not yet contain newer
revocations. Missing issuance metadata says `unavailable`; it is not a claim that
the certificate never had an owner or scopes. Failed/refused attempts belong in
the audit trail, not this list of issued certificates.

On **Workloads & Machines**, the broker section reads this durable history before
opening a new request. **Request agent identity** leads through input, server
preview, explicit issuance, and durable readback. The form includes the optional
task envelope rather than silently omitting it. After an uncertain response,
**Retry exact issuance** preserves the body and `Idempotency-Key`; editing is
locked. Starting a different request requires acknowledging that a certificate
may already exist. Clearing the form does not cancel or revoke an issuance.
Successful issuance clears proof and task input; the public certificate is only
copied on an explicit action. A page reload loses retry inputs, so inspect the
inventory and audit trail before starting again. The shared revocation center is
linked; a broker-specific one-call revoke is not claimed.

The source now contains this API/CLI/console workflow. Release qualification still
requires its fresh-image, browser, restart and negative-security receipts; focused
component tests alone do not complete the F61 vertical slice. The new Spanish and
German operator copy is machine-authored and requires human review before release.

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

The response is the certificate the workload should load, plus the original verified
subject. The SPIFFE URI includes the authenticated tenant, issuance route and method
before that mapped subject, as described above. Trust
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
