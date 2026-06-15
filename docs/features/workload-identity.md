# Workload identity — give software a verifiable identity, no secrets to steal

## What it is

A [workload](../glossary.md) is a running piece of software — a service, a container, a
CI job, an AI agent. Workload identity is how that software *proves what it is* to other
services, without anyone planting a long-lived password or API key inside it. trustctl
does this by combining two ideas: [attestation](../glossary.md) (cryptographic proof of
what and where a workload is) and short-lived credentials issued only to workloads that
pass attestation.

The mental model: instead of giving every employee a permanent badge they might lose,
you install a fingerprint scanner at each door. The workload doesn't carry a secret — it
*proves what it is* at the moment it needs access, and gets a pass that expires in
minutes. This page covers the [SPIFFE](../glossary.md) standard for workload identity,
trustctl's attestation chain, ephemeral issuance, lifecycle management for non-human
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

Everything here rests on attestation: before issuing anything, trustctl demands proof of
the workload's identity and verifies it. The framework is pluggable — an `Attestor`
knows how to verify one kind of proof — and trustctl ships six:

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

The verifier dispatches by method, computes a stable attestation ID inside the crypto
boundary (**AN-3**), adds an attestation node to the [credential graph](graph-query-ai.md),
and emits `attestation.verified` — or `attestation.rejected` and **nothing else** on
failure (fail-closed, **AN-2**). Every attester must pass a conformance harness that
proves it *accepts the genuine proof and rejects a forgery*. All signature/JWT/CMS
verification runs through `internal/crypto`.

*Code:* `internal/attest` (`Attestor`, `Verifier`, `Conform`) and
`internal/attest/{tpmquote,awsiid,gcpmeta,azureimds,k8ssat,githuboidc}`.

### The SPIFFE Workload API (F24) — the standard interface

[SPIFFE](../glossary.md) is the open standard for workload identity; its document is the
**SVID**, delivered as an X.509 certificate or a JWT. trustctl implements a
SPIRE-compatible Workload API server: a workload presents *selectors* (e.g.
`k8s:ns:default`, `k8s:sa:web`), the server matches them against registration entries
using set-subset semantics (you must present every selector an entry requires), and
issues the SVID. Signing goes through the crypto boundary (**AN-3**) to keys held in the
isolated signer (**AN-4**); a `NeedsRotation` helper flags an SVID for renewal once it's
half-expired (SPIRE's policy); issuance runs on a [bulkhead](../glossary.md) (**AN-7**)
and is audited (**AN-2**).

*Code:* `internal/protocols/spiffe` (`Server`, `FetchX509SVIDs`, `FetchJWTSVIDs`,
`NeedsRotation`, `WorkloadAPIServer`, `ServeWorkloadAPI`). **Status:** **served** as a
gRPC service on a Unix domain socket (`EXC-WIRE-02`, `protocols.spiffe.enabled`,
default off): a `spiffe-helper`/go-spiffe/Envoy-SDS workload dials the socket and
`FetchX509SVID` returns an SVID + trust bundle signed through the signer (AN-4). The
Workload-API gRPC/protobuf contract is vendored verbatim from go-spiffe so the wire
format is byte-identical.

### Ephemeral issuance (F25) — attestation in, short-lived cert out

The ephemeral issuer ties it together: it takes an attestation, verifies it (refusing to
sign if verification fails), mints a short-lived certificate (default TTL 15 minutes,
clamped to a per-method maximum), and **binds** the attestation to the credential in the
graph and audit trail. Every request needs an idempotency key (**AN-5**), so a retried
request returns the same credential rather than minting a second.

*Code:* `internal/ephemeral` (`Issuer`, `TTLPolicy`). **Status:** library-complete,
tested; not yet exposed as a served endpoint.

### Non-human identity lifecycle (F59)

Beyond a single credential, the *identity itself* has a lifecycle: created, scoped,
rotated, disabled, retired (a terminal state). trustctl models this as a guarded state
machine — every transition goes through one path that enforces the legal moves, updates
the identity's node in the credential graph, and emits a lifecycle event (`nhi.created`,
`nhi.rotated`, `nhi.disabled`, `nhi.expired`, **AN-2**).

*Code:* `internal/nhi` (`Manager`, `Create`, `Scope`, `Rotate`, `Disable`, `Expire`).
**Status:** the served REST routes `POST /api/v1/identities` and
`POST /api/v1/identities/{id}/transitions` (both idempotent, **AN-5**) are wired through
the orchestrator; the standalone manager is otherwise library-level.

### The AI-agent identity broker (F61)

AI agents are a sharp case: they appear quickly, act with real privileges, and chain
tools together, so an over-scoped or un-revocable agent credential is dangerous. The
broker is a dedicated issuance surface that (1) evaluates a [policy](policy-and-governance.md)
decision *before* issuing — a deny records `agent.identity.refused` and signs nothing;
(2) issues an attested, short-lived credential via the ephemeral issuer; (3) records the
agent and its credential in the graph so you can ask **blast radius** ("everything this
agent can reach") *before* trusting it; and (4) supports **one-call revocation** of every
credential an agent owns.

*Code:* `internal/broker` (`Broker`, `Issue`, `Revoke`, `BlastRadius`). **Status:**
library-complete and tested; not yet wired into a served endpoint.

## Use it

The non-human-identity lifecycle is served today:

```sh
# create a managed non-human identity (idempotent)
trustctl-cli identities create -f service-account.json

# transition its state (e.g. disable on decommission)
trustctl-cli identities transition <id> -f '{"to":"disabled","reason":"decommission"}'
```

Those map to `POST /api/v1/identities` and `POST /api/v1/identities/{id}/transitions`
(both require an `Idempotency-Key`). The **SPIFFE Workload API is now served** over a
UDS (`protocols.spiffe.enabled`; a workload `FetchX509SVID`s an SVID signed through
the signer). The ephemeral, attestation, and broker flows are exercised today through
their Go APIs and tests — for example, verifying an AWS instance and issuing a
15-minute SVID — pending their own served surfaces noted below.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| NHI lifecycle routes (F59) | **Served** — `/api/v1/identities`, `/transitions` |
| SPIFFE Workload API (F24) | **Served** — gRPC over a UDS (`protocols.spiffe.enabled`, `EXC-WIRE-02`); `FetchX509SVID` signs through the signer |
| Ephemeral issuance (F25) | **Library-complete**, tested; no served endpoint yet |
| Attestation chain (F30) | **Library-complete**, tested (6 attesters, conformance) |
| AI-agent broker (F61) | **Library-complete**, tested; no served endpoint yet |

The **SPIFFE Workload API is served** (gRPC/UDS); the attestation, ephemeral, and
broker components are built and tested behind their interfaces, with their own served
surfaces tracked in [Current limitations](../limitations.md). Operationally: each
attestation method needs its trust source configured (cloud roots, cluster JWKS, TPM
manufacturer roots), and short TTLs mean workloads must renew — which is the point, but
plan for it.

## Reference

- **Served routes:** `POST /api/v1/identities`,
  `POST /api/v1/identities/{id}/transitions`.
- **Attestation methods:** `tpm`, `aws_iid`, `gcp_iit`, `azure_imds`, `k8s_sat`,
  `github_oidc`.
- **SPIFFE:** `FetchX509SVIDs`, `FetchJWTSVIDs`; selector match is set-subset.
- **Events:** `attestation.verified/rejected/bound`, `ephemeral.issued`,
  `spiffe.svid.issued`, `nhi.*`, `agent.identity.{issued,refused,revoked}`.

## See also

[SSH](ssh.md) (attestation-gated SSH certs use the same chain) ·
[Issuance & certificate authorities](issuance-and-cas.md) ·
[Graph, query & AI](graph-query-ai.md) (blast radius) ·
[Policy & governance](policy-and-governance.md) (the broker's policy gate) ·
glossary: [workload](../glossary.md), [attestation](../glossary.md),
[SPIFFE/SVID](../glossary.md)

**Covers:** F24, F25, F30, F59, F61
