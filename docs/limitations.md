# Current limitations & what's not yet served

certctl is pre-1.0 and under active hardening. This page is the honest companion
to the capability list: it states plainly **what the running binary serves today**
versus **what is built and tested as library code but not yet wired into the
served product**, and which surfaces are explicitly Phase 2. Nothing here is
feature-gated — "open edition" and "commercial" run the same code; these are
maturity boundaries, not paywalls.

If a capability matters to your evaluation, check this page before relying on it.

## Served by the running binary today

`cmd/certctl` assembles and serves a control plane: the event log, projections,
orchestrator, and REST API, with the signing service supervised as a separate
out-of-process child (AN-4). What you can do end to end against the running binary:

- **Inventory and lifecycle** for owners, issuers, identities, and certificates —
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- **Real X.509 issuance**: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. This is exercised end to end in CI.
- **Authentication and RBAC** (API tokens and OIDC SSO sessions), **multi-tenancy**
  with PostgreSQL row-level security, and a **tamper-evident audit chain**.
- **Transport security** (TLS, internal or file-based), **idempotency** and the
  **outbox**, **observability** (`/metrics`, `/readyz`, W3C trace headers),
  **bulkheads + per-tenant rate limiting**, **backup/restore + disaster recovery**,
  and **safe schema migrations**.

The web UI and the `certctl-cli` drive this same served surface.

## Built and tested, but not yet served by the binary

These subsystems exist as **library code with real unit/integration/conformance
tests**, but are **not yet wired into the served API of the running binary**. They
are usable from Go today; "served, authenticated, end-to-end in the binary" is the
remaining integration work.

- **CA integrations** (9 under `internal/ca/`) and the **private CA hierarchy**
  (root/intermediate, cross-sign, rotation, and the m-of-n key ceremony — see the
  [key-ceremony runbook](runbooks/key-ceremony.md)).
- **Deployment connectors** (~10–11 under `internal/connector/`: nginx, Apache,
  IIS, HAProxy, F5, AWS ACM, Azure Key Vault, GCP Certificate Manager, NetScaler,
  Java keystore, plus Kubernetes). The lifecycle's `connector.deploy` step is
  acknowledged by the outbox but not yet routed to these in the served path.
- **Discovery**: network/filesystem scans, SSH key & trust inventory, agentless
  cloud-certificate enumeration, the **CBOM** with post-quantum posture, and
  **Certificate Transparency** monitoring.
- **Posture**: the **credential graph** (reachability, blast radius), **composite
  risk scoring**, and **drift detection**.

## Not WASM-sandboxed yet

CA and connector integrations are in-process Go packages today. The WASM plugin
host (wazero) and its capability model exist, but the shipped integrations are
**not yet sandboxed through it**. Treat them as trusted in-process code for now.

## Protocols

- **ACME** server with **ARI** is present; **only HTTP-01** is validated today.
- **EST**, **SCEP**, **SPIFFE** (Workload API), and the **SSH CA** issuance servers
  are Phase 2 — placeholders in `internal/protocols/`, correctly not served.

## CA key custody

The assembled issuing CA's key is now **persisted, sealed at rest** in the
signer's key store (R3.2): a signer restart **preserves** the CA instead of
silently rotating it, and the key survives across restarts. **HSM/KMS-backed
custody** (rather than a local sealed key file) and a served, m-of-n break-glass
flow are still future work — the key-encryption key is a local file by default.
See the [key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md).

## How to read the roadmap against this

The [README capability table](https://github.com/imfeelingtheagi/certctl#capabilities)
describes what is **built and tested**; this page tells you what is **served by the
binary today**. When the two differ, this page is the authority for what you can
rely on at runtime.
