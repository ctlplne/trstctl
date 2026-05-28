# CLAUDE.md — certctl (Unified Non-Human Identity Platform)

This file is the standing contract for any agent working in this repository. Read it
in full before touching code on any task. The rules below are not style preferences;
several of them are enforced by a custom CI linter and a PR cannot merge while they
are violated. When a sprint card and this file disagree, this file wins on
architecture and the sprint card wins on scope.

---

## 1. What we are building

certctl is a self-hosted, source-available control plane for every credential that is
not a human: X.509 certificates, SSH host and user certificates, secrets, API keys,
tokens, and SPIFFE workload identities. It discovers, issues, deploys, rotates,
revokes, and retires those credentials across hybrid infrastructure. The full
product definition lives in the PRD; this file captures only what an agent needs on
every task. There is no feature gating: the open-source edition is fully functional,
and revenue comes from commercial/enterprise licensing, support, and a managed
offering.

---

## 2. The non-negotiables (AN-1 through AN-8)

These are designed in from the first commit because retrofitting them is either
impossible or ruinously expensive. Do not defer them, do not stub them "for now"
unless a sprint explicitly says so, and never work around them.

**AN-1 — Multi-tenancy at the storage layer.** Every table carries a `tenant_id`.
Every query filters on it. Isolation is enforced by PostgreSQL row-level security,
not by application code. Single-tenant deployments simply run with one tenant.
PostgreSQL is the datastore in every deployment mode; there is no SQLite path.

**AN-2 — Event-sourced state.** State changes are emitted as immutable events to an
append-only log (NATS JetStream, embedded and file-backed for single-node, external
cluster for production). The event log is the source of truth. Both the relational
read state and the audit trail are *projections* of the event stream. Never write
derived/read tables directly to represent a state change — emit an event and let a
projection build the read model.

**AN-3 — Cryptography behind one boundary.** All cryptographic operations route
through `internal/crypto`, which defines backend-agnostic interfaces. No `crypto/x509`,
`crypto/rsa`, `crypto/ecdsa`, or related imports exist anywhere else. Adding an
algorithm or an HSM is one package change. Both X.509 and SSH signing route through
this boundary; the SSH CA is another implementation behind it, not a parallel stack.

**AN-4 — The signing service is a separate, sacred process.** Private-key operations
live in their own process with its own address space, reached over gRPC on a Unix
domain socket (or mTLS across nodes). It has no HTTP server, no SQL driver, no
third-party logging, and a minimal, fully-audited transport dependency. It is never
run in-process with the control plane — in single-binary mode it is a separate child
process. If it is compromised, the company is over; treat every change to it
accordingly.

**AN-5 — Idempotency on every mutation.** Every state-changing endpoint accepts an
`Idempotency-Key`. The orchestrator records the key with the operation; replays
return the original result rather than executing again. This is what stops a retried
issuance from minting two certificates.

**AN-6 — Outbox for every external call.** Any call out (upstream CA, connector,
webhook, notification) writes its intent to an `outbox` table in the *same database
transaction* as the state change. A separate worker performs the call. This gives
at-least-once delivery; idempotency makes the effect exactly-once.

**AN-7 — Bulkheads and backpressure.** Each subsystem has its own bounded worker
pool and queue. Full queues reject fast with structured errors. One slow connector
must never starve another subsystem, and a discovery scan must never exhaust the
pool the API depends on.

**AN-8 — Memory safety for key material.** Secret material lives in `[]byte`, never
`string` (Go's GC can copy strings freely). Buffers are `mlock`'d, marked
`MADV_DONTDUMP`, and explicitly zeroed when done (`memguard` or a manual zero loop
plus `runtime.KeepAlive`). A key should live in RAM for milliseconds, not
indefinitely.

---

## 3. What the linter enforces (CI-blocking)

The custom `go/analysis` linter in `tools/certctllint` fails the build on any of:

- a `crypto/*` import outside `internal/crypto` (AN-3);
- a repository query that does not filter on `tenant_id` (AN-1);
- a `string`-typed parameter or field in a package tagged as key-handling (AN-8);
- a mutating API handler that does not accept and honor an idempotency key (AN-5).

If you believe a violation is a false positive, fix the linter rule in its own change
with a test fixture — do not add a blanket ignore. `make lint` must be green before
you open a PR. `make test` and the full CI pipeline must be green too.

---

## 4. Repository map

```
cmd/
  certctl/            # control-plane binary (embeds signing service as child proc in single-node)
  certctl-signer/     # signing-service binary (AN-4) — minimal deps, no HTTP, no SQL
  certctl-agent/      # in-network agent
internal/
  crypto/           # AN-3 boundary; the ONLY package importing crypto/*
  signing/          # signing-service logic and its gRPC/UDS protocol
  events/           # AN-2 event log (NATS JetStream), envelopes, append/replay
  projections/      # read-model builders from the event stream
  store/            # PostgreSQL repositories, migrations, RLS policies (AN-1)
  orchestrator/     # lifecycle state machine, idempotency (AN-5), outbox dispatch (AN-6)
  api/              # REST (OpenAPI 3.1) + gRPC for agents; problem+json errors
  policy/           # embedded OPA/Rego (AN-7-bulkheaded)
  protocols/        # acme/, est/, scep/, spiffe/, ssh/ issuance servers
  pluginhost/       # WASM sandbox (wazero/extism), capability grants (F20)
  agent/            # agent workers: discovery, deployment, ssh trust, drift
  graph/            # credential graph (F21)
plugins/
  ca/               # CA plugins (WASM) — one dir per CA
  connectors/       # deployment connectors (WASM) — one dir per target
tools/
  certctllint/        # the architecture linter
web/                # React 18 + Vite + shadcn/ui
deploy/             # Docker Compose, Helm chart, K8s Operator
docs/               # documentation site + getting-started
```

Add a package-level `CLAUDE.md` (hub-and-spoke) when a package grows its own
conventions — keep this root file canonical and let leaf files cover specifics.

---

## 5. Stack and versions

Go 1.22+. PostgreSQL 14+ (bundled single-node for eval; external for production; no
SQLite). NATS JetStream 2.10+ (embedded file-backed for single-node; external cluster
for production). wazero for the WASM plugin host (in-process). React 18 + Vite +
shadcn/ui for the web UI. OPA embedded for policy. S3-compatible object storage is
optional and used only for long-term audit archive. Transport is gRPC over UDS or
mTLS; rate limiting is PostgreSQL-backed — do not introduce Redis or any other
datastore.

---

## 6. Testing discipline

Write tests before or alongside implementation, never after as an afterthought. In
particular:

- **Property-based tests** for the policy engine and for every protocol parser
  (ACME, EST, SCEP, X.509, SSH).
- **Differential tests** against reference implementations: Boulder for ACME, libest
  for EST, a known-good SPIFFE implementation for the Workload API.
- **Fuzz tests** on every parser that touches untrusted input, wired for OSS-Fuzz.
- **Conformance suites** published so forks and plugins can self-validate.
- Integration tests run against real PostgreSQL and real (embedded) NATS, not mocks,
  for anything touching the spine.

Coverage is a signal, not a target; prefer meaningful tests over coverage theatre.

---

## 7. How to work a sprint

Each task names a sprint by its ID (for example, S0.1). Find that card in the sprint
backlog (`'/Users/shankar/Desktop/certctl cowork/certctl-Sprint-Plan.md'`); the card is self-contained. Stay inside its scope.

1. Read the sprint card and this file. Restate, in your own words, what the sprint
   delivers and what it explicitly excludes.
2. Confirm the card's dependencies are already merged. If they are not, stop and say
   so rather than building on absent foundations.
3. Write the failing tests that encode the card's acceptance criteria first.
4. Implement the smallest change that makes them pass without violating the
   non-negotiables.
5. Run `make lint test` and the full pipeline. Both must be green, including the
   architecture linter.
6. Update the relevant docs and, if the package grew conventions, its `CLAUDE.md`.
7. Open one focused PR scoped to exactly this sprint. Do not bundle unrelated
   changes, and do not expand scope because something adjacent looks easy — note it
   for a future sprint instead.

---

## 8. Hard "do nots"

Do not import `crypto/*` outside `internal/crypto`. Do not put secret material in a
`string`. Do not write a query without a tenant filter. Do not mutate read tables to
represent state changes (emit an event). Do not give the signing service an HTTP
server, a SQL driver, or a heavy dependency. Do not make an external call outside the
outbox. Do not add a datastore (no Redis). Do not weaken `sshd`/`authorized_keys`
trust without explicit confirmation and rollback. Do not expand a sprint beyond its
card. Do not merge with a red linter or red CI.

---

## 9. Definition of done (global)

A sprint is done when its acceptance criteria are met and tested, `make lint test`
and CI are green, the architecture linter passes, public surfaces are documented,
the change is scoped to one PR, and anything deferred is written down as a follow-up
rather than left implicit.
