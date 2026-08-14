# Signing service — threat model and protocol design

- **Status:** Reviewed — accepted as the design of record.
- **Implements (design):** isolated signer process, building on the single crypto
  boundary and wipeable secret-memory buffers.
- **Drives:** the signer implementation; revisited by the HSM/KMS-backend and
  break-glass work.

> This document exists because the signing service is the one component whose
> compromise ends the company: threat-modeled and specified before a line of the
> signer is implemented.

---

## 1. Context and stakes

The signing service holds and uses private keys: the X.509 CA keys, the SSH CA
key, and workload/issuance keys. Whoever controls these keys can mint trusted
certificates and impersonate any identity in the customer's fleet — and there is
no recovery from undetected key compromise; every credential the platform ever
issued becomes suspect.

trstctl therefore makes the signer a separate process with its own address
space, minimal attack surface, and no incidental capabilities (no HTTP
server, no database, no third-party logging) — the CA keys never live in the
API process. This document defines that boundary, the protocol to reach it,
memory-safety obligations, the dependency budget, and the fuzzing plan.

## 2. Goals and non-goals

**Goals**

- A process/trust boundary that contains a control-plane compromise: code
  execution there must not yield the private keys.
- A precise, minimal, typed protocol, implementable directly.
- Memory-safety guarantees for key material at both the buffer and process
  level.
- An explicit, auditable dependency budget for the signer binary.

**Non-goals**

- No implementation beyond the protocol stub (`signer.proto`); the server,
  client, and child-process supervision land in the signer implementation.
- HSM/KMS backends, the SSH CA, PQC, ephemeral issuance, and break-glass/offline
  ceremonies are out of scope, referenced only where they constrain the design.
- Business authorization (who may request a signature, under what policy) is
  the control plane's job (F28 policy, F30 attestation, sensitive-operation
  approvals): the signer protects the key, not business intent. This split is
  load-bearing and is revisited in §4.5.

## 3. Process boundary

- **Separate process.** The signer is `cmd/trstctl-signer`, a distinct binary
  with its own address space, never run in-process with the control plane.
- **Single-binary mode.** The control plane launches the signer as a child
  process over a Unix domain socket (UDS). The child inherits no secrets via
  argv/env (socket path and config are passed explicitly); the parent
  supervises its lifecycle (see below).
- **Multi-node mode.** Across hosts the signer is reached over mTLS (TLS 1.3,
  AEAD-only suites enforced at build time); UDS is the default path, mTLS the
  cross-node escape hatch.
- **No ambient capabilities.** The signer runs as a dedicated, unprivileged
  user with no shell, no `exec`, no outbound network beyond its single
  listener, no HTTP server, no SQL driver (see §7). Process hardening
  (seccomp profile, `PR_SET_DUMPABLE`, `RLIMIT_CORE=0`) is covered in §6.
- **No silent non-Linux downgrade.** The signer refuses to start where it
  can't get process hardening, UDS peer-UID binding, or locked non-dumpable
  memory, unless given the explicit `--allow-insecure-dev-nonlinux` /
  `TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX` override.
- **Lifecycle.** Start → bind socket (0700 dir, 0600 socket) → handshake/peer
  check → serve → drain (refuse new work, finish in-flight) → zeroize all key
  buffers → exit. The control plane detects a crash via the connection and
  `Health`, restarts the child; in-flight requests fail `UNAVAILABLE` and
  retry (safe, §5.5).

## 4. Threat model

### 4.1 Assets

Private keys in RAM (CA keys, issuance keys), the signing capability itself,
and key metadata (handles, algorithms). Public keys and signatures are not
secret.

### 4.2 Trust boundaries

1. **Control plane ↔ signer** — the primary boundary, crossed by the protocol
   in §5; assume both fail independently.
2. **Signer ↔ operating system** — the signer trusts the kernel, defending
   against other processes/users on the same host (memory disclosure).
3. **Signer ↔ hardware backend** — a future boundary (HSM/KMS) moving keys out
   of process memory entirely.

### 4.3 Assumptions

- The kernel and hardware are trusted (until an HSM narrows this further).
- The control plane may be compromised independently of the signer: an
  attacker may get code execution in one without the other.
- Build and supply chain are governed by the dependency budget (§7) and
  reproducible builds.

### 4.4 Adversaries and mitigations (STRIDE)

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | A rogue local process connects to the signer's socket and asks it to sign. | UDS peer auth via `SO_PEERCRED` verifies the connecting process's uid matches the control-plane uid; cross-node uses mTLS with pinned client certs. Socket: `0700` directory, `0600` socket. |
| **Tampering** | Request/response altered in transit, or malformed requests exploit the parser. | UDS is a local kernel channel (no on-wire tampering); mTLS gives integrity across nodes. Requests are strictly validated; the decode/validation path is fuzzed (§8), with size and field bounds enforced (§5.4). |
| **Repudiation** | "I never asked for that signature." | The control plane records every signing request/response in the event log (the signer isn't the system of record); the signer emits only non-secret operational logs. |
| **Information disclosure** | Key bytes leak via swap, core dump, `/proc/<pid>/mem`, ptrace, logs, or error strings. | Keys live only in locked, wipeable secret buffers (mlock + `MADV_DONTDUMP` + zeroize); process-level `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, optional `mlockall`. No key bytes are ever logged; errors carry no secret material (§6). |
| **Denial of service** | A flood of expensive sign/generate requests starves the signer. | Bounded worker pool and request queue (per-subsystem bulkheads), per-RPC deadlines, max in-flight, max message size; coarse abuse control and policy gating happen upstream. |
| **Elevation of privilege** | Compromised signer escalates on the host. | Dedicated unprivileged user, no shell/`exec`, minimal syscalls (seccomp), single socket listener, no outbound network. |

### 4.5 The key-abuse threat (explicitly in scope to *bound*)

A compromised control plane is, by construction, authorized to ask the signer
to sign — it cannot distinguish a legitimate issuance from an attacker driving
an already-trusted control plane. This residual risk is not the signer's to
fully mitigate; defense in depth lives upstream and around it:

- Policy (F28) and attestation gating (F30) at the control plane decide *whether*
  a signature is allowed.
- Dual-control/JIT approvals for sensitive key classes.
- Rate limiting, anomaly detection, and the event-sourced audit trail.
- Per-key constraints the signer *can* enforce cheaply: a key may be created
  with an allowed-algorithm set and usage flags, and the signer refuses
  operations outside them. **Implemented:** `GenerateKey` accepts
  `allowed_purposes` (and optional `allowed_hashes`); `Sign` carries the
  asserted `purpose`; a mismatch fails with `FAILED_PRECONDITION`. Constraints
  are sealed with the key and survive a restart, so a caller holding the
  well-known `issuing-ca` handle (bound to `CA_SIGN`) still cannot coerce it
  into signing outside that purpose.
- **Per-Sign dual-control for crown-jewel keys**
  (**Implemented**): purpose constraints bound *which key class* a caller may
  use, but a digest-blind `Sign` still let a socket-reaching caller have a
  `CA_SIGN` key sign `sha256(<arbitrary attacker TBS>)`. A key may now be
  created dual-control: the signer refuses every `Sign` against it without a
  valid authorization token — an HMAC over the exact signing tuple (handle,
  purpose, hash, padding, digest) minted by an approval authority holding a
  secret the on-socket caller does not. The signer holds verifier material;
  the control plane gets only the per-intent token, from
  `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` (or the explicitly eval-only co-resident
  path). The token commits to one specific digest, cannot be replayed onto
  different bytes, and the approver secret is never exposed on the socket —
  so a control-plane/socket compromise can no longer coerce a dual-control
  key into forging arbitrary trust. The token travels as gRPC metadata (wire
  proto frozen); the flag is sealed with the key and re-enforced across
  restarts; the verifier lives behind the single crypto boundary in mlock'd,
  wipeable memory. A signer with no verifier, or a control plane with no
  independent token provider, fails closed.

What the signer guarantees is narrower and absolute: the private key bytes
never leave the process, even under full control-plane compromise. A
dual-control key additionally will not sign without independent authorization
bound to the exact digest, closing the digest-blind forge surface for those
classes. Raising the bar further — so even an attacker holding both the socket
and the approver secret cannot sign offline — is the job of HSMs and offline
ceremonies.

### 4.6 Out of scope

Kernel compromise, hypervisor/physical attacks (addressed later by HSMs), and
compromise of the build toolchain beyond what reproducible builds and the
dependency budget cover.

## 5. Protocol

### 5.1 Transport

gRPC over a Unix domain socket is the primary channel; gRPC over mTLS is the
cross-node channel — chosen for a typed, versioned contract with codegen,
deadlines, backpressure, and a well-defined status-code model, at the cost of
exactly two audited third-party dependencies (§7). HTTP/2 framing is an
implementation detail of gRPC; the signer exposes no general HTTP server.

The full wire contract is the committed `signer.proto` stub; the salient points
follow.

### 5.2 Peer authentication

- **UDS:** the socket is created in a `0700` directory owned by the signer user,
  as a `0600` socket. On accept, the signer reads `SO_PEERCRED` and rejects any
  peer whose uid isn't the configured control-plane uid — binding the channel to
  a specific local process identity without any shared secret.
- **mTLS:** TLS 1.3, AEAD-only cipher suites enforced at build time; the signer
  pins the control plane's client certificate, and the client pins the signer's.
  **Implemented:** the signer serves the cross-node channel from its mTLS
  listener (`--mtls-listen`, `--mtls-cert`/`-key`, peer `--mtls-peer-ca`/
  `--mtls-peer-pin`); the control plane dials it (`signer.mtls_address` +
  `signer.mtls_*`). Both directions verify the peer against its pinned CA and
  pin its exact public key, so a merely CA-signed-but-unpinned (or untrusted)
  peer is rejected at the handshake; a partial config fails closed. All TLS
  routes through the single crypto boundary; the signer keeps no HTTP server or
  SQL driver — mTLS is only a transport credential on the same gRPC
  `SignerService`.

### 5.3 Operations and data model

`SignerService` (see proto) exposes `GenerateKey`, `GetPublicKey`, `Sign`,
`DestroyKey`, and `Health`. Keys are referenced by an opaque `KeyHandle`; the
control plane stores the handle and the PKIX/DER public key, never
private-key bytes. `Sign` takes a handle, a pre-computed digest, the hash that
produced it, and (for RSA) a padding scheme, mirroring the platform's
signing-options type. Signing a digest (not a raw message) is the canonical
signer operation — it matches `crypto.Signer`/HSM semantics and is what X.509
CSR and certificate signing require — so the signer is a thin, audited front
to the single crypto boundary.

### 5.4 Limits and resource bounds

- Maximum request/response size (default 1 MiB; the signer signs digests/short
  messages, not bulk data).
- Maximum concurrent in-flight requests and a bounded queue (a per-subsystem
  bulkhead).
- A per-RPC deadline; work past the deadline is abandoned.

**Implemented:** the serving path caps concurrent HTTP/2 streams
(`MaxConcurrentStreams`) and adds a fixed-size in-flight semaphore over the
expensive RPCs (`Sign`, `GenerateKey`); excess is rejected immediately with
`RESOURCE_EXHAUSTED` (never queued unboundedly), and an RPC with no caller
deadline is given one. Cheap RPCs (`Health`, `GetPublicKey`, `DestroyKey`) stay
ungated, so a sign/keygen flood cannot starve a liveness probe, tunable via
`ServeOptions.MaxInflight`.

### 5.5 Error model and idempotency

Errors map to gRPC status codes and never contain secret material:
`INVALID_ARGUMENT` (bad algorithm/hash/empty fields), `NOT_FOUND` (unknown
handle), `RESOURCE_EXHAUSTED` (limits), `FAILED_PRECONDITION` (key usage
constraint), `UNAVAILABLE` (draining/restarting), `INTERNAL` (unexpected).
`Sign` and `DestroyKey` are safe to retry (even randomized ECDSA/RSA-PSS
signing is harmless to repeat, and `DestroyKey` is idempotent); `GenerateKey`
accepts an optional caller-chosen handle id for idempotent creation.

### 5.6 Versioning

The proto package is `trstctl.signing.v1`; evolution is additive within v1, with
a new package for breaking changes.

## 6. Memory-safety obligations

At the **buffer** level (delivered by the wipeable secret-memory buffers):

- Every private-key byte lives in a locked secret buffer: a page-aligned `mmap`
  region, mlock'd (never swapped), marked MADV_DONTDUMP (excluded from core
  dumps), and explicitly zeroized on destroy (manual zero loop kept alive with
  `runtime.KeepAlive`). Key material is raw bytes, never plain strings; the
  architecture linter enforces this in key-handling packages.

At the **process** level (delivered by the signer build):

- `setrlimit(RLIMIT_CORE, 0)` disables core dumps (belt-and-suspenders with
  `MADV_DONTDUMP`).
- `prctl(PR_SET_DUMPABLE, 0)` denies `ptrace` and `/proc/<pid>/mem` access from
  non-root peers.
- Optional `mlockall(MCL_CURRENT|MCL_FUTURE)` so no signer page is ever
  swapped.
- **No key bytes in logs, ever.** The signer logs only non-secret operational
  metadata, uses no third-party logging (§7), and scrubs error strings.
- Constant-time comparison for any secret comparison.
- Keys are zeroized promptly: ephemeral keys right after use; long-lived CA
  keys on `DestroyKey` and shutdown. Raw key bytes are never written to disk;
  key-at-rest (envelope encryption / KMS) is a later concern.
- **Transiently-parsed signing key zeroized after each `Sign`**
  (**Implemented**): the durable key lives only in the mlock'd secret buffer,
  but signing forces the standard library to materialize a parsed
  `*rsa`/`*ecdsa.PrivateKey` whose secret scalars are `big.Int` words on the
  Go heap (which Go cannot mlock). The signer's digest-signing path now
  zeroizes those scalars (D, and for RSA the prime factors and CRT precomputed
  values) immediately after the signature, kept from being elided with
  `runtime.KeepAlive` so the unprotected copy does not outlive the operation; a
  residue test asserts the scalars are zero afterward. This shrinks the
  in-clear window to the smallest Go allows — eliminating it entirely is the
  job of HSM/KMS custody.

## 7. Dependency budget

The signer binary's dependency surface is deliberately tiny and auditable;
adding anything requires explicit review.

**Allowed**

- The Go standard library (the low-level `crypto/*` primitives are reached only
  through the single crypto boundary — the signer imports the boundary, not
  those primitives directly).
- `google.golang.org/grpc` — the transport, audited and pinned.
- `google.golang.org/protobuf` — message encoding, audited and pinned.
- `golang.org/x/sys` — `prctl`, `setrlimit`, `mlock`/`mlockall`, `SO_PEERCRED`.
- trstctl's own crypto boundary and wipeable secret-buffer modules.

**Forbidden** (non-exhaustive; the intent is "nothing else")

- An HTTP server — the signer exposes no HTTP surface and never calls
  `http.Serve` / `http.ListenAndServe`. (`net/http` may still be transitively
  linked via gRPC's HTTP/2 transport — an implementation detail, not a
  violation. What's forbidden is standing up a server, not the package
  appearing in the graph; the build-time check below asserts the former.)
- `database/sql` or any database driver (e.g. `pgx`) — no datastore is in the
  signer's dependency closure.
- NATS or any message-bus client — the signer is not on the event spine.
- Any third-party logging library (e.g. zap, logrus) — logging uses the
  standard library only, and never logs secrets.
- ORMs, web frameworks, template engines, Redis, or any other datastore client.

A build-time check (`TestSignerDependencyClosure`,
`TestSignerHasNoHTTPServerCall`) asserts `database/sql`, the `pgx` driver, and
NATS are absent from `go list -deps ./cmd/trstctl-signer`, and that the signer
starts no HTTP server (`http.Serve`/`ListenAndServe`) — checking the shipped
binary, not this document's wording.

## 8. Fuzzing plan

Every parser that touches untrusted input is fuzzed (Go native fuzzing,
`FuzzXxx`), with a committed seed corpus under `testdata/fuzz` exercised under
`make test`. Continuous fuzzing runs in CI today via a per-PR/nightly Go-native
smoke job (`make fuzz-smoke` in `.github/workflows/ci.yml`) that replays the
committed corpus and fuzzes each target on a budget. A ready ClusterFuzzLite /
OSS-Fuzz config (`.clusterfuzzlite/`) auto-discovers and builds every target as a
libFuzzer binary; enabling the *hosted* runner is tracked as a follow-up.

Generated semantic properties are a separate gate, because “hostile bytes did
not crash” does not prove “valid structure kept the same meaning.” Policy, EST,
ACME, SCEP/CMS, X.509/PKCS#10, and SSH have pinned `testing/quick` seeds and
bounded counts. CI runs
`go test ./internal/crypto/ -run TestEveryMandatoryParserFamilyHasPropertyInvariants -count=1`
independently from `TestEveryUntrustedParserIsFuzzed`; deleting either kind of
coverage fails its own denominator.

- **Request decode + validation.** Protobuf decoding is
  `google.golang.org/protobuf`'s job, but our validation of decoded requests
  (algorithm/hash enums, handle format, size bounds) is fuzzed against
  malformed and adversarial inputs.
- **`Sign` input path.** Fuzz the handler's handling of arbitrary `message`
  bytes, hashes, and padding for panics and resource blowups.
- **Any DER/CSR parsing** the signer performs (if the build routes CSR parsing
  through it) is fuzzed; otherwise such parsing lives behind the single crypto
  boundary.
- Targets live alongside the signer code; CI replays the seed corpus on every
  change and fuzzes each target on a budget (fuzz-smoke plus ClusterFuzzLite),
  with a longer nightly batch.

## 9. Failure modes and degraded operation

- **Signer crash.** The control plane detects it (connection error / `Health`),
  restarts the child, and reloads long-lived keys from wrapped at-rest form;
  in-flight requests fail `UNAVAILABLE` and the control plane retries
  (idempotent, §5.5).
- **Drain/shutdown.** Stop accepting, finish in-flight, zeroize, exit.
- **Total outage / offline issuance.** Break-glass with an m-of-n quorum is a
  separate, later capability, noted here only as a known degraded mode.

## 10. Open questions

- Key-at-rest format for long-lived keys (envelope encryption; KMS-wrapped).
- Whether keys are generated in the signer or imported, and how import would be
  authenticated.
- ~~mTLS certificate provisioning for the cross-node path.~~ **Resolved:**
  operators supply four PEM files plus the peer pin (per end); a crypto-boundary
  helper mints a working, cross-pinned pair for evaluation/bootstrap (the Helm
  `isolated` topology mounts the material from a Secret).
- The exact seccomp syscall allowlist.
- `mlockall` for the whole process vs. per-buffer `mlock` only.

## 11. Review

Reviewer sign-off is captured in the pull request that adopts this design;
material changes during implementation must update this document in the same
change.
