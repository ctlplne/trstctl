# Signing service — threat model and protocol design

- **Status:** Reviewed — accepted as the design of record for S1.4.
- **Sprint:** S1.3 (design spike).
- **Implements:** AN-4 (design only). Builds on AN-3 (`internal/crypto`) and AN-8 (`internal/crypto/secret`).
- **Drives:** S1.4 (implementation), and is revisited by S8.1 (HSM/KMS backends) and S8.17 (break-glass).
- **Protocol stub:** `internal/signing/proto/signer.proto`.

> This document exists because the signing service is the one component whose
> compromise ends the company. It is specified before it is built, and its
> implementation PR (S1.4) is the one that most deserves careful review.

---

## 1. Context and stakes

The signing service holds and uses private keys: the X.509 CA keys, the SSH CA
key, and workload/issuance keys. Whoever controls these keys can mint trusted
certificates and impersonate any identity in the customer's fleet. There is no
recovery from undetected key compromise — every credential the platform ever
issued becomes suspect.

AN-4 therefore makes the signer a **separate, sacred process** with its own
address space, the smallest possible attack surface, and no incidental
capabilities (no HTTP server, no database, no third-party logging). This
document defines that boundary, the protocol used to reach it, the memory-safety
obligations on key material, the explicit dependency budget, and the fuzzing
plan.

## 2. Goals and non-goals

**Goals**

- A process and trust boundary that contains a control-plane compromise: code
  execution in the control plane must not yield the private keys.
- A precise, minimal, typed protocol that S1.4 can implement directly.
- Memory-safety guarantees for key material (AN-8) at both the buffer and the
  process level.
- An explicit, auditable dependency budget for the signer binary.

**Non-goals (for this spike)**

- No implementation beyond the protocol stub (`signer.proto`). The server,
  client, and child-process supervision land in S1.4.
- HSM/KMS backends (S8.1), the SSH CA (S8.10), PQC (S1.5), ephemeral issuance
  (S8.4), and break-glass/offline ceremonies (S8.17) are out of scope here and
  are referenced only where they constrain the design.
- Business authorization (who may request a signature, under what policy) is the
  control plane's responsibility (F28 policy, F30 attestation, S8.16 approvals).
  The signer protects the **key**; it does not adjudicate business intent. This
  split is load-bearing and is revisited in §4.5.

## 3. Process boundary (AN-4)

- **Separate process.** The signer is `cmd/trstctl-signer`, a distinct binary
  with its own address space. It is never run in-process with the control plane.
- **Single-binary mode.** The control plane launches the signer as a **child
  process** and communicates over a Unix domain socket (UDS). The child inherits
  no secrets via argv/env; the socket path and minimal config are passed
  explicitly. The parent supervises lifecycle (spawn, readiness, drain, restart).
- **Multi-node mode.** Across hosts the signer is reached over **mTLS** (TLS 1.3,
  AEAD-only suites enforced at build time, per S3.4's transport rules). UDS is
  the default and preferred path; mTLS is the cross-node escape hatch.
- **No ambient capabilities.** The signer runs as a dedicated, unprivileged user
  with no shell, no `exec`, and no outbound network except its single listener.
  It has **no HTTP server** and **no SQL driver** (see §7). Process hardening
  (seccomp profile, `PR_SET_DUMPABLE`, `RLIMIT_CORE=0`) is covered in §6.
- **Lifecycle.** Start → bind socket (0700 dir, 0600 socket) → handshake/peer
  check → serve → drain (refuse new work, finish in-flight) → zeroize all key
  buffers → exit. A crash is detected by the control plane via the connection
  and `Health`, which restarts the child; in-flight requests fail with
  `UNAVAILABLE` and the control plane retries (signing is safe to retry, §5.5).

## 4. Threat model

### 4.1 Assets

Private keys in RAM (CA keys, issuance keys), the signing capability itself, and
key metadata (handles, algorithms). The public keys and signatures are not
secret.

### 4.2 Trust boundaries

1. **Control plane ↔ signer** — the primary boundary, crossed by the protocol in
   §5. Assume the control plane and the signer fail independently.
2. **Signer ↔ operating system** — the signer trusts the kernel; it defends
   against other processes/users on the same host (memory disclosure).
3. **Signer ↔ hardware backend** — a future boundary (HSM/KMS, S8.1) that moves
   keys out of process memory entirely.

### 4.3 Assumptions

- The kernel and hardware are trusted (until an HSM narrows this further).
- The control plane may be compromised **independently** of the signer; an
  attacker may obtain code execution in the control plane without obtaining it in
  the signer.
- Build and supply chain are governed by the dependency budget (§7) and
  reproducible builds (S0.1).

### 4.4 Adversaries and mitigations (STRIDE)

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | A rogue local process connects to the signer's socket and asks it to sign. | UDS peer authentication via `SO_PEERCRED`: the signer verifies the connecting process's uid is the expected control-plane uid. Cross-node uses mTLS with pinned client certs. Socket lives in a `0700` directory, `0600` socket. |
| **Tampering** | Request/response altered in transit, or malformed requests exploit the parser. | UDS is a local kernel channel (no on-wire tampering); mTLS provides integrity across nodes. All requests are strictly validated; the decode/validation path is fuzzed (§8). Message size and field bounds are enforced (§5.4). |
| **Repudiation** | "I never asked for that signature." | The control plane records every signing request/response in the AN-2 event log (the signer is not the system of record). The signer emits only non-secret operational logs. |
| **Information disclosure** | Key bytes leak via swap, core dump, `/proc/<pid>/mem`, ptrace, logs, or error strings. | Keys live only in `secret.Buffer` (mlock + `MADV_DONTDUMP` + zeroize, AN-8). Process-level: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, optional `mlockall`. No key bytes are ever logged; error messages carry no secret material (§6). |
| **Denial of service** | A flood of expensive sign/generate requests starves the signer. | Bounded worker pool and request queue (AN-7 bulkheads), per-RPC deadlines, max in-flight, and max message size. Coarse abuse control and policy gating happen upstream in the control plane. |
| **Elevation of privilege** | Compromised signer escalates on the host. | Dedicated unprivileged user, no shell/`exec`, minimal syscalls (seccomp in S1.4+), single socket listener, no outbound network. |

### 4.5 The key-abuse threat (explicitly in scope to *bound*)

A compromised control plane is, by construction, **authorized** to ask the
signer to sign. The signer cannot distinguish a legitimate issuance from an
attacker driving an already-trusted control plane. This is a real residual risk,
and the signer is **not** the right place to fully mitigate it. Defense in depth
lives upstream and around it:

- Policy (F28) and attestation gating (F30) at the control plane decide *whether*
  a signature is allowed.
- Dual-control/JIT approvals (S8.16) for sensitive key classes.
- Rate limiting, anomaly detection, and the AN-2 audit trail.
- Per-key constraints the signer *can* enforce cheaply: a key may be created with
  an allowed-algorithm set and usage flags, and the signer refuses operations
  outside them. This limits, but does not eliminate, abuse. **Implemented
  (SIGNER-002/003):** `GenerateKey` accepts `allowed_purposes` (and optional
  `allowed_hashes`); `Sign` carries the asserted `purpose`; the signer refuses a
  mismatch with `FAILED_PRECONDITION`. The constraints are sealed with the key, so
  they survive a restart. The served control plane creates the issuing-CA key
  bound to `CA_SIGN`, so a caller that reaches the socket and holds the well-known
  `issuing-ca` handle still cannot coerce it into signing an SSH/code-signing/
  arbitrary-purpose artifact.
- **Per-Sign intent attestation / dual-control for crown-jewel keys**
  (**Implemented, RED-003**): purpose constraints bound *which key class* a caller
  may use, but a digest-blind `Sign` still let a socket-reaching caller have a
  `CA_SIGN` key sign `sha256(<arbitrary attacker TBS>)`. A key may now be created
  **dual-control**: the signer refuses every `Sign` against it unless the request
  carries a valid authorization token — an HMAC over the *exact* signing tuple
  (handle, purpose, hash, padding, and the digest itself) minted by an approval
  authority that holds a secret the on-socket caller does not (the signer holds
  only the verify side). Because the token commits to the digest it authorizes one
  specific to-be-signed object and cannot be replayed onto different bytes, and
  because the approver secret is never exposed on the socket, a control-plane/socket
  compromise can no longer coerce a dual-control key into forging arbitrary trust.
  The dual-control opt-in and the per-`Sign` token travel as gRPC metadata (the
  wire proto is frozen); the flag is sealed with the key and re-enforced across a
  restart; the authorizer (`internal/crypto.SignAuthorizer`) lives behind the AN-3
  boundary with its secret in mlock'd memory (AN-8). A signer with no authorizer
  fails closed on a dual-control key.

What the signer guarantees is narrower and absolute: **the private key bytes
never leave the process**, even under a full control-plane compromise. For a
dual-control key the signer additionally **will not sign without an independent
authorization bound to the exact digest**, so the digest-blind forge surface is
closed for those classes. Raising the bar all the way (so even a co-located
attacker holding both the socket and the approver secret cannot sign offline) is
the job of HSMs (S8.1) and offline ceremonies (S8.17).

### 4.6 Out of scope

Kernel compromise, hypervisor/physical attacks (addressed later by HSMs), and
compromise of the build toolchain beyond what reproducible builds and the
dependency budget cover.

## 5. Protocol

### 5.1 Transport

**gRPC over a Unix domain socket** is the primary channel; **gRPC over mTLS** is
the cross-node channel. gRPC is chosen for a typed, versioned contract with
codegen, deadlines, backpressure, and a well-defined status-code model — at the
cost of exactly two audited third-party dependencies (§7). HTTP/2 framing is an
implementation detail of gRPC; the signer exposes **no** general HTTP server.

The full wire contract is the committed stub
`internal/signing/proto/signer.proto`; the salient points
follow.

### 5.2 Peer authentication

- **UDS:** the socket is created in a `0700` directory owned by the signer user,
  as a `0600` socket. On accept, the signer reads `SO_PEERCRED` and rejects any
  peer whose uid is not the configured control-plane uid. This binds the channel
  to a specific local process identity without any shared secret.
- **mTLS:** TLS 1.3, AEAD-only cipher suites enforced at build time; the signer
  pins the control plane's client certificate, and the client pins the signer's.
  **Implemented (SIGNER-005):** the signer serves the cross-node channel via
  `signing.ServeServerMTLS` (binary flag `--mtls-listen`, plus `--mtls-cert`/`-key`
  and the peer `--mtls-peer-ca`/`--mtls-peer-pin`), and the control plane dials it
  with `signing.DialMTLS`/`DialReadyMTLS` (config `signer.mtls_address` + the
  `signer.mtls_*` material). Both directions verify the peer against its pinned CA
  **and** pin the peer's exact public key, so a merely CA-signed-but-unpinned (or
  wholly untrusted) peer is rejected at the handshake; a partial config fails
  closed. All TLS lives in `internal/crypto/mtls` (AN-3); the signer keeps no HTTP
  server and no SQL driver (AN-4) — mTLS is only a transport credential on the same
  gRPC `SignerService`.

### 5.3 Operations and data model

`SignerService` (see proto) exposes: `GenerateKey`, `GetPublicKey`, `Sign`,
`DestroyKey`, and `Health`. Keys are referenced by an **opaque `KeyHandle`**; the
control plane stores the handle and the PKIX/DER public key and never receives
private-key bytes. `Sign` takes a handle, a **pre-computed digest**, the hash
that produced it, and (for RSA) a padding scheme — mirroring
`internal/crypto.SignOptions`. Signing a digest (rather than a raw message) is
the canonical signer operation: it matches `crypto.Signer`/HSM semantics and is
what X.509 CSR and certificate signing require, so the signer is a thin, audited
front to the AN-3 boundary.

### 5.4 Limits and resource bounds

- Maximum request/response size (default 1 MiB; the signer signs digests/short
  messages, not bulk data).
- Maximum concurrent in-flight requests and a bounded queue (AN-7); excess is
  rejected fast with `RESOURCE_EXHAUSTED`.
- A per-RPC deadline; work past the deadline is abandoned.

**Implemented (SIGNER-001):** the serving path caps concurrent HTTP/2 streams
(`MaxConcurrentStreams`) and adds a fixed-size in-flight semaphore over the
expensive RPCs (`Sign`, `GenerateKey`) via a unary interceptor; the excess is
rejected immediately with `RESOURCE_EXHAUSTED` (never queued unboundedly), and an
RPC with no caller deadline is given one. Cheap RPCs (`Health`, `GetPublicKey`,
`DestroyKey`) are deliberately not gated, so a sign/keygen flood cannot starve a
liveness probe. The bound is tunable via `ServeOptions.MaxInflight`.

### 5.5 Error model and idempotency

Errors map to gRPC status codes and **never contain secret material**:
`INVALID_ARGUMENT` (bad algorithm/hash/empty fields), `NOT_FOUND` (unknown
handle), `RESOURCE_EXHAUSTED` (limits), `FAILED_PRECONDITION` (key usage
constraint), `UNAVAILABLE` (draining/restarting), `INTERNAL` (unexpected). `Sign`
and `DestroyKey` are safe to retry: signing the same input is harmless (even for
randomized ECDSA/RSA-PSS), and `DestroyKey` is idempotent. `GenerateKey` accepts
an optional caller-chosen handle id for idempotent creation.

### 5.6 Versioning

The proto package is `trstctl.signing.v1`; evolution is additive within v1, with
a new package for breaking changes.

## 6. Memory-safety obligations (AN-8)

At the **buffer** level (delivered in S1.2, `internal/crypto/secret`):

- Every private-key byte lives in a `secret.Buffer`: a page-aligned `mmap`
  region that is **mlock**'d (never swapped) and marked **MADV_DONTDUMP**
  (excluded from core dumps), and is explicitly zeroized on `Destroy` (manual
  zero loop kept alive with `runtime.KeepAlive`). Key material is `[]byte`, never
  `string`; the trstctllint AN-8 rule enforces this in key-handling packages.

At the **process** level (delivered in S1.4):

- `setrlimit(RLIMIT_CORE, 0)` to disable core dumps entirely (belt-and-suspenders
  with `MADV_DONTDUMP`).
- `prctl(PR_SET_DUMPABLE, 0)` to deny `ptrace` and `/proc/<pid>/mem` access from
  non-root peers.
- Optionally `mlockall(MCL_CURRENT|MCL_FUTURE)` so no signer page is ever
  swapped.
- **No key bytes in logs, ever.** The signer logs only non-secret operational
  metadata, and uses no third-party logging (§7); error strings are scrubbed.
- Constant-time comparison for any secret comparison.
- Keys are zeroized promptly: ephemeral keys immediately after use; long-lived CA
  keys on `DestroyKey` and on shutdown. Raw key bytes are **never** written to
  disk; key-at-rest (envelope encryption / KMS) is an S1.4/S8.1 concern.
- **Transiently-parsed signing key zeroized after each `Sign`**
  (**Implemented, SIGNER-008**): the durable key lives only in the mlock'd
  `secret.Buffer`. To produce a signature the standard library must materialize a
  parsed `*rsa`/`*ecdsa.PrivateKey` whose secret scalars are `big.Int` words on the
  Go heap (which Go cannot mlock). `internal/crypto.LockedSigner.SignDigest` now
  zeroizes those scalars (D, and for RSA the prime factors and CRT precomputed
  values) immediately after the single signature, ordered after the sign and kept
  from being elided with `runtime.KeepAlive`, so the unprotected copy does not
  outlive the operation. A residue test asserts the scalars are zero after the call
  returns. This shrinks the AN-8 window to the smallest Go allows; eliminating the
  in-clear materialization entirely (so the key never leaves hardware) remains the
  job of HSM/KMS custody (S8.1).

## 7. Dependency budget

The signer binary's dependency surface is deliberately tiny and auditable. Adding
anything to this list requires explicit review recorded in the PR.

**Allowed**

- The Go **standard library** (note: `crypto/*` is reached only through
  `internal/crypto`, per AN-3; the signer itself imports the boundary, not
  `crypto/*`).
- `google.golang.org/grpc` — the transport. Audited, pinned.
- `google.golang.org/protobuf` — message encoding. Audited, pinned.
- `golang.org/x/sys` — `prctl`, `setrlimit`, `mlock`/`mlockall`, `SO_PEERCRED`.
- `trstctl.com/trstctl/internal/crypto` and `internal/crypto/secret` — the AN-3
  boundary and AN-8 buffers.

**Forbidden** (non-exhaustive; the intent is "nothing else")

- An **HTTP server** — the signer exposes no HTTP surface and never calls
  `http.Serve` / `http.ListenAndServe`. (Note: the `net/http` package may be
  *transitively linked* by gRPC, whose HTTP/2 transport — `golang.org/x/net/http2`
  — imports it. That is an implementation detail of the allowed gRPC dependency;
  what is forbidden is *standing up an HTTP server*, not the package appearing in
  the build graph. The build-time check below asserts the absence of a server, not
  the absence of the package.)
- `database/sql` or any database driver (e.g. `pgx`) — the signer has no
  datastore; neither `database/sql` nor a driver is in its dependency closure.
- NATS / any message-bus client — the signer is not on the event spine.
- Any third-party logging library (e.g. zap, logrus) — operational logging uses
  the standard library only, and never logs secrets.
- ORMs, web frameworks, template engines, Redis or any other datastore client.

A build-time check (`TestSignerDependencyClosure`,
`TestSignerHasNoHTTPServerCall`) asserts that `database/sql`, the `pgx` driver,
and NATS are absent from `go list -deps ./cmd/trstctl-signer`, and that the
signer source starts no HTTP server (`http.Serve`/`ListenAndServe`) — checking the
shipped binary's closure and code, not merely this document's wording.

## 8. Fuzzing plan

Every parser that touches untrusted input is fuzzed (Go native fuzzing,
`FuzzXxx`), with a committed seed corpus under `testdata/fuzz` exercised under
`make test`. Continuous fuzzing runs in CI today via a per-PR/nightly Go-native
smoke job (`make fuzz-smoke` in `.github/workflows/ci.yml`) that replays the
committed corpus and fuzzes each target on a budget. A ready ClusterFuzzLite /
OSS-Fuzz config (`.clusterfuzzlite/`) auto-discovers and builds every target as a
libFuzzer binary; enabling the *hosted* runner is tracked as `EXC-FUZZ-01`.

- **Request decode + validation.** Protobuf decoding is `google.golang.org/protobuf`'s
  responsibility, but our **validation** of decoded requests (algorithm/hash
  enums, handle format, size bounds) is fuzzed against malformed and adversarial
  inputs.
- **`Sign` input path.** Fuzz the handler's handling of arbitrary `message`
  bytes, hashes, and padding combinations for panics and resource blowups.
- **Any DER/CSR parsing** the signer performs (if S1.4 routes CSR parsing through
  the signer) is fuzzed; such parsing otherwise lives behind `internal/crypto`.
- Targets live alongside the signer code in `internal/signing`; CI runs the seed
  corpus on every change and fuzzes each target on a budget (the fuzz-smoke job
  and ClusterFuzzLite), with a longer nightly batch.

## 9. Failure modes and degraded operation

- **Signer crash.** The control plane detects it (connection error / `Health`),
  restarts the child, and reloads long-lived keys from their wrapped at-rest
  form. In-flight requests fail `UNAVAILABLE`; the control plane retries
  (idempotent, §5.5).
- **Drain/shutdown.** Stop accepting, finish in-flight, zeroize, exit.
- **Total outage / offline issuance.** Break-glass with an m-of-n quorum is a
  separate, later capability (S8.17); referenced here only as a known degraded
  mode.

## 10. Open questions / decisions deferred to S1.4

- Key-at-rest format for long-lived keys (envelope encryption; KMS-wrapped in
  S8.1).
- Whether keys are generated in the signer or imported (and how import is
  authenticated).
- ~~mTLS certificate provisioning for the cross-node path.~~ **Resolved (SIGNER-005):**
  operators supply the four PEM files + the peer pin (per end) to the signer/control
  plane; `internal/crypto/mtls.GenerateSignerPeerMaterial` mints a working,
  cross-pinned pair for evaluation/bootstrap (the Helm `isolated` topology mounts the
  material from a Secret).
- The exact seccomp syscall allowlist.
- `mlockall` for the whole process vs. per-buffer `mlock` only.

## 11. Review

This is the reviewed design of record for S1.4. Reviewer sign-off is captured in
the pull request for this sprint; material changes during implementation must
update this document in the same PR.
