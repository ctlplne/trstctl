# Access gateway: design and threat model (A254–A258)

The access gateway lets agents, services and people reach databases and hosts without
ever receiving the upstream credential. It builds on the just-in-time PAM lane (F33):
requests, quorum approval, the tenant SSH CA, dynamic-secret providers, revocation and
signed audit. It is not a human PAM suite.

**Boundary.** The gateway never carries, proxies or inspects MCP traffic, and never
starts, sandboxes or hosts MCP servers. Per-tool authorization for agents (P8) is a
separate design with no component in the call path, and does not reuse the gateway.

## Pieces

| Piece | Role |
|---|---|
| Control plane | Approves and opens the session (F33), binds it to its gateway, mints a one-time ticket (stores only its SHA-256), queues the session as one agent job, revokes. |
| Gateway | `trstctl-agent` in its own process with the **gateway** role (granted explicitly, with `agents:relay.grant`; a host-role agent cannot serve it) and `--access-gateway-listen`. It claims session jobs in a claim loop of its own, holds each session's upstream credential in locked memory (a redeemed PostgreSQL login or Redis ACL user, or a key it generated for an SSH session and the certificate the tenant SSH CA issued for it), admits only connections carrying the session's ticket, signs in upstream itself and never returns the credential. |
| CLI | `trstctl access sessions connect <id> --ticket-file F`: a loopback listener; each local connection becomes one TLS connection to the gateway, verified as below. Stock clients (`psql`, `redis-cli`, `ssh`) connect to the loopback address. |

The gateway's outbound destinations are the control plane and the targets bound to it.
Its listener serves a certificate the agent CA signs for it (in the signer process, AN-4):
ServerAuth, for the host names clients reach it by (`--access-gateway-hosts`, each the host
of a target binding that names this agent — the control plane signs no other name), and
naming the gateway agent's SPIFFE ID as a URI SAN. Its key stays in locked memory and the
certificate is renewed before it ends. A client verifies it with ordinary TLS verification
against the tenant's agent CA for the host it dialed, then requires the exact SPIFFE ID, so
it knows which agent it reached. The gateway asks clients for no certificate: the ticket
inside the tunnel admits them.

## A session's life

1. **Request and approval** — unchanged from F33. A target bound to a gateway
   (`gateway_agent_id`, `gateway_address`) is part of the approved command: the binding is
   in the target digest, so changing it invalidates the approval.
2. **Open** — the control plane consumes the approval once, issues the upstream credential
   as for any session (PostgreSQL: a per-session login from the dynamic-secret provider
   with `rolvaliduntil` at the deadline; SSH: nothing yet — the session records its
   principal and the key ID `pam:<session>` its certificates will carry, and a request
   naming an `ssh_public_key` of its own is refused), records `pam.session.started` with
   `delivery: gateway`, the gateway and the ticket's SHA-256, and queues one agent job
   (`access.gateway.session`, keyed by the session, demanding the gateway role and that
   exact agent). The response carries the ticket (once) and how to verify the gateway —
   never the credential.
3. **Claim and redemption** — the gateway claims the job. PostgreSQL: redemption reopens
   the credential from the session's lease for that gateway only (exact agent, gateway
   role); it travels over the gateway's mTLS channel into locked memory. SSH: the gateway
   generates the session's key (ECDSA P-256, locked memory) and sends its public half with
   the job and attempt it holds (`SignJobSSHKey`); the control plane checks the lease is
   this agent's at that attempt, the session is still an active gateway SSH session of
   this agent's before its deadline, and the target still binds this agent and lists the
   principal, then the tenant SSH CA (in the signer, AN-4) certifies the key: key ID
   `pam:<session>`, the session's principal, valid until the session's deadline, and only
   `permit-pty` — no port, agent or X11 forwarding. A re-claim after a gateway restart gets
   a new key and a new certificate with the same key ID.
4. **Connect** — the client's first line is `TRSTCTL-GATEWAY/1 <session> <ticket>`; the
   gateway compares the ticket's SHA-256 in constant time, checks the deadline, then:
   for PostgreSQL it answers the client's startup itself, signs in upstream as the
   session login, hands the client the upstream session's parameters and readiness, and
   relays the protocol. The sign-in is the gateway's own (inside `internal/crypto`), not a
   database driver — the agent binary links none and never sends a query of its own: it
   answers the server's password request as libpq does (SCRAM-SHA-256, MD5 or cleartext,
   as the target's `pg_hba` demands; Kerberos, GSSAPI and SSPI are refused), passes only
   the client's harmless runtime parameters (`application_name`,
   `client_encoding`, `DateStyle`, `TimeZone`, `extra_float_digits`, `IntervalStyle`),
   and whenever it uses TLS it verifies the database's certificate against `sslrootcert`
   (a file on the gateway's host) or the system roots, including the host name —
   stricter than libpq's `prefer`, `require` and `verify-ca`.
   For SSH (inside `internal/crypto/sshgateway`) the admission answer carries the gateway's
   own SSH host key, which the CLI — having verified the gateway over TLS — writes to a
   known_hosts file for the stock client; the client's SSH handshake asks for no
   authentication (the ticketed tunnel was it). The gateway then signs in to the target as
   the session's principal with the session certificate, accepting only a host key the
   target's `host_key_fingerprints` pin (or a host certificate for one), and relays session
   channels — shell, exec, SFTP — and their requests; any other channel and agent or X11
   forwarding are refused.
5. **End** — at the deadline the gateway closes the session's connections, wipes the
   credential and reports; the native deadline (`rolvaliduntil`, certificate
   `valid_before`) holds even without it. **Revocation** recalls the session's job
   first, so the gateway's next lease extension (every few seconds) is refused and it
   closes the session; the upstream credential's revocation then proceeds as for any
   session.

## End states, each read back on its own

| State | Effect read back |
|---|---|
| New logins denied | The gateway no longer holds the session: a connection is refused. |
| Session terminated | The gateway's end-of-session report (`gateway_end`: `recalled` or `deadline`), after the session's recording is flushed and sealed; without it, `uncertain_until` the native deadline. |
| Upstream credential revoked | The PostgreSQL role is gone / the served SSH KRL holds the session's key ID, which every certificate the gateway was given for the session carries (F33). |

## Recordings (A255)

When the deployment stores recordings — an object store (`audit.archive_object_store`),
tenant sealing and the audit signing key — every gateway session job carries
`record: true` and the gateway records the session as it relays it.

- **What is recorded.** SSH: session-channel bytes both ways (`in`, `out`, `err`) and the
  session requests (exec commands, subsystem, pty, window size, environment, exit
  status); an SFTP channel is recorded as operations — open, read, write, remove, rename,
  mkdir, rmdir, setstat, symlink — with the path, the bytes moved and the result, never
  the file contents. PostgreSQL: each statement (simple queries; prepared statements and
  their bound values), each result's column names, its first rows up to a bound with a
  marker where rows stop being recorded, command tags and error codes; COPY data by size.
- **Masking happens at the gateway, before anything leaves it.** The session's injected
  credential (the PostgreSQL login's password) and well-known issued-token shapes (AWS
  access key IDs, GitHub, GitLab, Slack, Stripe and Google API tokens, JWTs, PEM private
  keys) become `[masked:<rule>]`. A secret split across writes is still found: each stream
  holds back only a tail that may still become a secret. The control plane's secret-scan
  rule set cannot be linked into the agent, so the gateway carries this list of its own.
- **Upload with backpressure.** Frames are JSON lines spooled under a bound and uploaded in
  order over the agent channel (`UploadSessionRecording`, by the gateway holding the job at
  that attempt; a recalled claim may still flush its tail). A full spool holds the
  session's traffic until the upload catches up — nothing is dropped.
- **Sealed, chained, signed.** The control plane seals each chunk for the tenant (AAD:
  tenant, session, place and the plaintext's SHA-256) into the object store, and records
  it (`pam.session.recording_chunk_stored`) with the chain
  `SHA-256(previous || chunk SHA-256)`. The gateway's final chunk — or, for a session that
  ended without one, two quiet minutes — closes the recording: a manifest of every chunk's
  place, digests and object and the chain head, signed with the deployment's audit key
  (`pam.session.recording_sealed`).
- **Verification.** `GET /api/v1/access/sessions/{id}/recording/verify` checks the manifest
  is the one signed, every chunk is present, unmodified and opens only in its place, its
  plaintext matches its digest, and the chain reaches the manifest's head; an edited,
  dropped or reordered chunk, or an edited manifest, fails it.
- **Access.** `recordings:read` plays a recording back by pages
  (`GET .../recording/frames?from=&limit=`) and watches a live one: with `wait` (up to 25
  seconds) a read long-polls for frames still being recorded, from the session's first
  moment; `recordings:export` exports a sealed recording whole with its manifest and the
  audit key's JWS (`GET .../recording/export`) and places or releases a legal hold. Neither
  comes with `access:read`; the built-in auditor role holds both and the CLI machine role
  neither. Every read is recorded (`pam.session.recording_read`: who, which recording, how).
  `trstctl access sessions watch <id>` renders a session live.
- **Termination and its uncertainty.** `access:terminate` ends another principal's live
  gateway session (`POST .../terminate`): its job is recalled — the gateway closes its
  connections at its next lease extension, within seconds — and its credential is revoked
  as for a revocation. The gateway's report of the end (`pam.session.gateway_ended`, read as
  `gateway_end`) acknowledges it. Until then a terminated session reads `uncertain_until`
  its native deadline: a gateway cut off from the control plane may keep serving until the
  credential stops working by itself, and acknowledges when it reconnects.
- **Maximum length.** `pam.max_ttl` caps every session at the open, and the gateway ends a
  session's connections at its deadline (`gateway_end: deadline`).
- **Retention and legal hold.** `pam.recording_retention` deletes a sealed recording's
  objects that long after it was sealed (`pam.session.recording_deleted`; the index and
  manifest digest stay, reading `deleted`), unless a legal hold keeps it; releasing the hold
  lets retention take it on its next pass.

## Session types (A256)

Every database type follows PostgreSQL's pattern: the session's credential is a per-session
login a dynamic-secret provider of the type's kind mints at the open, the gateway redeems
it and signs in with a sign-in of its own under `internal/crypto` (the agent binary links no
database driver), and the client's hop carries no credential. Types other than PostgreSQL
are served only through a gateway; the target builder refuses one without a binding.

- **Redis.** The provider's ACL user for the session (the role's key prefixes and commands;
  PING is always allowed). The gateway sends `AUTH <user> <password>` and, for a database
  other than 0, `SELECT`, over plaintext or `rediss://` verified against the system roots,
  then relays RESP. It reads each client command's name before forwarding anything: AUTH,
  HELLO with an AUTH option and RESET would change the connection's login, so they are
  never forwarded — a command the server answers with an error
  (`TRSTCTL-GATEWAY-REFUSED-<command>`) goes in their place, so the refusal reaches the
  client in order even when commands are pipelined, and the connection keeps the session's
  user. Inline (telnet-style) commands close the connection. A command is held whole, and
  recorded, before it is forwarded up to 1 MiB; past that it streams. Recordings keep each
  command with its arguments (each cut at 256 bytes, binary ones by size, 4 KiB per
  command) and each reply's RESP2 or RESP3 type with a rendering under the same bounds; a
  refused command is recorded by its name alone, never its arguments.
- **MySQL.** The provider's account for the session (its role's privileges on the
  provider's database). The gateway connects first and reads the server's handshake, then
  answers the client with a handshake of its own — the server's version and capabilities
  without TLS or compression, a fresh nonce, `caching_sha2_password` — and takes the
  client's response without checking any password. It signs in upstream with the client's
  own capability flags (less TLS, compression and connect attributes), so the relayed
  command phase means the same to both ends: `caching_sha2_password`'s fast path, or full
  authentication with the password encrypted to the server's RSA key (as a driver does
  without TLS), or `mysql_native_password` when the server switches to it; any other
  plugin is refused. The server's OK goes to the client, and commands are relayed.
  `COM_CHANGE_USER` would sign the connection in as another account, so the gateway
  answers it with an error itself and never forwards it; only a packet with sequence
  number 0 is a command, so LOAD DATA LOCAL file packets pass. Recordings keep each
  statement (queries, prepared statements, executions by statement and size, `USE`), the
  column names, the first ten text rows (values cut at 256 bytes, 4 KiB per result, binary
  rows by size) with a truncation marker, OK counts and error codes, masked.
- **MongoDB.** The provider's user for the session (`read` or `readWrite` on the
  provider's database). The gateway signs in with SCRAM-SHA-256 through `saslStart` and
  `saslContinue` on the user's database, over plaintext or TLS verified against `tlsCAFile`
  (a file on the gateway's host) or the system roots; with several hosts it asks each, on
  a connection of its own, whether it is the writable primary. The session's connection
  carries no hello of the gateway's: a server takes client metadata only in a
  connection's first hello, which is the stock client's. `saslStart`, `saslContinue`,
  `authenticate` and `logout` would change who the connection is signed in as, so the
  gateway answers each with an `Unauthorized` error itself and never forwards it; a
  handshake's `speculativeAuthenticate` and `compression` are removed (so nothing is ever
  compressed); compressed and legacy operations end the connection, and OP_QUERY is
  relayed only for a driver's first hello or isMaster. `mongodb+srv://` and mechanisms
  other than SCRAM-SHA-256 are refused. Recordings render each command and reply
  document (values cut at 256 bytes, binary by size, 4 KiB per document), masked; a
  refused command is recorded by its name alone.

## Failure modes

- **Control-plane restart mid-session** — the session row, its events and its job row are
  durable; the gateway keeps its claim and connections; the session ID derives from the
  approval and the deadline from the lease, so a restart neither duplicates nor extends
  it. An open interrupted between its event and its job is completed by the PAM expiry
  worker, which re-queues the job of every active gateway session (the job key is the
  session, so never twice).
- **Gateway restart** — its memory is gone and its connections drop; the job's lease
  lapses and the job is claimable again, so a restarted gateway re-claims and re-redeems
  it.
- **Partition between gateway and control plane** — no new claims; a held session
  continues until its deadline or until an extension is refused. A revocation during a
  partition takes effect when the gateway next reaches the control plane, and the native
  deadline bounds it regardless.

## What the gateway can see, and the threats

The gateway sees every session's plaintext: SQL statements and results, shell input and
output. That is why recording and masking (A255) happen there and why the role is a
deliberate grant.

| Threat | Answer |
|---|---|
| A stolen ticket | It admits connections to one session, at one gateway, until the session's deadline; revocation ends it. |
| A client connecting straight to the target | The client holds no credential the target accepts. |
| A client changing the connection's login (Redis AUTH, HELLO with AUTH, RESET; MySQL COM_CHANGE_USER; MongoDB saslStart, saslContinue, authenticate, logout, a handshake's speculativeAuthenticate) | Never forwarded: Redis gets a stand-in command the server refuses in its place, MySQL and MongoDB an error from the gateway, and a MongoDB handshake loses the field; the connection keeps the session's login. |
| A host impersonating the SSH target | The gateway accepts only a host key the target registration pins. |
| A gateway asking for more SSH certificates | Each is for a key it holds, for a session job it holds at that attempt, with the session's principal, key ID and deadline; the CA records every one (`ssh.cert.issued`) and revocation covers them all by key ID. |
| A compromised gateway | It holds only the credentials of sessions it is serving, each bounded by its deadline; it cannot mint credentials (only the control plane can, and SSH certificates only through the isolated signer). |
| Another tenant | The gateway is one tenant's agent; jobs, sessions and redemption are tenant-scoped under RLS. |
| A gateway impersonator | The CLI verifies the gateway's serving certificate against the tenant's agent CA for the host it dialed and requires the gateway agent's exact SPIFFE ID; the control plane signs a gateway's certificate only for hosts its own bindings declare. |

## Status

A254 is served: PostgreSQL and SSH through the gateway. The served proofs drive stock
`psql` and `ssh` through the CLI with no credential; refuse an unlisted principal and a
requester key at the open, another tenant at the API, an expired session at the gateway
and a straight connection at the target; and restart the control plane mid-session — the
live connection continues, the gateway's lease extends against the new process, and the
session keeps its one start, one job and deadline. A255 (recording, masking, live
termination) is served. A256 serves Redis (`TestServedGatewayRedisSessionsA256`, stock
`redis-cli`), MySQL (`TestServedGatewayMySQLSessionsA256`, stock `mysql`) and MongoDB
(`TestServedGatewayMongoSessionsA256`, stock `mongosh`); ClickHouse and Kubernetes follow,
then the agent launcher
(A257) and credential health and emergency access (A258).
