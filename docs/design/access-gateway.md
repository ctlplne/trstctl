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
- **ClickHouse.** The provider's user for the session (its role's ClickHouse role, valid
  until the provider's maximum lifetime). Its credential is a user and password with no
  address, so the session's job names the provider's endpoint (`upstream_url`, a public
  fact like an SSH target's address). The gateway serves ClickHouse's HTTP interface on the
  tunnel: every client credential is removed — basic auth, `X-ClickHouse-User` and
  `X-ClickHouse-Key`, certificate-auth headers, `user` and `password` parameters — and each
  request is signed in as the session's user, then forwarded (HTTPS verified against the
  system roots). The stock client is curl or any HTTP-interface tool; `clickhouse-client`
  speaks ClickHouse's native protocol, which the gateway does not serve. Recordings keep
  each request (method, path, the `query` parameter and the body's first 4 KiB) and each
  response (status, exception code, summary and the body's first 4 KiB), masked; bodies
  stream, they are never held whole.
- **Kubernetes.** The provider's TokenRequest token for a lease-scoped service account
  (its role bound by the provider; the token lives at least ten minutes). The session's job
  names the API server, its CA and server name (`upstream_url`, `upstream_ca_pem`,
  `upstream_server_name`, public facts). The gateway serves HTTP on the tunnel, removes a
  client's own credential and every impersonation header (`Impersonate-User`, `-Group`,
  `-Uid`, `-Extra-*`), adds the session's token to every request, and forwards it over
  HTTPS verified against the cluster CA. Exec, attach and port-forward upgrade the
  connection; the upgraded stream passes through untouched. The connect command writes a
  kubeconfig that names the tunnel and no user. Recordings keep each API request
  (method, path and query, the body's first 4 KiB) and response (status, the body's first
  4 KiB); a remote-command WebSocket stream is decoded into its stdin, stdout and stderr and
  recorded as a shell session's bytes are (masked), any other stream by its size.

## Agent launcher (A257)

`trstctl-cli access agent --account TYPE/ID:ROLE ... -- <command>` starts an agent or a CI
job with gateway sessions to the accounts its task is delegated, and no credential.

- **Delegated accounts.** An access bundle names the accounts its runs may open sessions
  to (`access_targets`: a target type and ID with the roles allowed on it, at most 16 per
  bundle). A run (A251) that requests or opens a session for any other target or role is
  refused with 403 and no review is requested. The delegation is read from the run's live
  grants on every request, so editing the bundle or removing a grant changes it at once.
  A principal that is not a run is limited by its permissions alone.
- **`access:sessions.open`.** Requesting, opening, reading the progress of and revoking
  one's own sessions, and nothing else of access. A bundle may carry it (it may not carry
  `access:write`, which includes it); revoking another principal's session still needs
  `access:write`.
- **The agent's own identity.** An unattended run acts as the agent: the operator grants
  the bundle to the agent's ID (its broker identity's `agent_id`) and mints a run for it,
  and the run's token goes to the CI job. Every session it opens records `requested_by:
  bundle-run:<agent>`. Reviews are not bypassed: each session still needs its approvals.
- **The launcher.** With that token it requests each account's session, waits for the
  approvals, opens each through its gateway and serves each session's tunnel on a loopback
  address from its own process. The command runs with `TRSTCTL_ACCESS_INSTRUCTIONS` (a file
  naming each account, its local address, its deadline and the stock client line),
  `TRSTCTL_ACCESS_<n>_TYPE|TARGET|ROLE|ADDR`, and for a single account of a kind the
  variables its stock client reads (`PGHOST`/`PGPORT`, `MYSQL_HOST`/`MYSQL_TCP_PORT`,
  `KUBECONFIG`). Its environment holds neither the caller's token nor any `TRSTCTL_*TOKEN*`
  variable; the tickets stay in the launcher and the gateway signs in for the command. A
  session delivered directly (its credential in the reply) is revoked at once and the
  command does not run. When the command exits, its sessions are revoked unless `--keep`
  is given.
- **One-call revoke.** Revoking the agent's broker identity (Q4,
  `POST /api/v1/broker/agent-identities/{id}/revoke`) also revokes the access runs minted
  for its agent ID, then every live session the agent opened, itself or through a run, as
  an operator's revocation does: the gateway closes the session's connections and the login
  is removed. `certs:issue` is all the call needs: ending what the identity opened is part
  of revoking it. The response lists the runs and sessions it ended, and a retry with the
  same key ends nothing twice.
- **What it does not do.** The command's network is not confined: it holds no credential
  for its accounts, but it can reach whatever its host can. MCP traffic never flows through
  the gateway or the launcher.

## Credential health, access templates and emergency access (A258)

- **Credential health.** A brokered account is a provider-backed target: the credential its
  provider holds signs in at the target. Once per `pam.health_check_interval` (default an
  hour), at a slot its name spreads over the interval, the control plane signs in with that
  credential, read from its references at that moment, and changes nothing (PostgreSQL,
  MySQL and ClickHouse run `SELECT 1`; Redis `AUTH` and `PING`; MongoDB a ping; Kubernetes
  reads the API server's discovery document). The outcome class (healthy, rejected, expired,
  locked, unreachable, error) is recorded as `pam.account.health_checked` and shows on the
  target. SSH targets hold no credential: each session's certificate is minted for it.
- **Never a lockout.** A sign-in the server judged and refused (rejected, expired, locked) is
  not repeated with the same credential. The worker keeps a keyed digest of the credential it
  refused and signs in again only when the stored credential changes, or when an operator
  checks the account now (`POST /api/v1/access/targets/{type}/{id}/health-check`, at most once
  a minute). A check that never reached a sign-in exchange (dial, TLS, a timeout) is retried
  twice in its slot. After a restart a failing account's current credential is taken as the
  refused one. Each credential value is therefore refused at most once.
- **Access templates.** A template sets the reason a session request records (the
  requester's note follows it), the approvals it needs (never fewer than the deployment's)
  and its maximum length. The request and the open both apply it, so the reviewed command
  binds them: a template changed or deleted after the review no longer opens the session.
- **Emergency access.** A named responder (a person on the tenant's list, never a bundle run
  or a token minted for someone else) opens a session at once, without the quorum, through
  the same targets and gateways. The grant (`pam.emergency.opened`) and a critical notice on
  the approval channels every approver already watches are recorded before anything is
  granted; a reconciler re-queues a notice a crash left out. The session lasts at most an
  hour. Its post-incident review stays pending until someone other than the responder,
  holding `access:approve`, records it (justified or unjustified, with notes), once.

## Browser sessions (A259)

- **The control plane is the browser's client.** A session opened with `"browser": true` hands
  its one-time ticket to the control plane, which keeps it in locked memory, bound to the
  person who opened it, until the session's deadline. The open's reply, and its idempotent
  replay, carries no ticket: the browser never holds a ticket or a credential.
- **Terminals.** For an SSH session the control plane dials the session's gateway with the
  CLI's verified TLS (the agent CA and the gateway agent's SPIFFE ID), presents the ticket and
  opens a shell over SSH with no client key: the gateway admits by ticket, serves SSH with the
  host key it named over that connection (pinned for the handshake), signs in to the target
  itself, and records and masks as for any session. The browser reads the terminal's output by
  long-polling (`GET .../terminals/{id}/output?from=&wait=`, at most 25 s, a 1 MiB backlog;
  a reader that falls behind is told the output was truncated) and types in idempotent
  batches. Only the session's opener can use its terminals, two at most. Revocation,
  termination or the deadline ends the gateway connection and with it the terminal.
- **Database console.** For a PostgreSQL session the control plane keeps one connection
  through the gateway for the opener (admitted by the ticket; the gateway answers as
  PostgreSQL and signs in upstream as the session's login) and runs one SQL text at a time
  (`POST .../sessions/{id}/queries`, idempotent): the reply holds the last result's columns
  and at most 1,000 rows (a cell beyond 4 KiB is cut and marked), or the database's own
  refusal with its SQLSTATE. The gateway records each statement and its bounded result as for
  a stock client.
- **Kubernetes exec.** For a Kubernetes session a terminal names a namespace, a pod and
  optionally a container and command (default `sh`, at most 16 arguments). The control plane
  admits with the ticket and speaks HTTP to the gateway over that connection, upgrading it to
  the exec WebSocket (`v5.channel.k8s.io`: channel 0 input, 1 and 2 output, 3 the final
  status, 4 a resize); the gateway adds the session's own token and forwards to the API server,
  so the service account's role decides what the exec may do and the control plane never holds
  the token. The exec's exit status (from channel 3) ends the terminal, and the gateway
  records the stream as for kubectl.
- **Reach.** The control plane must reach the gateway's address; a gateway it cannot reach
  serves the CLI only.

## Vaulted accounts (A261)

- A database target with `account_secret` is vaulted: when its gateway claims a session, the
  control plane hands it the application secret's current value (a DSN for the account) in
  place of a per-session lease, so a rotation between a session's open and its claim is
  honored. Revoking or ending the session removes nothing at the database: the gateway's
  recall ends its connections, and the account remains for the next session.
- The secret is kept current by A240's static rotation through the target's provider (the
  target's only role is the secret's role); a two-user rotation stages the other account and
  retires the first, so a session opened afterwards signs in as the new account and the old
  credential is refused.
- **Console.** Request privileged session → "Open in the browser" (an SSH request then sends
  no key: the gateway makes its own); once the session is open, "Open terminal" shows an SSH
  session in xterm.js, loaded on demand, with screen-reader mode on, "Open database
  console" a PostgreSQL session's SQL console with its result table, and on a Kubernetes
  session the pod form (namespace, pod, optional container) opens the same terminal in the
  pod.

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
| A client changing the connection's login (Redis AUTH, HELLO with AUTH, RESET; MySQL COM_CHANGE_USER; MongoDB saslStart, saslContinue, authenticate, logout, a handshake's speculativeAuthenticate; a ClickHouse or Kubernetes client's own credential or impersonation) | Never forwarded: Redis gets a stand-in command the server refuses in its place, MySQL and MongoDB an error from the gateway, a MongoDB handshake loses the field, and an HTTP request loses the header or parameter; the connection keeps the session's login. |
| A host impersonating the SSH target | The gateway accepts only a host key the target registration pins. |
| A gateway asking for more SSH certificates | Each is for a key it holds, for a session job it holds at that attempt, with the session's principal, key ID and deadline; the CA records every one (`ssh.cert.issued`) and revocation covers them all by key ID. |
| A compromised gateway | It holds only the credentials of sessions it is serving, each bounded by its deadline; it cannot mint credentials (only the control plane can, and SSH certificates only through the isolated signer). |
| Another tenant | The gateway is one tenant's agent; jobs, sessions and redemption are tenant-scoped under RLS. |
| An agent asking for an account its task was not given | A run reaches only the accounts its bundles delegate; any other request or open is refused with 403. |
| An agent's credential leaking through its environment, output or logs | The agent never holds one: the launcher keeps the tickets, the gateway signs in, and the command's environment holds no control-plane token. |
| A compromised agent | One call revoking its identity revokes the runs that act as it and ends its live sessions. |
| A health check pushing an account into lockout | A refused credential is signed in with once; the next sign-in waits for a new credential or an operator's check. |
| A browser-side compromise | The browser holds no ticket or credential; a stolen page drives the open terminal only while it lasts, as its opener. |
| A forged emergency grant | Only a named person opens one; the normal open still needs its approvals; the grant and its notice are recorded first; the responder cannot review it. |
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
(`TestServedGatewayMongoSessionsA256`, stock `mongosh`) and ClickHouse
(`TestServedGatewayClickHouseSessionsA256`, curl) and Kubernetes
(`TestServedGatewayKubernetesSessionsOnKindA256`, kubectl on kind): A256 is served. A257 (the
agent launcher) is served: `TestServedAgentLauncherA257` launches an agent with a run that acts
as it, and the agent completes a database task through the gateway with no credential in its
environment, its output, the launcher's output or the gateway's log; an account its bundle
does not delegate is refused; and one call revoking its identity revokes its run and ends its
live session. A258 (credential health, access templates and emergency access) is served:
`TestServedCredentialHealthNeverLocksOutA258` and `TestServedTemplatesAndEmergencyAccessA258`.

## PostgreSQL command guardrails (A262, first protocol)

A template can block a known PostgreSQL operation or hold it for human approval.
These rules also work with session recording turned off. Configure them in the
account folders panel's **Command guardrails** wizard, or replace a template's
`command_rules` through the existing revisioned template API. A folder applies
its template to every account in it. Editing a template changes new sessions;
an existing session keeps the exact revision that its activation approved.
Terminate that session when its existing authority must end. Credential check-out
is refused when the applicable template requires gateway command rules.

Enable `access.gateway.session.rules.v1` explicitly in
`agent_channel.claimable_job_kinds`, upgrade the bound gateway, and keep its
`--access-gateway-listen` enabled. The gateway must report the enforcing job kind
before a rule-bearing session opens. An old gateway cannot claim this kind;
a policy under the ordinary session kind is refused before credential redemption.
SSH exec, MySQL, Redis, MongoDB and ClickHouse guardrails use separate enforcing
job kinds below. Unsupported protocols cannot be configured with these rules.

Each rule has a stable UUID, name, enabled flag, `protocol: "postgres"`, known
`operations`, and `effect: "block"` or `"require_approval"`. A review rule also
requires `required_approvals` (1–3 distinct humans) and `review_ttl_seconds`
(5–45 seconds). The session deadline can shorten that wait. A matching block wins;
otherwise matching review rules use the largest quorum and shortest deadline.
Session auto-approval rules do not vote on commands. The original requester cannot
approve their own command, even if they also hold `access:approve`.

The gateway inspects post-authentication traffic locally. Its matcher and control
plane receive only known matched operation names, rule UUIDs, a connection and
occurrence identity, and one-way message/policy digests. They receive no statement
text, parameters, password, DSN or private key. Review is of an operation class
and the exact occurrence's digest; it is **not** review of arguments or a complete
statement preview. One simple-query occurrence can contain several statements.
The whole batch waits or is refused together. A prepared statement's new Bind is
a new occurrence, checked before upstream planning or parameter conversion. It
needs fresh approval on each binding. Cursor fetches resume the same bound query;
a binding whose unused approval expires must be replaced by a fresh Bind.

The source records `pam.command.blocked` or `pam.command.review_requested`, then
the human request as `pam.command.approval_requested`, and a terminal
`pam.command.review_decided`. The command approval's evidence has a closed public
vocabulary, so identity erasure preserves those facts and keeps consumption aligned
with the canonical request. Its approved grant is consumed in the same projection
transaction as the authorization. A retry compares the retained source event,
including beyond the broker's duplicate window. It cannot change an occurrence's
message, policy, connection, job or attempt. A historical grant does not authorize
a session that is ending or ended.

Read decisions with `GET /api/v1/access/sessions/{id}/actions` or
`trstctl-cli access sessions actions SESSION_UUID --limit 50`. The result pages by
first-observed time and ID. `status` is the recorded source decision;
`effective_status: "review_deadline_elapsed"` means a pending row's deadline
passed without claiming a terminal event. `authorized` means permission to
forward at that time, not successful target execution. The SQL console shows
pending review, its precise deadline, exact approval links and **Cancel query**.
Canceling or closing the client stops a held occurrence. Cancellation cannot undo
a statement already forwarded; check the target before retrying.

When source/audit service or capacity is unavailable, the gateway refuses rather
than forwarding without a durable decision. The fixed refusal marker includes the
public action ID. An offline local refusal log is not a durable source receipt.
The source has its own bounded command pool (four workers, queue 16), separate from
heartbeat and API work. The gateway limits each protocol to eight decision waits
and 8 MiB of held frames, and each target to four waits and 4 MiB. It reserves bytes
before allocating, caps a connection's input queue at 64 frames, statement text at
1 MiB, complete frontend frames at 1 MiB plus 8192 bytes, Bind parameter/format
counts at 1024, and statement/portal caches at 128 each. Unknown or oversized guarded
framing is refused. Guarded Parse/Bind/Close exchanges wait for real backend
acknowledgments and add Flush round trips. Throughput qualification remains owed.

These are lexical guardrails. Comments, ordinary case changes and batches do not
hide a direct blocked keyword; quoted values and identifiers are not commands.
Stored procedures, functions and dynamic SQL can disguise an operation. The served
proof executes `DO $$ BEGIN EXECUTE 'TRUNCATE ...'; END $$` with the same login:
the direct TRUNCATE is refused, while the disguised operation succeeds. Database
privileges provide containment. SQL-level PREPARE/EXECUTE and FunctionCall are
unsupported controls on guarded connections and are always refused; use the
ordinary wire prepared-statement protocol instead. COPY payload data is not
classified as SQL and is excluded from command evidence.

Current source proofs use a real PostgreSQL target, the mTLS gateway channel and
owned session jobs: direct refusal and readback, repeated prepared bindings,
rejected duplicate Parse cache poisoning, two distinct human votes, self-review
refusal, denial, expiry, disconnect, late-vote refusal and the documented bypass.
These are local source proofs. Exact installed-image replay, broader protocol
coverage and the deferred qualification gates remain owed.


## SSH exec guardrails (A262)

Enable `access.gateway.session.rules.ssh.v1` in
`agent_channel.claimable_job_kinds`, upgrade the bound gateway, and wait for its
executor report before opening a session with SSH rules. A PostgreSQL-only rule
gateway cannot claim this SSH job kind. In the template wizard choose **SSH** and
a direct program name such as `rm`, `chmod` or `systemctl`. API rules use
`protocol: "ssh"` and lowercase selectors; `block` and `require_approval` retain
the same precedence, independent quorum and short deadline as PostgreSQL rules.

The guard checks each complete SSH `exec` request before forwarding it. It
recognizes ordinary direct command positions, path basenames, quoting, escapes,
assignments, batches and pipelines. Arguments and quoted nested programs never
become operation facts. Uninspectable frames and here-documents are refused.
A ruled session refuses interactive `shell`, `subsystem` and `env` requests;
it does not pretend to filter keystrokes in an interactive shell. Ordinary SSH
sessions retain their interactive terminal and subsystem support.

A stock client can use `trstctl-cli access connect SESSION_ID` and the printed SSH
command, adding its remote command. A browser session presents an **SSH command**
form. The existing terminal endpoint accepts `ssh_command` (a complete command,
up to 64 KiB), then returns the command's output and exit status. A matching review
rule holds startup while the action list shows the exact occurrence, deadline and
approval link. Closing during review cancels the held action. Closing after
forwarding cannot undo an action that may already have run. Closing stdin alone
is not cancellation: stock exec clients commonly do that before a command ends.

This is a guardrail, not shell containment. `sh -c 'rm /owned/file'` hides `rm`
inside an argument and bypasses an `rm` rule; the same real target login is used
in the served bypass proof. Scripts, aliases, functions, command substitutions,
dynamically constructed program names, wrappers such as `sudo` or `env`, and
commands typed into an already started interactive program can also evade a
specific direct selector. Operators can add interpreter/wrapper selectors, but
only target permissions, restricted accounts and an appropriate target execution
environment provide containment. Program stdin is data, not another command
review input. An authorization record proves permission to forward the occurrence,
not successful target execution.

The target certificate/key and upstream sign-in never pass through this callback.
The control plane receives only configured public operation classes, rule/session
identifiers and digests. Channel count, queued requests, frame bytes and review
calls are bounded; queued frames reserve the shared target/protocol byte budget
before entering the queue. A disconnect cancels review without waiting for the
human deadline. Refused requests leave a fixed recording marker rather than a
recorded claim that the original command executed.


## MySQL text-query guardrails (A262)

Enable `access.gateway.session.rules.mysql.v1` in
`agent_channel.claimable_job_kinds`, upgrade the bound gateway and wait for its
executor report. Choose **MySQL** in the template rule wizard, or set
`protocol: "mysql"` with known uppercase operation selectors through the template
API. Block/review precedence, distinct-human quorum, exact frozen revision and
short review deadlines are the same as the PostgreSQL and SSH guards.

The gateway classifies complete post-authentication `COM_QUERY` statements.
Ordinary comments and quoted values/identifiers are excluded; executable
`/*!...*/` version comments are inspected conservatively, regardless of the
server's version. The lexer considers both backslash string-escape modes.
Operation classes, public identifiers and digests reach command review; statement
text, query values and the injected sign-in credential do not. Login-change
requests are refused before command evaluation. Rules work without recording.

This path currently supports text queries, empty query-attribute envelopes,
`COM_INIT_DB` as the public `USE` operation, `PING` and `QUIT`. Wire prepared
statements, query attributes with values, SQL-level prepared execution and
`LOAD DATA` are explicitly refused in a ruled session. No opaque execute is
silently forwarded. Unsupported one-way controls close the stream because adding
an unsolicited error packet could corrupt the next response. Guarded frames are
bounded at 1 MiB of SQL plus the command byte; oversized or fragmented frames end
the connection. Ordinary unruled sessions retain their existing protocol support.

A bounded reader reserves the shared target/protocol byte budget before allocating
a command body. It detects client disconnect while an action waits. Refused
request/response commands are replaced with fixed invalid SQL in the upstream
wire order, so a local error cannot jump ahead of an earlier pipeline response.
The refused original is never forwarded. Review authorizes that occurrence only;
a repeated text query needs a new review. An authorization record does not prove
target completion. Closing after forwarding cannot undo an already executed query.

Stored program bodies remain a bypass: `CALL app.a262_delete_guardrail()` can
delete a row even when a direct `DELETE` rule blocks it. The served proof uses an
INVOKER procedure and the **same** session login, with independent row readback,
so this is a demonstrated guardrail limit rather than a target-permission denial.
Use database privileges and controlled stored programs for containment.

Protocol references: MySQL's [COM_QUERY envelope](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html),
[prepared execution](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html)
and [executable comments](https://dev.mysql.com/doc/refman/8.4/en/comments.html).


## Redis command-name guardrails (A262)

Enable `access.gateway.session.rules.redis.v1` in
`agent_channel.claimable_job_kinds`, upgrade the bound gateway and wait for its
executor report. In the template wizard choose **Redis** and a known command name,
such as `DEL`, `UNLINK`, `SET` or `EVAL`; the template API uses `protocol: "redis"`.
The gateway checks a complete command before forwarding it, including when
recording is disabled. Human review uses the same distinct quorum, frozen template
revision and short deadline as the other command guards. Repeated identical
commands are separate occurrences and cannot reuse a prior review.

Only the public command class, identifiers and digests reach rule matching and
review. Keys, values, script bodies and authentication material are excluded from
those facts. AUTH, RESET and HELLO with AUTH are refused outside command-policy
evaluation. Scripts and function bodies are not parsed as a series of commands.
An `EVAL` script that invokes `DEL` bypasses a direct `DEL` rule when the same login
has both permissions; the served proof demonstrates this on the real target with
independent key readback. Match the script/function wrapper classes as well when
appropriate; use Redis ACLs for containment.

This ruled path accepts canonical RESP arrays of bulk strings, at most 1024
arguments and 1 MiB for a complete frame. Inline commands, unsupported framing,
unknown command classes and transactions are refused. MULTI/EXEC/DISCARD/WATCH/
UNWATCH end the stream after recording refusal, before a later pipeline tail can
execute with different semantics outside its intended transaction. Ordinary
unruled sessions retain their existing protocol support.

A separate bounded reader detects disconnect during human review. It reserves
the full 1 MiB frame allowance after the array header and before allocating a
body, then wipes/releases it after use. The shared 4 MiB target and 8 MiB protocol
budgets therefore allow at most four started frames per target and eight per
protocol; the queue also has a fixed frame limit. Saturation ends the connection
with a bounded best-effort RESP BUSY error. A connection failure can leave earlier
already-forwarded effects uncertain; cancellation cannot undo those effects.

Normal refusal replaces the original command with a fixed invalid command in the
same upstream wire order. A pipelined GET / refused DEL / GET produces its two
real value replies around the error, preserving the key. An authorization record
permits forwarding and never claims successful target execution.

Protocol references: Redis [RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/),
[transactions](https://redis.io/docs/latest/develop/using-commands/transactions/)
and [Lua scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/).


## MongoDB command-name guardrails (A262)

Enable `access.gateway.session.rules.mongodb.v1` in
`agent_channel.claimable_job_kinds`, upgrade the bound gateway and wait for its
executor report. Choose **MongoDB** in the template wizard, or use
`protocol: "mongodb"` and known lowercase command classes through the template
API. For example, `delete` and `findandmodify` are distinct selectors. Rules use
the same frozen revision, block precedence, independent human quorum and short
review deadline as the other command guards. Recording is optional.

Inspection happens after the gateway's SCRAM sign-in. The classifier receives the
command document's first field name; only its known public class, IDs and digests
reach matching, human review and action evidence. Document values, filters,
sequence documents and the injected credential are not predicates or review
previews. Client sign-in commands never enter rule evaluation. The existing
handshake removes speculative authentication and compression offers before
forwarding; a legacy OP_QUERY is accepted only for that sanitized handshake.

A complete client message is limited to 1 MiB, with a shared target/protocol byte
reservation before body allocation and a bounded disconnect-aware queue.
Compressed messages, other legacy operations, checksum/opaque flag modes,
unknown command classes and transactions are unsupported in ruled sessions.
Transaction fields cause refusal and stream termination before later queued
requests can run outside their intended transaction. Ordinary sessions retain
their existing protocol support. Normal unacknowledged messages remain on the
same guarded command path; a refused one has source evidence but no synchronous
reply, matching the client's choice of unacknowledged operation. Consult session
actions rather than treating lack of an error reply as target success.

A refusal returns a fixed `TRSTCTL_COMMAND_REFUSED` error with the original
request's responseTo correlation. It cannot be confused with a target permission
error. A pending action stays unsent; two distinct approvals release its exact
occurrence. Disconnect cancels it and later votes cannot cause the abandoned
action to run. Authorization permits forwarding, not a claim of target execution.

Equivalent effects can use different commands. A `findAndModify` request with
`remove: true` bypasses a rule naming only `delete`. The served proof uses the
same owned login's remove authority, verifies the document remains after refused
delete, then verifies it disappears through that alias. Aggregation pipelines
and command wrappers need their own selectors; these are guardrails. Target
privileges provide containment. The stock shell's observed `atlasVersion`
request is a public command class; forwarding it does not qualify a hosted service.

Protocol references: MongoDB [wire-message correlation and OP_MSG](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/)
and [findAndModify removal](https://www.mongodb.com/docs/manual/reference/command/findandmodify/).


## ClickHouse HTTP SQL guardrails (A262)

Enable `access.gateway.session.rules.clickhouse.v1` in
`agent_channel.claimable_job_kinds` and confirm the bound agent advertises it.
Choose **ClickHouse** in the template wizard, or use `protocol: "clickhouse"`
and uppercase SQL operation names. The gateway combines the URL `query` prefix
and POST body, including the separating newline, before evaluating a complete
request. It injects the held target login only after evaluation. Authentication
headers and the `user`/`password` parameters never enter the classifier or its
source facts. Action records contain public classes and digests, not SQL text.
A matching block returns HTTP 403 with `TRSTCTL_COMMAND_REFUSED`; a review holds
the request for the same independent quorum and deadline described above.

Supported rule-bearing input is a GET or POST to `/`, with at most 64 KiB of
headers and 1 MiB of combined SQL. Chunked HTTP bodies are fully bounded and
normalized before forwarding. Ambiguous repeated `query` parameters, compressed
or multipart input, `decompress`, SQL `FORMAT` data and `EXECUTE` controls are
refused. These restrictions apply even if no configured operation matches.
Ordinary sessions keep their existing protocol behavior. Use an unruled session
only when its separate authorization and target permissions permit it.

Each started request reserves a bounded byte budget before reading its body.
The reader can detect disconnect behind a complete pipelined request, canceling
held review without forwarding it. Input capacity exhaustion cancels held work
and returns HTTP 503 with `TRSTCTL_COMMAND_CAPACITY_FULL` before closing. Replies
stay in request order. Cancellation cannot undo a request already forwarded.
The review's `authorized` action state grants forwarding; target success still
requires the target response and independent readback.

These are lexical guardrails. Quoted values, identifiers and comments do not
match; functions, dictionaries and other operation classes can produce effects
outside a chosen selector. The served proof grants the exact same target user
both TRUNCATE and ALTER DELETE, blocks direct/mixed-case/split TRUNCATE requests,
and independently checks the row remains. That user's `ALTER TABLE … DELETE`
then removes it outside a TRUNCATE-only rule. Target grants remain the containment
boundary. `TestServedClickHouseCommandRuleBlocksAndRecordsA262` proves that limit;
`TestServedClickHouseCommandReviewWaitsAndCancelsA262` proves two-human release,
disconnect, pipelined disconnect and structured capacity cancellation against
the pinned local ClickHouse 24.8 target with stock curl. This is local runtime
proof, not a hosted-service qualification.

Protocol references: ClickHouse [HTTP query framing and authentication](https://clickhouse.com/docs/concepts/features/interfaces/http),
[SQL syntax](https://clickhouse.com/docs/reference/syntax), and
[ALTER DELETE and synchronous mutation settings](https://clickhouse.com/docs/reference/statements/alter/delete).


## Snowflake SQL API accounts (A263, stand-in proof)

Register a `snowflake` target with its dynamic key-pair provider, allowed provider
roles, `gateway_agent_id` and `gateway_address`. The console registration form
accepts those references and identifies this as stand-in proof. A provider is
configured with its account, SQL API endpoint and administrator key reference;
the existing dynamic-secret outbox creates and grants a fresh user for each
approved session. This target cannot use direct credential delivery. Session jobs
carry only endpoint/authority references; only their exact gateway can redeem the
sealed credential. Rules for other protocols cannot be silently attached here.

Run `trstctl access sessions connect <session-id> --ticket-file <file>` and use the
printed curl command. Send ordinary SQL API JSON such as
`{"statement":"SELECT CURRENT_ROLE()"}`. The client needs no Snowflake password,
key file or bearer token. The gateway strips client authentication and cookies,
then signs a fresh RS256 key-pair JWT expiring no later than the session. Its key
and token use locked, wiped buffers; the bearer bytes are serialized directly,
rather than retained as an immutable HTTP header string. Production upstreams use
verified HTTPS. HTTP is accepted only for the explicitly configured loopback lab.

This transport forwards SQL API submission, status, result-partition and cancel
paths under `/api/v2/statements`; it does not implement the SnowSQL wire protocol
or a browser-console login. Each request has a 64 KiB header bound and 1 MiB body
bound. Target requests use separate connections, close after the response and
cancel with their session. Requests/responses enter the existing masked, encrypted
recording and signed manifest. Termination recalls the gateway job, closes client
connections, and uses the provider's durable disable/drop operation. Closing a
request alone does not prove an already submitted asynchronous statement stopped;
use statement cancellation and confirm native status. Live cancellation and
account behavior remain a Track B proof.

`TestServedGatewaySnowflakeSQLAPISessionsA263` uses stock curl and the existing SQL
API stand-in with real RSA signature verification, key registration and user
removal. It exercises role and direct-login refusal, client-auth replacement,
wrong tenant/ticket, client file/output custody, termination, session expiry,
masked recording and signed verification. Partition/restart recovery and recording authorization/tamper/retention have not
been requalified for this account type on a packaged deployment.
A live Snowflake account is unverified.

Contract references: Snowflake [SQL API key-pair authentication](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)
and [statement submission, status and cancellation](https://docs.snowflake.com/en/developer-guide/sql-api/reference).

## AWS API accounts with STS (A263, LocalStack and stand-in proof)

An `aws` account uses an existing `aws-sts` provider and always binds a gateway.
The provider assumes the configured role through its durable issuance outbox; its
sealed temporary key and session token go only to that session's exact gateway.
The provider also pins the API origin, signing service and region:

```json
"gateway": {
  "endpoint": "https://s3.us-east-1.amazonaws.com",
  "service": "s3",
  "region": "us-east-1"
}
```

The supported services are currently `s3` and `sts`. A binding names one origin,
without credentials, a path, query or fragment. Use separate provider attachments
for different service origins. A requester cannot supply a new upstream host or
signing scope. The existing provider configuration revision participates in the
approval; its gateway configuration is copied before review. A target without
this binding is refused before a request can be approved. The legacy `aws-iam`
provider name does not enable gateway accounts; use `aws-sts`.

Register the account through the console or API with `target_type: "aws"`, its
provider ID, allowed roles and gateway binding. Approve the usual session, then
run `trstctl access sessions connect <id> --ticket-file <file>`. The CLI reads the
service and region from the original tenant-scoped session outbox intent and
prints a command such as:

```sh
aws --no-sign-request --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3api get-object --bucket owned-bucket --key note ./note
```

`--no-sign-request` applies to the local ticket-authenticated tunnel. The gateway
replaces client header/query authentication, signs the exact target method,
path, query, body and required headers with the held STS identity, and sends its
Authorization and session-token headers directly from locked bytes. The client
needs no AWS key or token. SDK or CLI operations that mint new credentials still
need appropriate target IAM restrictions; this gateway does not add containment
beyond the role's actual permissions. Presigned upstream authentication is removed.

Requests are limited to 64 KiB of headers and 1 MiB of body. The API origin uses
verified HTTPS; explicit HTTP loopback is for the lab. Upstream response headers
are bounded, HTTP upgrades are refused, and a session recall closes its live
connections. Recording masks the exact held key/token bytes before converting
request or response data to text, including a credential cut by the recording
head limit. Raw authentication headers are excluded. HTTP handlers finish before
the connection's key buffers are destroyed.

STS sessions have a native minimum lifetime of 15 minutes. Termination recalls
the gateway independently of native credential retirement. With the existing
`revoke_with_deny_policy` opt-in, the provider writes and reads back an inline
Deny for that exact assumed-role session. Without it, revocation remains pending
until native expiry. This does not promise that an already submitted operation
is undone, or that the special `GetCallerIdentity` operation is denied by IAM.
Console handoff is a separate, still-unverified surface.

`TestServedGatewayAWSSTSAccountA263` creates an actual LocalStack role and S3
object, obtains native STS leases and uses the stock AWS CLI without credentials
through the product's API-registered gateway account. Its separately identified
fixture checks the issued SigV4 signature and the role's one-object read grant,
then applies the exact session denial after the real IAM Put/Get policy calls.
The test also calls native STS GetCallerIdentity as its issued role through a
separate provider-pinned STS gateway target. It independently probes the S3
credential before and after denial,
refuses corrupt signatures and unauthenticated/out-of-role calls, closes a live
connection, checks durable revocation, and verifies sealed recording without the
issued key material. LocalStack itself does not enforce IAM. The signature code
also matches the already pinned AWS SDK on public reference inputs. This is
native wire plus stand-in authorization evidence; live AWS enforcement remains
Track B. Packaged-deployment partition/restart qualification is unverified.

Protocol references: AWS [SigV4 canonicalization and temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
and [temporary-credential use](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html).


## Google Cloud API accounts (A263, strict stand-in proof)

A `gcp` target uses the existing prepared-key `gcp-iam` provider. Bind a narrowly
scoped service account and a gateway before approving a session. The provider
uploads the session's public key through its durable issuance outbox; only the
exact gateway can redeem the sealed private key. Add this provider attachment:

```json
"gateway": {
  "endpoint": "https://storage.googleapis.com",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"]
}
```

The API origin has no user information, path, query or fragment. The token URL
and one to sixteen explicit scopes are copied into the reviewed provider binding
and session job. The credential's `token_uri` and client headers never select the
destination or authority. There is no `sub` claim or user impersonation. A target
without the OAuth binding is refused before approval. Register it in the console
or through the API with `target_type: "gcp"`, provider, allowed roles and gateway.
Use `trstctl access sessions connect <id> --ticket-file <file>`, then the printed
stock curl command with the required API path. The client holds no cloud key or
token; this is API access with a service account, and does not implement gcloud's
login state or human Cloud Console sign-in.

The gateway signs an RS256 assertion capped at one hour and the session deadline,
exchanges it at the fixed token endpoint, and holds the returned bearer token in
locked memory. Assertion, key and token scratch are wiped; serialized credential
requests are locked before network writes. Token responses are bounded to 64 KiB
and a positive native lifetime of at most one hour. A connection refreshes an
expired token while its session remains active. API requests have a 64 KiB header
and 1 MiB body bound. HTTPS verifies the target certificate; explicitly enabled
loopback HTTP is for the lab. Client bearer, API-key and forwarding authentication
is removed. Recordings exclude raw auth headers and mask exact held credentials
before text conversion, alongside the existing known-token masks.

Termination closes the gateway's live connections and durably deletes the exact
uploaded key. **Deleting a service-account key does not revoke an access token
already minted from it.** That token retains its native expiry; the gateway's
shorter deadline limits local use only. New keys may take a minute to propagate.
A rejected grant returns HTTP 503 with a propagation/scope retry instruction;
the gateway neither substitutes another identity nor retries without a bound.
Operations permitted to mint other credentials still require native IAM limits.

`TestServedGatewayGCPServiceAccountA263` uses a strict IAM upload/delete, RSA JWT,
OAuth and scoped-resource stand-in, real PostgreSQL/NATS and stock curl. It checks
API registration, tenant/role/ticket refusals, client custody, credential-free API
read, live recall, exact key deletion, rejection of a new grant, and the same
issued token's residual access followed by its native expiry. The recording is
masked, sealed and verified. This does not qualify live Google Cloud, native
gcloud, human console sign-in, or packaged restart/partition and recording
retention/tamper behavior for this type.

Native contracts: [service-account OAuth](https://developers.google.com/identity/protocols/oauth2/service-account)
and [service-account key lifecycle](https://docs.cloud.google.com/iam/docs/keys-create-delete).


## Azure application API accounts (A263, strict stand-in proof)

An `azure` target uses the existing `azure-entra` application's temporary
password. Its add/remove operations run through the durable provider outbox; the
sealed client secret is redeemed only by that session's gateway. Configure one
API origin and one resource scope on the provider:

```json
"gateway": {
  "endpoint": "https://graph.microsoft.com",
  "token_endpoint": "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token",
  "scopes": ["https://graph.microsoft.com/.default"]
}
```

Replace `TENANT` with the same explicit `azure_tenant_id` as the issuer. The token
URL must match that tenant and `authority_host` (default
`https://login.microsoftonline.com`). Shared tenant selectors such as `common`
are refused. The API origin has no user information, path, query or fragment;
the scope is one HTTPS resource ending in `/.default`. The provider's reviewed
configuration freezes origin, authority, application, tenant and scope. User
impersonation and delegated user permissions are not part of this grant.

Register `target_type: "azure"` in the console or API with the provider, allowed
roles and gateway. Approve a session, run `trstctl access sessions connect <id>
--ticket-file <file>`, and use its printed stock curl command with the API path.
The client receives a gateway ticket and holds no Azure password or access token.
This does not implement Azure CLI login or human Azure Portal sign-in.

The gateway encodes the client secret directly from locked bytes into a
client-credentials form, locks the serialized request before network I/O, and
uses verified HTTPS for token and API endpoints. Client bearer/cookie/API-key and
auxiliary identity headers are removed. Token responses are bounded to 64 KiB,
32 KiB of bearer data and a positive `expires_in` of at most 28 hours; local use
always ends by the session deadline. This accommodates token lifetimes longer
than one hour without claiming a shorter native lifetime. Tokens are opaque to
the gateway and are renewed with a new client-credentials grant, without refresh
tokens. API requests have a 64 KiB header and 1 MiB body bound.

Termination closes the live gateway connections and removes the exact issued
application password. Already-issued access tokens retain their native expiry;
password removal is not token revocation. Native application permissions remain
the authorization boundary, including any ability to mint further credentials.
Recordings exclude authentication headers and mask the held secret/token before
text conversion, alongside known-token masks.

`TestServedGatewayAzureApplicationA263` exercises strict Graph add/removePassword,
OAuth and permission-enforcing resource stand-ins with PostgreSQL/NATS and stock
curl. It proves API registration, held credentials, exact form encoding with
special secret bytes, tenant/role/ticket refusals, resource read/permission denial,
live recall, exact-password removal, new-grant refusal versus residual same-token
access and native expiry, real session expiry, and a masked sealed verified
recording. Live Azure, native Azure CLI, human Portal sign-in and packaged
restart/partition/recording authorization/tamper/retention remain unverified.

Native contracts: [client-credentials grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
and [token formats and lifetimes](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).


## Native AWS console handoff (A263, LocalStack and strict stand-in)

An `aws-console` target uses an existing `aws-sts` provider and a separate
reviewed console binding. It can coexist with that provider's API gateway binding;
API origins never select where console credentials are sent:

```json
"console": {
  "federation_endpoint": "https://signin.aws.amazon.com/federation",
  "destination": "https://console.aws.amazon.com/"
}
```

The supported native hosts are the commercial AWS sign-in and console domains,
including their regional subdomains, over HTTPS on port 443. User information,
query strings and fragments are refused. Federation uses `/federation`. An
explicit loopback lab exception supports the stand-in. Other AWS partitions and
arbitrary destinations are unqualified. Register the `aws-console` target with
its provider, allowed role and gateway in the console or API, and approve a
session (STS requires at least 900 seconds). `trstctl access sessions connect
<id> --ticket-file <file>` prints the local browser URL.

The local page names the approved target/role and the capture limits. GET mints
no native credential. Its explicit POST requires a matching loopback origin and
short session/host-bound review proof. It accepts `Idempotency-Key` when supplied,
checks it against the form key, and replays one original mint outcome for that
session. Federation Session JSON and form data are byte-backed, locked before
network writes and wiped afterward. Native sign-in tokens are bounded and held
locked. The second form posts the intended sign-in token directly to the fixed
native endpoint; STS keys never reach the browser. No credential enters a GET
URL, CLI output or gateway recording. Pages disable caching, framing and scripts
and suppress referrers. HTTP headers are bounded to 16 KiB; local forms to 4 KiB;
federation grants to 256 KiB; responses to 64 KiB and sign-in tokens to 32 KiB.

An ambiguous mint failure stays failed rather than blindly minting again. If a
gateway job is reclaimed after losing its in-memory handoff result, a new mint is
refused; open a fresh approved session. A control-plane restart with the gateway
still running does not itself discard that state. Paired-image restart and
partition proofs remain unqualified for this type.

**Recording covers the gateway handoff, not activity or cookies in the native
console.** The signed manifest and recording index/verification report
`scope: "native_console_handoff"`; changing the scope invalidates its evidence.
A `require_recording` access template refuses this type because full native
activity is outside gateway capture. Termination closes the local gateway and
uses the provider's exact-session denial when enabled. Native console credentials
may differ from the input STS key; this does not prove browser logout or native
cookie invalidation. Sign-in-token validity, console-session duration and the
local gateway deadline are distinct. No `SessionDuration` is supplied or shortened
native lifetime inferred from the POST flow.

`TestServedGatewayAWSConsoleHandoffA263` uses native LocalStack STS/IAM plus a
separately identified federation/login and permission stand-in. Stock curl walks
the actual forms without STS keys, with forged origin/proof and rebinding refusal,
one mint under replay, issued-role login, tenant/role/ticket boundaries, local
recall, role denial and custody checks. Handoff-only policy refusal, sealed
recording and offline signed scope are checked. This is not a live AWS, actual
browser-cookie, native sign-in expiry or native-console activity-capture proof.
Google service accounts and Azure application credentials implement API access;
they do not establish a human console login. Compatible human federation remains
unsupported by these provider attachments.

Native contract: [AWS custom identity broker console access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html).

## Remote desktop accounts (A263, xrdp stand-in)

A desktop target uses a vaulted account kept current by a `unix`, `windows` or
`ldap` static-rotation provider. Its one allowed role is the account secret's
name. The provider's optional `desktop` attachment fixes the RDP address,
certificate pin, domain and screen size. Neither the account's stored `host`
field nor the viewer can choose another server.

For example, add this public attachment to a reviewed local-account provider
that already enables static rotation and binds `desktop/operations` to its
managed account:

```json
{
  "desktop": {
    "address": "admin-host.internal:3389",
    "certificate_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "width": 800,
    "height": 600,
    "tls_only": true
  }
}
```

`tls_only: true` is explicit for the tested xrdp server. Omit it for Windows NLA;
the native helper refuses to fall back to TLS-only authentication. Every target
certificate must match the exact DER SHA-256 pin and be currently valid. Native
Windows/NLA and domain sign-in remain unverified by the xrdp proof.

The gateway needs Linux and the optional FreeRDP helper. Build it with the
security-maintained FreeRDP 2.11.x development package and OpenSSL headers:

```sh
sh internal/crypto/rdp/native/build.sh /usr/local/libexec/trstctl-rdp
trstctl-agent --access-gateway-listen 0.0.0.0:8443 \
  --access-gateway-hosts gateway.internal \
  --access-gateway-desktop-helper /usr/local/libexec/trstctl-rdp \
  --access-gateway-desktop-limit 4
```

The helper must be a protected absolute executable. A bounded protocol probe
checks its version and memory protections before the agent reports capability.
Give it sufficient `RLIMIT_MEMLOCK`; it fails rather than accepting credentials
without memory locking or no-dump protection. The helper is a separate process,
not part of the signer. Its password arrives only on a private pipe, never in
arguments or environment. Native owned password buffers are erased after
connection and on failures; complete third-party heap erasure is unmeasured.

Enable `access.gateway.session.desktop.v1` in the control plane's
`agent_channel.claimable_job_kinds`. Gateways without the helper do not claim
that kind. The target's gateway must report the native executor before a desktop
session opens. Encrypted recording storage and audit signing are required. The
native child pool defaults to four connections across the gateway; each desktop
session admits one active viewer. Full pools refuse before upstream sign-in.

Register a `rdp` target with `provider_id`,
`allowed_roles: ["desktop/operations"]`, `account_secret: "desktop/operations"`,
and its `gateway_agent_id` and `gateway_address`. The console offers the same
account-secret and gateway fields. Request and approve a session normally, then
run `trstctl access sessions connect` with its ticket file. The CLI prints the
stock VNC command. RDP runs upstream; RFB 3.8 runs inside the authenticated
mTLS/ticket tunnel downstream. Never expose this anonymous inner RFB endpoint as
a public listener. The viewer receives pixels and input events, not the upstream
password. Clipboard, drive, printer, audio, arbitrary channels and resize are
disabled; BMP Unicode and common navigation keys are supported.

Recording stores lossless PNG tiles with bounded dimensions. Each image is
accepted by recording before it reaches the viewer, so a slow object store
applies backpressure. The signed manifest binds `scope: desktop_pixels`. After
the session ends and the recording seals, its session-detail panel verifies the
manifest and chunk chain, then offers playback and seek. Exports carry the same
replay tiles. On-screen secrets are personal data: text regex masking does not
redact arbitrary pixels. Normal recording access, retention and legal-hold
controls apply. Termination and expiry stop interaction and reap the native
child; they do not prove target logout or stop background applications.

Qualification is **xrdp stand-in proof**: real PostgreSQL/NATS, reviewed provider
routing, two approvals, the stock TigerVNC viewer through the CLI ticket tunnel,
independent input-task readback, live termination, signed/encrypted recording
and decoded replay pixels. The UI renders the native recording export with
verification gating and seek. This does not qualify a Windows server, an AD
forest, native NLA success, third-party memory erasure, or packaged restart and
partition recovery.

Run the owned xrdp lab with `TRSTCTL_DESKTOP_LAB_BASE=<approved-cached-image@sha256:digest> bash scripts/labs/desktop.sh`. The script never pulls an image. It creates one labelled container, installs official Debian packages, runs the native helper and approved-session proofs, retains the signed export and package versions in its printed evidence directory, and stops only that container. This checks xrdp TLS mode; it does not qualify Windows NLA or Active Directory.

### AD native adapter foundation (A263, Samba stand-in)

The LDAP backend has an explicit `active_directory` mode for existing AD user
accounts. Public provider configuration and durable vault rotation are served;
the approved AD-backed desktop journey is described below. It does not turn generic `inetOrgPerson` issuance into an AD logon account.

The adapter pins verified LDAPS to the configured CA and server name, binds with
byte-backed credentials, and reads only the exact configured account. It refuses
unknown accounts, disabled or locked users, expired accounts, incomplete state,
and any nonzero bad-password count. Verification also refuses expired passwords.
It makes one user bind after this check, with no password retries. An administrator
must investigate unsafe state; this adapter does not unlock or enable accounts.
A check is one DC's observation and cannot prevent concurrent failures or prove
forest replication. A stale administrator credential can itself be refused by AD.

Password reset uses Microsoft's administrative `unicodePwd` replacement over TLS.
The bounded quoted UTF-16LE packet is written directly in locked memory and wiped.
Samba's native password grace period accepted a predecessor in the initial proof.
The adapter therefore installs an undisclosed random intermediate password before
the final password, making the immediately preceding password unknown. The native
test preserves the default grace period and password-history/complexity policy;
it proves the previously issued password is refused by stock `ldapsearch` after
rotation. Both replacements belong to the same existing rotation operation. An
uncertain replacement is an error and may leave the account needing recovery;
never assume its previous credential remains usable. Retirement of a paired predecessor also replaces through an undisclosed
intermediate credential. A single-account predecessor has already been replaced;
retirement preserves its live successor. Neither path deletes the user or changes
its memberships. Open sessions and Kerberos tickets are not revoked by
this adapter, and no multi-DC or native Windows result is claimed.

Prepared in-place rotations now freeze both intermediates and the final password
under encryption before any write. Version2 also freezes the actual verified
peer address, DC invocation and password-attribute version. The four native
positions distinguish forward intermediate, final replacement, inverse
intermediate and restored predecessor. A restarted worker proves only its exact
version-selected credential, then advances one position. Recovery from the first
forward intermediate completes the fixed replacement position before the inverse.
Native bad-password checks still prevent candidate retries. Existing version1
preparations remain readable with their earlier verification limits.

The native reset principal also reads rootDSE and Directory Service heuristics.
Constant key-version emulation is refused before preparation. The pinned DC route
and TLS identity remain fixed for the operation. These are observation and
attribution guards, not native compare-and-swap: concurrent outside administrator
resets can race the final read/write gap. External writers need a maintenance
window. The four actual worker-exit tests reload encrypted preparation, check
exact native version counts, then prove current/retired credentials with stock
LDAP. They do not claim power-loss or forest replication qualification.

The native proof runs against a separate owned Samba4.15.13-Ubuntu DC, a DNS-SAN
certificate and a three-attempt lockout policy. After an unrelated bad password
increments `badPwdCount` once, repeated verification calls leave it at one: no
additional target passwords were sent. This cached lab version is stand-in
coverage, not current Samba release qualification. The earlier Samba lab is kept.
See [Microsoft's password-reset protocol](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password)
and [Samba's password grace period](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#OLDPASSWORDALLOWEDPERIOD).

Rerun the isolated adapter proof with approved cached Samba and Debian image pins:
`TRSTCTL_AD_LAB_BASE=<samba-image@sha256:digest> TRSTCTL_AD_CLIENT_BASE=<debian-image@sha256:digest> bash scripts/labs/active-directory.sh`.
It creates a fresh domain and private network, leaves existing domains alone,
retains only public test output and version/policy evidence on the host, and stops
its exact two containers. Private administrator references stay inside the owned
containers. Its printed evidence directory identifies every retained resource.


### Configuring an existing AD account (A263)

Use a tenant-owned LDAP profile with `directory_mode: "active_directory"`,
`allow_static_rotation: true`, verified LDAPS, `password_ref` for the reset
administrator, and `users_dn` bounding existing managed users. Each allowed role
is its vaulted secret name and maps in `role_bindings` to one account DN.
An optional `rotation_accounts` pair alternates between two existing users.
Memberships are assigned by the directory administrator and stay unchanged.
The configured account and pair bindings are frozen for review; shared principals
between roles are refused before any password operation. This profile does not
issue arbitrary AD user leases.

For one account, rotation replaces the password in place. The API requires
`acknowledge_single_phase: true` and warns that applications can lose access until
they adopt the new secret version. Use the ordinary secret store and
`POST /api/v1/secrets/rotations` with the profile ID, secret key and account DN as
`old_ref`. The durable outbox resets the password, publishes the encrypted secret
version, verifies a fresh native bind and records completion. Reusing an
Idempotency-Key returns the original operation. Retirement of this single-account
predecessor preserves the successor that the rotation has already installed.

`TestServedADAccountRotationA263` proves this path with real PostgreSQL/NATS,
two rotations and stock LDAP readback, cross-tenant refusal and no plaintext
passwords in events. The rerun script now runs this served proof alongside the
native adapter proof in its isolated domain. This is assisted Samba stand-in
qualification. Final-image interruption/recovery remains owed; ordinary Windows/forest
deployment is unverified. The AD-backed desktop proof below is a local stand-in.


### Approved AD-backed desktop (A263, Samba and xrdp stand-in)

Add the existing `desktop` route to the explicit AD profile and set
`ad_logon_names` to a map from every managed account DN to its exact bare RDP
logon name. Include both members of a configured rotation pair. The `rdp` target
still names one vaulted `account_secret`, its one allowed role, gateway and fixed
RDP route/pin. The provider freezes only that role's account identities into the
session job. The gateway requires the vaulted `bind_dn` and `username` to match
one frozen identity before starting native authentication. A different role's
account, changed logon name or missing directory reference is refused.

Enable `access.gateway.session.desktop.ad.v1` in the control plane's
`agent_channel.claimable_job_kinds`. The named gateway must report this executor
without missing flags, with its access listener and checked native helper. This
separate version prevents an older desktop agent from ignoring AD identity fields.
The existing `access.gateway.session.desktop.v1` continues serving local desktops.
Live termination recalls both native versions by tenant and persisted session key,
so changing provider configuration cannot select the wrong recall destination.

The native proof uses Samba AD and xrdp with **LDAP-only PAM authentication**.
The local Unix password is locked; a limited directory reader locates the account,
and PAM binds as that account over verified LDAPS. A stock viewer executes a task
whose independently read file identifies the actual Unix session user. Normal
approval, tenant/gateway binding, private credential delivery, live termination,
and signed encrypted pixel replay use the existing served paths. The isolated
`active-directory.sh` script now reruns native password checks, durable vault
rotation and this desktop journey. It retains the synthetic replay export and
public version/policy results, then stops only its own two containers.

This is an LDAP-backed Linux desktop stand-in. It is not a domain-joined Windows
or NLA qualification. Directory lockout-state inspection currently applies to
rotation verification; it is not a forest-wide or cross-session RDP lockout
preflight. Pixel redaction, target logout, surviving background work, current
Windows/forest interoperability and final paired-image recovery remain outside
this proof. Shared authorization/recording controls and deferred broad gates
are owed at FINISH. Docker's default address pools need not be free: the script
allocates a bounded isolated /28 from 10.254.253.0/24, refusing overlaps; an explicit
`TRSTCTL_AD_LAB_SUBNET` can select another owned private subnet.

The AD dependent coordinator is host work, separate from gateway session authority.
Its parent freezes complete signed inventory, exact native identity, provider and
vault generation, restart order and local functional probes. The parent and sealed
child share one canonical operation identity, so deleting a projected parent link
cannot downgrade the work into ordinary static rotation. Each effect has a
canonical queued event, exact enrolled-host outbox grant and stable first signed
observation. A mutable SQL success cannot authorize the next effect or become
served verified evidence. Worker cutover and predecessor-process selection compare
all used results to those canonical sources. A completed source also refuses a
new claim or credential redemption after operational-row reconstruction.

Read-only SID inventory grants and exact native write/probe grants are separate.
Passwords are redeemed only for an active exact update step, from its sealed
forward or inverse generation, and wiped after native use. Service/pool stop,
update, start and useful-work phases are distinct. Tasks preserve a sealed start
fence and exact native instance; no uncertain start is automatically repeated.
Known completed failed instances are archived with their evidence before a
separate inverse. The parent restores native effects before publishing vault
recovery, and preserves an unrelated concurrent vault edit as an explicit conflict.
The Windows local SAM fixture and directory/host boundary fixtures have separate
qualification limits; neither establishes an AD forest deployment.


### Local administrator inventory boundary

The local-account reader enumerates the local Administrators alias by its built-in
SID, so a translated group name does not change what it reads. It keeps local
account SIDs, names and account flags; foreign members and nested groups are
counted separately. Domain controllers are refused because their account database
is the directory, rather than a member host's local SAM.

The host inventory wire contract binds one tenant, enrolled host and run. Its
report carries either complete public metadata or a bounded unavailable reason.
Unknown fields, duplicate fields, Unicode key aliases, malformed Unicode escapes,
foreign SAM prefixes and partial failed reads are refused. The independent native
reader has one worker slot and a thirty-second deadline. The operator-owned host
profile's `windows_local_accounts_inventory` grant permits only this read; it
adds no file roots, commands, credential redemption or password-write authority.

Host inventory is exposed through source-backed API and CLI commands. Native
Windows execution, scheduled password rotation and checkout-driven invalidation
remain separate proof obligations. The console selects an enrolled host and
reviews its exact signed inventory result.


### Local account password execution boundary

The native password primitive binds a member machine's local SAM and the exact
administrator account SID, name and flags. It reads the local password and lockout
policies before a reset and before authentication. Unknown failure counters,
locked accounts and insufficient remaining failure budget refuse execution; the
primitive never unlocks an account or changes its policy. Success requires a
network logon with the successor whose token names the exact SID, followed by one
refusal of the predecessor. A successful reset alone is insufficient evidence.

Password generation shares the existing Windows account policy. Private UTF-8
bytes are copied into locked memory and encoded directly into a locked, terminated
UTF-16 buffer for synchronous native calls. No password string, shell argument,
command script or plaintext journal is constructed. Every native buffer is
explicitly destroyed after use.

The caller must durably record the generation's start before the first native
write and retain the resulting public proof before publishing success. A started
attempt is never blindly reset or authenticated again after an uncertain outcome.
Native APIs address a local account by name: SID checks before and after each
phase detect observed changes but do not provide an atomic SID compare-and-set.
A trusted local administrator can still race a rename between those calls.

The owned Windows fixture covers two account contexts on one operating system.
Cross-compilation is separate from execution. Prepared credential transport,
enrolled fleet scheduling, checkout invalidation and offline return each require
their own integration and runtime evidence.

The agent's existing sealed report store also retains local account execution.
Each local SID has one bounded record containing its exact job, generation,
machine/account binding and start phase. The file is flushed before native work;
a completed proof is flushed before the caller can publish success. A retry reads
that exact proof without redeeming credentials or probing either password again.
A started attempt without a retained proof remains uncertain after restart and
after acknowledgment of a failed report.

Successful report acknowledgment preserves the latest public proof as a replay
fence. Only a distinct generation explicitly naming the acknowledged generation as its
predecessor can replace it. Recreated delivery IDs replay the original proof;
older ancestry and changed authority cannot reset the account again. Delivery
ordering never depends on a database-local outbox identity.
Independent accounts have independent queue order. The private child directory
holds at most 5,000 identity records; each record has a fixed byte bound, and
retired SID fences are preserved rather than silently evicted. Missing keys,
foreign registration bindings, invalid files and damaged ciphertext refuse work
without discarding evidence. Password bytes are never serialized into this
journal. Windows power-loss durability still requires native filesystem
qualification; flushing files does not establish that qualification.


### Enrolled local account execution transport

A native password job carries only public identifiers: tenant, enrolled host,
vaulted account, complete inventory run, exact local SAM/account binding,
rotation generation and predecessor host generation. Its digest commits to all
of those fields. A queued operation has no expiry merely because its host is
offline; a live claim lease and credential authorization bound execution when
the host returns. Native proof reports remain separate from delivery success.

The operator-owned host profile grants `windows_local_account_writes` as exact
`tenant_id`, `agent_id`, `machine_sid` and `account_sid` tuples. A SID is Windows'
stable account identifier. There are no wildcard tuples. Read-only inventory,
file roots, shell commands and domain-account membership grant no native password
write. The agent independently compares the intent's tenant and host with its
current client certificate before redeeming anything. An unsupported operating
system refuses execution before credential redemption.

One worker accepts native local account rotation; overlapping work rejects
promptly. It reads the durable journal first. A retained proof is reported with
its original observation time without another password redemption, reset or
login. An uncertain start remains fenced. A fresh execution redeems exactly the
predecessor and successor password byte fields for that claim, checks their
expiry, locks their buffers and wipes every wire copy. Duplicate, empty or extra
credential names refuse execution; rejected replies are wiped in full before
reporting. Locked password buffers are destroyed when the native phase returns,
before terminal-report network I/O. The
credential deadline further shortens the native execution context.

Only the public native proof is signed and retained in the existing sealed
terminal-report store. Server refusal or restart keeps the original report and
blocks new claims until acknowledgment. Exact acknowledgment also advances the
native generation journal; a successful RPC alone cannot manufacture native
proof absent from that journal. The transport fixture uses real mutual TLS and
verifies detached signatures, with a separately identified native-effect adapter.
It does not qualify the control-plane queue/broker, scheduled or checkout-driven
fleet lifecycle, or native Windows execution. Those require their own proofs.
