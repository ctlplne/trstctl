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
SSH exec guardrails use a separate enforcing job kind, described below. The other
database protocols remain unsupported for rules and are rejected when configuring
one. Their ordinary sessions retain their existing behavior.

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
