## [Unreleased]

### Added

- Orphaned and unused accounts (A276 part 2): brokered accounts are flagged orphaned (no owner, owner deleted, owner
  offboarded) or unused past `pam.unused_after` (default 90 days) by the PAM worker or `POST
  /api/v1/access/account-flags/scan`; `reassign` and `rotate_disable` actions are proposed for approval, applied once
  with the approval consumed, and read back on the flag and the target. Migration 0430, snapshot format 109, CLI
  `access account-flags list|scan|propose|apply` (CLI 858 -> 862, OpenAPI 791 -> 795), console **Orphaned and unused
  accounts**.
- Owners of brokered accounts (A276 part 1): every privileged access target is an NHI inventory record
  (`pam-account/<type>/<id>`, kind `privileged_account`, `privileged_account_records` in the record summary), so
  ownership assignments name its owner; targets read `owner_id` back; the console's targets table shows owners and
  assigns them.
- Recording search (A275 part 3): `GET /api/v1/access/recordings/search` (`searchPAMRecordings`, OpenAPI 790 -> 791),
  `trstctl access recordings search` (CLI 857 -> 858) and the console's **Search session recordings** search the tenant's
  recordings — SSH commands and output, SQL statements and results, desktop indexes; never typed input — within bounds,
  with masked results; every search is recorded as `pam.recording.searched` with its query masked.
- Risk categories (A275 part 2): command rules for PostgreSQL, MySQL and SSH can name `CREDENTIAL_READ`,
  `AUDIT_TAMPERING`, `BULK_DELETE` and `PRIVILEGE_CHANGE` (lowercase for SSH), which the gateway reads from the
  statement's tokens or the command's programs, flags, paths and redirections (through `sudo`-style wrappers); only
  the category name leaves the gateway. Any effect applies: alert, block or review. The console groups them apart
  from operation names.
- Session risk alerts (A275 part 1): command rules gain the `alert` effect with a `warning` or `critical` severity. A
  matching command runs once its `alerted` decision is durable, and its projection queues a `pam.session.risk` alert on
  the `notification.risk` channels naming the operations, target, person, rule and action, with the console link
  `/admin/access?session=<id>` that opens the session and its recording; the recording marks the action. The console's
  rule editor offers Alert and its severity, session actions show "Alerted; allowed to run", and the access page opens
  a linked session.
- Bypass detection on MySQL (A274 part 3): a MySQL connection, dated when a run first sees it, keeps one fingerprint
  while later runs see it still open (its connection id and the server's start), so a held outside connection raises
  one finding and one recorded sign-in rather than one per run; served proof against MySQL 8.4.
- Recorded sign-ins (A274 part 2): every sign-in bypass detection reads is recorded, metadata only, with the verdict of
  the run that first read it (what explained it, or nothing); `GET /api/v1/access/signins` (`listPAMSignIns`, OpenAPI
  789 -> 790 operations), `trstctl access signins list` (CLI 856 -> 857 commands) and the console's **Sign-ins to
  managed accounts** list them; `pam.signin_retention` (default 90 days) purges them while their findings stay.
- Bypass detection (A274 part 1): a `pam_signin` discovery source reads a provider's managed accounts' sign-ins through
  its administrator connection (sshd journal and auth logs, Windows logon events over OpenSSH, PostgreSQL, MySQL and SQL
  Server current sessions), explains each by a session, check-out, rotation or health check, and records each
  unexplained one as a `compromised_credential` finding. Discovery source catalog 25 -> 26 kinds; the console's
  Discovery source form creates it.
- Gateway sessions from the console (A273 console): the privileged session dialog requests every gateway session type
  (Redis, MySQL, MongoDB, ClickHouse, Snowflake, cloud APIs, the AWS console, remote desktop, network devices, web
  consoles), not only PostgreSQL, SSH and Kubernetes; an opened gateway session shows the CLI connect command and its
  one-time gateway ticket on request. The browser option is offered only for the types the browser opens itself.
- Emergency access (A258 console): an Emergency responders panel names the responders; the session dialog opens a
  session at once as a named responder after a confirmation that every approver is notified (a reason is required);
  post-incident reviews are recorded from the emergency grants table.
- Internal web admin consoles (A273 fix): the published session request, approval, activation and emergency session
  schemas admit `webconsole`, which the API already served.
- Break-glass accounts (A272 console): the access targets panel registers `breakglass` targets; a new Break-glass
  accounts panel releases one as a named responder after a confirmation that every approver is notified, shows its
  username, password, one-time code and hardware key holders once, checks it in, and lists emergency grants with another
  approver's post-incident review. Reviewed check-outs no longer offer break-glass or web console accounts.
- Accounts rotated in place (A271 console): the access targets panel registers `account` targets — an `esxi`,
  `vcenter-sso`, `redfish` or network device provider and one account secret, with no gateway fields — for check-out.
- Windows local administrator accounts (A268 console): the access targets panel registers `windows_local` targets — a
  native `windows` provider and one account secret, with no gateway fields — for check-out.
- Internal web admin consoles (A273 part 3): the console registers `webconsole` targets (account secret, https origin,
  CA, certificate name) and sets an access template's web sign-in (mode, sign-in page and fields or header, browser
  cookies). The served proof can hold its session open for a real browser (`TRSTCTL_A273_BROWSER_DIR`).
- Internal web admin consoles (A273 part 2): `webconsole` access targets vault a console's account and name its route
  (`web`: origin, CA, server name; loopback only with `pam.web_console_allow_loopback`); access templates set
  `web_sign_in` (`form`, `header` or `basic`, and `browser_cookies`), bound into the reviewed request and kept on the
  session; `trstctl access sessions connect` prints the address to open in a browser. The account cannot be checked out.
  The gateway refuses a console name that resolves to its own host or a link-local address. Migration 0428.
- Internal web admin consoles (A273 part 1): the access gateway serves `webconsole` sessions (agent job kind
  `access.gateway.session.web.v1`): it signs in for the operator through the console's own sign-in form, a header token or
  HTTP basic authentication, keeps the console's cookies, masks the credential out of every page and records each request
  and response, masked. The browser never receives the credential.
- Break-glass identity provider accounts (A272 part 3): the credential health worker checks each break-glass account's
  vaulted password once per interval with the identity provider's non-interactive sign-in (Okta, Entra ID; Google reads
  not supported) and never repeats a refused password, so a check never trips a lockout.
- Break-glass identity provider accounts (A272 part 2): `breakglass` access targets are released only through emergency
  access (`POST /api/v1/access/emergency-checkouts`, `trstctl access emergency checkout`): a named responder, once, every
  approver notified, the password plus the current TOTP code of the account's `totp` provider (never the seed), the
  hardware security key holders the provider records (`totp_providers`, `hardware_key_holders`); check-in rotates it. New
  event `pam.checkout.emergency_released`; migration 0427. OpenAPI census 788 -> 789, CLI 855 -> 856.
- Break-glass identity provider accounts (A272 part 1): `okta-user`, `entra-user` and `google-workspace-user`
  dynamic-secret providers rotate super administrator passwords through each provider's administration API, proved by one
  non-interactive sign-in where the provider has one (never retried). Provider catalog 53 -> 56 recipes.
- Account check-outs (A271 part 4): `account` access targets vault an account its provider rotates in place (ESXi,
  vCenter single sign-on, Redfish controllers, network devices); they are checked out, never opened as sessions, and
  check-in rotates them. Migration 0426.
- Hypervisors (A271 part 3): a `vcenter-sso` dynamic-secret provider resets vCenter single sign-on users' passwords
  with `dir-cli` in the appliance's root shell (administrator password only at its prompt) and proves each reset with a
  vSphere Automation API session; discovery lists the SSO Administrators group. New config field `sso_admin`. Provider
  catalog 52 -> 53 recipes.
- Hypervisors (A271 part 2): an `esxi` dynamic-secret provider rotates ESXi local account passwords through the vSphere
  Web Services API (`UpdateUser`, proved by signing in), never `vpxuser` or `dcui`, single-phase with acknowledgement and
  rollback; discovery lists local users with their roles. Provider catalog 51 -> 52 recipes.
- Server management controllers (A271 part 1): a `redfish` dynamic-secret provider rotates controller account passwords
  through Redfish's AccountService (HPE iLO first), proved by a new session on the new password, single-phase with
  acknowledgement and rollback; discovery lists accounts with their RoleId. Provider catalog 50 -> 51 recipes.
- Network devices (A270 part 3): `netdevice` access targets broker SSH sessions to a device account its provider rotates;
  the gateway signs in with the vaulted password (new job kinds `access.gateway.session.netdevice.v1` and
  `access.gateway.session.rules.netdevice.v1`), sessions are recorded, and `netdevice` command rules block device verbs
  by abbreviation. `eos`, `fortigate` and `bigip` providers take an optional SSH `addr` and `host_key_fingerprint` for
  sessions. Console registration; migration 0425.
- Network devices (A270 part 2): `eos`, `fortigate` and `bigip` dynamic-secret providers rotate device account passwords
  (and the EOS enable password) through eAPI, the FortiOS REST API and iControl REST over HTTPS with the device's
  certificate pinned, single-phase with acknowledgement and rollback; discovery reads all three. Provider catalog
  47 -> 50 recipes.
- Network devices (A270 part 1): `iosxe` and `junos` dynamic-secret providers rotate local account passwords (and the
  IOS-XE enable secret) through the device's CLI over SSH, single-phase with acknowledgement, keeping each account's
  privilege level or login class and rolling an unproven change back; privileged account discovery reads both.
  Provider catalog 45 -> 47 recipes.
- Remote desktop (A269 part 2): access templates gain `desktop_clipboard` (deny, to_target, from_target, both); the
  reviewed policy reaches the gateway and its native helper loads the RDP clipboard channel only for an allowed
  direction (bounded, indexed by length). Sessions now return the approval they consumed when read back. Migration 0424,
  snapshot format 107.
- Remote desktop (A269 part 1): a viewer's clipboard is refused without ending the desktop session (its text is never
  forwarded and the refusal is indexed without content), and desktop recordings carry a searchable index
  (`GET /api/v1/access/sessions/{id}/recording/index?q=`, `trstctl access sessions recording-index`). OpenAPI census
  787 -> 788, CLI 854 -> 855.
- Windows local administrator check-outs (A268): a vaulted local administrator account registered as a `windows_local`
  access target (its native `windows` provider and account secret) is checked out through A261 — reviewed, revealed
  once, never opened as a session — and checking it in, or its deadline, queues its in-place native rotation, which an
  offline host runs when it returns. Migration 0423 admits the target type.
- The Change sets template selector truncates its closed label within the field in WebKit,
  keeping mobile pages within their viewport while retaining every full option name.

- Automatic access approvals can match exact target/folder scope, authenticated roles, a local
  time window, a whole-reason ticket pattern and a maximum lifetime. Rules record a policy vote
  and matched facts; nonmatches keep human review. Console review, revisioned API and CLI edits
  apply prospectively. Durable evaluations preserve one decision and the original expiry across
  retries and rule edits; emergency-session access never uses automatic approval.

- Account folders apply one access template to every registered target's session requests and
  check-outs. Requests cannot select another template, and changed policy revisions require a new
  review. Templates can require recording, refusing direct sessions and credential check-outs.
  The console manages folders, membership and recording rules; CLI `access folders` and
  `access targets folder` use the same tenant-scoped, event-sourced API.

- Access gateway, PostgreSQL (A254 part 1): a PAM PostgreSQL target can be bound to a gateway-role agent
  (`gateway_agent_id`, `gateway_address`); a session to it returns a one-time ticket and the gateway's identity,
  never the credential. The gateway (`trstctl-agent --access-gateway-listen`, new `gateway` role) claims the
  session as an agent job, redeems its login into locked memory, admits only connections carrying the ticket,
  and signs in upstream itself; `trstctl-cli access sessions connect` tunnels a stock client to it over TLS
  verified against the agent CA for the gateway's host and its SPIFFE ID (the agent CA signs a gateway's
  serving certificate only for hosts its own target bindings declare). Revoking the session recalls its job, so
  the gateway ends its connections. The gateway's PostgreSQL sign-in is its own (`internal/crypto/pgsignin`:
  SCRAM-SHA-256, MD5 or cleartext as the target demands, TLS always verified), so the agent binary links no
  database driver. Design and threat model: `docs/design/access-gateway.md`.
- Access gateway, SSH (A254 part 2; A254 is served): an SSH target bound to a gateway pins the host keys it
  accepts (`host_key_fingerprints`). The gateway generates each session's key in locked memory and the tenant
  SSH CA certifies it for the job the gateway holds (`SignJobSSHKey`: key ID `pam:<session>`, the session's
  principal, ending at its deadline, terminal only); stock `ssh` with no key reaches the target through
  `trstctl-cli access sessions connect`, which writes the gateway's host key to a known_hosts file. Shell, exec
  and SFTP are relayed; forwarding is refused. Revoking the session puts its key ID on the served KRL.
- Session recordings (A255 part 1): with an object store, tenant sealing and the audit signing key, the gateway
  records every session — SSH bytes and requests, SFTP as operations without file contents, PostgreSQL statements
  with bounded results — masking the session's credential and well-known token shapes before anything leaves it.
  Chunks upload in order with backpressure (`UploadSessionRecording`), are sealed for the tenant into the object
  store and chained, and the recording closes with a manifest signed by the audit key;
  `GET /api/v1/access/sessions/{id}/recording` and `.../recording/verify` read and check it.
- Recording access, live termination and retention (A255 is served): `recordings:read` plays recordings back and
  watches live sessions (`.../recording/frames?wait=`, `trstctl access sessions watch`), `recordings:export` exports a
  recording with its signed manifest and places legal holds, and every read is recorded. `access:terminate` ends a live
  gateway session; the gateway's end report acknowledges it, and until then the session reads `uncertain_until` its
  native deadline. `pam.recording_retention` deletes sealed recordings unless a legal hold keeps them.
- Redis sessions through the access gateway (A256 part 1): a `pam.database_targets` entry or tenant registration of
  `target_type: "redis"` names a Redis dynamic-secret provider and a gateway, which is required. The gateway redeems
  the session's own ACL user, signs in with AUTH itself (`internal/crypto/redissignin`; `rediss://` verified against
  the system roots) and relays a stock client's RESP commands; AUTH, HELLO with AUTH and RESET are never forwarded
  (a command the server refuses goes in their place, so the refusal arrives in order and the connection keeps the
  session's user). Recordings hold each command and each reply's type with bounded, masked values; a refused
  command is recorded by name only. `trstctl-cli access sessions connect` prints the `redis-cli` command. Migration
  0392 admits Redis targets; PostgreSQL targets' approval digests are unchanged.
- MySQL sessions through the access gateway (A256 part 2): `target_type: "mysql"` names a MySQL dynamic-secret provider
  and a gateway. The gateway answers a stock client's handshake itself (no TLS, any password), signs in upstream as the
  session's account with the client's capability flags (`internal/crypto/mysqlsignin`: caching_sha2_password fast
  path or full authentication to the server's RSA key, mysql_native_password on an auth switch), and refuses
  COM_CHANGE_USER. Recordings hold statements, column names, the first rows of each result, OK counts and error codes,
  bounded and masked. `trstctl-cli access sessions connect` prints the `mysql` command; migration 0393 admits MySQL
  targets.
- MongoDB sessions through the access gateway (A256 part 3): `target_type: "mongodb"` names a MongoDB dynamic-secret
  provider and a gateway. The gateway signs in as the session's user with SCRAM-SHA-256 (`internal/crypto/mongosignin`,
  with the SCRAM client now shared with the PostgreSQL sign-in in `internal/crypto/scram`), refuses a client's own
  sign-in (saslStart, saslContinue, authenticate, logout) with Unauthorized, removes a handshake's
  speculativeAuthenticate and compression offer, and records commands and replies, bounded and masked.
  `trstctl-cli access sessions connect` prints the `mongosh` command; migration 0394 admits MongoDB targets.
- ClickHouse sessions through the access gateway (A256 part 4): `target_type: "clickhouse"` names a ClickHouse
  dynamic-secret provider and a gateway; the session's job names the provider's endpoint (`upstream_url`). The gateway
  serves ClickHouse's HTTP interface, removes every credential a client sends (basic auth, X-ClickHouse-User/Key,
  certificate-auth headers, user/password parameters) and signs each request in as the session's user; requests and
  responses are recorded with bounded, masked bodies that stream. `trstctl-cli access sessions connect` prints the curl
  command; migration 0395 admits ClickHouse targets.
- Kubernetes sessions through the access gateway (A256 part 5; A256 is served): `pam.kubernetes_targets` (or a tenant
  registration of `target_type: "kubernetes"`) names a Kubernetes dynamic-secret provider and a gateway; the session's
  job names the API server, its CA and server name. The gateway adds the session's TokenRequest token to every request,
  removes a client's own credential and impersonation headers, relays exec/attach/port-forward upgrades, and records
  API calls plus remote-command streams (stdin, stdout, stderr; masked). `trstctl-cli access sessions connect` writes a
  kubeconfig naming the tunnel and no user; migration 0396 admits Kubernetes targets. SQL Server moves to the x86
  block; Oracle sessions are recorded as what comes next.
- Agent launcher (A257): an access bundle names the privileged accounts its runs may reach (`access_targets`; a run
  is refused any other with 403), and the new `access:sessions.open` permission (request, open and revoke one's own
  sessions; `access:write` includes it) is what a bundle carries for it. `trstctl-cli access agent --account
  TYPE/ID:ROLE ... -- <command>` requests and opens each account's session through its gateway after its reviews,
  serves the tunnels from its own process and runs the command with instructions (`TRSTCTL_ACCESS_INSTRUCTIONS`,
  `TRSTCTL_ACCESS_<n>_ADDR`, `PGHOST`/`PGPORT`, ...) and no credential: every `TRSTCTL_*TOKEN*` variable is removed
  from its environment and the gateway signs in. Its sessions are revoked when it exits. An unattended run minted for
  an agent's ID acts as the agent, and revoking the agent's broker identity (Q4) now also revokes those runs and ends
  every live session the agent opened; the response lists them (`BrokerAgentIdentityRevokeResult`). Migration 0397
  adds `access_bundles.access_targets`. `access sessions connect` now prints a `psql` line for PostgreSQL sessions.
- Credential health, access templates and emergency access (A258; A258 is served): every provider-backed PAM target's
  stored credential is signed in with once per `pam.health_check_interval` (default an hour, spread by target name),
  read-only, and its health (healthy, rejected, expired, locked, unreachable, error) shows on the target; a credential the
  server refused is not tried again until it changes or an operator runs `access targets health-check`, so no check adds
  a second failed sign-in. Access templates (`/api/v1/access/templates`) set a request's reason, its approvals (never
  below the deployment's) and its maximum length. Named emergency responders (`/api/v1/access/emergency/responders`) open
  a session at once (`POST /api/v1/access/emergency-sessions`, an hour at most); every approver is notified on the
  approval channels and the grant's post-incident review stays pending until someone else with `access:approve` records
  it. Migration 0398 (credential health, templates, responders, emergency grants), snapshot format 90, OpenAPI census
  719 -> 730, CLI census 786 -> 797.
- Browser sessions, part 1 (A259): a session opened with `"browser": true` leaves its ticket with the control plane
  (locked memory, bound to its opener, until its deadline) and the reply carries none. For an SSH session the control plane
  opens a shell through the session's gateway (`POST /api/v1/access/sessions/{id}/terminals`; output by long-poll, typed
  input in idempotent batches, resize, close), and the console shows it in a terminal (xterm.js, loaded on demand, with
  screen-reader mode) from Request privileged session → "Open in the browser". The gateway still signs in, records and
  masks. OpenAPI census 730 -> 735.
- Browser sessions, part 2 (A259): a PostgreSQL session opened for the browser gets a database console (`POST
  /api/v1/access/sessions/{id}/queries`, idempotent; the last result's columns and at most 1,000 rows, or the database's
  refusal with its SQLSTATE) run by the control plane through the session's gateway, which signs in, records and masks.
  The console's "Open in the browser" now covers both target types; "Open database console" shows the SQL console.
  OpenAPI census 735 -> 736.
- Brokered-account lifecycle, part 1 (A261): a PostgreSQL or MySQL PAM target registered with `account_secret` is
  vaulted — its sessions go through its gateway signed in as the account that application secret holds (read when the
  gateway claims the session), so nobody receives the credential and nothing is minted per session. The secret is an
  A240 static credential its provider rotates; a rotation schedule rotates it, and sessions opened afterwards sign in
  with the new credential while the old one is refused. Migration 0401 (`pam_targets.account_secret`).
- Brokered-account lifecycle, part 2 (A261): check-outs of vaulted accounts. `POST /api/v1/access/checkouts` requests
  independent review; once approved its requester reveals the account's current credential once
  (`/api/v1/access/checkouts/{request_id}/reveal`, audited as `pam.checkout.revealed`, a second reveal refused);
  checking it in (`.../checkin`) or its deadline queues the static rotation that retires the revealed credential. The
  console's access page gains a check-out panel. Migration 0402 (`pam_checkouts`), snapshot format 93, OpenAPI census
  747 -> 752, CLI census 814 -> 819 (`access checkouts request|reveal|checkin|list|get`).
- Privileged account discovery, part 2 (A260 served): Active Directory users through the LDAP provider (transitive
  members of the groups that administer the domain, protected users); staged accounts are imported into a folder only
  after independent review (`/api/v1/access/discovery/imports`, applied with the approval; refused when an account
  changed since its review) and importing grants nothing; a staged account can be dismissed with a reason
  (`/api/v1/access/discovery/accounts/{id}/dismiss`); `GET /api/v1/access/accounts` lists imported accounts. The
  console's access page gains a discovery panel. Migration 0400, snapshot format 92, OpenAPI census 743 -> 747, CLI
  census 810 -> 814 (`access discovery import request|apply`, `access discovery dismiss`, `access accounts`).
- Privileged account discovery, part 1 (A260): a dynamic-secret provider becomes a discovery source
  (`/api/v1/access/discovery/sources`, on demand or every hour or more); a scan reads its target read-only through the
  provider's administrator connection and stages the privileged PostgreSQL roles, MySQL accounts, SQL Server logins or
  Linux/Unix local accounts (with sudo rights and authorized keys' fingerprints), each with what makes it privileged,
  and records what changed since the previous scan (`/api/v1/access/discovery/runs`, `/accounts`). Discovery grants
  nothing. Migration 0399, snapshot format 91, OpenAPI census 736 -> 743, CLI census 803 -> 810 (`access discovery
  sources list|save|delete`, `scan`, `runs list|get`, `accounts`).
- Browser sessions, part 3 (A259 served): a Kubernetes session opened for the browser gets a terminal in a pod. The
  terminal request names a namespace, a pod and optionally a container and command (default `sh`); the control plane
  opens the exec through the session's gateway (WebSocket `v5.channel.k8s.io`), which adds the session's own token, so
  the service account's role bounds it and the token never leaves the gateway. The exec's exit status ends the terminal,
  and the gateway records the stream. The console's session form offers Kubernetes, and a pod form opens the terminal.
- Cloud KMS keys and load-balancer TLS policies (X4): a `cloud_kms_key` discovery source with the `aws-kms` provider
  lists every key in a Region through the read-only `ListKeys`, `DescribeKey` and `GetKeyRotationStatus` calls, with
  its type and size from the key spec, usage, state, manager, origin and automatic-rotation status (`enabled`,
  `disabled`, `not_supported` for keys KMS cannot rotate, `unknown` with KMS's error code), and flags a key KMS could
  rotate but is not rotating; key material is never read (proven against LocalStack KMS). A `load_balancer_tls`
  source reads the TLS policy each AWS Application or Network Load Balancer listener (`aws-elbv2`) or F5 BIG-IP
  virtual server (`f5-bigip`, iControl REST as a read-only user) enforces, and records one crypto-inventory finding
  per listener at the oldest version it allows, so a listener that allows TLS 1.0 is one weak TLSv1.0 finding,
  replaced when the policy is tightened (proven against ELBv2 and BIG-IP stand-ins).
- Live discovery of cloud access keys (M3): a `cloud_access_key` discovery source with the `aws-iam` provider
  lists every IAM user's access keys with status, creation date, age and last use (date, service, Region) through
  the read-only `ListUsers`, `ListAccessKeys` and `GetAccessKeyLastUsed` calls, flags an active key unused for
  90 days as stale (risk 80), and shows the keys in the NHI inventory as API keys; no secret access key is ever
  read, and the air-gap guard confines the calls. Proven against LocalStack IAM.
- Live checks for leaked secrets (P14 is served): with `secrets.validity_checks.enabled`, a scan checks each AWS
  access key pair it finds where it found it (an STS GetCallerIdentity signed with the pair, so the secret never leaves
  the host) and records the finding's `validity`; each check's endpoint must be declared in the checks' outbound
  allowlist and a per-provider rate bounds them. A secret found in a collected Slack channel names its poster and the
  tenant owner with the poster's email.
- ServiceNow two-way sync (P13 is served): a ServiceNow change request approved or rejected decides the trstctl
  request intake opened from it, once (relay job `ticket.status`); `POST /api/v1/incidents/executions/{id}/close`
  (`trstctl incidents executions close|closure`) closes a trstctl incident and resolves the ServiceNow incident its
  response dispatch opened (correlation `trstctl:incident:<id>`), and a replayed update changes nothing.
- Factory provisioning for devices (P12 is served): factory batches (`POST /api/v1/edge/factory-batches`,
  `trstctl edge factory-batches create|list|show|manifest|reconcile`) give a production-line station a quota of birth
  certificates under one edge delegation. `trstctl-agent --factory-issue` certifies each device's own CSR offline with
  no listener and refuses past the quota; the journal reconciles when the station reconnects, recording any birth
  certificate past the quota as over-production. Devices enroll on first boot and renew over EST at
  `/.well-known/est/factory` with a proof signed by their birth or operational key, through the relay enrollment proxy.
- ACME revocation of a certificate trstctl doesn't hold (N10 is served): a Certificate Transparency finding can be
  revoked at an ACME external CA. trstctl reads the certificate back from the log that recorded it, checks it against
  the finding, gets its own ACME account authorized for every DNS name in it through the issuer's DNS-01 provider,
  then asks the CA to revoke (RFC 8555 §7.6). **Revoke at issuer** now offers ACME CAs for CT findings.
- MDM device check-in behind approval (N9 is served): `POST /api/v1/mdm/{mdm}/devices/{id}/check-in/approval-requests`
  asks for one device trstctl has read from its MDM; after another reviewer approves, `POST .../check-ins` queues one
  job for the MDM schedule's relay, which calls Intune's `syncDevice` or sends a Jamf Pro blank push to that computer
  and records the MDM's answer (`GET /api/v1/mdm/{mdm}/check-ins`; `trstctl mdm check-in ask|run`,
  `trstctl mdm check-ins`). New relay kind `mdm.device.check_in`. The approval queue now also lists AD CS decision
  requests (N1), which reviewers could previously approve only by ID.
- A Slack app for approvals (N8): install per tenant through Slack's consent (bot token sealed under the tenant key),
  pick the approval channel, and approve or deny requests with buttons; members link their Slack users with a
  one-time code (`/trstctl link <code>`), and a press decides through the API's own approval route as that member.
  Every request from Slack is signature-checked (`trstctl integrations slack …`).
- Response playbooks for SOAR tools (N7): `clients/soar/` is a vendor-neutral pack of playbooks a SOAR runs as
  plain HTTP calls against trstctl's API — revoke a compromised certificate, rotate a leaked stored secret and
  resolve its finding, retire a triggered honeytoken — with idempotency keys built from their inputs and the
  exact API scopes their token needs, checked against the served OpenAPI document and run against the served API.
- Native leak-scan collection (N6): a third-party scan source with `collect` has trstctl read the content from
  the provider — an image from its registry over the OCI distribution API (every platform, config and layer
  files, digests checked; anonymous, bearer or token-service credentials), Slack channel history, Jira issues,
  GitHub Actions run logs and GitLab job logs — in the layout of the provider's export, so findings name the
  image, message, issue, or CI run or job; the content stays in a private temporary directory removed after the
  run.
- trstctl as the OpenID issuer clouds trust (N5): with `protocols.spiffe.oidc_issuer_url`, the token-exchange
  tenant has a published issuer `<base>/oidc/<tenant-id>` (discovery document and key set, the signer-held SPIFFE
  JWT key), exchanged tokens carry it as `iss`, and AWS (AssumeRoleWithWebIdentity), Google (workload identity
  federation) and Azure (federated credentials) can trust them with no cloud key on the workload;
  `GET /api/v1/workloads/oidc-issuer` (`trstctl workloads oidc-issuer`) shows what to register.
- AWS decoy keys are also looked for in a CloudTrail trail's log files (N4): an account attachment may name
  its trail (`trail`: bucket, Region, key prefix, organization ID, accounts), and the leader reads the trail's
  log files from S3 — every account of an organization trail, and data events when the trail logs them, which
  LookupEvents never returns. Each file is recorded once; each decoy use shows the calling and logging
  accounts, `event_category` and `found_in`; the account catalog shows what the trail read. Proven against
  LocalStack S3 with files in CloudTrail's layout.
- Secrets: an AWS STS provider with `revoke_with_deny_policy` ends a revoked lease's
  session before it expires through an inline policy on its role that denies that one
  session (`aws:userid`), read back before the revocation completes; denials of expired
  sessions are pruned, the provider catalog reports `deny_policy`, and leases show
  `revocation_method` (`deny_policy` or `native_expiry`). Proven against LocalStack;
  AWS's enforcement of the denial is a live proof (N3).
- Renewal waves for the switching kit (A265 is served): `POST /api/v1/switching/imports/{id}/waves/preview`
  assigns imported rows to deployment targets and names every row it leaves out and why, plus the fingerprints
  the other product must stop renewing; `POST .../waves` issues each row's single trstctl identity through the
  ordinary issuance policy so trstctl renews it from then on; `POST /api/v1/switching/waves/{id}/rollback`
  (refused while an issuance or renewal is in flight) withdraws queued deploys, pauses the renewals and returns the
  rows to watch-only. The endpoint watch flags a wave row the other product renewed (`trstctl switching waves`).
- MCP client configuration discovery on hosts (P7 host detectors are served): `trstctl-agent
  --inventory-mcp-config-roots` reads MCP client configuration files by format and reports each configured MCP
  server — transport, program or host, and which fields hold a static credential, never a value — as `mcp_server`
  findings in discovery and the shadow NHI posture; an unchanged rescan sends nothing and writes no event.
- The switching kit, parts one and two (A265): `POST /api/v1/switching/imports/preview` maps another
  certificate-management product's export (CSV or JSON, described by format, with a column map for its own
  column names) without changing state, giving every row one outcome — mapped, mapped with named gaps,
  duplicate, unparseable or expired — with folder profile proposals, owners per application group, the rows
  already in the inventory and a digest; `POST /api/v1/switching/imports` applies exactly that digest, and the
  leader records the certificates (watch-only, never renewal candidates) and owners in bounded batches,
  linking certificates already in the inventory instead of rewriting them. `POST
  /api/v1/switching/imports/{id}/watch` matches every imported certificate to what its endpoints serve, under
  the control plane's egress rules with private ranges only by explicit grant, flagging serves_other,
  unreachable and no_endpoint, and repeats daily (`trstctl switching import|imports`).
- AD CS approve and deny through the relay, behind approval (N1 is served): a request an AD CS template holds for a
  CA manager is approved (`certutil -resubmit`) or denied at the CA by the issuer's domain-joined relay only after
  another reviewer approves the exact decision, and only while the CA still holds it as pending; `GET
  /api/v1/external-cas/{id}/adcs-decisions` shows each decision queued, decided with the CA's disposition, or failed
  with the relay's reason.
- Azure Key Vault disable, labeled not revoked (N2 is served): `POST /api/v1/certificates/{id}/key-vault-disable`
  disables the exact Key Vault certificate version the inventory found, through a `write_token_ref` configured
  beside the vault's discovery source, from an outbox job with readback; every answer says it is not a revocation
  and the inventory row keeps its status.
- The edition and qualification ledger (A253 is served): `go run ./tools/editionledger` generates
  `docs/editions-ledger.md` and `.json` from the license table and the feature map; the README and
  `docs/editions.md` carry its generated blocks, the Editions API and the console name the no-license
  edition Free as the ledger does, and guards fail on drift, on another name for it, and on a page that
  misstates the core's source-available license.
- Evidence report templates (A252 is served): five scheduled report types — lifecycle, access, rotation,
  incident response and qualification evidence — replay one window of the tenant's event log, sign like
  every scheduled report and verify offline. Each counts its sections' events by type, tallies outcomes,
  names up to 25 opaque subject IDs per section, reads the current state as counts, and says what it could
  not observe; no event body, certificate, secret, token or name is carried. `GET
  /api/v1/reports/evidence/{kind}` (`trstctl reports evidence`) renders one unsigned for review.
- The console's **Agent access** page (A251 is served): bundles, grants with the effective
  authority after every change, authority lookup with delegation chains and bounds, a run for
  yourself with its token shown once and launch lines, runs with revoke, and activity search and
  export.
- Agent access activity and the run launcher (A251, second part): `GET /api/v1/access/activity`
  (`trstctl access activity`) searches bundle, grant and run changes and each run token's
  recorded uses, newest first, by bundle, principal or text; `GET /api/v1/access/activity/export`
  returns the matching rows as one metadata-only JSON document (no token, token hash,
  Authorization value or request body). `trstctl access run --bundle <name> -- <command>` mints a
  run under your own grants, gives the command its token as `TRSTCTL_TOKEN` (never your own), and
  revokes the run when the command exits.
- Agent access bundles (A251, first part): `POST /api/v1/access/bundles` saves a reusable set of
  permissions for custom agents, CI jobs and private MCP servers; a grant gives it to a user or
  a machine; `POST /api/v1/access/runs` (the new `access:bundle.run` permission) mints a run's
  short-lived credential under the caller's own live grants, returned once with launch lines.
  A run's authority is derived again from its grants at every request: removing one of several
  grants leaves exactly what the others give, and deleting a bundle, offboarding a member or
  revoking the run stops it on the next request. Grant changes return the principal's effective
  authority; `GET /api/v1/access/authority` adds active runs, delegation chains and the
  revocation and outage bounds. Nobody hands an agent more than they hold, and a bundle never
  carries authority over access.
- Package readiness, third part (A250 is served): a registry directory holds several versions
  side by side (the Go `list`, the npm document's `latest`, the PyPI page and `maven-metadata.xml`),
  and `make sdk-install-check` now installs one version and upgrades each SDK to the next from the
  same registry, running the round trip on both. A tagged release attaches the four packages as
  `trstctl-sdk-registry_<version>.tar.gz` with SLSA provenance. A CI job checks the CLI and agent
  archives on clean Linux and macOS runners: checksums, unpack, run, and the commit `--version`
  reports.
- SDK packages from a local registry (A250, second part): `scripts/release/sdk-packages.sh`
  (`make sdk-packages`) builds the Go module, the npm tarball (now compiled JavaScript and
  declarations, so plain Node loads it), a pure-Python wheel and the Maven jar of one version with
  `manifest.json` and `SHA256SUMS`; `go run ./tools/sdkpack serve` serves them as a Go module
  proxy, an npm registry, a PEP 503 index and a Maven repository. `make sdk-install-check` (in CI)
  installs each by exact version in a clean environment and runs auth, read, rotate and revoke
  against a served control plane, with retries keeping their Idempotency-Key and waiting out
  `Retry-After`. The Java SDK's `PkiSecret` now carries the certificate ID.
- One SDK surface for secrets, PKI and revocation (A250, first part): the Go and TypeScript SDKs
  gain the secrets-store calls (create, get, rotate, delete) and PKI-secret issuance the Python
  and Java SDKs had, and all four gain certificate revocation (`RevokeCertificates`,
  `revokeCertificates`, `revoke_certificates`). The Go SDK takes and returns secret values as
  `[]byte` and wipes its own copies. Each SDK's tests show a retried mutation keeps its
  Idempotency-Key and waits out `Retry-After`.
- Unattended evaluation cycles (A249, third part; A249 is served): `trstctl evaluate --cycles n
  --interval d` repeats the chosen journeys with nobody watching, into one pack
  (`trstctl.evaluation-pack/v3`) that keeps every cycle. A cycle cut short because the control
  plane could not be reached is `interrupted`: the command waits up to `--recovery-timeout` for
  `/readyz` and records the outage, and the run passes only if the next cycle passes after it.
  After the first cycle the certificate journey issues the enrolled identity's next certificate
  through renewal. The incident journey runs once.
- Incident journey for `trstctl evaluate` (A249, second part): `--journeys certificate,incident`
  responds to a compromise of the key behind the certificate the certificate journey deployed —
  the effect-free compromise preview, a revoked-credential game day (static preview and mocked
  rehearsal), the reviewed command that revokes it at the CA and has the host agent stop the
  listener, then OCSP and this machine's handshake to check both. `--force-failure incident`
  reports the last check as a failure.
- Workload identity journey for `trstctl evaluate` (A249, second part): `--journeys workload`
  dials the Workload API socket (`--workload-socket` or `$SPIFFE_ENDPOINT_SOCKET`) as a workload,
  checks the X.509-SVID it is handed against the trust bundle (one SPIFFE ID, the key is the
  SVID's), verifies a JWT-SVID for a run-unique audience offline against the JWT bundle, and
  requires the socket to validate the token for that audience and refuse it for another.
  `--force-failure workload` reports that last check as a failure. The pack keeps the SPIFFE ID
  and the token's digest only.
- Reviewed change sets in the console (A248, third part): the **Change sets** page under Govern &
  administer writes the same typed set as the API and GitOps — from a template (onboard an
  application, grant a member roles, add a connector target), the form or JSON — plans it,
  shows the per-object plan, and applies only the reviewed plan digest. An edit after planning
  marks the plan stale, and a `409` asks for a new plan. With a model configured, the page drafts
  a set with AI and plans it the same way.
- Evaluation across journeys (A249, first part): `trstctl evaluate --journeys
  certificate,secrets,ssh` adds a secrets journey (create, read back by digest, rotate,
  `trstctl run` into a child process that checks the value without printing it, delete and
  read 404) and an SSH journey (issue a user certificate for a generated key, verify it
  offline against `/ssh/ca`, revoke it, find its serial in `/ssh/krl`) to the same signed
  pack, format `trstctl.evaluation-pack/v2` when more than the certificate journey runs.
  `--force-failure <journey>` makes one step expect what did not happen, so the pack shows
  that failure as one. `--deployment-target` is now needed only for the certificate journey.
- AI drafts of reviewed change sets (A248, second part): `POST /api/v1/changes/draft` (CLI
  `changes draft`) turns a request in words into a typed change set with the configured model and
  plans it like any other, never applying it. The model gets the tenant's names only — no specs,
  configs, chains, emails or member subjects — a request holding a key, token or password is
  refused before the model call, and each draft records `ai.change_set.drafted` (digests, never
  the request). Without a model it answers 503 and nothing else changes. Fixed: an owner without
  an escalation chain now reads back as planned (its stored null chain is the empty chain).
- Reviewed configuration change sets (A248, first part): one typed set of certificate profiles,
  CA bindings, connector targets, member role grants and owners, written as JSON or YAML.
  `POST /api/v1/changes/plan` (CLI `changes plan -f`) refuses a malformed or over-broad set, one
  carrying a secret value, and one beyond its author's permissions (`changes:write` plus each
  object's own permission; member grants get the members API's checks), then lists per object
  the identities, credentials, grants, destinations, approvals, events and verification
  involved. `POST /api/v1/changes/apply` (CLI `changes apply -f <set> <plan_digest>`) needs the
  reviewed plan digest, refuses a plan the tenant has moved past, writes each object through
  the operator's own command and reads it back. New permission `changes:write`.
- Rehearsals of failure scenarios (A247): save a scenario — approval resumption,
  target outage, renewal failure, revoked credential, stale policy, restore or retry — with its
  candidate, data set (named identities, or a scrubbed failure: identifiers and codes, no values)
  and the effect each step should have (`POST /api/v1/rehearsals/scenarios`, CLI `rehearsals
  scenarios save`; revise with `PUT`). A run (`rehearsals run`, permission `incidents:game-day`)
  replays it as a static preview against the configuration, a mocked rehearsal of the
  documented behavior, a sandbox execution against a non-production target (a retry runs the
  target's dry-run test twice through the idempotency layer) or a live observation of
  production's records (a restore reads the newest signed drill attestation), and records the
  tool and connector versions, the candidate, the data set's digest, the expected effects and
  what it observed. Its label is its mode's: a mocked success reads `mocked: matched`, never
  live. A sandbox replay reads environments from the target and owner records and refuses
  production ones and data sets that name stored secrets; a step a mode cannot run yet blocks
  the run.
- Operations dashboard, upgrade preflight and rollback (A246): **Deployment health** (`GET
  /api/v1/operations/dashboard`, CLI `operations dashboard`) shows backup freshness, restore
  proof, queue lag, signer readiness, data freshness and dependency health with the numbers
  behind each state. `trstctl --upgrade-preflight` reads what a binary would apply to the
  database, what blocks it and how the upgrade is rolled back, changing nothing; it exits 1 when
  blocked. A failed migration leaves the ones before it applied and itself rolled back, and a
  failed concurrent index build drops its invalid index, so the previous binary runs and the
  fixed one continues. The restore drill reads the restored events, CA keys and stored secrets
  back against the backup, and its signed attestation carries the counts. Install and failover
  runbooks join the upgrade and disaster-recovery runbooks.

### Fixed

- Signed third-party scan artifacts accept binary RSA and ECDSA signatures whose first or
  last byte is whitespace. Only base64 text loses surrounding whitespace; changed artifacts
  and incomplete signatures remain refused.
- With `TRSTCTL_MIGRATE_AUTO=false` the startup gate counted core migrations only: an extension
  family's new migration passed it and was applied at startup, and `--migrate-status` did not
  list it. Both now read every migration source (A246).
- A tenant refusal answered bootstrap enrollment and the agent channel with the condition that
  refused it; every surface again answers "tenant service is suspended or offboarded", and the
  condition stays on the server.

- One operations view for rotation, revocation and proof (A245): `GET /api/v1/operations/ledger`
  (CLI `operations ledger`, the Operations page) lists certificate rotations, connector deliveries,
  secret rotations and approvals in nine normalized states — verified only on consumer evidence,
  uncertain when an effect's outcome is unknown; `GET /api/v1/operations/ledger/{id}` (CLI
  `operations ledger get`) shows one operation's causal chain and its exactly scoped retry and
  rollback; `GET /api/v1/identities/{id}/revocation-report` (CLI `identities revocation-report`, the
  revoked identity's detail) keeps CA status, deployed material, new connections and open sessions
  apart. An issuance approval now binds the platform CA when the identity names no issuer, so
  moving it to another CA supersedes the approval.
- Application view for certificates (A244): `GET /api/v1/identities/{id}/application` (CLI
  `identities application`, the console's **Application view** in an identity's detail) shows
  the owner, profile and its enrollment methods, the exact issuer, the destination and latest
  delivery, what was seen at the endpoint and from which vantage, approvals with what changed
  under them, the next automated action and failed prerequisites, recent alerts, the recover,
  revoke and retire actions, a value-free review plan and reusable defaults (the console carries
  them into the destination form). Identity list items carry `inventory_state`: requested,
  issued, delivered, served (shown as *Seen in use*), revoked or retired.
- Issuance approvals bind the destination and the issuer (A244): an approval asked for an identity
  that deploys to a target now records that target and its configuration revision, and the
  identity's issuing authority, in its evidence (covered by the intent digest). Editing the
  target, rebinding the identity, or a different issuer supersedes the approval when it is decided
  or used, as a changed profile already did. `GET /api/v1/connectors/targets/{id}/impact` and
  `GET /api/v1/profiles/impact/{name}` (CLI `connector target impact`, `profiles impact`) show what
  a change would reach: the certificates that use the target or profile, and the open approvals it
  would supersede.

- Secret migration runs (A243): `POST /api/v1/secrets/migrations/assess` reads an export in common
  formats — dotenv, JSON or YAML, per environment and folder — into native names
  (`<project>/<environment>/<folder>/<key>`), translates its references (`${NAME}`,
  `${folder/NAME}`, `${environment:folder/NAME}`) into `${secret.<name>}` so chains stay chains,
  keeps multiline values and metadata (description, tags, owner), and records a value-free plan
  bound by digest to the values it was made from: per object import, reissue (a credential the
  export could not carry) or blocked (a missing environment, an unresolved reference or a cycle,
  an environment the caller may not write, a secret another run's export still writes). Permissions
  translate only where nothing widens: an environment-wide read becomes viewer and write developer;
  folder grants, admin, wildcards, mixed access or an existing different membership are held for
  review, and an environment the export restricted that is open here blocks its objects unless
  accepted explicitly. `stage` imports by the digest as new versions (a stale digest is refused)
  while the export's system stays each secret's one writer — native writes, promotions and restores
  to those secrets answer 409 until cutover; `permissions` (access:write) applies only translated
  grants; each consumer's first read of its secrets, as its own subject, is recorded; `cutover`
  needs every consumer to have read; `reissue` issues new values for credentials the export could
  not carry, recorded as reissued and never as migrated; `rollback` restores the versions the run
  found, deletes what it created and keeps what changed since, converging when retried. CLI:
  `trstctl secrets migrate assess|list|show|stage|permissions|cutover|reissue|rollback`.

- Connector modules on the relay (A242): a third-party WASM connector now ships a signed
  manifest (`<name>.manifest.json` + `.sig`, signed by the key that signed the module) naming
  its version, the module's SHA-256, the host ABI range, its permissions (capabilities,
  host:port and path resources, and how the relay may add the target's credential: `basic`,
  `bearer` or `header:<Name>`), actions, idempotency and revocation behavior, setup inputs and
  limits. A module runs under exactly the grant its manifest asks for, which must fit the
  operator's `--connector-plugin-capability` grant (and `--connector-plugin-credential`
  ceiling); its memory and per-call time are bounded, and each module has its own worker pool
  so one that spins or floods cannot occupy another's. A module runs only once its operator
  approves it (`trstctl-agent --approve-connector-module <name>` prints the review and what it
  adds over the current approval, recorded in `--connector-plugin-approvals`); a later version
  that asks for no more loads under the same approval, one that asks for more, is older or comes
  from another publisher waits and is reported as awaiting approval. A failed module call
  reaches the control plane as exact evidence (name, version, digest, entry point and the class
  the host observed: trap, timeout, rejected, grant-denied or the status it returned) while the
  job stays queued; a `create-new` module's retry asks its `readback` first and does not repeat a
  deploy that landed, and a module's readback feeds the deploy's verification like a native
  connector's. `trstctl-agent --check-connector-modules` is the conformance kit. The relay's
  signed census carries each module's version, state, actions, idempotency, revocation, setup
  inputs, limits and health, and lists modules awaiting approval with what an approval would
  add (only loaded modules count as carried for routing and destinations). The connector
  catalog API returns it (`module` on each relay plugin), the Connectors console shows it,
  offers loaded modules as destination types with a setup form built from their inputs, and
  the API checks a module destination's configuration against those inputs (required, typed,
  secret inputs only as references).

- Integration catalogs say how far each entry is proven (A242): the connector catalog and the
  secret-sync target catalog carry `qualification` on one ladder (discovered, implemented,
  served, locally-proven, vendor-qualified). The sync catalog flags the signed webhook and
  generic CI JSON as `generic`, never native, and lists the integration catalog's unbuilt
  targets as `discovered` with a `note` on what each waits for. Both console catalogs show the
  rung.

- Hosted secret-sync targets (A241): `heroku`, `render`, `railway`, `fly`,
  `digitalocean-app-platform`, `northflank`, `qovery`, `cloud66`, `laravel-forge`, `circleci`,
  `travis-ci`, `bitbucket`, `teamcity`, `spacelift`, `humanitec`, `rundeck`, `checkly`, `windmill`,
  `zabbix`, `portainer`, `devin`, `daytona`, `ona`, `trigger-dev`, `cloudflare-workers`,
  `cloudflare-pages`, `cloudflare-secrets-store`, `azure-app-configuration`, `oci-vault`,
  `ovh-secret-manager`, `databricks-secrets`, `supabase-secrets`, `camunda` and `chef`, each
  bound by one `binding` string in its type's grammar (internal/synctarget) and run by one
  engine (`secretsync.HostedSyncPusher`). Every hosted target takes a scoped sync: it lists,
  reads back and deletes keys. A scoped sync to a flat (variable-name) destination joins its
  prefix without a slash and blocks a key the target can't hold; a receipt-only target (whose
  vendor never returns a secret) plans `unchanged` only when this version's delivery job
  succeeded and says a change made outside the sync can't be seen. The sync target catalog
  now says, per target, whether a scoped sync can target it (`scoped_sync`), what it reads
  back (`readback`) and how far it is proven (`proof`); the console's catalog shows both.
  Each target is proven through the served API against a stand-in built from the vendor's
  API reference (create, update, drift, delete, unmanaged keys kept, no value in a plan or
  the logs); none has a live account proof yet.

- Snowflake key-pair rotation (A240): a `snowflake` role bound to `user <NAME>` rotates that existing user's key pair in
  two phases through its two key slots; retirement unsets the predecessor's slot only while it still holds that key.
  Verified by `SELECT 1` as the user. Built against a stand-in of the SQL API.

- Google Cloud service-account key rotation (A240): `gcp-iam` providers with `allow_static_rotation` rotate a stored key
  in two phases (a new key beside the predecessor, deleted at retirement); verification reports `not_available`.

- Windows local account rotation (A240): `windows` providers rotate local account passwords on a Windows host serving
  OpenSSH, as an Administrators member authenticating with a key, the host key pinned; the only command is
  `Set-LocalUser`, its encoded script naming the account and the password on stdin. Two-user pairs and acknowledged
  in-place changes work as for `unix`. Proven on a windows-latest runner serving OpenSSH to itself.

- Okta and Databricks client secret rotation (A240): `okta` (an app's client secret, two per app) and `databricks` (a
  service principal's OAuth secret, five per principal) rotate in two phases and issue no leases. A rotation adds a
  secret beside the one in use and retirement removes the old one (Okta: deactivate, then delete); only secrets of a
  bound client are ever removed. Verified by client authentication at the vendor. Built against stand-ins.

- Azure Entra client-secret rotation (A240): `azure-entra` providers with `allow_static_rotation` rotate a stored
  client secret in two phases — a second password beside the predecessor, verified with a client-credentials token
  request at `authority_host`, and retirement removes only passwords the provider added (display name `trstctl-...`).
  Built against stand-ins of Graph and the identity platform.

- Hosted API key rotation (A240): `openrouter`, `fireworks`, `litellm`, `supabase`, `convex`, `dbt`, `cloudflare` and
  `cloudflare-r2` providers issue
  leases and rotate in two phases with one shared engine. Each key is created with the administrator's credential
  under the target the role is bound to (a credit limit, a user, a model list, a project, a deployment and its
  actions, a permission set, a template token's policies), named for the lease or command, and deleted at revocation only after the provider's
  naming is checked; a retried creation replaces its earlier attempt's key. Keys are verified with the vendor's own
  read where one exists (Supabase, Convex and R2 report `not_available`). Built against stand-ins of each vendor's API.

- SAP HANA dynamic secrets (`type: hana`): each lease is a user with a generated password and no password lifetime,
  granted only the existing HANA roles its role is bound to; the password and names travel only as parameters of an
  anonymous SQLScript block. Revocation deactivates the user, disconnects its sessions and drops it. Its lab test runs on
  an x86 CI runner against SAP HANA, express edition.

- Oracle Database dynamic secrets (`type: oracle`): each lease is a user with a generated password granted only the
  existing Oracle roles its role is bound to; the password and names travel only as binds, quoted by the database.
  Revocation locks the user, kills its sessions and drops it. A role with `rotation_accounts` instead rotates between
  two existing users (A240). Proven against Oracle Database Free (26ai).

- Cassandra dynamic secrets (`type: cassandra`): each lease is a login role with a generated password, granted only
  the existing Cassandra roles its role is bound to; only the password's bcrypt hash travels in CQL (`HASHED PASSWORD`).
  Revocation drops the role, so the next login fails and an open connection is refused once the node's caches expire.
  One node is contacted, over verified TLS or plaintext to a literal loopback or private IP. Proven against stock
  Apache Cassandra 5.0.9.

- Rotation library with consumer cutover (A240): two-user rotation for PostgreSQL, LDAP, MongoDB, Oracle, SQL Server
  (and Azure SQL contained users) and Unix/Linux local accounts (`rotation_accounts`): stage sets a new password on
  the account consumers are not using, retire sets one nobody holds on the other, and both keep their grants, roles or
  groups. `consumers` and `retire_after_seconds` hold the predecessor until the named consumers report the new version
  or an approved deadline passes, and the command view keeps `credential_valid` apart from `consumer_adoption`.
  Single-phase providers (`auth0`, an in-place `unix` account) run only with `acknowledge_single_phase`; `datadog` and
  `openai` keys issue leases and rotate in two phases. Proven against PostgreSQL, OpenLDAP, MongoDB 7.0, Oracle
  Database Free, SQL Server 2022 (x86 CI lab) and a Debian OpenSSH host; Auth0, Datadog and OpenAI are built against
  stand-ins of their APIs.

- IBM API Connect dynamic secrets (`type: ibm-api-connect`): each lease is a credential (client ID and generated secret)
  on the consumer app its role is bound to (`"<org>/<catalog>/<consumer-org>/<app>"`), carrying that app's
  subscriptions, created through the platform API with the api_key grant; revocation deletes the credential and the
  gateway then refuses its client ID. Built against a stand-in of the platform API.

- ElastiCache and MemoryDB dynamic secrets (`type: aws-elasticache`, `type: aws-memorydb`): each lease is an RBAC user
  with a generated password and the role's access string, compiled from literal key prefixes and explicit safe commands
  exactly as for the Redis provider (`redis_acl_roles`; raw ACL rules and categories are refused), added to one
  ElastiCache user group or MemoryDB ACL (`user_group`) once AWS reports the user settled. Revocation deletes the user,
  which AWS removes from every group and cluster. Requests are SigV4-signed with the configured access key. Built
  against stand-ins of the ElastiCache Query API and the MemoryDB JSON API.

- Snowflake dynamic secrets (`type: snowflake`): each lease is a Snowflake service user (`TYPE = SERVICE`) that
  authenticates with a key pair the provider generates (the lease returns the private key; no password exists, so none
  reaches SQL text or query history), granted only its role's roles and set to expire in Snowflake after the
  provider's maximum lifetime in whole days (`DAYS_TO_EXPIRY`). The administrator calls the SQL API with a key-pair JWT
  signed inside the crypto boundary. Revocation disables the user, aborting its running queries, then drops it. Built
  against a stand-in of the SQL API.
- Dynamic-secret providers that delete principals by name (ClickHouse, RabbitMQ, MongoDB Atlas, Kafka, Couchbase,
  Milvus, SQL Server, Azure SQL, Snowflake) now refuse to delete one without the full issued-name shape (prefix, role and
  the lease digest suffix), not just the prefix, so an administrator named, say, `trstctl_admin` is never deleted.

- GitHub App dynamic secrets (`type: github-app`): each lease is an installation access token narrowed to the role's
  permissions and named repositories (`"contents:read,metadata:read on api,web"`), minted with an RS256 app JWT signed
  inside the crypto boundary. GitHub ends a token after an hour; revocation ends it at once by presenting it (the lease
  keeps its sealed token until then), and a lease can't be extended. A token broader than requested is revoked and
  refused. Built against a stand-in of GitHub's API.

- SQL Server and Azure SQL dynamic secrets (`type: mssql`, `type: azure-sql`): an `mssql` lease is a login with a
  generated password and a user in the configured database that joins the role's database roles (`"db_datareader"`);
  an `azure-sql` lease is a contained database user. Revocation disables the login, ends the principal's open sessions
  (SQL Server keeps a dropped principal's sessions) and drops the user and login. The password reaches SQL Server only
  as a parameter, never in statement text. Their lab tests run against SQL Server 2022 Developer Edition on an x86 CI
  runner (the image is x86 only); Azure SQL is proven through SQL Server's contained database users.

- Milvus dynamic secrets (`type: milvus`): each lease is a Milvus user with a generated password and only the Milvus
  roles its role is bound to (`"orders_reader"`), created through the RESTful API; revocation drops the user (and its
  role grants) and Milvus refuses its next request. Proven against stock Milvus 2.6.26 standalone.

- Couchbase dynamic secrets (`type: couchbase`): each lease is a local Couchbase user with a generated password and
  only its role's roles on the named buckets (`"bucket_full_access on orders"`, the Community Edition's data role, or
  Enterprise roles such as `"data_reader,query_select on orders"`), created through the management REST API;
  revocation deletes it and Couchbase refuses its next request. Proven against stock Couchbase Server Community 8.0.2.

- Kafka dynamic secrets (`type: kafka`): each lease is a SCRAM-SHA-512 user with a generated password and only its
  role's ACLs on topics, consumer groups and transactional IDs (`"read,describe on topic:orders; read on
  group:orders-app"`; a trailing `*` makes a prefix). Revocation deletes the ACLs, which refuse a client still
  connected on its next request, then the credential, so the next login fails. Brokers are reached over verified TLS
  (SASL_SSL), or SASL_PLAINTEXT to a literal loopback or private IP only. Proven against stock Apache Kafka 3.9.0.

- MongoDB Atlas dynamic secrets (`type: mongodb-atlas`): each lease is a database user in one Atlas project with a
  generated password and its role's built-in roles (`"<role> on <databases>"`), which Atlas deletes after the
  provider's maximum lifetime (`deleteAfterDate`, at most 7 days); revocation deletes it. The Admin API is called with
  a service account's token. Built against a stand-in of the Atlas Admin API.

- Tailscale dynamic secrets (`type: tailscale`): each lease is a single-use, ephemeral, preauthorized auth key carrying
  its role's ACL tags and expiring with the provider's maximum lifetime; revocation deletes it. The key request is
  never retried blindly. Built against a stand-in of Tailscale's API.

- RabbitMQ dynamic secrets (`type: rabbitmq`): each lease is a RabbitMQ user with a generated password and its
  role's permissions in one virtual host (`"<permissions> on <queues or exchanges> in <vhost>"`, names matched
  exactly), created through the management API as `admin_user`; revocation deletes the user and closes its open
  connections.

- Elasticsearch dynamic secrets (`type: elasticsearch`): each lease is an API key, created by `admin_user`, that
  expires with the provider's maximum lifetime and holds only the index privileges its role is bound to
  (`"<privileges> on <index patterns>"`); revocation invalidates it, and a retry first invalidates any key an
  uncertain attempt left for the lease.

- ClickHouse dynamic secrets (`type: clickhouse`): each lease is a ClickHouse user with a generated password,
  valid until the provider's maximum lifetime and holding the ClickHouse role its lease role is bound to, created
  through the HTTP interface as `admin_user`; revocation drops the user, and a retry replaces the same user.

- OAuth 2.0 access-token dynamic secrets (`type: oauth-client-credentials`): each lease is a new token from an
  authorization server's token endpoint (client credentials grant) carrying only the scopes its role is bound to;
  a token with other scopes, another type or a lifetime outside the lease and `max_ttl` is refused (and revoked
  when possible). A token can't be extended. With `revocation_endpoint` revoking the lease revokes the token there
  (RFC 7009) and the catalog marks the provider confirmed; without it the revocation stays pending until the
  token's expiry (TTL-only). An uncertain token request is never retried blindly.

- TOTP dynamic secrets (`type: totp`): each lease carries the current RFC 6238 code of a seed the control plane
  holds and `valid_until`, the end of its time step; the code can't be renewed or withdrawn, so the catalog marks
  it TTL-only and `max_ttl` can't exceed the period.

- LDAP dynamic secrets (`type: ldap`): each lease is a directory entry with a password the directory sets and hashes,
  in the group its role is bound to, deleted at revocation, over LDAPS verified against the configured server name.
  The dynamic-secret provider catalog now states each adapter's authority and whether its revocation is confirmed or
  TTL-only.

- Secret rendering for host applications: `trstctl-agent --secret-render-config` keeps `{{ secret "name" }}`
  templates rendered into files with atomic writes and the file's mode, runs the application's reload hook, and
  asks the application to prove it uses the new value. Delivery reports (`trstctl-cli secrets deliveries
  report|list`) keep "injected" apart from "verified", and a control-plane outage keeps the last file only until
  its freshness bound, across agent restarts. Templates can use dynamic leases (`{{ lease "provider/role" "field" }}`):
  a lease is renewed in place or replaced, and the replaced lease is revoked only after the application verifies the
  new credential.
- Secret volumes for pods (`deploy/kubernetes/csi-secrets.yaml`, CSI driver `secrets.csi.trstctl.com`): a pod names
  its secrets in an inline CSI volume, and the node plugin reads them with the pod's own service-account token into a
  memory filesystem it mounts, with no Kubernetes Secret object. Republishes deliver new versions (reported as
  injected), remove a file the pod may no longer read, and apply a freshness bound while the control plane is away.

- Scoped secret sync: `trstctl secrets scoped-syncs define|preview|apply` keeps every secret under a source prefix
  in step with a KV v2 destination under a prefix. The value-free plan lists create, update (with drift named),
  delete within the reviewed scope, and keys the sync didn't write, which it never touches; nested-key and
  two-source collisions are blocked, a changed source or destination makes the plan stale, and a crash after a
  remote write settles by reading the destination back. An `auto` scoped sync is applied by the control plane when
  its sources change (nothing blocked); a blocked plan is recorded and waits for review. The console's Secrets →
  Sync page defines, previews, applies and switches scoped syncs.

- Folder restore for secrets projects: `trstctl secrets projects restore preview|apply` puts an environment or a
  folder back to a point in time as new versions in one batch, keeps secrets created since, and refuses a version
  whose credential a rotation retired, revoked or let expire. The console's project page offers Promote or restore.

- Environment promotion for secrets projects: `trstctl secrets projects promote preview` returns a value-free plan
  (per key: create, update, unchanged or blocked, plus the target secrets left alone) and its digest, and
  `promote apply` writes the plan as one batch of new versions when the digest still matches. References into the
  source environment are pointed at the target. A reference cycle, an ungranted restricted hop, a reference that
  exists only in another tenant, an unresolvable reference or a retired source credential blocks the promotion,
  and a secret changed after the preview makes the plan stale.

- Secrets projects and environments: `trstctl secrets projects create|show` and `members grant|revoke` group an
  application's secrets by environment (by name, `<project>/<environment>/…`) in the same native store. A restricted
  environment is readable and writable only by members granted it, on every surface including references and the
  Vault-compatible KV routes; a denied read answers as a missing secret. Membership changes need `access:write`, and
  the project view names unknown ownership. The console's Secrets → Projects and environments page shows them, with
  the owner's certificates and identities and their expiry health beside the secrets.

- An SMTP reply intake for ACME email challenges: `protocols.acme_email.smtp_listen` receives RFC 8823 replies for
  the challenge address only, verifies each one's DKIM signature for its From domain (rsa-sha256 and
  ed25519-sha256, keys from DNS or pinned in `dkim_keys`) and hands it to the ACME server; a reply that fails is
  refused with a 5xx reason so it bounces to the sender. STARTTLS is offered when the control plane has a certificate.

- S/MIME certificates over ACME (RFC 8823): with `protocols.acme_email`, an ACME client orders an `email`
  identifier and answers the `email-reply-00` challenge. The server mails token-part1 through the outbox and the
  configured SMTP relay, verifies the reply against stored digests (a wrong mailbox or token validates nothing, and a
  wrong response invalidates the challenge), and issues a signing-only certificate with the emailProtection EKU and
  the address as its only SAN. A CSR that asks for encryption is refused.

- Move a leaked secret into the vault: `trstctl secrets scans move <finding-id> --repo <checkout> --name <secret>`
  re-finds the value a redacted repository finding names in your own checkout (the pinned gitleaks, its report on a
  pipe), stores it as a native secret and links the finding with
  `POST /api/v1/discovery/findings/{id}/secret-move`; no value reaches a finding, event or log. The finding closes
  as remediated only after the secret is rotated, a consumer reads the rotated version and a completed scan no longer
  sees the leak; a failed scan never closes it, and the history commits that held the value stay listed on it.

- Native GitHub webhooks for repository secret scanning: `secrets.scan_webhooks` names a hook and its secret, and
  `POST /api/v1/secrets/scans/hooks/{id}` verifies GitHub's `X-Hub-Signature-256` before queueing a scan of the
  pushed commit; a wrong or missing signature is refused and redeliveries queue nothing new.

- OAuth token exchange (RFC 8693): `POST /oauth2/token` swaps a workload's platform token (a Kubernetes projected
  service-account token, a CI id_token) for a five-minute, scoped JWT-SVID signed in the isolated signer and
  verifiable offline against `GET /oauth2/jwks`; subject tokens are single-use and every exchange is recorded.

- Single-use machine login tokens: an `oidc` or `jwt` login token is recorded (as a digest) until it expires and
  refused if presented again, on any replica and across restarts; a token refused for another reason never uses up
  a valid one.

- Misuse detection (Enterprise governance): from trstctl's own usage record, a dynamic-secret lease requested from a
  client network the token has not used on three days, and an hour of secret reads well above the token's baseline,
  each raise one finding and one alert with evidence on the risk notification route; repeats fold into the day's
  finding and alerts are capped per tenant per hour.

- Usage-based posture from trstctl's own activity: API-token requests are recorded with their client network and
  action (bounded: one event per token, network, action and hour plus doubling counts), machine logins count as
  uses of their login method by the attested workload, and `GET /api/v1/nhi/posture/stale?unused_days=N` (CLI
  `--unused-days`) flags credentials with no recorded use for N days and use from a source not yet seen on three
  days — with no operator input. A recorded telemetry gap suspends "unused" instead of counting as non-use; the
  graph shows each token's last use.

- Access graph, step 2: a dynamic-secret lease now shows what its login reaches, read from the target. A
  PostgreSQL lease links to its database with the login role and the grants PostgreSQL reports for it; an AWS
  STS lease links to the IAM role it assumed with the role's attached and inline policies from IAM
  (`dynamic_providers[].iam_endpoint`, default the partition's IAM). The leader reads new leases within a minute
  and every lease every six hours, changing nothing upstream; a target it cannot read shows the grants as
  `unknown` with a reason and is retried, never shown as having none.
- Code-signing keys in an HSM or cloud KMS: `code_signing.keys[].managed_key_provider` and `managed_key_id`
  bind a code-signing key to an Enterprise managed key instead of a signer handle; startup checks it is active
  and of the configured algorithm. Every signature runs in the provider through the isolated signer, which now
  journals managed-key signatures by operation id (`SignManagedKeyRequest.operation_id`), so a retried signing
  command gets the same signature instead of a second one.
- Signing approvals with stock tools: while a code-signing approval is pending, the Notation plugin and the
  PKCS #11 module hold the tool's request open and sign once an approver grants it (`TRSTCTL_APPROVAL_WAIT`,
  default ten minutes); a denied or expired approval stops the tool with the reason. The signing mechanism
  is part of what is approved (`pkcs11:CKM_ECDSA_SHA256`, `notation:ECDSA-SHA-256`).
- PKCS #11 module for code signing: `libtrstctl-pkcs11` (`make signing-clients`, in `clients/signing`) offers
  trstctl code-signing keys to jarsigner, osslsigncode and other PKCS #11 tools. The PIN is the API token,
  each key comes with its certificate chain, the private-key handles are never extractable, and each
  signature (ECDSA P-256 or RSA, SHA-256) is made by trstctl's signer and checked against the certificate
  before the tool gets it. A refused signature is `CKR_FUNCTION_REJECTED` with trstctl's reason.
- Signing with stock tools: a code-signing key's certificate chain can be configured beside it
  (`code_signing.keys[].certificate_chain_file`, checked against the key at startup) and is served at
  `GET /api/v1/code-signing/keys/{key_id}/certificate`; `POST /api/v1/code-signing/keys/{key_id}/csr`
  returns a certificate request the key signs inside the signer, recorded as `codesign.csr_signed`. The new
  `clients/signing` module (MPL-2.0) adds `notation-trstctl`, a Notation plugin that signs through the
  code-signing API, and cosign can attach a trstctl signature that stock `cosign verify` accepts. The key
  never leaves the signer, and a refused request stops the tool with trstctl's reason.
- Planned CA switch: a migration run started with `revoke_predecessors` moves each cohort to the new issuer
  and revokes every previous certificate (superseded) through the CA that issued it, but only after the
  endpoint serves the new chain. A failed canary pauses the run with nothing revoked; resuming retries exactly
  the failed members as the same jobs, so no second successor is signed; starting the same switch again changes
  nothing.
- Audit feeds to syslog and Elasticsearch: beside Splunk HEC and Sentinel, an audit feed can deliver to a
  syslog receiver over TLS (`syslog+tls://host:6514`; RFC 5424 messages, octet-counted as RFC 5425 requires;
  the receiver is verified through the system roots or a CA certificate reference) or to an Elasticsearch
  bulk endpoint (`https://host/<index>/_bulk`, API key reference). Every collector receives the same audit
  records in sequence order with the chain trailer; a redelivered batch adds nothing to the index, and a
  stalled receiver holds only its own queue.
- Persistent DNS validation (dns-persist-01, the IETF draft): the ACME server offers it when
  `protocols.acme_dns_persist.issuer_domain_names` names this CA, and each order validates against the
  applicant's standing `_validation-persist` TXT record for this CA and account, so renewals need no DNS
  change; a deleted record or one naming another account refuses the next order. An ACME authority with
  `upstream_dns_persist` answers the challenge by publishing that record once through the DNS-01 provider
  configs and never retracting it. Proven against Pebble 2.10.1.
- CBOM import and code and image scanning: `POST /api/v1/cbom/imports` (`trstctl-cli cbom import --source
  vendor:|source:|image:<name>`) merges a vendor's, a code scan's or an image scan's CycloneDX CBOM into the
  crypto inventory with its source in every location; importing the same BOM again changes nothing.
  `trstctl-cli cbom scan-source` finds RSA, ECDH, ECDSA and legacy algorithms in Go, Java and Python code
  with file and line, and `trstctl-cli cbom scan-image` runs an installed CBOM scanner over an image,
  directory or archive; both run offline. Discovery coverage counts vendor, source-code and container-image
  crypto as observed while an import is recent.
- Closed-loop verification for migrations: a run started with `require_observed_traffic` advances each wave only
  when the live receipt and an observer agent's new connections at every endpoint agree, pauses when the wire proof
  is late, and then marks the observer's finding for the old certificate remediated naming both proofs.
- Passive network crypto observer: an agent granted the new observer role and started with
  `--observe-interface` reports, from the handshakes it sees, each endpoint's TLS version, cipher suite and
  key-exchange group (X25519MLKEM768 by name), TLS 1.2 certificates, SSH key exchange and plaintext
  HTTP/LDAP, never payload. The server accepts observations only from the observer role, and passive traffic
  is now an observed class in discovery coverage.
- Keystores and crypto libraries on hosts: `--inventory-keystores` reports each key entry of a Java
  keystore or PKCS#12 file (alias, key type and size, public-key fingerprint; no key material leaves the
  host, and a JKS key is never decrypted), and `--inventory-crypto-libraries` / `--inventory-go-binaries`
  report OpenSSL and Go versions with whether each can negotiate X25519MLKEM768. CBOM host-config scans
  now read HAProxy, Envoy, the OpenSSL configuration file and `java.security`; a HAProxy file that allows
  TLS 1.0 raises one weak finding.
- Access reviews that act: a revoke decision revokes the reviewed PAM session, API token, machine
  session or dynamic-secret lease once (an exact retry replays, a second decision is refused) and the
  item closes only when the credential reads revoked, with that evidence; a keep decision renews the
  owner's attestation and sets a next review date. `POST /api/v1/access/reviews/generate`
  (`trstctl-cli access reviews generate`, console) builds a campaign from who can reach a resource in the
  access graph or from owners whose attestation is stale. Decoy logins no longer appear in the graph.
- Decoy secrets: register a stored secret as bait (console, `trstctl-cli secrets honeytokens secrets`,
  `/api/v1/secrets/honeytokens/secrets`). Every read of its value through the API, its history, a
  resolved reference or the Vault-compatible API raises one critical alert per reader, naming who read
  it; listing names, metadata, previews, inventory and the graph never alert. Only people who can plant
  decoys see which secrets are bait.
- One-call revoke of an AI agent identity: `POST /api/v1/broker/agent-identities/{id}/revoke`,
  `trstctl-cli broker agent-identities revoke` and a console action in the broker record revoke that one
  broker certificate exactly like the revocation center (CA ledger, signed CRL, OCSP, agent key set), naming
  who revoked it. Broker issuance now records who asked for each identity, so the credential graph shows
  person → agent → credential → the tools its scopes name.
- Decoy database logins: a PostgreSQL dynamic-secret provider that lists the role `decoy` mints a login
  that reaches only its own empty database and looks like any generated login (console,
  `trstctl-cli secrets honeytokens databases`, `/api/v1/secrets/honeytokens/databases`). trstctl never
  uses it, so the first login with it raises one critical alert; probes and administration never do.
- Who can reach a database, host or API: the credential graph now holds people (tenant members),
  their roles and AI agents (from agent-broker issuance), with the credentials they hold (API
  tokens, machine sessions, PAM sessions, dynamic-secret leases) and the approvals behind them.
  `GET /api/v1/graph/reachers/{id}` (`trstctl-cli graph who-can-reach`) names each credential that
  reaches a node, who holds it and who approved it, every link with its record and confidence, and
  states what it cannot see; `GET /api/v1/graph/path` (`trstctl-cli graph path`) returns the path
  from one node to another. A PAM session now records the approval it consumed. The Graph page
  shows the new node kinds and both questions.
- CycloneDX 1.6 CBOM export of the crypto inventory: one cryptographic-asset component per asset
  with algorithm, key size, quantum security level, protocol and where it was observed, a coverage
  statement, signed with the audit evidence key and verifiable offline with
  `trstctl-cli cbom verify-cyclonedx`; a console download and a CLI export.
- Hardware attestation for PKCS#11 edge CA keys: a token's own attestation of the key (read by the
  agent from the token's certificate objects) that reaches a vendor root the segment pins records
  the delegation as hardware-key attested, with the device serial and key policies; a segment can
  require it.
- Annotate a leaked credential where it was seen: a third-party scan finding from a Slack export,
  a Jira export, a CI log or a container image can be written back as a thread reply, an issue
  comment, a commit status at GitHub or GitLab, or an OCI referrer on the image, by an operator or
  automatically, naming the rule and the finding and never the secret.
- Code-host secret stores in discovery: GitHub Actions secrets (repository, environment and
  organization; metadata only) and GitLab CI/CD variables (project and group, hidden variables
  flagged), with the same optional content inspection for certificates and credentials.
- API keys, tokens and private keys inside external secret stores: with content inspection, a
  cloud secret source checks each value it reads from AWS Secrets Manager, Google Secret Manager,
  Azure Key Vault or Vault KV against built-in credential rules and records each match with its
  rule, field, a masked display and a fingerprint shared by every copy of the credential; the value
  is wiped and never stored.
- Act at the identity provider on an abusive OAuth grant: an OAuth grant finding can revoke the
  user's grant at Okta, Microsoft Entra or Google Workspace, and block the app at Okta or Entra,
  through an admin connection the discovery source names by token reference.
- Workload identity for the Azure managed-key signer: `managed_keys.azure.workload_identity` exchanges
  the platform's projected federated token for short-lived Entra tokens, replacing the static bearer
  token file.
- Cross-reconciliation of an AWS KMS account against trstctl's managed-key record: an `awskms`
  authority source and a `managed_keys` authority, so a reconciliation round witnesses keys only
  one side holds and keys whose state drifted.
- Attack-path validation for exposed NHIs: a cloud network paths source with an AWS account's
  read-only credentials answers, per public endpoint, whether the account's route tables, network
  ACLs and security groups admit the internet, and names the resource that decides it.
- Cloud certificate stores in CA migration runs: a GCP Certificate Manager target that names a
  certificate map entry joins a run with no agent; the control plane installs the successor, reads
  the entry back as the live gate and re-binds the predecessor on rollback. AWS Certificate Manager
  and Azure Key Vault are refused at start with the reason they cannot restore a predecessor.
- Unattended domain validation for DigiCert and Sectigo: with `upstream_dns01`, trstctl completes
  CertCentral's DNS TXT validation and Sectigo SCM's TXT domain control validation through the
  tenant's DNS-01 provider configs (`allow_upstream_dv`), under the same CAA check and retraction as
  ACME upstream validation.
- Revoke a rogue certificate at its issuer: a certificate found in Certificate Transparency (for
  example one issued in your own vendor account outside trstctl) is revoked by serial at the
  external CA you name, and the finding shows revoked once the CA confirms; inventory findings
  revoke through the exact revocation.
- Upstream revocation for DigiCert, Sectigo, Venafi, AWS Private CA, Google CAS and step-ca: a revoke
  through trstctl reaches the vendor's API with the reason, the certificate shows revoked in
  inventory, and a retry changes nothing; the issuer capability matrix now shows revoke for each.
- AD CS revocation through trstctl: an `adcs` issuer that names a `revocation_relay` hands each
  revocation to that domain-joined relay, which revokes with certutil, publishes a new CRL and reads
  the row back before trstctl records the certificate revoked.
- AD CS CA database reads through a relay: a domain-joined network relay runs certutil against one
  CA as its own domain identity and returns only per-disposition counts (issued, pending, revoked,
  denied, failed), queued from the Posture panel, the API or the CLI; a failed read shows the relay's
  reason and keeps the previous counts.
- AD CS issuer health: `GET /api/v1/adcs/issuers/health` (CLI `trstctl adcs issuers health`, console
  Posture → AD CS issuers) reports healthy, degraded, failing or idle for each AD CS issuer from its
  recorded issuances and diagnosed refusals, with the latest cause and remediation. AD CS template
  permission denials (0x80094012) are now diagnosed as such instead of unknown.
- "Modernize this template": an inventoried AD CS template becomes a trstctl profile with its
  risky properties removed (names confined to its DNS domain so the requester no longer supplies
  the subject; Any Purpose, Smart Card Logon, PKINIT and Certificate Request Agent usages dropped;
  manager approval kept as dual control; 90-day validity), from the AD CS posture grid, the API
  (effect-free preview first) or the CLI.
- ACME and EST in front of AD CS templates: a certificate profile's `upstream_external_ca` routes
  protocol enrollments under it (ACME, EST, SCEP, CMP) to a configured external CA such as an
  `adcs` entry, after the profile's checks pass; the client receives the upstream leaf and chain.
  Console rule builder, API (unknown upstreams refused at save) and OpenAPI carry the field.
- Kerberos authentication for AD CS Web Enrollment: an `adcs` external CA can name a realm,
  principal, KDCs and a keytab (`kerberos_*`); trstctl answers the Negotiate challenge with a
  fresh service ticket per request and never holds or sends a password. Kerberos and Basic are
  mutually exclusive, and a Kerberos failure never falls back to Basic.
- Intune reads without a hand-rotated bearer: an Intune MDM poll schedule can name an Entra app
  registration (`client_credentials`: directory and application (client) ID); `token_ref` then
  holds its client secret and the network relay exchanges it for a Microsoft Graph token on each
  read (OAuth client-credentials grant, token held only in memory). Console schedule form, API and
  OpenAPI carry it; the Intune report export moved to Graph v1.0.
- Dynamic SCEP challenges for Jamf Pro and other MDMs that fetch a one-time challenge per device
  (`hmac-dynamic`): a policy names a `challenge_credential_ref`, the MDM fetches each challenge
  from `/scep/mscep_admin/{policy id}` with that credential (Jamf Pro: Dynamic-Microsoft CA), and
  the SCEP gate verifies it against the policy it names and consumes it once in the durable
  replay fence. Console, API and CLI carry the credential reference and the challenge page path.
- Tenant download of its own signed audit archives: with the separate `audit:archive.read`
  permission, `GET /api/v1/audit/archives` lists the tenant's archived segments and
  `GET /api/v1/audit/archives/{id}` returns one (`?format=jws` for the raw segment; CLI
  `trstctl audit archives list|get`; console Audit → Archived segments). Segments are addressed by
  opaque ID only, verified as the tenant's own signed retention segment before release, rate
  limited per tenant, and every download is recorded as an `audit.archive.downloaded` audit event
  first. A downloaded segment verifies offline with `trstctl audit verify --format retention-jws`.
- Event-field protection (crypto-shred) opt-in: a tenant can read its protection state, preview
  and enable per-tenant encryption of its sensitive event fields through
  `/api/v1/privacy/event-protection` (CLI `trstctl privacy event-protection`, console Privacy
  panel), naming its current registration and a retention window its policy chooses. A bounded
  worker prepares the key; status reads `active` only after the key reads back. After
  offboarding and the retention window, the key is destroyed with a signed record, and a rebuild
  or a restore of an earlier backup shows the tenant's sensitive fields as erased while audit
  verification and other tenants are unaffected. Events recorded before activation stay readable.
- Named ServiceNow and Jira ticket-intake schedules with independent relay jobs
  and cursors, explicit mailbox-to-owner mapping, and an Approvals setup wizard.
  Legacy sources remain `default`; removal preserves history and blocks active
  work. Missing or ambiguous ownership remains visible and cannot bypass issuance.

- Opt-in certificate CI export through a separate tenant-bound ServiceNow write
  binding. The outbox worker uses IRE and independently reads the fixed certificate
  class before recording a durable verification receipt. API, CLI and console show
  queue and verification status; ownership reconciliation remains read-only.

- Per-tenant private HTTPS notification receivers: an operator can grant exact
  networks through `notifications.tenant_private_egress`. API endpoint validation
  and outbox delivery use the same tenant grant. Tenants cannot grant themselves
  access; DNS, redirect, TLS and air-gap checks remain in force.

- Provider console sign-in through OIDC: with `provider.oidc.login` configured, the Provider console
  signs operators in with the IdP's authorization code flow (state, nonce and PKCE S256) and holds
  an HttpOnly, SameSite=Strict Provider session instead of a pasted bearer token. The ID token is
  verified offline against the pinned keys with the client id as audience and the same role and
  MFA claims; no token reaches the browser, every request re-reads the SCIM directory row, and
  sign-out revokes the session.
- Provider SCIM group removal: removing an operator from the `provider-admin` or
  `provider-operator` group through SCIM now revokes that role, recorded as a
  `provider.operator.role_revoked` authority event naming the group and the SCIM token, instead
  of being refused. Group PATCH applies its operations in order (the Okta and Entra request
  shapes), replace and PUT revoke whoever they leave out, and the operator stays active with no
  role, which OIDC and SAML refuse on the next request. A user created without roles holds none
  until a group push assigns one, and `GET /Groups` answers a `displayName` or `id` filter. The
  access console shows such an operator as holding no role.
- Attested edge delegation renewal: a segment policy can set `renewal_enabled` (with
  `renewal_window_days`, default 7), and a host agent run with `--edge-renew` renews its delegated
  edge CA over the agent channel inside that window. The TPM key signs a fresh CSR and TPM2_Certify
  vouches for it over the new challenge; the control plane holds the renewal to the mint's gate
  (one attestation verifier for both), requires the same delegated CA key, and mints a delegation
  with the old one's lifetime, linked by `renewed_from` and `renewed_by`. An expired, revoked or
  already renewed delegation does not renew, and a refused attestation leaves it to expire. The
  console's segment form has the renewal setting and the delegation list shows renewals.
- Edge journal upload: a host agent run with `--edge-journal-upload` sends its edge issuance journal
  over the mutual-TLS agent channel when it connects, after a heartbeat that follows failed ones,
  and when the journal grows, so issuances made while the host was offline reconcile without an
  operator posting the file. The control plane reconciles each certificate against the delegation
  of that host that issued it (the host is the agent's channel certificate name; host-role agents
  only), through the same path as the CLI and console reconcile, with the agent as the actor. The
  agent records the acknowledged prefix in `<journal>.uploaded` and sends only new entries.
- External CA ledgers in reconciliation: a reconcile authority can read an EJBCA CA's issuance
  ledger (`ejbca` source: REST v2 certificate search over mutual TLS) or a step-ca CA's (`stepca`
  source: its PostgreSQL `x509_certs` and `revoked_x509_certs` tables, read-only), and an
  `inventory` source scopes the certificate inventory to the same CAs. A round between the two
  witnesses drift both ways: certificates the CA issued that the inventory lacks, certificates the
  inventory holds that the CA never recorded, and revocations only one side knows. Both sides read
  the CAs in `issuer_certificates_file` and certificates unexpired at the observation, identity
  from each certificate's DER. A ledger that moves during the read, or is larger than
  `max_objects`, fails the observation instead of reporting part of it. The ids `trstctl-self` and
  `trstctl-ca` now refuse a source block.
- Hybrid-to-pure ML-DSA certificate cutover: a PQC migration run can target pure ML-DSA for a
  certificate whose current leaf is the hybrid composite (the console offers such certificates).
  The plan marks that reissue `cutover`; starting the run holds its host job, the finding reads
  `awaiting_acknowledgment`, and the start response counts it in
  `certificate_cutovers_awaiting_acknowledgment`. Once a quorum of signed relying-party
  acknowledgments for the identity's PCAS retirement policy is recorded inside its window (a policy
  PCAS already retired on that quorum still counts), a leader worker queues the held job unchanged
  and records `pqc.migration.cutover_released` with the relying parties and the ack-set digest; the
  host then generates the ML-DSA key and returns only its CSR. Without the quorum the cutover waits
  and the served leaf stays hybrid.
- Scheduled CA rollover drafts: with `ca.rollover_draft_band_months` (`TRSTCTL_CA_ROLLOVER_DRAFT_BAND_MONTHS`,
  off by default) set to a CA calendar band, an active signer-backed authority entering it gets a
  `rekey_ca` ceremony opened for it with the reviewed plan — its profile and lifetime and a
  scheduled-rollover reason — at the approval floor. `GET /api/v1/ca/authorities` and the CA console
  show the draft and its approvals; nothing rotates until custodians approve and a person executes
  the re-key with that plan. An authority that cannot be re-keyed online records why.
- Certificate byte recovery: `POST /api/v1/certificates/{id}/der-recovery` (`trstctl-cli
  certificates recover-der`, the certificate detail's **Certificate bytes** actions) gives an
  inventory row recorded without its certificate — a scan, a cloud listing, an older import — the
  certificate itself, from a mint of the tenant's CAs that retained it (`ca_ledger`, by serial) or
  from the `host:port` the row names (`endpoint`, dialed by the control plane under the egress
  rules). Bytes are attached only when they hash to the row's fingerprint and the row held none,
  with where they came from; the row then joins authority agreement checks. Certificate responses
  carry `certificate_bytes_held`, and the detail `der_recovery`.
- Verification address suggestions: `GET /api/v1/connectors/targets/{id}/verification-suggestions`
  (`trstctl-cli connector target verification-suggestions`) lists the `host:port` addresses where a
  discovery scan saw a certificate trstctl delivered to the target, with those findings as
  evidence, and `POST /api/v1/connectors/targets/{id}/verification-address`
  (`connector target confirm-verification-address`, the console's **Verification address** panel)
  sets one as the target's `verify_address` only when an operator confirms it — never an address
  no finding suggests, and never on a target that changed since the suggestions were read.
- Certificate Transparency SCT verification and inclusion proofs: a CT submission can name
  each log's public key in `log_public_keys` (the console takes it after the log's URL).
  Every SCT a log returns is kept: verified against that key over the exact RFC 6962
  entry (the certificate, or a precertificate's issuer key hash and TBS) or flagged invalid
  with the reason; a log without a key keeps its SCT unverified and the response says so.
  For each verified SCT the leader fetches the log's signed tree head, checks it with the
  same key and verifies the entry's audit path to its root, recording the inclusion proven
  (index, tree size, root), pending, not included once a tree head signed past the 24-hour
  merge delay still lacks it, or a failed proof. `GET /api/v1/certificates/{id}` and the
  certificate detail show each log's answer (`transparency`). Logs that serve only the
  static CT API are submitted to and their SCTs verified, but their inclusion is not checked.
- Addresses outside the declared segments: `GET /api/v1/discovery/coverage/candidates`
  (`trstctl-cli discovery coverage candidates`) lists the addresses trstctl's own sources
  recorded in the last 30 days — certificate deployment locations, verified endpoints,
  external observations and verification addresses — that no declared segment covers,
  by the same rule sweeps use (excluded segments count as declared). The coverage register
  names them and the console lists them with a one-step segment declaration. Never a
  complete list: an address no source has recorded cannot appear.
- Revocation checks for scanned certificates: with `agent_channel.probe_scanned_certificates`
  on (off by default), a relay's TLS discovery sweep keeps the leaf it finds and up to four
  issuers served after it, each only if it hashes to what the relay reported, and revocation
  health probing checks that certificate's own serial at its CRL distribution points and
  OCSP responders against the served issuer that signed it. `GET /api/v1/certificates/{id}`
  and the certificate detail show those relay-signed answers (`revocation_observations`,
  including whether the CRL lists the serial); probe answers carry `scope` and the endpoint
  list stays one row per endpoint.
- Host recovery after containment: a host profile's containment binding can name a
  `recovery_action`, and `POST /api/v1/connectors/targets/{id}/recovery-check` (CLI
  `connector target recovery-check`, console **Check host recovery readiness**) asks
  the target's enrolled host, in a read-only `endpoint.recovery_check` job enabled with
  `endpoint.contain`, whether its profile pins one and what the listener answers now;
  the signed answer carries SHA-256 digests, never the action's path. A replacement
  preview for a listener containment stopped reads `ready` only after such a check
  shows a recovery action the connector runs while deploying and a listener not
  serving the contained leaf, and creating the replacement otherwise answers 409.
- Managed CA leaf recovery: `POST /api/v1/certificates/managed-ca-recoveries`
  (`trstctl certificates inventory-managed-ca -f leaf.pem`) gives a managed CA leaf a
  version-1 `ca.endentity.issued` mint recorded by serial only its inventory row from
  the public certificate an operator supplies, when the tenant's managed CA signed it
  by its stored certificate and that CA's mint recorded the serial; the leaf is then
  revocable through the inventory workflow.
- Archive legal holds: `POST /api/v1/archives/legal-holds` (object and reason,
  `audit:write`), `DELETE` on `/{id}` and `GET` (CLI `archives legal-holds
  place|release|list`) place and release an S3 legal hold on one archive object under
  the tenant's prefix; the outbox sets or clears it in the bucket and the hold reads
  applied or released only after the bucket reads it back. With the archive under
  Object Lock, a report legal hold also holds the report's object, and the run and
  console show that hold's state.
- S3 Object Lock on the archives trstctl writes: with `object_store.object_lock_mode`
  (`GOVERNANCE` or `COMPLIANCE`) and `object_lock_retention` (at least `24h`), every
  audit archive segment, report artifact and backup set written to the object store
  carries that retention. `trstctl doctor` checks the bucket has Object Lock enabled
  (OBJ-LOCK). The report retention reads a report object's lock first and leaves a
  protected report in place, recording `artifact_removal_deferred_until` on its run
  (a day at a time under a legal hold) and removing it once the lock has ended.
- Tenant custom roles: `PUT /api/v1/access/roles/{name}` defines a role as a named
  subset of the permissions built-in roles grant (only from permissions the caller
  holds), `DELETE` removes one no member holds, and `GET /api/v1/access/roles` lists
  them with `custom: true`; CLI `access roles define|delete` and the People and roles
  console. Assigning a custom role needs every permission it grants. A role resolves
  on every request, so a change applies at once.
- SCIM group-to-role map: `auth.scim.tokens[].group_roles` maps a directory group to a
  built-in or custom role; an unmapped group that is not named for a built-in role is
  still refused, and a group mapped to an undefined custom role is refused by name.
- SCIM token rotation without a restart: a rewritten token file is read again within
  two seconds; a rewrite that cannot be used keeps the last good token.
- Report retention and legal holds: with `audit.report_retention` (or
  `TRSTCTL_AUDIT_REPORT_RETENTION`, at least an hour; off by default), the
  report scheduler queues the removal of every completed run's signed report
  older than the window that no person holds; the outbox removes it from the
  archive directory or the object store and records the run expired only after
  reading the archive back and finding it gone, after which the download
  answers 410 and the run receipt and its SHA-256 remain.
  `POST /api/v1/compliance/report-runs/{id}/legal-hold` (with a reason) and
  `DELETE` on the same path (`trstctl-cli compliance report-runs legal-hold` and
  `release-hold`, `audit:write`) hold a completed report past the window and
  release it; a hold also cancels a removal already queued. The console's
  signed-runs list places and releases holds and shows removed reports.
- Compliance reports in full backups: `--full-backup-dir` captures every
  completed report run's signed report (from `audit.archive_dir` or the archive
  object store) as an encrypted `report-archive` artifact with an index, a full
  restore puts each back where its run's reference says and reads it back
  against its digest, and the restore drill restores them into its isolated
  target and attests the count.
- SPIRE JWT authorities through trstctl: the SPIRE upstream authority plugin
  publishes each SPIRE server's JWT signing key to
  `POST /api/v1/spiffe/upstream-jwt-keys` and returns every unexpired key the
  tenant's SPIRE servers have published, sending the set again when another
  server publishes, so SPIRE servers that share a trust domain through trstctl
  verify each other's JWT-SVIDs. `GET` on the same path (and
  `trstctl-cli spiffe upstream-jwt-keys list`) shows the published keys.
- The host Workload API offers `unix:path:` selectors on macOS: the agent reads
  the caller's executable from its audit token (`LOCAL_PEERTOKEN`, with
  `LOCAL_PEERPID`), and only while the token's pid version still owns the pid,
  so an entry can require a workload's binary path there as it can on Linux.
- Vault-path dynamic credentials: a stock Vault or OpenBao client reads native
  leases at `database/creds/<role>` (username and password), `aws/creds/<role>`
  and `aws/sts/<role>` (an STS session with its assumed-role ARN) and
  `kubernetes/creds/<role>` (a ServiceAccount token), or at
  `<provider>/creds/<role>` when several providers offer the role, and looks
  up, renews (database leases) and revokes them through `sys/leases`; a
  synchronous revoke returns once the provider confirms removal.
- Three secret-sync targets: `webhook` POSTs templated JSON signed with HMAC-SHA256
  over a timestamp and the body (`X-Trstctl-Signature`, `X-Trstctl-Timestamp`), so
  a receiver can refuse a changed or replayed delivery; `aws-parameter-store`
  writes SecureString parameters; `netlify` sets secret environment variables.
- Dynamic-lease rotation: `POST /api/v1/secrets/rotations` with
  `dynamic-lease:<provider>` and `ttl_seconds` replaces the lease an application
  secret publishes with a new lease of that lifetime on a PostgreSQL, MySQL or
  Redis provider, as a durable command: the new lease's credential becomes the
  next secret version once a database session (or Redis AUTH and PING) proves it,
  and the old lease is revoked at the provider. The console's rotation form takes
  the lease TTL.
- `trstctl-kms-wrap`, the signer key store's KMS/HSM wrap adapter, ships in the
  images. With `--kms-provider`/`--kms-key-ref`/`--kms-wrap-command` (Helm
  `externalKMS`), the signer's data keys are wrapped under an AWS KMS key, a
  Cloud KMS CryptoKey, an Azure Key Vault or Managed HSM key, or (in the HSM
  signer image) a PKCS#11 token AES key, and the key store no longer opens
  without that key. Helm's `wrapCommand` defaults to the adapter and
  `adapterConfigSecret` carries its configuration. The signer checks the adapter
  before it serves, so an unreachable or disabled key stops startup with the
  provider's reason.
- Several managed-key providers at once: `managed_keys.providers` lists the
  providers a deployment runs together (for example a PKCS#11 HSM and AWS KMS),
  and the isolated signer builds them all. A key is created under the provider
  its request names, `managed_keys.tenant_providers` pins a tenant to one, and
  every key reports its provider. Actions find a key's provider from its handle.
- Deployment KEK rotation: the operator tenant (`secrets.kek_operator_tenant_id`)
  rotates the deployment KEK, the key behind every credential of a tenant without
  its own key domain, from the local key file onto a key under an operator wrapper
  file or an HSM key the isolated signer holds (console deployment key panel,
  `trstctl-cli platform deployment-kek`, `/api/v1/platform/deployment-kek`). New
  data is wrapped under the new generation at once; the leader re-wraps every
  stored data key, unmigrated tenants' history and the deployment's sealed files
  while requests are served, reads them all back, then retires the previous
  generation. Under an HSM key, stored credentials decrypt only through the
  signer.
- KMIP client registrations: with `protocols.kmip.client_registrations`, one KMIP
  listener serves every tenant's own clients. A tenant registers a client (Transit
  page, `trstctl-cli kmip clients`, `/api/v1/kmip/clients`) and gets a one-time
  enrollment; the client's first request binds its own TLS certificate with that
  username and password, and the certificate then selects the tenant. Each tenant
  sees only its own objects, a new enrollment moves a client to a new certificate,
  and a removed registration is refused at its next request.
- KMIP key pairs: the KMIP listener creates RSA and ECDSA key pairs (Create Key
  Pair), activates them (Activate), signs and verifies with them (Sign, Signature
  Verify), and serves Get Attributes, Get Attribute List and Add, Modify and Delete
  Attribute for names, contact information and `x-` text attributes. Both halves
  start Pre-Active; the private key stays sealed in the server and is not returned
  to Get unless the client created the pair with Extractable set. A revocation for
  key or CA compromise leaves an object Compromised. PyKMIP 0.10 drives the path in
  an opt-in proof.
- Kubernetes CSR approver (opt-in): with `--k8s-csr-approver`, the agent asks
  the issuing CA whether it would issue each pending native
  `CertificateSigningRequest` for a trstctl signer name
  (`POST /api/v1/ca/authorities/{id}/issue/evaluate`, the checks issuance makes,
  without signing; `trstctl-cli ca authorities evaluate-leaf`) and writes
  Approved, or Denied with the CA's reason. A Kubernetes approver still decides
  by default. `deploy/kubernetes/rbac-csr-approver.yaml` carries the grant.
- Agent clock-skew warning: every heartbeat carries the agent's clock and its
  answer carries the control plane's. An agent more than
  `agent_channel.clock_skew_warning` (default 2 minutes) off is named on the
  Agents page and in `GET /api/v1/agents` with the measured drift, counted by
  `trstctl_agents_clock_skewed_total` (alert `TrstctlAgentClockSkew`), and warned
  in the agent's own log. Agents still time renewal by their own clock.
- Relay connector plugins: a module reads its deploy's certificate, fingerprint
  and target (`input.read`) and asks the relay to make its HTTP calls
  (`net.http`). The relay adds the target's credential, splices the private key
  into the body by reference and removes every redeemed value from the reply, so
  the module deploys as the appliance's administrator without holding the
  password or the key. A module that exports `test` answers connector tests under
  a read-only grant (no file writes, HTTP `GET` and `HEAD` only). A reference
  module ships in `plugins/connectors/reference/`.
- Relay failure log: an agent that claims jobs keeps its newest 200 failed
  deploys in a file on its own host (`--deploy-failure-log`, beside `--key` by
  default, mode 0600): when, the job and attempt, the connector and target, the
  step that failed and why, with redeemed values, PEM blocks and the values of
  authorization headers and credential-shaped fields removed.
  `trstctl-agent --show-deploy-failures` prints it. The control plane still
  receives only a closed phrase for a failed deploy.
- Operator-granted agent roles: an operator holding `agents:relay.grant`
  changes an enrolled agent's roles (`POST /api/v1/agents/{id}/roles`,
  `trstctl agents roles grant`, **Change roles** on the Agents page) without
  re-enrolling it. The grant is recorded as an event; the agent's heartbeat asks
  it to renew, the renewal signs exactly the granted roles and records which
  grant it signed, and the agent reconnects with the new certificate. The agent
  list shows the change as pending until a renewal signs it. Roles never come
  from the CSR: a renewal CSR asking for a role the renewal is not signing is
  refused with the role named, on the agent channel and the HTTP renewal
  endpoint.
- Relay egress policy: every connection an agent opens to run a job (appliance
  and API calls, endpoint checks, discovery scans, directory reads, TLS probes)
  refuses link-local addresses, cloud instance metadata, unspecified and
  multicast addresses, and `trstctl-agent --relay-egress-allow` refuses everything
  the operator does not list (CIDRs, addresses, `address:port`). The check runs
  on each request's named destination, so a proxied request is covered, and on
  each dial's resolved address. Windows service installation keeps the
  allowlist across restarts.
- Outcome pages: three pages in the docs (certificate automation and assurance,
  agent and workload identity assurance, and cryptographic risk and migration
  assurance) list each outcome's end-to-end workflow, the evidence every step
  leaves, how strongly each step is proved today (naming the test), the feature
  doc that explains it, and what comes next. The console home gains an
  Outcomes section that routes to each workflow's starting screen.
- Evaluation kit: `trstctl evaluate` runs one certificate journey against an
  endpoint the evaluating team chooses, through the control plane's own API:
  discovery by the control plane's TLS handshake, ownership, issuance on the
  platform CA (with the key generated on the host for an agent-executed target),
  deployment, verification by the command's own TLS handshake, renewal,
  revocation checked over OCSP, and a signed audit export. It writes an
  evidence pack with each step's outcome and whether it was observed or only
  recorded, a pass/fail verdict and the run's limits; a step after a failure is
  skipped, never passed. `--sign` signs the pack with the audit-evidence key
  under its own artifact domain, and `trstctl evaluate verify` checks it
  offline with a pinned audit key set.
- Customer assurance report: `GET /api/v1/reports/assurance` (`trstctl-cli
  reports assurance`) and the `customer_assurance` scheduled report type put a
  tenant's credential assurance into plain sentences in its white-label brand:
  inventory and ownership coverage; expiring, renewed and failed credentials;
  endpoint verification and how changed credentials were verified; incidents
  with their signed evidence; each figure compared with the previous report.
  The signed run carries a self-contained branded HTML rendering. `trstctl-cli
  compliance report-runs verify` checks any saved scheduled report offline
  against the signing key from `GET /api/v1/compliance/report-signing-key`. A
  Provider schedules the report through a tenant template, whose report
  schedules can now announce each run on the customer's channels, and lists and
  downloads a customer's signed runs at
  `/provider/v1/tenants/{id}/assurance-reports`.
- Provider tenant templates: versioned templates of customer tenant objects
  (certificate profiles, the lifecycle policy, CA bindings, connector targets,
  notification channels, member role grants and report schedules). A Provider
  onboards a delegated customer from a version, which registers the customer's
  core tenant when needed and writes each object through the customer's own
  commands; reads back each customer's drift from its version; and rolls a new
  version out across customers after a preview, refused if any customer changed
  since. Each application is an audited Provider authority event.
- Cryptographic risk report: `GET /api/v1/reports/crypto-risk` (CSV through
  `/export`, `trstctl-cli reports crypto-risk`, and the `crypto_risk` scheduled
  report type) lists every weak, distrusted or quantum-vulnerable key with what
  depends on it, the NIST IR 8547 deadline that applies (initial public draft:
  112-bit keys deprecated after 2030, all disallowed after 2035) and the
  crypto-readiness action or recommended next step, in the order to act on. Each
  scheduled run lists what changed since the previous one, read back from the
  archive and signature-checked first.
- MCP evidence tools and structured findings. Six read tools answer posture and
  exposure questions from the served read routes with the agent's own token:
  `posture_findings`, `weak_key_exposure`, `distrust_exposure` (the certificates
  and host trust stores a distrust-list entry affects, each with evidence IDs),
  `assurance_record`, `revocation_status` and `crypto_inventory`. Every MCP tool
  result now carries structured findings (finding ID, evidence IDs, source, time,
  confidence) beside its narrative, under a JSON Schema the tool listing publishes;
  `trstctl-cli mcp serve` advertises it as each tool's output schema and returns
  structured content. Discovery findings filter by `distrust_entry` and
  `key_strength=weak`.
- Agent-to-agent identity over A2A 1.0: a reference pair on the official A2A Go
  SDK (`test/interop/agentframeworks/cmd/a2aagent`). The serving agent's Agent Card
  declares mutual TLS and the delegated-credential header as its security
  requirements and is signed with its trstctl certificate key; the calling agent
  verifies the certificate chain and agent ID, then the card signature with that
  key; every request is authorized by the caller's delegated scope before a task
  exists. The integration suite proves an in-scope task and refuses an
  out-of-scope skill, a borrowed credential, an untrusted CA and a wrong agent.
- MCP authorization with a trstctl agent identity: `GET /agent-keys/{tenant}/{agent}/jwks.json`
  publishes the public keys of an agent's valid broker certificates (a revoked
  certificate's key leaves at once), so the customer's authorization server can
  authenticate the agent with `private_key_jwt` and issue it tokens for an MCP
  server. The reference tool server gains an OAuth resource-server mode (protected
  resource metadata, audience- and scope-checked bearer tokens) and the reference
  agent a client that follows the metadata, authenticates with its identity key,
  and uses the authorization server's token exchange. A lab test proves the flow
  and the revocation against Keycloak; see `docs/guides/mcp-authorization.md`.
- Agent delegation for relying services: each tenant has its own agent issuing
  CA in the signer, published at `GET /api/v1/agent-delegation/issuing-ca` with
  its SPKI SHA-256 so a relying service pins it (another tenant's credentials
  never verify against it), and `GET /api/v1/agent-delegation/credential-status`
  reports `active`, `revoked`, `expired` or `unknown` with the credential's
  SHA-256, so a revoked delegation stops working at a relying service within its
  status window instead of at expiry. CLI: `agent-delegation issuing-ca get`,
  `agent-delegation credential status`. Reference integrations under
  `test/interop/agentframeworks`: an MCP tool server on the MCP Go SDK that honors
  a tool call only within the calling agent's delegated scope, and an agent built
  with the Agent Development Kit for Go (with a scripted model) that calls it with
  its agent identity and delegated credential; the agent delegation integration
  suite runs both against the real signer, and now runs in CI.
- External observers: `POST /api/v1/observers` registers a monitor outside trstctl
  (probectl or any other), and `POST /api/v1/observations` takes what it saw at an
  endpoint — vantage, time, reachability, health, served leaf and chain
  fingerprints. Each report is compared with what trstctl's newest endpoint
  verification expects at that address (`match`, `mismatch`, `unreachable`,
  `unexpected`); a mismatch raises a finding, as does an unhealthy endpoint within
  seven days after the renewal that produced its certificate; a match is
  independent evidence on the certificate's assurance record. Completed renewals
  and connector rollbacks queue signed `rotation.completed` / `rollback.completed`
  events to every enabled observer from the transaction that records them. CLI:
  `observers register|list|update`, `observations record|list`; the observer
  contract is documented in `docs/guides/external-observers.md`.
- Credential assurance records: `GET /api/v1/certificates/{id}/assurance-record`
  (`trstctl certificates assurance-record`) joins one certificate's discovery,
  owner, issuance (CA, the deciding event, profile revision and approval),
  every delivery and verification (served fingerprint, which comparisons ran,
  vantage, the agent or relay and its signed receipt), renewals, revocation and
  the audit entries that name it, each with an evidence ID, and states which
  stages were independently observed, recorded only, or absent. The isolated
  signer signs it under its own artifact domain;
  `trstctl certificates verify-assurance-record` verifies a saved record offline
  against a pinned audit JWK set, and any changed value fails. The response
  includes a Markdown rendering; compliance evidence packs carry the records of
  the certificates whose lifecycle changed in their window; the certificate
  drawer builds and saves the record.
- Lifetime-reduction readiness: `GET /api/v1/certificates/validity-readiness`
  (`trstctl certificates validity-readiness`) evaluates every active certificate
  under the CA/Browser Forum TLS Baseline Requirements 2.3.1 section 6.3.2 steps
  (200 days from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15). Each step
  gets a verdict per certificate (`renews`, `at_risk` or `manual`, with reasons)
  from the scheduler's own inventory: what renews it, how its renewal is
  deployed and verified, what holds it, and when the scheduler starts it. A new
  profile field, `public_tls`, says a profile issues publicly trusted TLS server
  certificates; the report flags such a profile whose `max_validity` exceeds a
  step's maximum, or that has none. `.../export` returns CSV naming the BR
  version in its file name and on every row. The console's renewal tab shows the
  report in place of the client-side 47-day simulator, and the profile builder
  sets `public_tls`. The rogue-certificate posture holds a public TLS
  certificate's lifetime to the dated maximum for its issuance date, counted the
  BR way (notBefore through notAfter inclusive).
- The control plane runs the shipped connector families in the WASM sandbox by
  default (`connectors.isolation: wasm`, `TRSTCTL_CONNECTORS_ISOLATION`). The
  binary embeds one digest-pinned first-party connector module; each deploy,
  readback, rollback, takedown, preview, TLS-posture or appliance-key operation
  runs in a fresh wazero instance whose only effects are the sandbox operations
  its grant permits, and whose memory is wiped afterwards. Every family is
  proven to behave identically in and out of the sandbox. The connector catalog
  reports each family's `isolation`. `in_process` keeps the previous behaviour.
- Enrolled host agents and network relays run the shipped connector families in
  the same WASM sandbox by default (`trstctl-agent --connector-isolation`,
  `in_process` to opt out). The relay builds every family through the control
  plane's constructor census, so a relay-built connector is the same connector.
- `POST /api/v1/ai/query` plans questions beyond certificate expiry: certificate
  questions combining expiry windows, expired, status, issuer, key algorithm,
  subject or SAN name, owner and no-owner clauses (as a list or an exact count),
  "who owns" a certificate, crypto assets by algorithm, key size, quantum
  vulnerability or policy, and credential-graph inventories. Each is answered
  exactly from a typed query, beginning with "Interpreted as:"; anything outside
  the grammar is still scoped evidence marked insufficient. The audit record
  (`ai.query.answered` v3) adds the plan kind, its clause kinds and the count.
- Tenant attestors for agent delegation: `POST /api/v1/agent-delegation/attestors`
  (`trstctl-cli agent-delegation attestors register|list`) records a tenant's
  attestor public key and attestation method as an immutable first-writer
  event, provisions it into the isolated signer over its authenticated
  transport and reports `provisioned` only after the signer reads the exact
  binding back. The signer verifies a tenant's attestation evidence only
  against that tenant's attestors, for the registered method and no higher
  class; attestors no longer need operator provisioning on the signer host.
- `/readyz` gains `ssh_krl` (the SSH revocation list can be brought up to the
  event log, when the SSH CA is served) and `audit_read` (audit history can be
  read), so a restarted replica stays out of rotation until its KRL and audit
  reads can be served.
- Continuous audit anchoring at a known cadence (Enterprise audit compliance
  with `protocols.tsa` enabled): whenever a tenant's audit log has grown, the
  leader timestamps the tenant's full audit chain on `audit.anchor_interval`
  (`TRSTCTL_AUDIT_ANCHOR_INTERVAL`, hourly by default, `0s` off) and appends
  the timestamp to the tenant's own log as an `audit.anchored` record.
  `trstctl-cli audit verify --tsa-root ... --anchor-cadence 1h` re-checks every
  anchor inside an unbroken run of exported records, refuses a record that
  entered the chain after an anchor it predates, and requires every record to
  be covered within the cadence; the receipt reports the series as
  `anchor_series`. `GET /api/v1/audit/anchors` (`trstctl-cli audit anchors`,
  Audit console) shows the cadence, state and recent anchors.
- The TSA's certificates are entries of the issuing CA's ledger, so its CRL and
  OCSP responder answer for them. `trstctl-cli protocols tsa certificates
  list|rotate|revoke` (`/api/v1/protocols/tsa/certificates`, Protocols console)
  moves the TSA onto a fresh signer-held key, revoking the outgoing certificate
  with a reason, and revokes a certificate rotated out earlier. Audit exports
  carry the CA's OCSP answer for each TSA certificate their timestamps rely on
  (`validation`), and `trstctl-cli audit verify` checks it against the pinned
  root, refusing every timestamp under a certificate revoked for key or CA
  compromise and those at or after any other revocation; `--tsa-crl` brings a
  fresher CRL and `--require-tsa-revocation` refuses an unchecked certificate.
- Each tenant's anchors are kept in an RFC 6962 anchor log. Audit exports carry
  a head of that log signed with the audit export key (JWS envelopes move to
  schema 2 when they carry it; stream trailers gain `anchor_log`) and an
  inclusion proof for every anchor record they hold; `?anchor_log_from=<size>`
  adds a consistency proof from an earlier head. `trstctl-cli audit verify`
  checks them with `--audit-jwks` and, with `--previous-anchor-log`, proves the
  log only grew since a head kept from an earlier receipt.

- A TrustBundle can also be distributed as an Opaque Secret in each target
  namespace (`spec.target.secret`; outside the agent's namespace this needs
  the opt-in grant in `deploy/kubernetes/rbac-trust-secrets.yaml`) and as a
  ClusterTrustBundle (`spec.target.clusterTrustBundle`) that pods mount
  through a projected volume. The opt-in CSI node plugin in
  `deploy/kubernetes/csi-trust.yaml` (driver `trust.csi.trstctl.com`,
  `trstctl-agent --csi-trust-socket`) serves a TrustBundle to a pod as an
  inline volume and republishes it when it changes. A TrustBundle that cannot
  be distributed is now marked `Ready=False` (reason `DistributionFailed`)
  with the cause, instead of keeping an earlier Ready.
- A TrustBundle can be rolled out from the control plane to several clusters,
  canary first: `POST /api/v1/kubernetes/trust-rollouts` (`trstctl-cli
  kubernetes trust-rollouts start|list|get|pause|resume`, Workloads console).
  Each cluster's agent receives the bundle in the answer to its posture report,
  applies it as a TrustBundle it owns (never one someone else created), and
  distributes it; a cluster reads verified only when its own controller
  reports the bundle distributed with the rollout's SHA-256, and the other
  clusters wait for the canary. The agent ClusterRole gains TrustBundle
  create/update/patch; `--k8s-trust-rollouts=false` keeps rollouts out.
- The Kubernetes agent's controller is event-driven: it lists and watches its
  issuers, trstctl Certificates, TrustBundles, cert-manager
  CertificateRequests, native CertificateSigningRequests and the ConfigMaps it
  distributed, and a work queue converges each object as its event arrives
  (about a second instead of the next poll), with a full re-check every
  `--k8s-resync` (default ten minutes). trstctl Certificates are renewed with a
  new key two thirds of the way through their validity and reissued when their
  spec changes or their Secret is deleted; `status.notBefore`, `notAfter`,
  `renewalTime` and `specHash` record it.
- The Kubernetes Operator manages the control plane's network surface the way
  the Helm chart renders it: a Service (`spec.service`), a default-deny
  NetworkPolicy (`spec.networkPolicy`) and an optional Ingress
  (`spec.ingress`). With `signerMode: isolated` it runs the signer as its own
  pod behind its own Service and a NetworkPolicy that admits only that control
  plane, generates the mutually pinned mTLS pair unless you name your own
  Secrets, renews it a month before it expires, and rolls both pods onto a new
  pair. `spec.signer.authTokenCommand` and `spec.signer.allowCoResidentAuthorizer`
  wire signer authorization as the chart does, and combinations the control
  plane would refuse set the resource `Blocked` with the reason. The operator
  deletes only objects it labels as its own and refuses to take over others.
  Its Role gains delete on Deployments, Secrets, Services, NetworkPolicies and
  Ingresses, and get/create/update/patch on Services, NetworkPolicies and
  Ingresses.

- Certificates can carry a device-bound custody claim the device's TPM signed.
  When an ACME `device-attest-01` attestation certifies a key the TPM generated
  and will not release (`sensitiveDataOrigin`, `fixedTPM`, `fixedParent`), the
  certificate records custody `device` / `device_bound` / `non_exportable` and
  keeps the attestation; `GET /api/v1/certificates/{id}/key-attestation` (console
  download, `trstctl-cli certificates key-attestation`) returns it, and
  `trstctl-cli certificates verify-key-attestation` re-checks it offline against
  TPM roots you choose. The edge sub-CA's TPM lane now refuses an attested key
  the TPM could release.
- A tenant's key domain can be rotated: `POST
  /api/v1/platform/tenant-key-domain/rotate` (console tenant custody panel,
  `trstctl-cli platform tenant-key-domain rotate`) makes a new generation of
  the tenant's domain KEK under the same or another configured wrapper,
  re-wraps every stored data key and the tenant's event history without
  decrypting a payload, and promotes the new generation. Both generations stay
  readable until then, and a failed rotation resumes with the same target.
  Copies taken before a rotation still open with the previous generation.
- A CA can be imported together with the private key it already has: after
  two custodians approve an `import_ca_key` ceremony, `trstctl-cli ca
  authorities key-offer` fetches the signer's one-time import key (HPKE with
  the MLKEM768-P256 hybrid KEM), `wrap-key` seals the PKCS#8 key to it on the
  operator's machine after checking it is the certificate's key, and
  `import-key` has the signer open it, refuse it unless it matches the
  certificate, and hold it under the ceremony's handle with CA-signing
  constraints and dual control. The control plane relays only sealed bytes.
  The console starts the ceremony from **Certificate authorities → Imports**
  and hands over the import request and the commands.
- A signer-backed CA authority's key can be revoked: two custodians approve a
  `revoke_ca` ceremony for the exact authority and reason, and `POST
  /api/v1/ca/authorities/{id}/revoke` (`trstctl-cli ca authorities revoke`, or
  **Certificate authorities → Lifecycle → Revoke a CA key**) executes it. The
  isolated signer refuses every signature with the key from then on, in every
  signer process sharing its keystore; the authority stops issuing; its
  certificate is revoked on a managed parent's CRL; and the response carries
  the signer's own readback. A leaf of a revoked authority is reported as not
  revocable on that authority's CRL, and the periodic CRL refresh skips it.
- The managed-key production-assembly proof has an arm64 profile:
  `make dod-gate-arm64` runs it on a native arm64 host against the release's
  `linux/arm64` control plane and cgo HSM signer, with the same custody substrate
  and entries as the amd64 proof, and CI runs it on GitHub's arm64 runner. The
  proof runner image builds for either architecture from the same pinned inputs,
  and the proof now waits out a queued (202) managed-key receipt the way a client
  does instead of reading it as the key.
- Transit key creation and rotation are facts in the event log: a
  `transit.key.created` or `transit.key.rotated` event names the key, its kind
  and the version, under a fact ID saved with that version's sealed material, and
  is appended only after the material is saved. The versions listing reports each
  version's `fact_id` and whether the log records it; a fact whose append failed,
  and the versions saved before this release, are recorded by a reconcile pass.
- A tenant's key domain can live in the signer under an HSM key: migrate with
  `wrapper_kind: "pkcs11"` and a wrapper ID the control plane lists in
  `secrets.tenant_seal_pkcs11_wrappers`. The signer (the `signer-hsm` image, the
  BYOK license, `--tenant-kek-config`) creates the tenant's domain KEK, keeps it
  wrapped by an AES-256 key the operator provisions on the HSM over PKCS#11, and
  wraps and unwraps the tenant's data keys itself; the database keeps only the
  wrapped KEK and the control plane never holds it. Seal and unseal work as for
  a local wrapper file, a lost HSM key fails only that tenant closed, and the
  console's tenant custody panel offers the choice.
- Transit keys are shared by every replica: each tenant's keyring is a sealed
  row in PostgreSQL, saved before a create or rotate is reported and reloaded
  when a replica lacks a key or version, so a key made on one replica works on
  all of them and after a restart. A keyring an earlier version kept in
  `transit.keyring_dir` is imported at startup, and the file is left in place.
- Authority agreement can observe a KMIP server: an authority entry with a
  `kmip` source block reads object metadata over KMIP 1.4 with a client
  certificate (Locate, Get Attributes, and certificate values; never key
  values). An observation that cannot be complete fails instead of reporting
  part of the server, and `allow_tls12` opts in a server whose TLS stops at 1.2.
- A Cisco ISE destination can name its node and certificate roles
  (`node_hostname`, `certificate_roles`): deploys then import system certificates
  named for their fingerprint and bound to those roles, so the destination rolls
  back by moving the roles to the predecessor and reads back the certificate
  serving them. Cisco is no longer an architecture exception in the relay parity
  program.
- An F5 BIG-IP (a single device), NetScaler, A10 Thunder, PAN-OS firewall or Cisco
  ISE destination can have the appliance generate its own private key:
  `"key_generation": "appliance"` with a pinned network relay. The relay asks the
  appliance for a key and a CSR in an object named for the renewal job, the control
  plane signs the CSR, and the certificate is installed against the appliance's key,
  so no key crosses the relay or the control plane. Custody records the key as
  appliance-generated and appliance-held. Rollback binds a predecessor back with
  its own appliance key without reading it, and a renewal picked up again sends the
  same CSR (for Cisco ISE, which names its requests itself, the relay keeps ISE's
  request ID for the job on the control plane). A PAN-OS destination needs
  `ssl_tls_profile` and `commit_admin`, a Cisco ISE destination its node and roles, an F5
  HA pair keeps control-plane keys, and the destination dialog offers the choice
  where the family supports it (the connector catalog's
  `appliance_key_generation`).

### Security

- MCP certificate writes take the identity lifecycle gate. `issue_certificate` and
  `rotate_certificate` used to issue straight from a named CA authority, outside the
  policy gate and dual control. They now act on a lifecycle identity (`identity_id`,
  with the agent's own CSR for issuance) through its transition route with the agent's
  credentials: a deny-all policy refuses them, and under dual control an issuance is
  proposed (`outcome: proposed`, an approval request, `mcp.tool.proposed`) and runs
  only when the same call is repeated after a distinct approver approved it, while a
  rotation is refused. A call naming `authority_id` is refused. Approval decisions and
  certificate mutations outside the lifecycle gate are never MCP tools. `trstctl-cli
  mcp serve` accepts an `idempotency_key` argument and names the key a proposed write
  is bound to.
- The signer's attestation verifier checks the key ID inside attestation
  evidence as a single path segment and reads the key through a directory
  handle. Before, the key ID was joined into a file path unchecked, so evidence
  could name another public key file on the signer's floor as its attestor.
- Every image now ships one trust store: the pinned, checksum-verified Alpine
  `ca-certificates-bundle-20261020` filtered at build time by the shipped
  distrust list (`internal/crypto/trust/distrust.json`), which leaves exactly
  Mozilla's 118 websites roots. The list names the three emSign roots Mozilla
  removed on 2026-10-20 and, by public key, the eight eMudhra intermediate CAs
  whose P-384 private keys are small integers anyone can recover; matching by
  key also catches their AAA Certificate Services cross-signs. The control
  plane, signer-hsm and agent-pkcs11 images previously trusted the Debian or
  distroless bundle (150 and 142 roots, including those emSign roots and AAA
  Certificate Services, 42 and 49 roots Mozilla no longer trusts for websites,
  and 10 and 25 it does that were missing); the Alpine-based images trusted
  the three removed roots. Go 1.26.10, which trstctl has built on since
  2026-10-21, already rejects any chain through the eight intermediates in
  trstctl's own binaries; builds and images from before 2026-10-21 (v0.6.0
  included) do not, and nothing before this change protected non-Go software
  in the images or guarded against another weak key under the same roots.
  `trstctl-trustbundle` (filter, probe, list) is the build-stage tool; the
  Node images read the system store (`NODE_OPTIONS=--use-openssl-ca`).
- Every outbound TLS client now checks a runtime distrust list after normal
  verification, on resumed sessions too: a verified chain through a distrusted
  root, intermediate or key (the three emSign roots and the eight eMudhra
  intermediates by SPKI, so their cross-signs are caught) fails the handshake
  with the entry named, while a server that also presents a clean path still
  connects, as Go's own distrust list behaves. The check lives in the shared
  transport builders (`internal/netsec`, the egress guard), on the process
  default transport every binary installs at startup, and on an
  operator-pinned external CA root as well; operators add entries with
  `trust.distrust_file` for sites that cannot take a release the day a CA is
  distrusted, and the shipped entries cannot be removed.
- Ambient outbound clients that trusted the system store directly (the
  identity-provider metadata and JWKS client, secret-sync pushers,
  dynamic-secret backends, cloud token and discovery clients, AWS IAM, connector
  HTTP operations, DNS-01 providers, telemetry, the OTLP exporter, the model
  client, the CLI without a CA file, the operator's and the agent's Kubernetes
  clients) now come from the `internal/netsec` builders, so the runtime distrust
  check covers them, each at the timeout it had before; none gains the SSRF
  guard, because their endpoints are operator-configured and may legitimately
  be private. The architecture linter (SEC-005) also refuses an `http.Transport`
  or `tls.Config` literal built outside `internal/netsec`, `internal/egress` and
  the crypto boundary.
- `make trust-audit` builds every image and compares the roots Go loads from
  each (Go's own Linux rule, `SSL_CERT_*` included) with Mozilla's current
  websites trust list from CCADB and the shipped distrust list; a root Mozilla
  does not trust for websites, a distrusted certificate or key, or a redirected
  store fails and names the image and the root. It runs daily
  (`.github/workflows/trust-audit.yml`) and gates the release workflow from the
  `release-evidence` job, which every publishing job needs;
  `trstctl-trustbundle audit` is the step behind it. Ordinary builds and pull
  requests still use no network.
- Weak-key detection (`internal/crypto/weakkey`, modeled on badkeys): an
  elliptic-curve key whose private scalar is small (|k| up to 2^24 + 2^16, by
  baby-step giant-step; the eMudhra intermediates' were 4 to 237), RSA moduli
  with small factors, close primes, the ROCA structure, impossible exponents,
  a prime shared with another key in the same inventory (batch GCD), and keys
  on operator-supplied blocklists such as Debian's 2008 list
  (`TRSTCTL_TRUST_WEAK_KEY_BLOCKLIST_FILES`; trstctl ships none, the Debian list
  is GPL-3). Private keys an agent finds are now named for every RSA size and
  curve (an RSA-1024 key used to have no algorithm at all) and reported weak
  with the reason. The distrust list carries each entry's subject key
  identifier, so a leaf under one of the eight intermediates is found from its
  authority key identifier. See docs/security/weak-keys.md.
- Every certificate trstctl discovers is rated while its bytes are at hand:
  agents rate what they find (files, Kubernetes, PKCS#11, Windows and every
  trust store), cloud discovery rates what the provider returns, and the CT
  monitor rates the hits it keeps. The verdict (weak key with reasons;
  distrusted certificate or issuer, naming the entry) travels as finding
  metadata and raises the risk to 85 or 95. The control plane re-rates every
  agent report against its own distrust list and replaces any distrust claim
  in it, so a host trust store holding emSign ECC Root CA - G3 is a finding
  even from an older agent.
- A relay's network scan rates the whole served chain, not only the leaf, and
  reports it as hashes and closed check codes (the scan protocol admits no
  certificate bytes or free text); the control plane applies its own distrust
  list and words the reasons.
- CBOM certificate-key assets are rated from the served leaf and chain: a key
  with a structural weakness, or one whose certificate depends on a
  distrust-list entry, is weak and out of policy whatever its size, with the
  reason and the migration plan that replaces it.
- The CA key ceremony refuses weak keys and proves possession. The signer
  refuses a weak key it generates, mints or imports, and an HSM or KMS key
  that fails is zeroized (closed code `provider_key_weak`). No weak key is
  certified as a CA, and imports and cross-signs refuse a CA certificate that
  is weak or on the distrust list. A signer-held key signs a fresh challenge,
  verified against the exact public key going into the certificate, before it
  is certified as an intermediate or bound to an import. The managed-key
  custody probe now carries a fresh nonce.
- The leader runs batch GCD over each tenant's RSA public keys every six hours
  (CA authorities, inventory certificates and the keys agents, cloud discovery
  and the CT monitor now report) and records a `weak-key` finding wherever a key
  shares a prime with another, as a discovery run under the product-owned
  `weak-key-audit:batch-gcd` source. Reported RSA keys are also rated against
  the operator's blocklists, which only the control plane holds.
- A distrusted root an agent finds in a host trust store can be removed through
  trust distribution (`POST /api/v1/discovery/findings/{id}/remove-distrusted-root`,
  `trstctl-cli discovery findings remove-distrusted-root`, or **Remove from host
  trust store** in the console's finding detail). The exact host agent
  reads the file, removes it only when it holds just that root and the agent's own
  distrust list names it, and reports a signed result onto the receipt; bundles,
  other certificates and paths outside the host profile are refused and left
  alone. Agents take an operator distrust list with `--distrust-file`.
- An offline root's import can carry `possession_signature`, the root's
  signature over the import ceremony's challenge, made on the offline system
  with the OpenSSL commands in the key ceremony runbook (the console prints
  them). Every CA creation and import now records how possession of the key
  was established (`self_signature`, `signer_challenge`, `offline_signature`
  or `not_proven`) in its response and its creation event.

### Fixed

- ACME S/MIME orders (P15): a CSR that names the mailbox as its common name, as stock S/MIME
  clients do, is issued; the protocol profile gate took that common name for a DNS name and
  refused the order. Proven with a stock RFC 8823 client library through a real mail server, and
  a stock mail client verifying a message signed with the certificate.

- A host destination whose key the control plane generates (no `"executor": "agent"`) deploys again. Since a host
  destination must name its agent in `required_agent_id`, the credential grant still asked for the key-custody marker
  as well, so the assigned agent was refused the sealed deploy ("credential redemption was not granted") and every such
  deploy failed. The grant now binds the work to the agent the target's reviewed configuration names, whichever side
  generates the key; a target naming another agent, or none, is still refused.

- The Windows agent MSI installs again on current Windows releases: Windows Installer applied the service's
  restart-on-failure actions without the start right a restart action needs, so the install failed with error 1939
  and rolled back. The agent's service now sets its restart policy (30 seconds, 60 seconds, then 5 minutes) on itself
  whenever it starts, and `--service=install` sets it at registration; the MSI keeps only the setting that counts an
  error exit as a failure.

- `gcp-iam` revocation deletes only keys of the bound service account: a reference naming any other resource, or
  another account's key, is refused instead of becoming a DELETE path (A240).

- Repository secret scans of a `clone_url` now run with the real scanner: the clone lands in a temporary directory
  outside the configured scan roots, which the scanner refused, so every cloned repository scan failed; that one
  directory is now the clone scan's root. A cloned repository's finding also keeps one identity across scans (its
  fingerprint no longer names the temporary directory), so a rescan sees the same finding instead of adding another.

- CBOM import refused ordinary image scans: the shared 1 MiB mutation body limit applied before the import's
  own limit, and an import held at most 5,000 components, while the real cbomkit-theia's CBOM for a small Alpine
  image is about 6 MiB and 8,000 components. An import now reads its own body (up to 32 MiB) and holds up to
  50,000 components.
- The code-signing approval docs described the legacy identities approval route and a new Idempotency-Key;
  the served flow is `POST /api/v1/approval-requests/{id}/approvals` (or `/denials`) and repeating the same
  request with the same key, which consumes the approval once.
- The RFC 2136 DNS provider's TSIG-signed updates are accepted by DNS servers: the signature now covers
  every TSIG variable RFC 8945 lists, including Other Len, which was left out, so a standards server (BIND,
  Knot, PowerDNS, miekg/dns) refused every signed update as "bad signature" and DNS-01 through RFC 2136
  never published.
- A SPIRE server whose upstream authority is the trstctl plugin no longer stops
  at startup when trstctl does not serve JWT key publication (an older trstctl
  answers 404): the plugin reports publication as unsupported, so SPIRE logs a
  warning, keeps its JWT keys in its own bundle and starts; the next JWT key
  rotation publishes again.
- The SPIRE upstream authority docs said the plugin's token needs `certs:issue`;
  the intermediate CSR route needs `issuers:write`, and it signs only under an
  approved ceremony for each CSR, which the docs now say.
- Moving a tenant into its own key domain, or rotating that domain, now re-wraps
  the tenant's shared transit keyring with its other secrets. The keyring stayed
  under the previous key, so a replica that started afterwards, or any replica
  after a restart, could not open it, and the tenant's transit keys stopped
  working.
- A CA authority's leaf route (`POST /api/v1/ca/authorities/{id}/issue`) now
  refuses a subject key the tenant recorded as compromised (422, naming the
  compromise), as every other certifying path already did; it signed one before.
- A staged agent upgrade's soak window now ends when its reason says. Recording
  the soak cleared the ring's dispatch, so the next sweep sent the ring's agents
  a second round of upgrade jobs and the window started over; a campaign that
  dispatches nothing could move its window forward on a later sweep. Either way
  the soak might never end.
- The Kubernetes agent no longer stops its controller pass on a cluster without
  cert-manager (native CSRs and TrustBundles were never reconciled there), no
  longer rewrites every TrustBundle ConfigMap and status on every pass, keeps a
  ConfigMap's other keys when it updates the bundle, and renews trstctl
  Certificates, which it used to issue once and leave to expire.
- The Kubernetes Operator could not create a control plane on a real cluster:
  its owner references lacked the `uid` the API server requires. Its pods now
  also run as the image's non-root user with that group owning mounted
  Secrets, so the 0440 KEK and signer-authorization files are readable.
  Upgrading the operator rolls each managed control plane once onto the
  corrected pod template.
- The first issuance of an identity bound to a host-executed destination never
  completed in a tenant that had not yet issued a certificate from the platform
  CA: after handing the work to the host agent, the issuance command tried to
  refresh a CRL the tenant could not have yet and retried forever. The CRL step
  now runs only when the command itself issued a certificate.
- Rogue certificate detection flagged every ECDSA certificate as a weak key
  (risk 85) and never an RSA-1024 one: it read only the bare algorithm name, so
  "ecdsa" matched "dsa". It now rates the certificate itself when trstctl holds
  it (key, signature hash, structural weaknesses), else the verdict discovery
  recorded, else the recorded algorithm name, and gives the reasons in
  `weak_key_reasons`. A certificate that is, or chains to, a CA or key on the
  distrust list is a new critical `distrusted_issuer` finding naming the entry
  and how it matched.
- SSH fleet and Workloads no longer label every discovered raw host key as
  outside SSH CA trust. The inventory reports observed key locations and
  standing grants; proving CA posture requires sshd trust and served-certificate
  evidence. The unsupported `under_ca` and `hosts_not_under_ca` fields were
  removed from the API and generated clients.
- Raw SSH revocations now survive control-plane restarts and reach other replicas
  through the event-backed KRL. Raw SSH mutations use the API guard, including
  tenant admission, permissions, rate limits, ABAC and idempotent replay.
- Direct SSH user certificate issuance requires an explicit principal allowlist;
  host certificates reject user options. SSH issuance events record the caller,
  principal names and validity window.
- Restarting the control plane during an incident fleet re-issuance no longer
  lets the legacy batch worker revoke a wave's certificates before their
  replacements exist; revocation always waits for a verified successor.
- The built-in `viewer` and `mcp` roles no longer include `secrets:read`, which
  revealed application secret values in plaintext. Grant it deliberately through
  `operator`, `cli`, `admin` or a custom role.
- Roles set on a tenant member now decide that person's session. Before, sign-in
  roles from a tenant mapping or `default_roles` were added to them, so a member
  set to `viewer` could still hold `admin`. A member record without roles keeps
  the sign-in roles.
- Only a caller that holds every permission can grant the `admin` role. An
  `operator` or a role-provisioning token can still assign every other role.
- An API token minted for another subject can no longer approve or deny on that
  subject's behalf; every approval route refuses it. Approvals now count people,
  not token names.
- API tokens minted through the API expire after 90 days by default and cannot be
  given a longer expiry (`auth.api_tokens.max_lifetime`; `0` opts out).
- Agent renewal over HTTP now refuses revoked certificates and offboarded agents,
  as the agent channel already did; before, one renewal call undid a revocation.
- Agent renewal, over HTTP and over the agent channel, can no longer change which
  agent a certificate names; a CSR naming another agent is refused with 403.
- The workload co-sign listener requires pinned mutual TLS on `host:port`, creates
  `unix:` sockets owner-only with a peer uid check, and bounds request size and
  concurrency. Before, any process that reached it could obtain co-signatures.
- `/metrics` no longer names tenants: the outbox dead-letter, delivery-timeout and
  circuit metrics are labeled by destination only, and the metrics registry now
  refuses any tenant label.
- `ca.ceremony_min_approvals` (`TRSTCTL_CA_CEREMONY_MIN_APPROVALS`) sets the
  fewest custodian approvals a CA key ceremony may require; requests can raise
  the threshold but not lower it, and `regulated` governance requires at least 2.
- Notification delivery details open at the heading, keeping the outcome visible
  before operators tab through the dialog.
- Certificate replacement explains when a matching identity is already renewing
  and links to its lifecycle evidence without allowing concurrent replacement.
- Certificate detail drawers keep populated lifecycle evidence and metadata
  inside narrow and intermediate-width viewports.
- Signer help identifies PCAS succession as core and the license option as the
  gate for Enterprise managed-key providers.
- SAML sign-in started from the console resumes the requested local page,
  including query filters and fragments. A signed, expiring context binds the
  destination to that login attempt; IdP-initiated login keeps its configured default.
- The console offers each configured browser sign-in method, including SAML-only
  and LDAP-only deployments. Directory sign-in has accessible credential fields,
  safe retry guidance, password clearing and verified-session navigation.
- SP-initiated SAML browser login now sends its secure correlation cookies on
  the identity provider's cross-site POST. State, request-ID and signature checks
  remain required; OIDC and authenticated session cookie policies are unchanged.

### Changed

- The stale NHI posture no longer calls an API token unused when trstctl has no usage telemetry for it: before
  this release every token older than 90 days read as unused.
- An audit export or search that is an unbroken run of records selected only
  by time or sequence now carries the hashes its records have in the tenant's
  full audit chain, and its `prev_hash` is that chain's head just before its
  first record (before, every selection was re-hashed from the archived
  prefix). Content-filtered selections are unchanged. Search responses now
  include `prev_hash`, and record-stream trailers mark a full-chain export with
  `"chain": "tenant"`. Saved exports from either rule verify as before.
- CA-agnostic outbound issuance (F4) is now listed as served. Its last
  residual, the Kubernetes CSR and TrustBundle posture routes, already served
  the authenticated reports the cluster agents send and is proven by the
  definition-of-done census against a real kind cluster; the catalog,
  requirements and limitations had kept calling those routes descriptor-only.
- A `k8s_ingress_gateway` discovery source can be bound to the host-role agent
  running in the cluster (`cluster_agent_id`, `owner_id`, optional
  `verify_address`). Each run then keeps a `k8s_secret` destination and a
  certificate identity per TLS block and queues the first issuance to that agent,
  which generates the key inside the cluster, sends only a CSR, writes the TLS
  Secret and reads it back; the certificate records `key_storage=kubernetes_secret`.
  Resources report `delivery_queued`, then `delivered`, or `not_delivered` with the
  agent's own reason while a failed attempt is retried. A source without an agent
  still reports each resource `not_delivered` with the reason. A `k8s_secret`
  destination saved without `executor=agent` is refused.
- The outbound clients that used Go's default client with no timeout at all
  (secret-sync pushers, dynamic-secret backends, the ACM, Certificate Manager
  and Key Vault discovery clients, the Azure and GCP token clients, AWS IAM,
  connector HTTP operations, the nine DNS-01 providers and the CLI connector
  client) now time out after 30 seconds; a request that needs longer fails
  instead of hanging. Callers that inject their own client are unaffected.
- Tenant SAML, LDAP and SCIM now require Enterprise SSO, included in Enterprise
  and inherited by Provider. Their implementations live under `ee/enterpriseauth`;
  OIDC, shared session persistence and tenant authorization stay core. Configuring
  these tenant methods without the attached licensed implementation refuses startup.

- PCAS operator/security guides now live in the public documentation. Edition
  references identify PCAS, AGID, XREC, VDEC, PQC and remediation as core;
  obsolete family-specific gate targets are replaced by direct integration and
  conformance commands while the core/EE boundary gate remains. The smaller
  commercial tree measured 70.7% coverage; its enforced floor rises from 65%
  to 70%. Patent claim traceability remains under `ee/docs/`.

- Managed tenant provisioning saves the reviewed request and its original
  idempotency key before sending it. Operators can recover an uncertain result
  from the same account after reloading or reopening the browser, without
  generating a conflicting registration request. The server checks the reviewed
  tenant and operator before creation or replay so another tab's account switch
  cannot silently change the account used for provisioning.

- Managed tenant provisioning now accepts its existing provider metadata under
  the required event privacy policy, while retaining closed field validation.

- Authority agreement reports now show only the authenticated tenant's
  authorities, counts, resolution metrics and collection status. Reconciliation
  replay keeps witness ownership separate across tenants and rejects conflicting
  event tenants before changing projection state.

- Core PQC migration and rollback remain available after a commercial license
  expires, with tenant authorization and idempotency checks preserved. Edition
  disclosures now place PQC in Free Core and the operator guide reflects the
  current rehearsal command.

- Remediation is part of Core: incident and guided remediation routes now mount
  without a commercial license in both normal and Core-only builds. Tenant
  isolation, RBAC, policy, idempotency and outbox requirements are unchanged. The
  credential-compromise workflow library moved from `ee/incident` to
  `internal/incident` under BUSL-1.1.

- **Licensing.** The core moved from the Mozilla Public License 2.0 to the
  Business Source License 1.1 (Licensor certctl LLC): production use is permitted
  under the Additional Use Grant, the Free tier needs no signed license, and each
  release converts to MPL-2.0 four years after it is published. `clients/` stays
  MPL-2.0; `ee/` stays proprietary. Every core file's SPDX header reads
  `BUSL-1.1`.
- **The patent-pending families and PQC are core.** PCAS (`internal/succession`,
  `internal/translog`, `internal/rpverify`), AGID (`internal/agentid`), XREC
  (`internal/reconcile`), VDEC (`internal/decommission`) and PQC (`internal/pqc`,
  `internal/pqcruntime`, `internal/pqcmigration`, `internal/kmip`) moved out of
  `ee/` and attach in every build through `cmd/*/attach_families.go`; the
  `pcas`, `agent-delegation`, `reconcile`, `vdec` and `pqc` license features are
  gone (a license file that still names them parses and grants nothing extra).
- **Migration ledger.** The `-- SPDX-License-Identifier:` line is outside a shipped
  migration's content digest; a ledger row recorded by an earlier binary under the
  previous identifier is recognized and re-stamped with `checksum_adopted_at`.
- **The Terraform provider is its own MPL-2.0 module.** `terraform-provider-trstctl`
  moved from `cmd/terraform-provider-trstctl` and `internal/terraformprovider` to
  `clients/terraform` (module `trstctl.com/terraform-provider`), licensed MPL-2.0
  with the rest of `clients/`. Its module path sits outside `trstctl.com/trstctl`,
  so the compiler refuses any import of the control plane's `internal/` packages:
  the provider reaches trstctl only through the served REST API. `make build`,
  `make reproducible-check`, `make sdk-test` and the registry release script
  build and test it from that directory, and the Terraform SDK modules are no
  longer requirements of the core module.
- **No published pricing.** Reference list prices and wholesale bands are gone
  from the docs (`docs/pricing.md` is removed), the README and the editions API:
  `GET /api/v1/editions` no longer serves `reference_price_bands`, and
  `pricing_posture` is now `commercial_posture`, stating that Enterprise and
  Provider terms are agreed per customer and not yet published. The console's
  editions panel no longer renders a price table.

## [0.6.3] - 2026-09-19

Tagged after 0.7.0 on the same line of development; it carries one change.

### Changed
- CI: CodeQL is scoped to shipped product code, so analysis time goes to the
  binaries that ship rather than to tooling and fixtures.

## [0.7.0] - 2026-09-16

### Fixed
- Provider authority and customer service state are enforced on every
  provider-plane mutation, and completed credential requests are recovered
  rather than dropped.
- Live tenant policy is isolated per tenant, and the lifecycle surfaces show
  the actual authority that governs each identity.
- Tenant authority is preserved through governed lifecycle recovery.
- Local bootstrap token creation is recorded through events, so the audit
  trail covers it like every other issuance.
- Retained-batch subscription callbacks are joined before cleanup in the
  events tests, removing a teardown race.

### Changed
- The console is English-only (R07); the locale plumbing that shipped no
  translations is gone.
- Documentation explains the first-member role provisioning handoff.

## [0.6.0] - 2026-09-15

The development milestone that closed the summer hardening train: 1,762
commits since 0.5.4. The last weeks before the tag repaired the verified
lifecycle and operator journeys, bounded retained-history transport and
decoding, activated existing SSH trust on retry with effective-config
validation, retained verified PostgreSQL archives in server test shards,
made the lint tool distinguish fresh upsert keys from exclusive locks, and
refused repeat signing when retained issuance needs a rebuild. The dated
entries below are the train's own log.

### Bundled PostgreSQL authenticates executable bytes before startup (2026-09-09)

- The evaluation database verifies its independent committed archive checksum
  before extraction or execution, including on a cold download. Maven's checksum
  sidecar remains an additional transport check.
- Each start extracts authenticated bytes into a fresh private directory. The
  archive cache includes platform, version and digest; stale extracted binaries
  cannot survive a pin change. Existing database data and legacy caches remain
  intact.
- Rooted extraction rejects unsafe paths, links and file types, and enforces
  expansion limits.
  Complete archives and executable trees are published atomically. Startup errors
  preserve their original cause and never stop an unproven existing server.
- Regression tests call the actual startup wrapper and check executable markers,
  tampered archives, extraction limits and concurrent publication. Legacy test
  and developer-tool loaders remain outside this served-path provenance claim.

### Lint tool failures cannot qualify unchecked source (2026-09-08)

- Formatting and architecture lint stop on failed prerequisites, including an
  unavailable temporary file or a failed analyzer build.
- The EE lint gate validates the full scanner report and exit status, requires
  every configured linter, retains diagnostics and refuses malformed results.
  It reports potential baseline reductions without editing the baseline file.
- The EE scanner also bounds output while running and stops its process group
  on timeout or cancellation. A scanner that leaves children behind fails.
- Regression tests inject tool failures into the actual Make recipes and verify
  that incomplete checks fail before later work can hide them.

### Dark-segment enrollment relay failover is observable and stock-ACME-safe (A4, 2026-08-12)

- **A relay returned an ACME directory whose absolute URLs named the control
  plane.** A stock client followed the second URL directly, so the claimed dark-
  segment path failed even though isolated `/directory` and `/acme/*` proxy tests
  passed. Relays now require one stable `--enroll-proxy-public-url` and preserve
  that HTTP authority while the socket still dials only the configured control-
  plane endpoint. Signed request bodies and protocol responses remain byte-for-
  byte pass-through, and the proxy still attaches no agent credential.
- **Control-plane endpoint failover was mistaken for relay redundancy.** Each
  certificate-bound network relay now reports its operator-named
  `--enroll-proxy-segment`, public URL, verified/unavailable/unverified upstream counts,
  process-lifetime forwarded/refused/failure counters, and last forward/failover
  times on its authenticated heartbeat. The immutable event stream rebuilds the
  tenant projection; `GET /api/v1/agents`, generated SDKs, and the Protocols
  console show the exact per-segment relay rows and redundancy count.
- A configured endpoint starts **unverified**, not healthy. Only a completed
  response proves health; retry-cooldown expiry merely permits another probe.
  A real HTTP 502 from the control plane remains the client's response, while
  only an out-of-band transport failure changes upstreams.
- The assembled acceptance starts two relay subprocesses behind one segment URL.
  A stock `golang.org/x/crypto/acme` client registers through the primary, the
  primary process dies, and the same client completes a real signer-backed order
  through the secondary. Its transport refuses the control-plane authority and
  records zero attempted direct routes.

### The repository has an intake path and a code of conduct (2026-08-02)
- **README.md and CONTRIBUTING.md told readers to open an issue; nothing was
  behind that invitation.** `.github/ISSUE_TEMPLATE/` now carries a bug report
  and a feature request as GitHub issue forms, each requiring only what a
  maintainer needs to reproduce or judge the report — version/commit, what
  happened versus expected, and steps for a bug; the problem, the proposal, and
  whether it lands in core or `ee/` for a feature.
- **A vulnerability could be filed as a public issue in one click.** SECURITY.md
  says not to; nothing enforced it at the point of filing. Blank issues are now
  disabled and a contact link routes a would-be reporter to SECURITY.md before
  the new-issue form, with a second link to `docs/limitations.md` so a
  not-yet-served subsystem is not reported as a defect.
- **CODE_OF_CONDUCT.md adopts the Contributor Covenant 2.1 verbatim**, with the
  enforcement address taken from the one SECURITY.md already publishes rather
  than a second address that could drift. A guard in `docs/issue_intake_test.go`
  pins all of it, including that the two addresses stay the same.

### Broker-issued agent credentials can be task-scoped (B-7, 2026-07-26)
- **Only the chain-bound delegation path could bind a credential to one
  authorized task.** The broker's single-hop path — the one an AI/MCP agent
  actually uses — could not carry an AGID-05 task envelope at all, so a broker
  badge had standing scope and nothing narrower. `POST
  /api/v1/broker/agent-identities` now accepts `task_envelope_base64` and
  returns the `task_envelope_digest` the credential binds, which the caller
  can recompute to confirm the scope it authorized.
- **An envelope the build cannot verify is refused, not ignored.** This is the
  rule that makes the binding worth anything: silently issuing an *unscoped*
  credential in place of the scoped one a caller asked for is precisely the
  outcome an attacker would engineer, so a Community / core-only build (which
  attaches no gate) rejects the request. Requests carrying no envelope are the
  ordinary single-hop badge, untouched — INV-A10 zero removal holds.
- **The gate reuses the delegation gate's own verification**
  (`taskenv.VerifySignatureAndExpiry`): requester signature over the canonical
  bytes, resolved through an operator-provisioned trust store on the signer
  floor that the caller cannot inject into, plus the expiry window. The bound
  digest is computed from the envelope that just passed, so a substituted
  envelope cannot be bound in place of the signed one, and the binding is
  emitted into the audit chain (AN-2) rather than living only in a response.

### A migration can be reviewed before it runs (B-3, 2026-07-26)
- **You could start a fleet-wide re-issuance; you could not look at it first.**
  `POST /api/v1/pqc/migrations/plan` (and `trstctl-cli migration plan`,
  Enterprise PQC) previews the plan — which assets would be re-issued and to
  what, which TLS findings would be rolled out, and **the residuals it will
  not touch** — with no run id, no outbox row, and no event. The residual list
  is the half that makes the preview honest: a plan that only showed what it
  *will* do would overstate coverage.
- **The preview cannot lie about the migration.** It calls the same
  `BuildPlan` the start path calls, over the same CBOM assets, so a divergence
  between preview and execution would have to be a divergence inside the plan
  builder itself — not two implementations drifting apart.
- The licensed READ seam grew the response writers it was missing
  (`WriteJSON`/`WriteError`/`WriteProblemUnauthorized` beside the existing
  `Tenant`), so a licensed GET renders errors in exactly the core's
  problem+json shape instead of inventing its own.

### Signing history is verifiable after the fact (B-4, 2026-07-26)
- **Code signing served the two mutations and nothing that answered
  afterward.** You could sign with a managed key or keylessly, but nothing
  told you which identities had signed or whether the transparency-log entry
  actually landed. `GET /api/v1/code-signing/identities` (and `trstctl-cli
  code-signing identities`) lists recent operations with their identity kind
  and each one's transparency state — `verified`, `pending`, `failed` with its
  reason, or `not-published` — plus the two counts a reviewer asks for first.
- **Verification is not a second source of truth.** Rekor publication rides
  the outbox, and the handler refuses to acknowledge an entry whose signed
  receipt does not verify — so a delivered outbox row *is* a verified entry,
  and the view reads that state rather than a parallel flag that could drift
  from it. The query reads no sealed command bytes, so the plaintext identity
  assertion and artifact digest never leave the signer boundary through it.

### The SSH estate outside the CA is readable (B-2, 2026-07-26)
- **The SSH surface covered the credentials trstctl issues and nothing about
  the ones it does not.** CA status, trust rollouts, attested user certs and
  revocation were all served, while discovered SSH keys sat in the inventory
  with no view answering the operator's actual question: which hosts still
  have standing key-based access that certificate rotation cannot reach.
  `GET /api/v1/ssh/fleet` (and `trstctl-cli ssh fleet`) rolls those keys up
  per host — key count, standing-access count, orphaned count, key types,
  sources, observation window — ordered worst host first, so the hosts most
  needing to come under the CA sort to the top.
- **The not-under-CA claim is structural, not inferred.** Every row behind the
  view is a raw key, because a certificate minted by the SSH CA is never
  stored as an `ssh_key`; each host therefore carries `under_ca: false`
  explicitly, and the response repeats the count so a dashboard does not have
  to restate the invariant. Metadata only — fingerprints, types, locations —
  never private key material.

### The connector catalog reports its sandbox contract (B-6, 2026-07-26)
- **The catalog described what a connector deploys, never what it may do.**
  An operator authorizing a privileged deployment could not see the two facts
  that matter: what the connector is permitted to touch, and what happens on a
  redelivery. Each catalog row now carries `native` (this build has a native
  implementation), `capabilities` (the declared sandbox grant — `fs.read`,
  `fs.write`, `net.dial`, `process.exec`, sorted), and `replay_safety`
  (`reconciled` when the receiver converges on retry, otherwise
  `at-most-once`).
- **Read from the live registry, not written beside the description**, so the
  catalog cannot drift into claiming a capability the process would not
  enforce. Reporting never constructs a connector. A connector this build does
  not implement natively reports no capabilities and the conservative
  at-most-once contract, and a control plane assembled with no registry claims
  nothing at all.

### The running system is readable from the console (B-5, 2026-07-26)
- **`/admin/system` showed posture, not the system.** It rendered what the
  product *claims* — edition, support tier, scale plan — but not the readout
  an operator wants when something looks wrong. That answer existed only on
  `/healthz` and `/readyz`, which are unauthenticated infrastructure probes
  shaped for a load balancer. `GET /api/v1/platform/system` (and
  `trstctl-cli platform system`) reports the build version/commit/date, the Go
  toolchain, process start time and uptime, the **live** AN-4 signer topology
  (`child`/`external`/`none` — what is actually attached, not what the config
  intended), whether the FIPS module is routing `crypto/*`, and per-dependency
  reachability for the database, event log, and signer.
- **It reuses the same probes as `/readyz`**, so the console and the load
  balancer can never disagree about whether the spine is up — the failure mode
  that makes an operator distrust both. Probes are bounded at 3s so a hung
  dependency degrades this endpoint instead of hanging the caller, and the
  readout carries no addresses, DSNs, or configuration values: a component is
  reachable or it is not.

### Worker-pool backpressure is readable from the API (B-1, 2026-07-26)
- **AN-7 stops being invisible to operators.** Every subsystem has had its own
  bounded pool since the first commit, but the only way to see one backing up
  was to scrape the metrics endpoint. `GET /api/v1/operations/bulkheads` (and
  `trstctl-cli operations bulkheads`) now reports each pool's workers,
  capacity, queue depth, computed saturation, and its
  submitted/completed/rejected/panicked counters — so "is a queue backing up,
  and which one" is one authenticated read. The snapshot is process-wide
  operational telemetry: subsystem names and numbers, never tenant or
  credential data. A control plane assembled without the bulkheaded surfaces
  answers `served: false` rather than 404, because "nothing is saturated
  because nothing is wired" is a truthful answer. Unbounded pools report 0%
  instead of dividing by zero. The new operation carries the whole contract
  chain in the same change: OpenAPI golden, the pinned SDK spec, generated FE
  types, and the feature-catalog mapping with its count ratchets raised
  deliberately.

### The Kubernetes issuer controller elects one reconciler (B1 residue, 2026-07-26)
- **N nodes stop reconciling the same cluster-scoped objects.** The agent ships
  as a DaemonSet, so every pod was reconciling the same trstctl
  `Issuer`/`ClusterIssuer`/`TrustBundle` resources — harmless, because signing
  and status writes are idempotent, but it multiplied API-server work and
  audit noise by the node count. A `coordination.k8s.io` Lease
  (`trstctl-agent-issuer-controller`, 30s, identity from the downward API's
  `POD_NAME`) now elects one reconciler with a compare-and-swap on
  `resourceVersion`, so a stale renewal loses instead of stomping the holder;
  a follower takes over within one lease duration. Missing Lease RBAC logs
  once and reconciles anyway — duplicated idempotent work beats no controller
  at all. Covered by tests for single-leader election, the cold-start create
  race, and expiry takeover.

### A maintainer transfer document (D7, 2026-07-26)
- **The operational knowledge leaves one head.** `MAINTAINERS.md` is written
  for someone who did not build this: the system's mental model in a
  paragraph, the architecture linter's eight analyzers and how to extend one
  (including why there is no `//nolint` escape hatch), the three invariants
  that have **no** analyzer and lean on dependency-closure tests instead, a
  map of where the danger is (crypto boundary, signer process, RLS store, the
  three attach seams), what each meaningful CI gate failing actually means,
  how release publishing is gated, and why the docs are grep-tested. Pairs
  with the nine existing runbooks as the transfer set.

### Dependency license audit runs in CI (D9, 2026-07-26)
- **Copyleft contamination is now caught by us, not by diligence.**
  `make license-audit` resolves every module actually linked into the shipped
  binaries (`trstctl`, `-signer`, `-agent`, `-operator`), classifies each
  license, and fails on strong copyleft (AGPL/GPL/LGPL/SSPL/CDDL/EPL) or a
  module with no recognizable license text; it runs beside govulncheck in CI
  and uploads a JSON receipt. Current state: **83 modules, zero copyleft** —
  41 Apache-2.0, 21 MIT, 19 BSD, 1 MPL-2.0, 1 public-domain. The classifier
  matches license *titles* in priority order rather than grepping for "GPL",
  because MPL-2.0's own Exhibit B names the GNU GPL as a compatible secondary
  license — a naive scan reports every MPL dependency as a GPL finding.

### Contribution terms: DCO for core, CLA only for `ee/` (D2, 2026-07-26)
- **The IP terms are written down before the first outside contribution.**
  `CONTRIBUTING.md` states the split plainly: core is MPL-2.0 and accepts
  patches under the **Developer Certificate of Origin** (`git commit -s`, no
  copyright assignment), while the proprietary `ee/` tree requires a signed
  CLA — with the honest note that most `ee/` requests can be met by a core
  change plus a seam, which stays DCO-only. A blanket CLA would tax every
  drive-by fix in core; DCO-only everywhere would leave the commercial tree
  undistributable. README links it and a PR template carries the checklist.

### Migration runs get a CLI (A0.4a, 2026-07-26)
- **`/api/v1/pqc/migrations` is no longer curl-only.** `trstctl-cli migration
  start | status | rollback` drives the licensed crypto-migration surface
  through the same route table every other command uses, with the
  `Idempotency-Key` discipline the mutating routes require. Against an
  unlicensed server the routes are absent, so the CLI reports 404 — the
  honest answer for a feature that edition does not serve. Documented in
  docs/cli.md with a worked example and mapped into the feature catalog
  (F16), so the CLI-vs-feature parity gate covers it.

### Break-glass succession is wireable; the dead migration twin is gone (A0.4b, 2026-07-26)
- **PCAS class-downgrade break-glass can now actually be configured.** The
  production minter passed a nil verifier, so a downgrade was refused
  unconditionally and `NewSignedBreakGlassAuthorizer` had only test callers.
  The signer now loads an operator-provisioned break-glass authority PUBLIC
  key from `<signer-keystore>/pcas-breakglass-authority.pem` (the same
  operator-provisions-trust pattern as the XREC plan bundle — never a
  control-plane input) and, when present, accepts a valid single-use token
  signed by that authority with durable spent-state inside the custody dir.
  Absent stays fail-closed; **present-but-unparseable fails startup** rather
  than looking configured while behaving as if it were not.
- **Deleted the dead fleet-migration twin.** `ee/pqcmigration.Orchestrator`
  (the discover→stage→reissue→track loop) and the whole `ee/fleet` package
  had zero non-test callers — both were shadowed by the differently
  architected served implementation (`ee/pqcmigration` api/server/plan) and
  by core's served CA-compromise fleet re-issuance. Removing them deletes
  ~400 lines of code that read as shipped and was not.

### Agent collector scope stated; api_key failures name their cause (A0.2c, 2026-07-26)
- **The unwired agent collectors are disclosed, not implied.** PKCS#11 token,
  Windows certificate/trust store, and in-cluster Kubernetes Secret
  collection exist as the injected-enumerator boundary in
  `internal/agent/discovery` but the shipped agent constructs no enumerator
  for them — limitations.md now says **not offered** and the package says so
  at the constructors, so nobody reads them as served. Adding one is an
  enumerator plus a flag, which is the point of the seam.
- **An `api_key` source with neither observations nor findings now says so.**
  It used to fall through to the generic "no server-side connector is
  configured for discovery source kind api_key", which read as "api_key is
  not served" when the real cause was an empty config.

### secret_store sources gain a real executor (A0.2b, 2026-07-26)
- **The creatable-but-never-runnable kind is gone.** `secret_store` sources
  now dispatch through the same served secret-manager connectors as
  `cloud_secret` (aws-secrets-manager, gcp-secret-manager, azure-key-vault,
  hashicorp-vault — the kinds share the providers config shape), instead of
  dead-ending in the generic "no server-side connector" fallback. Providers
  outside the served set (kubernetes-secrets, cicd-store) fail
  with the connector's specific "unsupported provider" refusal; building
  those listers stays demand-driven P-track work. Empty-provider errors are
  now kind-aware.

### Discovery schedules tick server-side (A0.2a, 2026-07-26)
- **"Continuous monitoring" stops needing an external cron.** A leader-only
  scheduler (`RunDiscoveryScheduler`, started with the CRL and lifecycle
  workers) sweeps every minute and queues a run for each enabled schedule
  whose source has no in-flight run and no run newer than its
  `interval_seconds` — through the exact event + projection + outbox path an
  operator-initiated run takes (AN-2/5/6), tagged
  `requested_by: discovery-scheduler`. A failed run counts as an attempt so a
  broken source retries next interval instead of hot-looping; one sweep
  queues at most 100 runs per tenant (AN-7 ahead of the bulkheaded worker).
  The due decision is a real-PostgreSQL integration test under RLS,
  including in-flight suppression, failed-run backoff, the sweep limit, and
  tenant isolation.

### Decision: the issuing CA key stays classical, on purpose (A0.3g, 2026-07-26)
- **Post-quantum keys are subject keys, not issuer keys, and that is now a
  recorded decision instead of an undisclosed ceiling.** Rationale: (1) a
  pure ML-DSA issuer breaks every stock TLS client that must chain to it,
  while an ML-DSA *subject* under a classical issuer interoperates today —
  the hybrid/pure subject leaf is where the market is; (2) the harvest-now/
  decrypt-later threat targets confidentiality (KEM), not the issuer
  signature: a classical issuing CA can be rotated to a PQ issuer when
  clients are ready, and nothing already issued becomes forgeable
  retroactively before then; (3) the mechanics (`signOpaqueTBS`'s classical
  allowlist, the hardcoded ECDSA-P256 issuing handle) are one contained
  boundary change behind `internal/crypto` when the CA-hierarchy PQC work
  (P8/F57 follow-up) schedules it — the crypto-agility property this
  architecture sells. limitations.md already discloses the ceiling; the
  roadmap owns the lift.

### The PQC census proofs run in CI on every push (A0.3f, 2026-07-26)
- **"PQC issuance is proven" stops depending on someone remembering a build
  tag.** A new required check, `pqc e2e (dodproof)`, runs
  `TestDODPQCProductionAssembly` — stock-OpenSSL pure ML-DSA-65 EST
  enrollment, the two-entry hybrid SVID Workload API response, and the
  CBOM→migration TLS rollout with rollback — against the exact shipped
  artifact on every push. The job gates loudly on an ML-DSA-capable stock
  OpenSSL (>= 3.5) so runner drift cannot silently skip the proof; the check
  is pinned into branch-protection.json, docs, and a guard test.

### The additional Workload-API SVID is audited like the classical one (A0.3e, 2026-07-26)
- **The licensed second SVID stops being invisible to the event log.** The
  Workload API's additional-issuer mint now emits the same
  `spiffe.svid.issued` audit event and credential-graph node the classical
  SVID gets, with its hint in the payload (`x509-additional:<hint>`), so
  posture can tell the pair apart. Profile parity note: the classical SVID's
  EKUs are equally fixed by the SVID signing profile, so the additional
  issuer's serverAuth/clientAuth EKUs are parity, not drift; and like every
  Workload-API SVID it is deliberately ephemeral — audited, graphed, but not
  an inventory row.

### Direct-API issuance scope decided; dead licensed twin removed (A0.3d, 2026-07-26)
- **The identity API's server-side classical keygen is a decision, not a
  gap.** `issuanceDispatcher.issueLicensed` was assigned at boot and called
  nowhere — a dormant seam diligence would flag. It is deleted; the
  dispatcher documents that ephemeral NHI identities take server-generated
  classical keys by design, and CSR-based enrollment (including licensed
  subject algorithms) belongs to the enrollment protocols through
  `protocolIssuer`, whose licensed twin is live and tested.

### ACME's algorithm transparency is pinned by test (A0.3c, 2026-07-26)
- **"ACME never parses the CSR" is now a contract, not an accident.** A new
  test drives a full RFC 8555 order with a real client and finalizes with a
  CSR whose proof-of-possession the core parser rejects; the order completes
  and the CA seam receives byte-identical CSR data. If anyone "hardens"
  finalize with a core-parser check — breaking the licensed issuer's
  ownership of subject-algorithm verification — this test fails and names
  the seam contract.

### Profiles can name post-quantum algorithms when licensed (A0.3b, 2026-07-26)
- **`allowed_key_algorithms` stops failing closed on licensed labels.**
  `crypto.Classify` gains a licensed-classifier seam
  (`InstallLicensedAlgorithmClassifier`, filled by attachPQC with
  `ee/pqc.ClassifyAlgorithm`), so profile authoring accepts ML-DSA / SLH-DSA
  / hybrid signature labels — and still rejects ML-KEM labels, which cannot
  sign certificates. Enforcement stays exact-match: a profile listing
  `ML-DSA-65` admits pure ML-DSA-65 CSRs; a hybrid enrollment carries a
  classical subject key and remains governed by its classical family label.
  Unlicensed binaries keep failing closed on all of it.

### CMP gains the licensed-CSR seam (A0.3a, 2026-07-26)
- **CMP can now carry subject algorithms the core toolchain cannot check.**
  `ParseCMPRequest` previously verified the carried PKCS#10 with the strict
  core parser *before* any licensed parser could see it, so CMP hard-rejected
  what EST already accepted. `ParseCMPRequestWithVerifier` delegates exactly
  the inner-CSR check to an injected verifier — PKIMessage protection stays
  core-verified, unconditionally — and the served mount binds the same
  licensed-aware verifier EST uses. Covered by seam tests proving the
  verifier is consulted with the exact CSR bytes, a refusing verifier fails
  closed, and tampered protection still dies even with an accepting
  verifier. (SCEP intentionally keeps the core-only path: its CMS reply
  cannot be delivered to a signature-only subject key — a protocol limit
  documented in limitations.md, not a code gap.)

### Terraform provider + Python SDK become published artifacts (B6, 2026-07-26)
- **The provider's acceptance test now actually runs.** CI drives a REAL
  `terraform apply` (pinned terraform 1.9.8, SHA256SUMS-verified download)
  through the provider's plan/apply/read/delete loop on every push —
  previously `TRSTCTL_RUN_TERRAFORM_ACC` was set nowhere and the test was
  dead weight.
- **Release tags publish the provider in the Terraform Registry layout.**
  `scripts/release/terraform-registry-assets.sh` builds per-OS/arch zips
  (binary named `terraform-provider-trstctl_v<version>`), the protocol-6.0
  registry manifest, and a GPG-signed SHA256SUMS; the release job uploads them
  as GitHub Release assets with SLSA provenance. Signing requires the
  protected `terraform-registry-signing` environment — unsigned assets are
  refused rather than emitted.
- **The Python SDK ships to PyPI and the Release.** A release job stamps the
  tag version into `clients/sdk/python`, builds sdist+wheel, `twine check`s
  them, uploads them as Release assets with SLSA provenance, and pushes to
  PyPI via the protected `pypi-publishing` environment (`PYPI_API_TOKEN`) —
  missing credentials fail loud, never skip silently.

### SPIRE upstream-authority plugin ships (B2, 2026-07-26)
- **The SPIRE plugin is now an obtainable artifact, not a build-from-source
  exercise.** `trstctl-spire-upstream-authority` joins `make build`'s `CMDS`
  and the reproducible-binary check, and every release tag publishes
  `trstctl-spire-upstream-authority-linux-{amd64,arm64}` GitHub Release assets
  with a SHA-256 manifest and their own SLSA provenance
  (`trstctl-spire-upstream-authority.intoto.jsonl`), gated on the same
  test/required-checks contexts as every other publishing job. SPIRE loads the
  plugin from its own host (`plugin_cmd`), so it deliberately stays out of the
  container image; docs/limitations.md now states the exact distribution
  contract instead of a bare "served".

### CBOM licensed posture — real FIPS targets (A0.1, 2026-07-26)
- **A licensed binary's CBOM now names its migration targets.** The MPL core
  still emits edition-neutral `licensed-*` placeholders and recognizes no
  licensed algorithm family — that fence is deliberate and unchanged. A new
  seam, `cbom.InstallLicensedPosture`, is filled from the tagged PQC attach
  block with `ee/pqc/cbomposture.CBOMTargetFor` +
  `ee/pqc/cbomposture.CBOMClassifyKey`, so with
  FeaturePQC licensed the inventory maps classical signatures →
  **ML-DSA-65 (FIPS 204)**, key establishment → **ML-KEM-768 (FIPS 203)**, and
  deprecated DSA → **SLH-DSA-SHA2-128s (FIPS 205)**; ML-DSA / ML-KEM / SLH-DSA
  / SPHINCS+ / Kyber / Dilithium / hybrid labels classify as strong and not
  quantum-vulnerable instead of "unrecognized"; and pure post-quantum assets
  carry `future-ready` — which makes `percent_migrated` a live number instead
  of a structural zero. Hybrid assets deliberately stay `migration-required`:
  they are quantum-safe today but the migration endpoint is the pure
  post-quantum algorithm. Covered by `ee/pqc/cbom_test.go`, including a mixed
  classical + post-quantum estate reporting 25% migrated.

### Static console demo enablement (demo.trstctl.com, 2026-07-25)
- **The console can now ship as a zero-backend static demo.** A build-time
  flag (`VITE_TRSTCTL_DEMO=1`, set only by the demo-site build in
  trstctl-website) makes preview mode available in a production bundle,
  lands the visitor signed-in on the showcase, and — new for preview
  everywhere — activates transport isolation: the API client refuses every
  server call before fetch, with translated error copy (2 new keys per
  catalog; digests re-pinned, machine translations flagged for review).
  The product embed never sets the flag, and a new embed-purity gate
  (`internal/webui/demo_purity_test.go`) fails the build if the committed
  console ever carries the preview identity.

### Design-review remediation (R-01…R-09, 2026-07-25)
- **Every form control in the console now actually has a style.** An external
  design review found — and we verified — that `.ui-input`, the class worn by
  ~145 inputs/selects/textareas across 11 pages, was defined in no stylesheet,
  ever: every form field rendered as raw native browser chrome (white fields
  in the flagship dark theme). The family now exists (token-correct field,
  36px to pair with buttons, themed select/textarea/file variants,
  aria-invalid state), native checkboxes/radios ride a gold `accent-color`,
  and a new foundation guard fails the build if any referenced `ui-*` class
  has no rule — it immediately caught a second stillborn class (`ui-button`,
  10 raw buttons now on the Button primitive).
- **Forms became primitives (DESIGN.md rule 14).** `Input`/`Select`/
  `Textarea` plus a `Field` unit that owns label/description/error and their
  aria wiring; piloted on Request Credential's zod+RHF form; raw-control
  counts in pages are budget-ratcheted downward (migrate-when-touched).
- **Focus is its own token (rule 2, both themes).** Focus rings rode
  `--brand-accent`, which is gold-family in light mode — collapsing the
  gold-acts/mint-focuses semantics. A dedicated `--focus` token keeps mint in
  both themes, swept through every focus ring, with a 3:1 non-text contrast
  guard and a mint-hue-family pin.
- **Discipline sweeps.** Eyebrow: nine hand-rolled tracked-uppercase clusters
  (Secrets ×8, Login) plus shell/pqc/styleguide stragglers migrated to the
  primitive, with a tracking ratchet. Shell toggles moved to the Button
  primitive, killing a focus ring class that resolved to no configured color.
  Dead tokens deleted (`--console-accent`, unused density rungs) — the suite
  was certifying them as alive. Rule 15 codifies Card-vs-`ui-panel` and
  DataGrid-vs-`ui-table` criteria; monolith pages split as touched
  (web/AGENTS.md). Repo-wide prettier normalization un-reds CI's
  format:check after the dependency refresh.

### Live dashboard tiles (S-N1, 2026-07-24)
- **Home's numbers stay current without an operator reflex.** The Dashboard's
  eight resources moved off `useResource` onto the query layer with a live-tile
  contract (certctl's PERF-H1 pattern): KPIs poll every 30s and the audit rail
  every 60s while the tab is visible, hidden tabs poll nothing, and returning
  to the tab refreshes exactly the live queries immediately. The optional-probe
  readers (NHI inventory, secrets count, open incidents, recent audit) now fail
  soft to their empty fallbacks, so a missing or erroring optional endpoint can
  never stall the first-run gate or error the whole dashboard.

### Per-locale catalog split (S-C10, 2026-07-24)
- **The entry chunk drops a third: 239 → 163 kB brotli.** The es-ES and de-DE
  production catalogs moved to per-locale modules loaded on demand by the
  I18nProvider; English (the source catalog) and the pseudo transforms stay
  eager. Until a lazy catalog resolves, lookups fall back to English — never
  to raw keys — and the tree re-renders translated the moment the module
  lands (covered by a new in-session locale-switch test). Strings are
  byte-identical to their pre-split location, so the translation-review
  digests did not move; the `satisfies` completeness contract survives in the
  split modules, and the entry size-limit budget is lowered to 185 kB to lock
  in the win.

### Compact locale wire catalogs (AUD-121, 2026-08-12)
- **Reviewed translations keep their keys; the browser stops downloading those
  keys twice.** A checked generator emits value-only lazy runtime catalogs in
  the canonical English message order, then reconstructs the keyed map when a
  locale loads. Keyed es/de sources, type-level completeness, placeholder
  checks, and review digests remain authoritative and byte-identical. The build
  rejects stale generated mirrors, and the 640 kB all-JavaScript ceiling stays
  unchanged.

### Console engineering train (S-C4 / S-C5 / S-C8 / S-C9, 2026-07-24)
- **S-C5 — the data and form layers arrive.** TanStack Query is the console's
  query layer (`src/lib/query.tsx`; provider in `AppRoutes`), piloted on
  Owners: the cache is the row truth, mutations write through and invalidate —
  the refetch `useResource` never had. Mutation forms go schema-first with
  zod + react-hook-form, piloted on Request Credential with per-field errors.
  Adoption policy in `web/AGENTS.md`: new surfaces use the new layers;
  existing pages migrate when touched.
- **S-C9 — typography primitives and a real merge fix.** `Eyebrow` and `Num`
  encode the micro-label and inline-data rules; `text-2xs` replaces the five
  `text-[10px]` arbitraries. The Eyebrow test exposed a latent bug: cn()'s
  tailwind-merge dropped the custom font-size tokens as color conflicts —
  fixed by registering the token scale, for every cn() call site.
- **S-C8 — Storybook workbench.** Storybook 10 (react-vite + a11y addon)
  renders stories against the real tokens with a dark/light toolbar; six
  starter story files cover the primitives and shared components. Coverage
  extended 2026-07-24 to the data-heavy set — DataGrid (sorting, selection +
  bulk slot, and all five list states), the full chart palette (tones,
  StatTile, Meter, BucketBar, time bars, Donut, Sparkline/AreaTrend),
  CredentialChip, the DetailDrawer/Dialog overlays, and StatePrimitives —
  10 titles / 38 stories in the static build.
- **S-C4 — Playwright e2e + visual regression, authored.** Shell smoke (rail,
  scoped sidebars, palette, the `?tab=` redirect) and masked dark-theme visual
  baselines, targeting the seeded demo stack (`npm run e2e`). Browsers were
  not installable in the authoring sandbox — first local run generates
  baselines (`--update-snapshots`).
- **Contracts.** `web/AGENTS.md` is the console's leaf contract; DESIGN.md
  rules 5/6/12 updated to the primitives and the workspaces-vs-lenses ruling;
  the root AGENTS.md now states the AN-4/6/7 enforcement asymmetry plainly;
  the visual-asset audit (design-audit/10) confirms nothing reader-facing
  depicts the retired chips shell.

### IA train closeout (S-C3 / S-C6 / S-C7, 2026-07-24)
- **S-C3 — the console code-splits by page.** Every authenticated surface is a
  lazy route chunk (70 chunks; the entry is the shell + vendor + the typed
  i18n catalogs), with a Suspense boundary at the shell outlet that announces
  loading. The compressed budget is enforced by `npm run size` (size-limit:
  entry, largest page chunk, and total shipped JS); Vite's raw-size warning
  threshold sits just above the entry so a new oversized chunk still trips it.
  Follow-up noted: per-locale catalog splitting would shrink the entry further.
- **S-C6 — the command palette groups by space and speaks verbs.** Route
  results render under space headings in rail order (Home first; spaceless
  routes last under Routes), Enter-activates-first agrees with the visible
  order, and four permission-gated verb entries land where the verb happens:
  Rotate a secret, Grant workload access, Issue SSH user certificate, and
  Preview blast radius.
- **S-C7 — the workspaces-vs-lenses rule is now written down.** A tab becomes
  a sidebar route only when it is a distinct served workspace (own evidence,
  own workflows, own name); an alternate view over the same object domain
  stays a URL-addressable in-page tab. Rulings: Secrets' six workspaces are
  routes (S-C2); Certificates' four tabs and Discovery's four tabs are lenses
  and stay. Home's five inventory counters now deep-link into their spaces,
  completing the every-number-is-a-link pass.

### Secrets workspaces as routes (S-C2, 2026-07-23)
- **The Secrets mega-page's six workspaces are sidebar routes now.** The store
  keeps `/secrets`; **Secret engines** (`/secrets/engines`), **Machine access**
  (`/secrets/access`), **One-time shares** (`/secrets/sharing`), **CI scanning**
  (`/secrets/scanning`), and **Sync targets** (`/secrets/sync`) each own a row
  in the Secrets space sidebar, grouped Store & engines / Access & sharing /
  Delivery & scanning. The in-page tab strip is gone; historical
  `/secrets?tab=` deep links redirect permanently with their remaining query
  intact (the C-A1 `/platform` precedent). Every route carries its own H1 and
  title (naming parity), RBAC gate, and feature evidence; the rail-row budget
  consciously grows by five (ceiling 38).

### Unified shell (spaces IA, 2026-07-23)
- **The console is now five spaces behind an icon rail.** The S-B2
  chips-in-sidebar module switcher became a left rail of spaces that each own
  every surface of one concern — *Certificates & PKI*, *Secrets*,
  *Workload & SSH*, *Posture & response*, and *Platform* — with Home carrying
  the Dashboard, Journeys, and the needs-action worklists. The URL decides the
  active space (deep links light up their owning space; picking a space lands
  on its first permitted route), the per-space audit lenses and 34-row rail
  budget survive, and no route URL, nav label, or feature ID changed, so
  bookmarks and API couplings are untouched. Operator docs (web-console, the
  demo click-through, platform-and-api) describe the new shell.
- **DA-02 closed — the secrets auth-method console.** Secrets → Access now grants
  workload credentials in-console (scoped standing tokens or TTL-bound ephemeral
  keys, reveal-once, list + revoke), projects the configured machine-auth methods
  (issuer, audience rules, scopes, source) with a per-tenant, event-sourced
  disable/enable overlay enforced at the login exchange, and serves the
  issued-session ledger (`GET /api/v1/secrets/sessions`) with idempotent,
  event-sourced revocation (`machine_sessions` projection, migration 0086).
  New API surface: `GET /api/v1/secrets/auth-methods`,
  `POST /api/v1/secrets/sessions/{id}/revoke`,
  `POST /api/v1/secrets/auth-methods/{name}/disable|enable` — with CLI parity
  (`secrets auth-methods list|disable|enable`, `secrets sessions list|revoke`).
- **The `/platform` grab-bag became three routes** — `/admin/access`,
  `/admin/system`, `/admin/editions` — each deep-linkable and fetch-scoped.
  This is the train's only URL change and every historical `/platform` (and
  tab) link redirects permanently; rollback is a nav-config revert.
- **DA-10:** incident intake uses identity pickers and served vocabularies —
  no more pasting raw UUIDs on faith. **DA-14 closed as a class:** the i18n
  extraction ratchet (now AST-based) reads zero hardcoded user-facing strings
  and is sealed at zero. **47-day readiness** panel now lives on the global
  home, ahead of the 2027-03-15 100-day step.
- **Locales:** Spanish is joined by **German (de-DE)** as a production locale;
  both catalogs are completeness-enforced by the type system. Long-tail
  machine-seeded entries are enumerated for human translation passes.
- Rail budget consciously re-set 32 → 34 rows for the admin split; entity-noun
  consolidation deliberately deferred behind an evidence checklist.

### Security & hardening
- Remediation pass (R0–R9) hardening the served, multi-tenant profile: served
  end-to-end **revocation** (a revoked credential stops validating in the product's
  inventory/records), an idempotent first-API-token bootstrap, served X.509 issuance
  with CDP/AIA/SKI and certificate-profile enforcement, quorum-gated cross-signing,
  versioned event envelopes with version-aware projections, bounded/tenant-scoped
  lifecycle history, and TTL'd idempotency keys.
- Supply chain: GitHub Actions and base/runtime images pinned by digest, the
  embedded-PostgreSQL binary pinned against a committed provenance manifest, a
  CycloneDX SBOM and `govulncheck` gate in CI, CODEOWNERS over the root-of-trust
  paths with required code-owner review, and checksum-verified CI tool installs.
- Docs/observability honesty: a reality-tested `docs/limitations.md` that states
  served-vs-library status for every advertised capability, so the binary cannot
  silently over-claim.

### Added
- `CHANGELOG.md` (this file), linked from the README and SECURITY.md (DOCS-005).

### Changed — web console information architecture (IA train)

*Superseded within this release: the module-switcher chrome below evolved into
the five-space unified shell (see "Unified shell (spaces IA)" above). The
defect-class guards it introduced — `naming_parity`, `nav_completeness`,
`module_map`, demo-data isolation, docs IA parity — carry forward unchanged
and still gate the spaces IA.*

- **Option A — refined rail.** The sidebar is re-grouped into four question-shaped
  bands (Inventory / Issue & automate / Detect & respond / Govern & administer) and
  every previously hidden product surface (CA hierarchy, certificate profiles, SSH
  trust, code signing, operations, notifications, privacy, integrate, API explorer)
  is now visible in navigation. One name per surface: nav label, page `<h1>`, and
  document title agree everywhere (a permanent `naming_parity` guard enforces it).
  Platform gains a dedicated **Editions & license** tab, quarantining commercial
  licensing rows off the operational Access and System tabs.
- **Option B — module workspaces.** A top-of-rail **Module** switcher (Certificates &
  PKI, Secrets, SSH, Signing, Fleet) scopes the middle band to one product; the
  cross-domain global planes (identities, discovery, risk, posture, graph, incidents,
  approvals, governance, audit) stay visible under every module. Module homes carry a
  thin served KPI strip that deep-links into filtered lists. The shared audit stream
  gains per-module lenses via `?module=` with a clearable scope chip — one stream, one
  hash chain, N lenses, never per-module silos.
- **Dashboard integrity & renew.** Real-mode dashboards render served data only (the
  fabricated demo trend/activity/bands are gone) and the four action KPIs are wired to
  live counts; the expiring-certificate worklist and detail drawer now offer Renew,
  wired to the identity lifecycle transition.
- **No route/URL changes.** The entire IA change is navigation chrome; every route
  keeps its path, so deep links, journeys, and muscle memory survive. Permanent CI
  guards (`naming_parity`, `nav_completeness`, `module_map`, demo-data isolation, docs
  IA parity) keep the fixed defect classes from returning.

## [0.5.4] - 2026-06-27

### Added
- Expanded the shipped console from a basic shell into task-oriented workspaces for
  certificate lifecycle, secrets, discovery, NHI risk and posture, CA hierarchy,
  incidents, governance, privacy, integrations, and platform operations. The same
  train added feature-to-route coverage guards, generated API types, responsive
  navigation, localization, accessibility checks, and a read-only preview identity.
- Served the next platform integrations: secret rotation/sync and scanning,
  SSO/SCIM/ABAC and break-glass administration, a cert-manager issuer controller,
  Terraform and Python clients, signed compliance evidence, OTLP export, passive
  federation, JIT access, signed WASM plugins, and cloud managed-key custody.
- Introduced the single-repository open-core edition boundary: core/Enterprise/
  Provider status, offline license seams, Provider metering/branding/isolation, and
  explicit Enterprise fences for remediation, federation, managed-key/KMIP custody,
  and governance evidence.

### Changed
- Reworked the console around shared data grids, task-first navigation, responsive
  mobile/desktop layouts, theme controls, and served-state disclosures instead of
  advertising routes without product wiring.

### Security
- Required independent signer authorization, replay-safe issuance recovery,
  encrypted disaster-recovery backups, bounded public protocol/request state,
  bounded outbox execution, default-private optional AI egress, digest-pinned
  deployment artifacts, and release-gate checks before publishing.

## [0.5.3] - 2026-06-18

### Fixed
- Stopped the release workflow from uploading unsigned Windows agent artifacts.
- Corrected the release workflow's shellcheck failure.
- Prepared the compose-profile artifacts consumed by the repository lint gates.

## [0.5.2] - 2026-06-18

### Security
- Hardened tenant offboarding, tenant-bound machine login, byte-backed secret and
  provider credentials, signer content authorization, ceremony purpose binding,
  certificate-profile EKU enforcement, SSRF-protected notifications, bounded
  request parsers, and the local-development plaintext transport exception.
- Made the architecture analyzer run as a repository-wide vet tool and added
  regression guards for tenancy, crypto custody, signer isolation, idempotency,
  outbox/bulkhead behavior, release provenance, and served-surface wiring.

### Fixed
- Routed lifecycle renewal and ACME revocation through persisted platform state,
  rebuilt agent/profile projections from events, made CRL reads side-effect free,
  versioned legacy secret events, and made rotation/reconciliation replay-safe.
- Productized disaster recovery with streamed restore, under-replicated JetStream
  fail-closed behavior, fair outbox leasing, online lease indexes, migration-lock
  polling, isolated-signer Helm wiring, and pinned agent enrollment transport.
- Added stock-client conformance for ACME, EST, SCEP, CMP, and RFC 3161, then fixed
  their CI/release fixtures, OPA v1 policy compatibility, and SCEP AES envelopes.

## [0.5.1] - 2026-06-16

### Added
- Added and exercised SCEP, CMP, MDM enrollment, the constrained-device EST client,
  SPIFFE workload identity and attesters, incident response, SSH CA workflows, code
  signing, PQC migration, the secrets/dynamic-secret/KMIP stack, discovery and
  governance, and the grounded read-only AI/MCP surface.
- Wired the assembled binary to serve issuance protocols, OIDC sessions, the React
  console, signed WASM plugins, the steady-state agent channel, the Kubernetes
  operator, cross-node signer mTLS, FIPS builds, and BYOK/HSM key lifecycle.

### Security
- Completed the first broad hardening sweep across revocation, signer
  abuse-resistance and dual control, tenant isolation, parser bounds and fuzzing,
  event-spine resilience, deployment defaults, release signing/provenance, and
  architecture guard tests.

## [0.5.0] - 2026-06-13
- Hardening milestone toward an enterprise-GA bar for the self-hosted, multi-tenant
  profile: isolated signer custody (sealed CA key persisted across restarts), the
  assembled control-plane server (`cmd/trstctl` → `internal/server`) serving the
  event spine, projections, orchestrator, and REST API, and the architecture linter
  (`tools/trstctllint`) enforcing AN-1/AN-3/AN-5/AN-8 in CI.

## [0.4] - 2026-05-31
- Pre-release development milestone.

## [0.3] - 2026-05-31
- Pre-release development milestone.

## [0.2] - 2026-05-31
- Pre-release development milestone.

## [0.1] - 2026-05-31
- Initial tagged development milestone.

[Unreleased]: https://github.com/ctlplne/trstctl/compare/v0.5.4...HEAD
[0.6.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.3
[0.7.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.7.0
[0.6.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.0
[0.5.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.4
[0.5.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.3
[0.5.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.2
[0.5.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.1
[0.5.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.0
[0.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.4
[0.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.3
[0.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.2
[0.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.1
