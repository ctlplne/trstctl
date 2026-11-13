# Discovery & inventory — find every certificate, key, and secret you already have

## What it is

Before you can manage credentials, you have to _know they exist_. Discovery is how
trstctl finds the credentials already scattered across your infrastructure —
[certificates](../glossary.md), SSH keys, and [secrets](../glossary.md) — and the
**inventory** is the single, tenant-scoped list it keeps them in.

Think of it like a building's master key register: someone has to walk every floor,
write down every lock and every key, and keep that register current as locks change.
trstctl is that walker and that register, for machines.

In the console, open **Discover**. The page starts with the credentials that need a
decision. Choose **Run scan** to use an
existing discovery source or add your first one.

trstctl discovers credentials five ways, and each suits a different corner of your
estate: scanning the network from outside, asking a
[trstctl Edge runtime](../glossary.md#agent-trstctl-edge-runtime) what a host can see from
inside, pulling inventory straight from cloud provider APIs, reading SSH key files and
trust config, and connecting to external secret stores. Everything they find lands in
one inventory.

## Why it exists

Almost every organization has more machine credentials than it can name, and the ones
nobody remembers are the ones that cause outages and breaches: the certificate that
expires on a forgotten load balancer at 3 a.m., the SSH key a contractor left behind,
the API token hard-coded in a script five years ago. You cannot rotate, revoke, or
risk-score a credential you do not know about.

Discovery turns "we think we have a few hundred certs" into a precise, queryable
list — the foundation every other trstctl feature builds on. Risk scoring, drift
detection, the credential graph, and lifecycle automation all read the inventory.

## How it works

### The inventory (F1) — the source of truth that is actually a projection

The inventory is a PostgreSQL table of certificate **metadata** — subject, SANs,
issuer, serial, SHA-256 fingerprint, key algorithm, validity window, where it's
deployed, and lifecycle status. It never stores a private key.

Nothing writes to that table directly — a core trstctl design rule
([event sourcing](../glossary.md)). When a certificate is discovered or issued, the
orchestrator appends a `certificate.recorded` event to the append-only, tamper-evident
log, and a _projector_ reads that event and builds the table row. The table is a
**projection** — a derived view you could delete and rebuild from the log — which is
why trstctl can survive a database loss: the truth is the event log, and the inventory
is a fast index into it.

Ingestion is idempotent: the row key is `(tenant_id, fingerprint)`, so seeing the same
certificate twice refreshes one row instead of creating a duplicate, and the ingest API
requires an [`Idempotency-Key`](../glossary.md) so a retried request can't double-record.
Certificate parsing routes through the single isolated cryptography path, so the
inventory code itself never touches the low-level X.509 libraries directly.

`GET /api/v1/certificates/health` serves a tenant-wide expiry dashboard from that same
projection: total and lifecycle-status inventory counts, expired and 7/30/90-day
expiry bands, source breakdown, and the soonest-expiring certificates. Total and
source counts preserve revoked and superseded history. Expiry action counts, bands,
and the soonest-expiring list include only active certificates, so a retired
predecessor does not raise a new expiry warning. The expiry bands sum to the active
count. A short-lived certificate issued through the approved JIT workflow remains in
inventory and the separate `expected_ephemeral` band, even after a later discovery
observation changes its source label. Its planned expiry is excluded from renewal
alarms, the expiry worklist and alert delivery; request a fresh attested credential
through **Workloads** instead. The `active` count is the retained lifecycle status,
so it includes a JIT record until revocation or retirement even after its validity
window closes. Issued, manually imported, and discovery-fed active certificates all
count, including one found on a load balancer after a different CA issued it.

### Find a certificate across the inventory

Open **Certificates** and use **Search certificates** to find a known credential
without loading unrelated pages first. Search checks the authenticated tenant's
subject, SANs, issuer, serial, fingerprint, lifecycle status, and deployment location.
The list stays paginated; its loaded count is not a total search-result count.

The console waits briefly after typing, cancels obsolete reads, and keeps the search
field available while a request runs or returns no matches. Changing the search,
page size, or expiry window starts a new page sequence. The issuer, profile, team,
and environment controls still filter the matching rows loaded in the console.

API clients use `GET /api/v1/certificates?q=<text>&limit=20`. Matching is a
case-insensitive literal substring; a complete certificate UUID also matches.
Percent signs and underscores are literal characters, not wildcards. The trimmed
query must be valid UTF-8, contain no NUL, and have at most 256 characters; invalid
queries return 400. Omit `q` or pass whitespace to use the ordinary inventory query.
For subsequent pages, send `next_cursor` as `cursor` with the same `q` and
`expiring_before`. The existing page-size limit is 1–100. Search runs before both
pagination and the expiry filter's result limit; it does not retrieve private keys,
issuance responses, or custody receipts. Broad substring searches can scan the
tenant's metadata; this endpoint does not establish a large-estate latency guarantee.
When `expiring_before` is set, the result contains active certificates only. Omit it
to search historical revoked and superseded rows as well.

### Recover the certificate behind a scanned row

Some paths record what a certificate says without the certificate itself: a network
scan or a cloud listing without `agent_channel.probe_scanned_certificates`, an older
import. With that setting on, a `cloud_certificate` run keeps the certificate the
provider returned when it hashes to the certificate listed, with the issuers returned
after it (AWS ACM and GCP Certificate Manager return the chain; Azure Key Vault returns
the certificate alone), and a row an earlier listing recorded without bytes gets them
from the next run. The certificate detail says so (`certificate_bytes_held: false`), and such a
row cannot take part in [authority agreement](../configuration.md#authority-agreement) checks, which
identify a certificate by the issuer and serial inside its bytes. **Certificate
bytes → Look up in this tenant's CA records** (`certificates recover-der <id>` with
`{"method": "ca_ledger"}`) finds a mint of the tenant's CAs that retained the
certificate by the row's serial; **Read from host:port** (`{"method": "endpoint"}`)
reads the certificate that address serves from the control plane — for a private
address the console sends that one address as the allowed CIDR, which needs
`egress:private`. Either way the bytes are attached only when they hash to the row's
fingerprint and the row held none; the answer says `recovered`, `already_held`,
`not_found`, `mismatch` (the endpoint serves another certificate) or `unreachable`,
and the detail then shows where the bytes came from.

### Network discovery (F2) — scanning from an enrolled [network relay](../glossary.md#network-relay)

Network discovery connects from an explicitly enrolled agent with the `network`
role to IP/port ranges you define, performs a normal
[TLS](../glossary.md) handshake, captures the certificate each host presents, and
records its metadata. No software is installed on the targets — it sees exactly what
any client on the network would see.

The scanner runs in its own bounded [lane](../glossary.md): a bounded pool of workers
(default 16, queue 256). When the queue fills, it slows the producer instead of dropping
targets or exhausting the pool the API needs, so a big scan can never starve the rest of
the system. The handshake and certificate parsing both go through the single isolated
cryptography path, and the scanner applies the shared SSRF guard and a reserved-IP
denylist before dialing expanded CIDRs, so a scan cannot be turned into a loopback,
RFC1918, link-local, or cloud-metadata probe.

Operators can safely save a `network`, `ssh`, or `adcs` source before its relay is
enrolled. Saving records configuration; it does not scan. Plan preview and
`GET /api/v1/discovery/sources/{id}/preflight` return `ready`, the exact connection
origin, and `blocked_reasons` from the same server-owned readiness rule. If no
non-offboarded network-role relay has sent an authenticated heartbeat within two
configured heartbeat intervals, manual and scheduled run admission both refuse
the run before a run event or outbox row is created. A stale relay may have an
expired channel certificate; re-enroll that exact agent and wait for a fresh
heartbeat. The console explains the fix instead of leaving an impossible run
silently queued.

Readiness also checks the server's agent dispatch allowlist. A healthy relay is not
enough when `discovery.run` (or the source’s exact `adcs.inventory` /
`adcs.inventory.enrollment_groups` / `adcs.inventory.endpoint_probe` kind) is absent from
`agent_channel.claimable_job_kinds`: preview and saved-source preflight name that
exact configuration gap, and run admission returns a conflict before creating an
event or outbox row. The console therefore cannot report “ready” for work the
server is configured never to hand out.

Once at least one eligible relay is online, the run executes from the outbox worker.
External probes are journaled first and delivered at-least-once, so a temporary relay
disconnect after admission is durable and retryable instead of being done inline by
the request handler. Readiness proves that an eligible relay exists; it does not claim
that a particular relay is connected at every millisecond.

#### What a run tells you, target by target

A completed run carries one outcome per assigned target in `target_results`
(`succeeded`, `failed`, `blocked`, or `rejected`, with the reason for anything that
did not succeed). A `partial` run's `error` names the targets that failed or were
blocked, so **Discover → Runs** shows which listener is the problem instead of a bare
count. Listeners that need an application-level upgrade to TLS are handled without a
protocol hint: when a reachable target rejects a bare TLS ClientHello, the scanner
retries with the PostgreSQL SSLRequest negotiation and inventories the certificate the
server then presents.

Running the same source again refreshes its findings instead of duplicating them: a
listener observed by a later run keeps its one finding (and its triage decision) with
`first_seen_at`, `last_seen_at`, `seen_count`, and `run_id` moved to the latest run,
so the console and the open-finding counts describe the estate once.

#### Recover a failed or partial run without erasing the failure

Open **Discover → Runs** and choose **Retry** on a `failed` or `partial` run. The
console first rechecks the source's current relay and scope prerequisites. If the
source is ready, `POST /api/v1/discovery/runs/{id}/retry` creates a new queued run
with the same source, schedule binding, and dry-run mode. The original terminal run
is never changed or deleted. The replacement stores `retry_of_run_id`, so the table,
API, event replay, and a page reload still answer “which failure did this replace?”
The console shows newest runs first; **Load older runs** follows the bounded
history. API clients can request `GET /api/v1/discovery/runs?order=recent&limit=50`
and pass each returned `next_cursor` with the same `order` to page by creation
time and run ID. The CLI exposes the same mode with
`trstctl discovery runs list --order recent --limit 50` and accepts the returned
cursor with `--cursor`. Omitting `order` keeps the original ID-order contract.

This is intentionally not available for `queued`, `running`, or `succeeded` runs. An
active run must finish; a successful run can be repeated from its source as a fresh
scan. Every retry requires an `Idempotency-Key`, so a browser, proxy, or human sending
the same request again receives the first replacement instead of queueing duplicates.
Headless operators use `trstctl-cli discovery runs retry <failed-run-id>` and get the
same server rule. If recovery is blocked, restore or enroll the required network-role
relay, then retry with a new idempotency key; never rewrite the old run or its outbox
row.

If a relay's signed result says it discovered more credentials than it actually
included, the control plane fails that run and imports **no** findings from it.
It retains the signed receipt, marks the exact agent job failed, and acknowledges
the terminal report so one bad sealed result cannot block every later job after
a restart. **Discover → Runs** and the API show the count mismatch and the need
to retry. Use the same **Retry** action above after the relay is updated; the
old failed run remains in the audit trail.

### Continuous monitoring rollup

`GET /api/v1/discovery/monitoring` (CLI: `trstctl discovery monitoring`) is a single
read-side rollup over the tenant's discovery sources, enabled schedules, last runs,
findings, and certificate inventory — it creates no new state and joins the same
`discovery.*` and `certificate.recorded` projections other endpoints already read. Each
source row shows whether it's scheduled, the monitoring interval, the latest run
status, current execution readiness, the exact blocker and connection origin,
finding counts, and pointers to `/api/v1/certificates` and
`/api/v1/discovery/findings`. The console keeps this exact rollup under
**Monitoring and exact scan evidence**. The credentials needing a decision appear
first; operators can still expand the underlying CT, drift, coverage, source,
schedule, run, and repository-path proof when they need to verify or troubleshoot it.

### Agent-based discovery (F3) — what each host can see from the inside

A network scan only sees what a host _presents on a port_. Plenty of credentials never
appear on the wire: a certificate sitting in a file, in a PKCS#11 token, in the Windows
certificate store, or in a Kubernetes Secret. The trstctl **agent** runs on the host and
enumerates those local sources, then reconciles what it finds into the inventory over
its mutually-authenticated ([mTLS](../glossary.md)) channel. Each source is
independent: if one token errors, the agent records the error and keeps going, so one
broken source can't hide the rest.

The agent enrolls into the control plane with a one-time bootstrap token
(`POST /enroll/bootstrap`); `GET /api/v1/agents` then lists it, and
`POST /api/v1/agents/{id}/offboard` emits an `agent.offboarded` event, keeps the row
visible as a tombstone with actor/reason evidence, and causes the agent's mTLS
certificate to be rejected on future heartbeat, renewal, and inventory RPCs.
`POST /api/v1/agents/{id}/cert-revocations` takes the exact client-certificate
serial, SHA-256 fingerprint, or both. The control plane commits an independent
tenant-scoped denial before publishing either removal event, so an already-open
mTLS connection is refused on its next RPC even if the event projection fails.
The pending command retains the exact event for restart recovery; the projected
tombstone and revocation row remain rebuildable from the event log. This agent
channel checks its own denial on every RPC and renewal; it does not wait for
CRL or OCSP propagation to terminate agent access.

In **Agents → Fleet status and safe actions → Revoke certificate**, identify the
exact client certificate with its serial or SHA-256 fingerprint. On the agent host,
`openssl x509 -in agent.crt -noout -serial -fingerprint -sha256` reads those values
without exposing the private key. The console requires at least one selector and
explains that the next agent request is refused, including a request on a connection
opened before revocation. If the certificate cannot be inspected, **Offboard agent**
denies the whole agent identity. Operators can use the same selector with the API or
CLI; an empty selector does not mean “current certificate.”

Enrollment is deliberately two steps in **Agents → Add agent**:

1. **Review exact enrollment plan** asks
   `POST /api/v1/agents/enrollment-tokens/preview` what the token _would_ allow. The
   server returns the trimmed agent identity, signed certificate roles, public agent
   address, TLS name the new agent must verify, required permissions, and any blockers.
   This call creates no token, event, job, or agent connection.
2. **Mint one-time token** appears only while that exact plan is ready and unchanged.
   Editing the identity or either role hides the plan and requires a new review. Minting
   then calls the separate idempotent token route, and the token is shown once; the
   browser does not save it to local or session storage.

Leaving the identity blank means any agent identity in the caller's tenant may use the
token. Selecting **Network relay**, **Observer**, **Access gateway** or **Session
observer** also requires `agents:relay.grant`; ordinary `agents:write` authority cannot
silently turn a host agent into a relay or an observer. If the public
agent address or TLS name is missing, preview says exactly what must be configured and
minting stays unavailable. Headless operators use `trstctl agents enroll-token-preview`
with the same JSON body before `trstctl agents enroll-token`.

**Changing an enrolled agent's roles.** The roles live in signed SANs on the
agent's certificate, so they change at a renewal, never by editing a row, and no
re-enrollment is needed. An operator holding `agents:relay.grant` records the
complete role set with **Agents → Fleet status and safe actions → Change roles**,
`POST /api/v1/agents/{id}/roles` with `{"roles": ["host", "network"], "reason": "…"}`,
or `trstctl agents roles grant <agent-id>`. The grant is an `agent.roles.granted`
event; `agents:write` alone cannot record one. The agent's next heartbeat asks it
to renew, the renewal over the agent channel signs exactly the granted roles and
records which grant it signed (`agent.cert.renewed`, schema 2, carries the new
certificate's roles), and the agent reconnects with the new certificate. The agent
list shows the change as `pending` ("Next renewal: …") until a renewal signs it and
`applied`, with the new certificate's serial, after; the roles column keeps showing
what the presented certificate carries. An agent built before this release ignores
the request and takes the roles at its scheduled renewal, with about a third of its
24-hour certificate left. Removing the network role works the same way; the old
certificate stays valid until it expires, so revoke it as well when the change is
urgent. An offboarded agent cannot take new roles.

A renewal never takes roles from the CSR. A CSR that asks for a role the renewal is
not signing is refused with the role named, on the agent channel and on the HTTP
renewal endpoint (`/enroll/renewal`), which carries the presented certificate's roles
over unchanged and does not apply grants.

The agent's own discovery sources are `filesystem`, `pkcs11`, `windows-store`,
`k8s-secret`, `trust-store`, and `private-key` — the read has to happen on the host,
since only it can see its own files, tokens, Windows store, trust stores, browser
profiles, or in-cluster Secrets. An enrolled agent sends metadata-only `ReportInventory`
batches over the same mTLS channel it uses for heartbeat and renewal. Its first
authenticated heartbeat must register the agent before an inventory batch; otherwise
the RPC asks it to heartbeat first. The server rejects
inline secret-looking metadata keys, caps batch size, and ingests in the bounded agent
lane so a noisy fleet cannot starve the API. `GET /api/v1/agents` advertises the
accepted source kinds for each enrolled endpoint, and the Agents console shows the same
capability list.

Only a completed inventory run whose recorded executing agent ID matches the
receiver-stamped finding can create graph trust-store or service-dependency edges.
Manual imports remain visible as discovery findings but cannot claim agent authority.
Generic `POST /api/v1/discovery/sources` declarations cannot create the reserved
`agent` kind or an `agent:` source name; enrolled reporters create these records
through the authenticated inventory channel. The CT monitoring setup also refuses
an `agent:` name, so a watchlist cannot reserve or replace a host's source. CT
updates return a conflict if their requested name belongs to another source kind
or to a different CT source ID; operators must choose an unclaimed name. A generic
source declaration cannot change the kind bound to an existing name either; its
preview reports that ownership conflict before the operator starts the mutation.
The `secretscan:`, `secret-repo:`, and `secret-third-party:` source names are also
reserved for their product workflows. Configure those scans through the Secrets
tool or its dedicated API, not by creating a generic discovery source or CT monitor
under a product-owned name. The `weak-key-audit:` name belongs to the inventory
weak-key audit, whose runs appear in run history (see
[Weak keys](../security/weak-keys.md)).
Repository and third-party scan source names end with their stable source ID. That
keeps otherwise identical labels separate when a repository/ref contains a colon
or when two third-party artifacts share a provider, source, and event.

The selected-agent panel links to **View discovery runs** and **View discovery
findings**, so collector claims can be checked against the server's actual evidence.
An offline or stale agent cannot provide current evidence. First check its service and
network path. If the endpoint has the wrong certificate or capability role, revoke that
certificate or offboard the agent, then enroll it again with a newly reviewed one-time
token. Offboarding never deletes the old row: the actor, reason, and time remain as a
tombstone, so recovery cannot erase the failure that caused it.

For Linux certificate files, the shipped agent can inventory public certificate roots at
startup with `--inventory-cert-roots`, reporting references, fingerprints, and
certificate metadata only — never private keys or secret values.

**Kubernetes TLS Secrets.** A cluster is frequently the largest single population of
certificates an organization holds, and the one nobody has an inventory of. Run the agent
in-cluster with `--inventory-k8s-secrets` and it enumerates the `kubernetes.io/tls`
Secrets in **its own namespace** through the in-cluster service account, reporting each
Secret's certificate metadata over the same mTLS inventory path as every other source.

The exact contract: it reads `tls.crt` — public certificate material — and never
`tls.key`; no key bytes cross the agent channel. It needs list access to Secrets in that
namespace. A Secret whose certificate does not parse is skipped rather than failing the
pass, so one malformed Secret does not cost you the inventory of the rest; an
unreachable API server is an error rather than an empty result, because reporting "no
certificates" for a cluster you could not reach is worse than reporting nothing.

One agent can cover more than its own namespace. `--inventory-k8s-namespaces all`
lists every namespace the service account may list and inventories each one;
`--inventory-k8s-namespaces payments,edge` names the namespaces to read. Each finding
still carries its namespace and Secret name, and only `tls.crt` is read. The RBAC is
the operator's choice: `deploy/kubernetes/rbac-inventory-namespaces.yaml` is the
opt-in, read-only cluster grant (list namespaces, list Secrets) for `all`; for a named
list, bind a namespaced Role with list on Secrets in each namespace. A namespace the
service account cannot list is reported as an error naming that namespace, never as
an empty inventory, and the readable namespaces are reported first, so a missing
binding shows up as a gap in the run rather than as a clean cluster.

**PKCS#11 tokens.** HSMs and smart cards hold the certificates an organization cares
most about and inventories least. The default agent image is statically linked and
cannot load a PKCS#11 module, and it says so: `--inventory-pkcs11-module` there fails
with "built without cgo" instead of reporting an empty token, and the shipped census
the agent sends on heartbeat does not list `pkcs11`. The release publishes a second
agent image, `ghcr.io/ctlplne/trstctl-agent-pkcs11` (built from
`deploy/docker/Dockerfile.agent-pkcs11`, `make agent-pkcs11-image` locally), with cgo,
glibc, SoftHSM and OpenSC's `opensc-pkcs11.so` on board; vendor modules such as
`libykcs11.so` or an nShield/Luna Cryptoki are mounted in. Run that image with
`--inventory-pkcs11-module /usr/lib/softhsm/libsofthsm2.so` (or the vendor path),
optionally `--inventory-pkcs11-token <label>` to pick one token and
`--inventory-pkcs11-pin-file` for tokens whose certificate objects are not public.

The contract matches the other collectors: a read-only session, objects of class
`CKO_CERTIFICATE` only, `CKA_VALUE` and `CKA_LABEL` read, never a private-key search and
never `C_Sign` or an export; a token or PIN that cannot be opened is an error, never an
empty inventory. Findings carry the token and object label as their location (not the
module path, which differs per host for the same physical token). The repository's
SoftHSM container test loads the real module, writes a certificate and a key pair onto
a token with `pkcs11-tool`, and checks that the agent reports the certificate and
nothing about the key.

### CA, trust-store & private-key discovery

`GET /api/v1/ca/discovery` rolls up CA estates: configured public upstream CAs,
configured private upstream CAs, and imported private CA hierarchy authorities, all in
one tenant-scoped response with source id, source kind, public/private scope, status,
and pointers such as `/api/v1/external-cas/{id}/issue` or
`/api/v1/ca/authorities/{id}/issue`. It intentionally omits certificate PEM and
private-key bytes — operators use it to see which CAs are connected, then follow the
referenced route for issuance or import.

Trust-store discovery is a separate agent collector, because a trusted CA is not the
same thing as a deployed service certificate. The agent reads public trust anchors from
OS trust directories, Java `cacerts`/JKS files, NSS profile exports, browser profile
exports, and Windows trust-store enumerators, tagging each finding with
`trust_store_kind` (`os`, `java`, `nss`, `browser`, or `windows`) and
`private_key_present=false`. It also reports the certificate SHA-256 fingerprint
and SPKI SHA-256 public-key identity. The graph counts a store as trusting a managed
issuer only when one of those exact identities matches; a subject-name-only match
is a separately visible unverified candidate, not an authoritative edge. This lets
the control plane answer "what does this host trust?" without ever moving a key or
mistaking two same-name roots for the same authority. The control plane stamps the
host from the reporting agent's verified mTLS identity, so several stores or anchor
paths on one machine remain several stores across one host.

**Finding exposure.** `GET /api/v1/discovery/findings?distrust_entry=<entry name>` lists
the findings whose reader matched a distrust-list entry, and `?key_strength=weak` those
whose key was rated weak (CLI `trstctl-cli discovery findings list --distrust_entry "<entry name>"` or
`--key_strength weak`). The MCP `distrust_exposure` and `weak_key_exposure` tools answer
from these and the rated certificate inventory. `?fingerprint=<SHA-256>` (A172-L2; CLI
`--fingerprint`) lists every finding that names one certificate or key, whatever its
kind, source or run — a certificate seen on a listener, its private key on a host, the
root in a trust store — and accepts the colon-separated hex certificate viewers show.
A finding's detail in Discover has **Show every finding with this fingerprint**, and
the list says while it is narrowed. The same filter also lists every leaked secret that
holds the stored credential with that fingerprint (A172-L1, below), and a leak's detail
has **Show where this credential is stored**.

**Removing a distrusted root.** When the control plane's distrust list names a
trust-store anchor itself (for example emSign ECC Root CA - G3, by key), the finding
can be removed from the host through trust distribution:
`POST /api/v1/discovery/findings/{id}/remove-distrusted-root` with the finding's
`fingerprint` and `anchor_path` as reviewed (`connectors:write`; CLI
`trstctl-cli discovery findings remove-distrusted-root --force`). The removal is queued
for the exact host agent that found the anchor, which must run with `--relay-claim`
and a `--host-exec-profile` whose `allowed_roots` include the anchor's directory. The
agent reads the file itself (the control plane never holds its bytes), and removes it
only when it holds exactly that one certificate and the agent's own distrust list names
it: the shipped entries plus any operator list given with `--distrust-file`. The
receipt ends as `trust_anchor_removed`, `trust_anchor_absent`,
`trust_anchor_removal_refused` (a bundle, another certificate, a root the agent's list
does not name, or a path outside the profile or behind a symlink) or
`trust_anchor_removal_failed`. A bundle such as `/etc/ssl/certs/ca-certificates.crt` is
never edited: remove that root with the host's trust tool (`update-ca-certificates`,
`update-ca-trust` or the platform equivalent). Only OS trust-store files are
removable this way; Java keystores, NSS databases, browser exports and the Windows
store need their own tools. A removed source file reaches bundles built from it the
next time the host's trust tool runs.

Private-key-material discovery answers the companion question: "what sensitive key
files exist here?" Point the agent at canary directories with
`--inventory-private-key-roots`. It reads each regular file locally, classifies PKCS#8,
PKCS#1 RSA, SEC1 EC, OpenSSH, and encrypted private-key containers through the isolated
cryptography boundary, wipes the file buffer after inspection, and reports only the
path, format, algorithm, file-mode metadata, and — when the key is parseable — a
fingerprint derived from the public key. Encrypted keys are located and tagged as
encrypted, but no passphrase is requested and no private bytes ever reach the control
plane.

### Passive network crypto observer (X1)

Active scans see what an endpoint offers a scanner; an observer sees what real clients
negotiate. An agent granted the **observer** role (`agents:relay.grant`; it sees which
systems talk to which) and started with `--observe-interface <if>` watches a mirror or
span port, or its own host's interface, on Linux (`CAP_NET_RAW`; other platforms report
an error, never an empty observation set). A kernel filter keeps only the ports in
`--observe-ports` (default 443, 8443, 636, 993, 995, 465, 22, 80, 389, 5432, 3306, 25,
587, 143, 110; at most 32), and the agent reads only the first bytes of each connection, in order, up to
16 KiB a direction. The filter reads through up to two VLAN tags (802.1Q, and QinQ with
an 802.1ad outer tag; X1-L2), so a trunk's mirror port works: the kernel carries a
frame's outer tag out of band and a QinQ frame's inner tag stays in the frame. On its own
host's interface the agent reads only frames the host receives, so watch a mirror port
to see both directions of a host's own connections:

- TLS: the negotiated version, cipher suite and key-exchange group (X25519MLKEM768 and the
  other ML-KEM hybrids by name), the server name, and for TLS 1.2 the server certificate
  (fingerprint, key type and size, expiry). TLS 1.3 encrypts the certificate, so the
  observation says `certificate_visible=false` and the active probe reads the chain.
- SSH: both banners and the key exchange, host key and cipher the two sides agree on
  (RFC 4253's choice), so `mlkem768x25519-sha256` and `sntrup761x25519` read as
  post-quantum.
- TLS reached inside another protocol (X1-L4): SMTP and IMAP STARTTLS, POP3 STLS, the
  LDAP StartTLS extended operation, PostgreSQL's SSLRequest (after a refused GSSAPI
  request too) and MySQL's SSL request packet. The observer reads the TLS handshake that
  follows like a direct one and records how it was reached as `upgrade`
  (`smtp-starttls`, `imap-starttls`, `pop3-stls`, `ldap-starttls`, `postgresql-ssl`,
  `mysql-ssl`). A database's own TLS settings show here: PostgreSQL 17's default
  `ssl_ecdh_curve` (prime256v1) keeps its sessions on secp256r1 even between OpenSSL 3.5
  peers that offer X25519MLKEM768.
- QUIC and DTLS over UDP (X1-L4): datagrams to a watched port are read too. A QUIC
  handshake (HTTP/3) is TLS 1.3 inside the client's and the server's Initial packets,
  whose protection anyone can remove — RFC 9001 derives its keys from the client's
  connection ID and a published salt — so the observer decrypts them as the server does
  (QUIC versions 1 and 2), reassembles the ClientHello however many packets it spans (an
  ML-KEM hybrid key share needs two), and reads the server's group and suite; the rest of
  the connection stays unreadable. DTLS 1.0 and 1.2 hello messages, and the server's
  certificate and ECDHE group, are read in the clear across records and datagrams,
  through a cookie exchange; DTLS 1.3 encrypts its certificate as TLS 1.3 does. Findings
  are `tls_handshake` with `protocol` `quic` or `dtls`; port 443 is watched by default,
  so HTTP/3 is, and a DTLS service's port joins `--observe-ports`.
- Plaintext: an HTTP request line or an LDAP operation before StartTLS on a watched port,
  a PostgreSQL startup message or a MySQL login sent without TLS, or a mail login, AUTH
  or MAIL command before any STARTTLS raises one `plaintext_protocol` finding per
  endpoint (`postgresql-startup`, `mysql-login`, `smtp-plaintext`, `imap-plaintext`,
  `pop3-plaintext`).

No payload byte is stored or reported: the buffers are dropped once the handshake is
read, and an HTTP path or LDAP bind never leaves the parser. Each endpoint and set of
handshake facts is one finding with connection and client counts, first and last seen,
reported every `--observe-report-interval` (default one minute) under the
`network-observer` source; the server accepts that source only from a certificate that
carries the observer role, and only observation kinds from it. The flow table is bounded
(`--observe-max-flows`, default 2048); a connection that does not fit or is not a
handshake the observer reads is counted, never buffered, and every report carries the
observer's own CPU time, heap and drops. Segments that arrive ahead of a gap — a
reordered or retransmitted ClientHello or server flight — are held, at most 16 a
direction and only inside the 16 KiB the observer reads, and read once the gap fills
(X1-L3; counted as `reordered`); a gap that never fills ends reading of that
connection, counted as out of order, and what it held is dropped.

A saved capture reads the same way: `--observe-pcap <file>` (a classic pcap, as
`tcpdump -w` writes it, of Ethernet, raw IP or Linux cooked frames; pcapng is refused
with a hint to save it as pcap) makes an agent with the observer role read the file once
at start, for the ports in `--observe-ports`, and report its handshakes like an
interface's under interface `pcap:<file name>`. Use it for a capture taken where no agent
runs, such as a network team's tap. Observations are discovery
findings, kept across restarts, and they make `passive-wire-traffic` an observed class
in [computed coverage](../design/cbom-coverage.md).

### Host TLS session observer (X5)

TLS 1.3 encrypts everything after the ServerHello, including the certificate, so a wire
observer cannot see which certificate a TLS 1.3 connection used. The session observer
reads it on the host instead, from the TLS library, with no proxy in the path. An agent
granted the **session-observer** role (`agents:relay.grant`; it sees every process's
connections on its host) and started with `--observe-tls-sessions` attaches probes to the
host's OpenSSL 3 libraries (`libssl.so.3` and `libcrypto.so.3`, found in the usual library
directories or named with `--observe-tls-libraries LIBSSL,LIBCRYPTO`). It needs Linux 5.17
or later on x86-64 or arm64, `CAP_BPF` and `CAP_PERFMON` (or `CAP_SYS_ADMIN`) and the
host PID namespace; other platforms report an error, never an empty observation set.

For each TLS handshake a process on the host makes or accepts, the agent reports the
process and its executable, which side it was on, the negotiated version, cipher suite
and key-exchange group (X25519MLKEM768 and the other ML-KEM hybrids by name), the server
name, whether the server first sent a HelloRetryRequest, and the peer's certificate
(fingerprint, key type and size, expiry): the server's for a client, the client's for a
server using mutual TLS. The probes copy only the plaintext handshake records an SSL
exchanges with its own socket, each direction stopping at its first record that is not
a handshake record, and the certificates libssl parses during the handshake; no
application data and no encrypted byte leaves the kernel, and only a certificate's facts
are kept. Findings are `tls_session` items under the `tls-session-observer` source, one
per process, side, server name, negotiated facts and peer certificate, with a session
count, reported every `--observe-tls-report-interval` (default one minute) with the
probes' own drops; they say `application_data_read=false`, and they make
`host-tls-sessions` an observed class in [computed coverage](../design/cbom-coverage.md).
The server accepts that source only from a certificate that carries the session-observer
role, and `tls_session` findings from no other source. When an operator removes the role,
the agent renews at once, and its next role check, within seconds, detaches every probe.

**AI assistants and MCP servers on hosts (P7).** Desktop assistants and IDEs list
the MCP servers they start or call in JSON configuration files, and a server's
credential is often pasted straight into that file. `--inventory-mcp-config-roots`
names home or configuration directories; the agent reads the `.json` files under them
(JSON with comments and trailing commas included, package trees skipped) and
recognizes MCP client configuration by its format — an `mcpServers` object, or a
`servers` object at the top level or under `mcp` whose entries carry a command or a
URL — never by product. Each configured server becomes an `mcp_server` discovery
finding on the host: the file, the server's name, its transport (`stdio`, `http`,
`sse`, `websocket`), the base name of the program it starts or the
`scheme://host[:port]` it calls, and `static_credential` with `credential_fields`
naming where a credential is written as a literal — an environment entry such as
`env:TRACKER_TOKEN`, a header such as `header:Authorization`, an argument such as
`arg:--password`, or a URL's user information or query parameter. A reference
(`${input:…}`, `${env:…}`, `$NAME`) is not flagged. The value itself is never
reported, hashed or kept: the agent classifies it as bytes and wipes the file's bytes,
and the control plane refuses a report whose metadata could carry one. Findings
appear in discovery and in the [shadow NHI posture](observability-and-risk.md)
with their host, and an `mcp_server` with a static credential is rated high. The agent
keeps a digest of what it last reported beside its key, so a rescan that finds no
change sends nothing and writes no event. Each report is the host's whole MCP
inventory, so a server the newest report no longer lists is gone from the host: the
finding reads `removed_at` (the time of that report), the console shows it as removed
from the host, and it leaves the open shadow posture (counted under `removed`). Its
triage is kept, and it reads present again if a later report lists it. When the last
configuration is removed, the agent sends one empty report saying so. Finding MCP endpoints by probing approved
network ranges is what comes next (P7's network probe, after P8's design). Status:
served (host detectors).

**Disabling a certificate in Azure Key Vault — not a revocation (N2).** Key Vault
cannot revoke a certificate; only its issuing CA can. For a certificate the inventory
found in Key Vault (source `cloud-azure-keyvault`), `POST
/api/v1/certificates/{id}/key-vault-disable` (`trstctl-cli certificates
key-vault-disable <id> -f reason.json`) disables the exact certificate version it was
found as, so the vault stops serving it to the applications that read it there.
Discovery never writes to a vault: the disable uses a separate `write_token_ref`
configured beside the vault's `azure-keyvault` entry in a `cloud_certificate` discovery
source (an operator-approved `env:` reference, like every discovery credential), and a
vault without one refuses the request. The call runs from an outbox job and counts
only when the vault reads the version back disabled. Every answer is labeled: status
`disabled`, `revoked: false`, and the note that the certificate stays valid until it
expires or its CA revokes it; the inventory row keeps its status. `GET
/api/v1/certificates/{id}/key-vault-disables` lists them. Status: served.

Keystores get the same treatment (X2). `--inventory-keystores` names Java keystores
(JKS, JCEKS, BCFKS) and PKCS#12 files, directories or globs; a directory walk reads `.jks`,
`.jceks`, `.bcfks`, `.keystore`, `.ks`, `.p12` and `.pfx` files. Each key entry is reported as
private-key metadata: the alias, the key type and size, the public-key fingerprint (the
same basis as a key file, so one key found in both places correlates) and the chain length,
all read from the entry's certificate. A JKS or JCEKS key is never decrypted: both keep
certificate chains in the clear, so their entries are listed even without the store
password and marked `integrity_verified=false` until a password from
`--inventory-keystore-password-file` (one per line, tried before the published default
`changeit`) matches the store's integrity digest. A JCEKS store's secret keys (X2-L2) are
stepped over sealed, never opened, and counted as `keystore_secret_keys` on its key
findings; a store of secret keys only, such as a Hadoop credential store, is reported once
as the keystore with that count. A Bouncy Castle FIPS keystore (BCFKS, X2-L2) is encrypted
as a whole, so like a PKCS#12 file it is read only with its password: its integrity MAC
checks the password, the store is decrypted to reach the certificates, its private and
secret keys stay sealed, and a store no password opens is reported `locked`. A PKCS#12 file is
read for its certificates only: its MAC checks the password, the contents holding
certificates are decrypted, and a key bag is never decrypted (X2-L3); a file no password
opens is reported `locked`, with nothing listed. Every key of a PKCS#12 file is reported
(X2-L1): a Java PKCS12 keystore, as keytool writes it, holds one key bag per alias, and
each is listed at `<file>#<alias>` with the chain the file holds for it (its certificate
by the key's `localKeyID`, then each issuer the file carries, checked by signature).
Certificates outside every key's chain, such as the keystore's trusted entries, are
counted as `keystore_trusted_certificates`.

`--inventory-crypto-libraries` names TLS libraries (`libssl`, `libcrypto`, GnuTLS's
`libgnutls`, NSS's `libsoftokn3`) and `--inventory-go-binaries` names Go programs. The
agent reads each version from the file itself (the library's version string, the binary's
build information; nothing is executed or loaded) and says whether that version can
negotiate the X25519MLKEM768 hybrid key exchange: OpenSSL 3.5 and later and Go 1.24 and
later can (unless built with `tlsmlkem=0`), Go before 1.24 cannot, and BoringSSL reads
`unknown`, because it has no release versions. X2-L4 adds the others:

- LibreSSL by its release notes: 4.3.0 and later can (4.3.0 added the key share; 4.4.0
  makes it libtls's preferred group), earlier versions cannot.
- GnuTLS by what the build carries: 3.8.8 added X25519MLKEM768 as experimental, only
  in builds with a post-quantum backend, so a build that names the group can and one
  that names none (or a version before 3.8.8) cannot.
- NSS: its software token (`libsoftokn3`) names the version, and `libnss3` beside it
  names the groups the installation supports; `unknown` when no `libnss3` is beside it.
- OpenSSL before 3.5 through its configuration: the library names its `OPENSSLDIR`,
  and when that directory's `openssl.cnf` activates oqsprovider (its module present in
  the library's `MODULESDIR`, or the path the section names), ML-KEM is added: `yes`
  when the configuration's default `Groups` list names an ML-KEM hybrid, `unknown` when
  it names none (programs then offer it only if they set their own groups), `no` when the
  provider's module is missing. An `OPENSSL_CONF` set for one program is not seen.

Beside them the agent reads the host's system crypto policy (X2-L6), on Fedora, RHEL and
their relatives: `/etc/crypto-policies/config` names the policy every TLS library starts
from (DEFAULT, LEGACY, FUTURE, FIPS, with sub-policies such as `DEFAULT:PQ`), and the
OpenSSL back-end it generates sets the TLS groups OpenSSL offers. It is one more
`crypto_library` finding, library `crypto-policies` and the policy as its version, with
its own answer: `yes` when the policy keeps the ML-KEM hybrid groups in OpenSSL's
defaults, `no` when it leaves them out (OpenSSL 3.5 then offers X25519MLKEM768 only to
applications that set their own groups), `unknown` when its OpenSSL back-end sets no
groups. A LEGACY policy rates as the highest risk of these findings: it also allows
SHA-1 signatures, 1024-bit DH and DSA, and TLS 1.0. A host with no policy reports none.

### SSH credential discovery (F42) — keys and standing access

SSH is where forgotten access hides. trstctl inventories SSH credentials two ways: a
network-side SSH handshake captures each host's **host key**, and the on-host agent
reads host keys, user keys, `authorized_keys` grants, `known_hosts` trust anchors, and
each configured `sshd_config`'s trust posture (A115): the fingerprints of the CAs in its
`TrustedUserCAKeys` file, its `RevokedKeys` list (KRL version and digest, a plain key
list, or a missing file), each `HostCertificate` it presents (signing CA, CA signature
verified or not, key ID, principals, validity), and `AuthorizedKeysFile`. It reads the
global section the way sshd resolves it (first value wins, `HostCertificate`
accumulates, `Include` files in place) and counts `Match` blocks rather than applying
them. The posture is reported when the agent connects, so restart the agent after
changing `sshd_config`. The same agent path locates and classifies SSH and TLS
private-key files as metadata-only findings instead of copying key bytes into the
control plane.

On-host SSH collection is explicit, not a surprise filesystem crawl. Configure only
the paths the agent may read with `--inventory-ssh-host-key-globs`,
`--inventory-ssh-user-key-globs`, `--inventory-ssh-authorized-keys`,
`--inventory-ssh-known-hosts`, and `--inventory-ssh-sshd-configs`. Every flag is empty
by default. For example:

```sh
trstctl-agent ... \
  --inventory-ssh-host-key-globs '/etc/ssh/ssh_host_*_key.pub' \
  --inventory-ssh-authorized-keys '/home/*/.ssh/authorized_keys' \
  --inventory-ssh-known-hosts '/etc/ssh/ssh_known_hosts,/home/*/.ssh/known_hosts' \
  --inventory-ssh-sshd-configs /etc/ssh/sshd_config
```

The agent reports the result over its existing mTLS inventory RPC. The control plane
derives the tenant from the verified agent certificate, appends discovery events, and
projects the metadata into `GET /api/v1/ssh/fleet`. Operators can read the same view
with `trstctl ssh fleet` or in **Machine & Workload Trust → SSH trust**.

Two flags make the result actionable. **StandingAccess** marks an entry that grants
persistent login (an `authorized_keys` line). **Orphaned** marks a standing-access grant
whose comment field is blank — meaning nobody can say whose key it is. An orphaned
standing-access key is exactly the thing a security team wants surfaced. Only the
fingerprint is ever stored, never private key material (held in wipeable memory and
zeroed after use).

The control plane serves `ssh` discovery source/run/finding records and executes
non-invasive SSH host-key scans from the discovery outbox worker. Source configs accept
explicit `targets` (`host:port`) or CIDRs plus ports, run on a bounded worker lane, and
use reserved-address filtering unless the operator explicitly allows private or loopback
diagnostic targets.

### Discovery source kinds, one shape

Eight more source kinds follow an identical pattern: create a source with a `kind` and
a `config`, queue a run, read back metadata-only findings. Rather than walk through
that shape eight times, here is what each one actually finds:

| Source kind                           | What it finds                                                                                                                                                                                                                                                                                 | Config essentials                                                                                                                                                                         |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cloud_certificate` (F49)             | Certificates the cloud provider already knows about: AWS ACM, Azure Key Vault, GCP Certificate Manager                                                                                                                                                                                        | `providers[]` (region/vault/project plus `access_key_id_ref`, `secret_access_key_ref`, or `token_ref`); inline credentials are rejected before storage                                    |
| `cloud_access_key` (M3)               | IAM users' long-lived access keys, a Google Cloud project's service-account keys (M3-L1) and a Microsoft Entra tenant's app-registration client secrets (M3-L2), with owner, status, age and last use; an active key unused for 90 days is flagged stale                                                                                                          | `providers[]` with `provider: aws-iam`, `access_key_id_ref`, `secret_access_key_ref`, optional `session_token_ref` and `endpoint`; or `provider: gcp-iam`, `project`, `token_ref`, optional `endpoint` and `activity_endpoint`; or `provider: azure-entra`, `token_ref`, optional `endpoint` |
| `cloud_kms_key` (X4)                  | Keys a cloud KMS holds with type, size, usage, state and automatic-rotation status; a key KMS could rotate but is not rotating is flagged unrotated                                                                                                                                           | `providers[]` with `provider: aws-kms`, `region`, `access_key_id_ref`, `secret_access_key_ref`, optional `session_token_ref` and `endpoint`                                               |
| `load_balancer_tls` (X4)              | The TLS policy each AWS load-balancer listener or F5 BIG-IP virtual server enforces; one crypto-inventory finding per listener at the oldest version it allows                                                                                                                                | `providers[]`: `aws-elbv2` (`region` + AWS references) or `f5-bigip` (`endpoint` + `token_ref` or `username_ref`/`password_ref`)                                                          |
| `nhi_cross_surface`                   | Non-certificate machine identities across six surfaces: IdP, cloud, SaaS, on-prem, code, and CI                                                                                                                                                                                               | `observations[]`: `surface`, `system`, `external_id`, `principal`, `owner`, `credential_kind`, `scopes`; needs at least one observation per surface                                       |
| `service_account` (CAP-NHI-03)        | AD/on-prem and cloud service accounts                                                                                                                                                                                                                                                         | `accounts[]`: `surface` (`active_directory` or `cloud`), `provider`, `account_id`, `principal`, `credential_refs`; needs at least one of each surface                                     |
| `oauth_grant`                         | Third-party OAuth apps, grants, and scopes; a second pass flags abused or malicious grants                                                                                                                                                                                                    | `grants[]`: `provider`, `app_id`, `principal`, `resource`, `scopes`, `consent_type`, `third_party`, `owner`; no client-secret or token field exists                                       |
| `nhi_behavior`                        | Behavior anomalies (unfamiliar IP, geo, or user-agent; usage spikes; off-hours activity) against a learned per-principal baseline                                                                                                                                                             | `events[]`: `principal`, `occurred_at`, `ip`, `geo`, `user_agent`, `action`, `usage_count`, `baseline`; optional `business_hours` window                                                  |
| `credential_compromise` (CAP-ITDR-02) | Leaked, replayed, or honeytoken-flagged credentials (OWASP NHI2 signals)                                                                                                                                                                                                                      | `signals[]`: `principal`, `credential_ref`, `credential_kind`, `provider`, `detector`, `observed_at`, `reason`, `confidence`, `evidence_refs`                                             |
| `k8s_ingress_gateway` (CAP-K8S-03)    | Kubernetes `Ingress`/`Gateway` API TLS needs; with a cluster agent bound, hands each TLS block to that agent, which generates the key in the cluster and writes the Secret; without one, reports each resource not delivered                                                               | `resources[]`: `kind` (`Ingress` or `Gateway`), `namespace`, `name`, `tls_secret_name`, `hosts`, `auto_issue`; optional `cluster_agent_id`, `owner_id` (required with it), `verify_address` |
| `secret_store` / `api_key` (F35, F36) | Secrets, API keys, tokens, and PATs by reference only — path, name, or ARN plus a masked fingerprint, never a value; also covers cloud secret-manager import from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and HashiCorp Vault KV for certificate material stored as secrets and, with content inspection, the API keys, tokens, and private keys stored in them (`secret_store_api_key`, masked and fingerprinted) | path/name/ARN, `masked_fingerprint`, scope, expiry, `rotation_age_days`; secret-shaped fields (`token_value`, `secret`, `password`, `private_key`) are rejected before a source is stored |

All eight run through the discovery outbox worker, normalize their input into
metadata-only findings carrying a stable provenance string (`<kind>:<key-parts>`), and
append the standard `discovery.*` audit events. Several also stamp a `capability` tag
used for compliance/ITDR mapping (for example `CAP-ITDR-02`, `CAP-ITDR-03`) — see
[Observability & risk](observability-and-risk.md) for how findings feed risk scoring and
posture. Every finding also becomes a node in the [credential graph](graph-query-ai.md)
with its provenance and risk score; a related bridge ingests leaked-credential findings
from scanners (gitleaks, trufflehog) into the same graph, again excluding the secret
value structurally.

One worked example — the shape is identical for the other seven kinds; change `kind`
and `config` (the create → run → findings CLI flow is the same one shown for `network`
under **Use it** below):

```json
{
  "kind": "oauth_grant",
  "name": "quarterly-oauth-consent",
  "config": {
    "grants": [
      {
        "provider": "okta",
        "app_id": "0oa-payments",
        "principal": "payments-bi-export",
        "resource": "google-workspace",
        "scopes": ["drive.readonly"],
        "consent_type": "admin",
        "third_party": true,
        "owner": "finance-platform"
      }
    ]
  }
}
```

For `oauth_grant` specifically: a grant with provider threat signals, a dangerous or
`.default` scope, `offline_access` combined with high-privilege admin consent, an
unverified publisher, a missing owner on a privileged grant, or a suspicious redirect
URI additionally emits an `oauth_grant_abuse` finding tagged `capability=CAP-ITDR-03`.
Ordinary high-risk-but-owned grant inventory stays `oauth_grant` only, so trstctl does
not count inventory as detection.

An `oauth_grant` source may also name admin connections, one per provider (A170,
A171):

```json
"providers": [
  {"provider": "okta", "base_url": "https://example.okta.com", "token_ref": "env:OKTA_ADMIN_TOKEN"},
  {"provider": "microsoft", "base_url": "https://graph.microsoft.com", "token_ref": "env:GRAPH_ADMIN_TOKEN"}
]
```

From a grant finding, **Revoke grant at provider** (or `trstctl-cli discovery findings
revoke-oauth-grant ID`) removes every grant and refresh token that user gave the
application, and **Block app at provider** (`... block-oauth-app ID`) deactivates the
Okta app or disables the Entra service principal; once a block is confirmed,
**Unblock app at provider** (`... unblock-oauth-app ID`, A171-L1) reactivates the app or
re-enables the service principal. Google Workspace grants can be
revoked; its apps are blocked in its own admin console. An Entra application an
administrator consented to for every user (a Graph grant with consent type
`AllPrincipals`, which names no user) offers **Revoke admin consent at provider**
instead (A170-L1): it deletes that admin consent and leaves each user's own grant.
The finding then shows what the provider confirmed, read back from the provider
(A170-L2); a grant or app the provider still shows after confirming is recorded failed.

The same actions can run without an operator when a detection lands (A170-L3): a tenant
policy's `nhi_posture` rule may ask for `revoke_oauth_grant` or `block_oauth_app` on an
`oauth_grant_abuse` detection (posture family `oauth_abuse`, with `provider` in its
input), and the leader's sweep queues exactly the request the buttons queue, recorded on
the finding by `system:nhi-posture` with the rule. See
[Policy and governance](policy-and-governance.md) for the rules.

### Annotate a leaked credential where it was seen

A third-party secret scan (CI logs, container images, Slack and Jira exports) can write
each finding back at the provider (A174). Ingest the export with an `annotation`
connection:

```json
"annotation": {"base_url": "https://slack.com", "token_ref": "env:SLACK_BOT_TOKEN"}
```

For a CI log add `system` (`github` or `gitlab`), `repo` and `commit_sha`; for an image,
`repository` and `digest`; Jira may add `username_ref` for basic authentication, and so may
a registry whose token server takes a login (A174-L2: trstctl answers the registry's Bearer
challenge with a token from its realm, and on a registry without the OCI referrers API
lists the referrer in the `sha256-<subject>` referrers tag index). Each
finding then records where it sat (the Slack channel and message, the Jira issue, the
commit, the image), and **Annotate at provider** on the finding (or `trstctl-cli
discovery findings annotate ID`, or `auto: true` on the ingest) writes one note there: a
reply in the Slack thread, a comment on the Jira issue, a failed commit status, or an
OCI referrer on the image. The note names the rule and the finding, never the secret,
and the finding shows what the provider confirmed.

When the finding is resolved (recorded remediated or dismissed), its note is settled at
the same provider so it stops telling people to rotate a credential that is already
handled: the Slack reply is deleted, the Jira comment is rewritten to say the finding was
resolved, the commit status turns to success under the same context, and the image
referrer is deleted. The finding shows the settlement under `provider_actions.resolve_annotation`.

### Cloud secret managers

A `cloud_secret` or `secret_store` source lists the secrets an authorized principal can
see in AWS Secrets Manager, Google Secret Manager, Azure Key Vault and HashiCorp Vault KV
(`providers[]`, credentials by reference). By default it records each secret's metadata
(name, location, rotation and update times) as a `cloud_secret_resource` finding and
never reads a value.

Two more providers cover the code hosts' CI/CD secret stores (A173), each with a
`token_ref` and an optional `endpoint` for a self-hosted server:

| Provider | Scope fields | What it lists |
|---|---|---|
| `github-actions` | `owner` + `repo`, `environments`, `org`, `stores`, `user_codespaces` | Repository and organization secrets in each chosen store — `actions` (the default), `dependabot`, `codespaces` — plus environment Actions secrets and, with `user_codespaces`, the token owner's own Codespaces secrets. GitHub never returns a value, so this provider is metadata-only and refuses `inspect_content`. |
| `gitlab-ci` | `project`, `group` (ID or full path), `instance` | CI/CD variables with type, protection, masking, environment scope; with `instance: true`, the instance-level variables every project inherits (GitLab lists them to an administrator's token only). A hidden variable's value is never returned and is reported as not inspectable. |

Four more providers read the secret stores teams run beside the cloud managers (OD-13).
Each signs in with its own credential reference and takes an optional `endpoint` (the
server URL for a self-hosted Infisical, Conjur or Akeyless gateway, the API of a
self-hosted Bitwarden), `path_prefix`, `name_prefix` and `inspect_content`:

| Provider | Sign-in and scope fields | What it lists |
|---|---|---|
| `infisical` | `client_id` + `client_secret_ref` (Universal Auth) or `token_ref` (an access token); `project`, `environments`, `path_prefix` (the secret path) | Each project's environments and every folder below the path: key, folder, version, type, tags and dates. A metadata-only run asks Infisical to leave values out (`viewSecretValue=false`) and still wipes every response body. |
| `conjur` | `account`, `login` (`host/<id>` or a user), `api_key_ref`; `path_prefix` (a policy path); `endpoint` required | The variables the login may read: ID, owner, policy, annotations and how many versions each holds. The resource listing never carries a value; inspection reads each variable that holds one. |
| `akeyless` | `client_id` (the access ID) + `client_secret_ref` (the access key); `path_prefix` (a folder) | Static secrets in the folder and below: name, type, tags, version and dates, across every `list-items` page. Inspection reads values by name in small batches. |
| `bitwarden-secrets-manager` | `token_ref` (the machine account's access token); `identity_endpoint` for a self-hosted server | The secrets the machine account can read, with their projects and dates. Secrets Manager encrypts names and values on the client: the access token signs in and also carries the key that opens the organization key, so trstctl decrypts names in memory (`internal/crypto/bwsm`) and never stores a value. |

Two more read the stores of password managers and app secret platforms (OD-14), each with
a `token_ref`:

| Provider | Scope fields | What it lists |
|---|---|---|
| `1password-connect` | `endpoint` (the Connect server, required), `vaults` (IDs or names) | Items in each vault the Connect token can read: title, category, tag count, version, update time. Field values are read one item at a time only with `inspect_content`, and a credential finding names the field. |
| `doppler` | `project`, `configs` | Secret names in each project's configs, from the names-only endpoint, so a metadata-only run never receives a value; with `inspect_content` each config's values are read once. |

Infisical (v0.167.8) and Conjur Open Source (1.27.0) are proven against their official
images, pinned by digest, in a served lab run; Akeyless, Bitwarden Secrets Manager,
1Password Connect and Doppler against in-repository stand-ins written from their public
API references and SDK. The Secrets page lists the six beside the cloud managers, and the
source wizard asks for each one's own sign-in.

Each GitHub finding names its store (`store`: `actions`, `dependabot` or `codespaces`) and
scope (`repository`, `environment`, `organization` or `user`); a user's Codespaces secrets
are keyed by their login, which the provider reads from `GET /user`. An unknown store, or
environments without the `actions` store, fails that provider with the reason. Dependabot and
Codespaces secrets need their own read permissions on the token (for a fine-grained token,
Dependabot secrets and Codespaces secrets, and Codespaces user secrets for the owner's own).
A GitLab instance's variables are read from `GET /api/v4/admin/ci/variables`; any other token's
403 fails that provider saying an administrator's token is required. Like project and group
variables, their values are wiped once read unless content inspection is chosen.

With `inspect_content: true` on a provider, trstctl also reads each value it is allowed
to, holds it only in wipeable memory, and looks inside it (A172):

- certificates become `x509_certificate` findings and inventory rows;
- API keys, tokens and private keys become `secret_store_api_key` findings. The built-in
  rules recognize AWS access key IDs and secret access keys, GitHub and GitLab tokens,
  Slack tokens and webhook URLs, Stripe live keys, Google API keys, npm tokens, SendGrid
  keys, trstctl API tokens, JWTs, PEM private keys and Google service account key files.
  A value that is a JSON object, or a Vault secret's fields, is read field by field, and
  the finding names the field.

A credential finding records the rule, the credential kind, the field, a masked display
(the credential's public prefix and its length, a PEM block's BEGIN line, or a service
account's email) and a fingerprint: a SHA-256 of the credential that is the same
wherever it is stored, so two stores holding one key show one fingerprint. A private
key's finding also records `spki_sha256`, the SHA-256 of its public key: the same hash a
certificate for that key has, read whatever the key's encoding (an encrypted key has
none). The credential graph links the stored key to every certificate in the inventory
with that public key (`KEY_OF`), so the certificate's blast radius starts at the secret
store that holds its key. The value is wiped after inspection and never stored, logged
or shown. There is no generic high-entropy rule: a string that matches no rule is not
reported.

A credential leaked in a repository, a CI log, a chat or a wiki page lines up with its
stored copies (A172-L1). The scanners report where a leaked secret is, never what it is,
so trstctl reads the finding's line back from the scanned tree, matches it in memory with
the same rules, fingerprints the credential the scanner's match covers (gitleaks reports
its columns; a scanner without columns counts only when the line holds one credential)
and wipes the line. The `leaked_secret` finding records `credential_fingerprint` and
`credential_rule`; its own fingerprint stays the scanner's location. `?fingerprint=` with
a stored credential's fingerprint then lists its secret-store copies and every leak that
holds it. A leak found only in history (the line no longer holds it), a line holding
several credentials the scanner's position cannot tell apart, or a credential the rules
do not recognize records none.

### Cloud network paths

A `cloud_network_path` source (A167) holds one AWS account's read-only network
credentials, as references: `providers[]` with `provider: aws-ec2`, `region`,
`access_key_id_ref`, `secret_access_key_ref`, an optional `session_token_ref` and an
optional `elb_endpoint` (default `https://elasticloadbalancing.<region>.amazonaws.com`,
held to the same egress checks as `endpoint`). It needs `ec2:DescribeNetworkInterfaces`,
`ec2:DescribeSecurityGroups`, `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`,
`elasticloadbalancing:DescribeLoadBalancers` and `elasticloadbalancing:DescribeListeners`
and nothing else. It does not
sweep the account: it answers for the endpoints the NHI exposure posture names, when an
operator validates them from Risk → exposure (**Validate paths in the cloud**) or with
`POST /api/v1/nhi/posture/exposure/attack-paths`. For each public address the control
plane finds the network interface that holds it, then follows the path a packet from the
internet would take: the subnet's route table must send `0.0.0.0/0` (or `::/0`) to an
internet gateway, the network ACL's first internet-wide rule for the port must allow it
in and the reply out, and a security group on the interface must admit the port from the
internet. The verdict names the resource that decided it. "The internet" is judged a
block at a time (A167-L5): each half of the IPv4 space, and IPv6 global unicast
(`2000::/3`, where every public IPv6 address is allocated). A route or rule counts for a
block when its range holds the whole block, so `::/0` and `2000::/3` both stand for the
IPv6 internet and an IPv6 address is judged by IPv6 rules and routes only; the most
specific route holding a block decides it, so a split default (`0.0.0.0/1` and
`128.0.0.0/1`) overrides `0.0.0.0/0` and a `2000::/3` route overrides `::/0`; and a rule
for half the IPv4 internet admits that half. The path is open when any block passes
every stage.

What holds the address changes the path (A167-L2). An interface Elastic Load Balancing
manages for an application, network or classic load balancer is judged as that load
balancer: it must listen on the port over TCP (HTTP, HTTPS, TCP, TLS, SSL or TCP_UDP),
read with `DescribeListeners` across every page (or the classic `DescribeLoadBalancers`),
and its own security groups must admit the port — a network load balancer created without
security groups is filtered by the subnet's network ACL alone; an open path reads
interface, load balancer, security group, network ACL, route table, internet gateway, and
a port it does not listen on is blocked at the load balancer (`listener`). A NAT gateway's
address admits no connection from the internet and is blocked at the NAT gateway
(`nat_gateway`). The subnet's internet-wide route is read for where replies go: to a NAT
gateway, an egress-only internet gateway, a peering connection or a virtual private
gateway it blocks the path at the route table, naming that target, and a blackhole route
names the missing target; to a transit gateway, a gateway load balancer endpoint or an
appliance it makes the verdict unknown, naming that resource, unless a network ACL or
security group on the way blocks it outright. When the route leads to the internet
gateway, the gateway's own route table (ingress routing) is read too, and a route that
steers the interface's subnet through an inspection endpoint or appliance makes the
verdict unknown the same way. A dry run of the source
checks only that its providers can be built; a full run, and every run a schedule on the
source queues (A167-L4), re-validates the endpoints the exposure posture names — at most
50 a run, records never validated first and then the longest unchecked, so successive
scheduled runs cover the whole posture — and records each address's verdict under the
run, with one run target per address. Each source keeps its own latest verdict per
address: one whose account holds the address (open or blocked) outranks another
account's "not in account", so adding a second account never hides the first's.

The same source can read a Google Cloud project (A167-L1): `provider: gcp-compute` with
`project`, `token_ref` (an OAuth 2.0 bearer token with Compute Engine read scope) and an
optional `endpoint` (default `https://compute.googleapis.com`). It needs
`compute.instances.list`, `compute.firewalls.list` and `compute.routes.list` on the
project (the Compute Network Viewer role, `roles/compute.networkViewer`, grants them)
and nothing else; every list is followed across its pages. The control plane finds the
instance whose network interface holds the external address, then follows Google's
documented VPC semantics: the network's applicable route for `0.0.0.0/0` (or `::/0`)
with the lowest priority number must send the traffic to the default internet gateway,
and the ingress firewall rule with the lowest priority number that applies to the
instance (by network, target tag or service account) and names the internet-wide range
for the port decides, a deny winning a tie; with none, the network's implied ingress
deny blocks it. An open verdict names the firewall rule that admits the internet and the
path through the route to the gateway; a blocked one names the denying rule or the route
with another next hop, or the network itself when its implied deny or the absence of an
applicable route decided, and its reason says which. Hierarchical and network firewall
policies, Cloud NGFW rules and paths through load balancers or Cloud NAT are not read
yet, so an instance they govern is judged by its VPC firewall rules and routes alone.

The same source can read an Azure subscription (A167-L1): `provider: azure-network` with
`subscription_id`, `token_ref` (a Microsoft Entra access token for Azure Resource
Manager) and an optional `endpoint` (default `https://management.azure.com`). It needs
`Microsoft.Network/publicIPAddresses/read`, `networkInterfaces/read`,
`virtualNetworks/subnets/read`, `networkSecurityGroups/read` and `routeTables/read` on
the subscription (the built-in Reader role grants them) and nothing else; the public IP
list is followed across its pages, and a `nextLink` that leaves the endpoint is refused.
The control plane finds the public IP holding the address and the network interface it
is attached to, then follows Azure's documented semantics: network security groups are
processed after the public IP is translated to the interface's private address, the
subnet's group first and then the interface's, each deciding with its first matching
inbound rule by priority and Azure's default rules last (`DenyAllInBound` at 65500), and
the traffic must be admitted by every group present. A rule applies when its source is
`*`, the `Internet` tag or the internet-wide range, its protocol TCP or any, its ports
cover the port, and its destination is any address, the virtual network, a range
holding the interface's private address or an application security group the interface
belongs to. A Standard public IP no group opens stays closed (Basic addresses with no
group are open), and a subnet route that sends `0.0.0.0/0` (or `::/0`) to anything but
`Internet` breaks the reply. The verdict names the group (`network_security_group`), the
route table (`route`) or the public IP (`public_ip`, also for a NAT gateway's address
or one associated with nothing). A public IP on a load balancer, application gateway or
firewall is reported as unknown with that attachment; Virtual Network Manager security
admin rules and routes learned over BGP are not read yet.

### Cloud access keys

A `cloud_access_key` source (M3) finds the long-lived access keys an AWS account's IAM
users sign in with. It holds one account's read-only credentials as references:
`providers[]` with `provider: aws-iam`, `access_key_id_ref`, `secret_access_key_ref`, an
optional `session_token_ref` and an optional `endpoint` (default
`https://iam.amazonaws.com`). It needs `iam:ListUsers`, `iam:ListAccessKeys` and
`iam:GetAccessKeyLastUsed` and nothing else. A run lists every user (all pages), each
user's keys and each key's last use, and records one `cloud_access_key` finding per key
(at most 10,000 a run) with:

| Metadata | Meaning |
|---|---|
| `user`, `access_key_id`, `status` | The key's owner, its ID and `Active` or `Inactive` |
| `created_at`, `age_days` | When the key was created and how old it is |
| `last_used_at`, `last_used_service`, `last_used_region` | Its last use, as IAM records it; `never_used: true` when it has none |
| `unused_days`, `stale` | Days since its last use (or since creation when never used); `stale` is true for an **active** key unused for 90 days or more |

A stale key carries risk score 80, any other key 30. A finding holds no secret access key
(IAM never returns one after creation) and nothing else from the account. The keys show
in the NHI inventory as `api_key` rows, and an inactive key is never flagged. The source
reaches only its endpoint: a private endpoint needs `allow_private_endpoint` with
`private_egress_cidrs`, and with the air-gap guard on (`air_gap.enabled`) a run reaches
only hosts the guard allows, so an account outside them fails the run and records
nothing.

A `gcp-iam` provider (M3-L1) reads a Google Cloud project's user-managed service-account
keys: `project`, a `token_ref` to a short-lived read-only OAuth token, an optional
`endpoint` (default `https://iam.googleapis.com`) and an optional `activity_endpoint`
(default `https://policyanalyzer.googleapis.com`). The token needs
`iam.serviceAccounts.list`, `iam.serviceAccountKeys.list` and Policy Analyzer's
`serviceAccountKeyLastAuthentication` activity. A run lists every service account (all
pages) and its user-managed keys, and reads each key's last authentication from Policy
Analyzer. A finding's `user` is the service account and `access_key_id` the key ID;
`status` is `Active`, `Disabled` (the key or its account) or `Expired`; `expires_at` is
the key's expiry; `last_used_at` its last authentication, or `never_used: true`, and the
same 90-day rule makes an active key stale. When Policy Analyzer cannot be read, the keys
are still recorded with `last_use_unknown: true`, none is called stale for want of it,
and the run is `partial` with the reason; a missing last use is never read as non-use.

An `azure-entra` provider (M3-L2) reads a Microsoft Entra tenant's app-registration client
secrets: a `token_ref` to a short-lived Microsoft Graph token and an optional `endpoint`
(default `https://graph.microsoft.com`). The token needs `Application.Read.All`, and
`AuditLog.Read.All` for each secret's last sign-in (Graph's app credential sign-in
activity, a premium directory feature). A run lists every application (all pages,
following next-page links only on the Graph endpoint) and its client secrets, never a
secret's value or hint. A finding's `user` is the application's name, `app_id` its
application ID, `access_key_id` the secret's key ID and `secret_name` its description;
`status` is `Active` or `Expired`; `expires_at` its end date; `last_used_at` its last
sign-in, or `never_used: true`, and the same 90-day rule makes an active secret stale.
Without the sign-in activity, the secrets are still recorded with `last_use_unknown: true`
and the run is `partial`, as for Google Cloud.

### Cloud KMS keys

A `cloud_kms_key` source (X4) inventories the keys an AWS account's Key Management Service
holds in one Region. It holds the account's read-only credentials as references:
`providers[]` with `provider: aws-kms`, `region`, `access_key_id_ref`,
`secret_access_key_ref`, an optional `session_token_ref` and an optional `endpoint`
(default `https://kms.<region>.amazonaws.com`). It needs `kms:ListKeys`,
`kms:DescribeKey` and `kms:GetKeyRotationStatus` and nothing else. A run lists every key
(all pages, at most 10,000) and records one `cloud_kms_key` finding per key:

| Metadata | Meaning |
|---|---|
| `key_id`, `arn`, `region` | The key and where it lives |
| `key_spec`, `key_type`, `key_bits` | The key spec and the type and size it means: `SYMMETRIC_DEFAULT` is AES-256, `RSA_2048` is RSA 2048, `ECC_NIST_P256` is ECDSA P-256, `HMAC_256` is HMAC 256 |
| `key_usage`, `key_state`, `key_manager`, `origin`, `enabled`, `multi_region`, `created_at` | As KMS reports them |
| `rotation` | `enabled`, `disabled`, `not_supported` (asymmetric and HMAC keys, imported key material and custom key stores — KMS cannot rotate them automatically, so they are not asked) or `unknown` (KMS refused the read, with its error code in `rotation_error`, or the key is pending deletion) |
| `rotation_period_days`, `next_rotation_at` | When KMS reports them |
| `unrotated` | `true` for a key KMS could rotate automatically but is not rotating |

An unrotated key carries risk score 60, any other key 20. A finding never holds
key material, and the run changes nothing in KMS. Like every cloud source, a private
endpoint needs `allow_private_endpoint` with `private_egress_cidrs`, and the air-gap
guard confines the calls.

### Load-balancer TLS policies

A `load_balancer_tls` source (X4) reads the TLS policy each load-balancer listener
enforces, with `providers[]` of two kinds:

| Provider | Configuration | What it reads |
|---|---|---|
| `aws-elbv2` | `region`, `access_key_id_ref`, `secret_access_key_ref`, optional `session_token_ref` and `endpoint` | Every HTTPS and TLS listener of the Region's Application and Network Load Balancers and its security policy's protocol versions and ciphers (`DescribeLoadBalancers`, `DescribeListeners`, `DescribeSSLPolicies` and nothing else) |
| `f5-bigip` | `endpoint` (the management URL) and `token_ref`, or `username_ref` and `password_ref`, for a read-only (Guest or Auditor) user | Every virtual server that presents a client SSL profile, and the versions the profile's options leave enabled (`no-tlsv1`, `no-tlsv1.1`, `no-tlsv1.2`, `no-tlsv1.3` each turn one off), through two iControl REST GETs |

Each listener is one `tls_listener_policy` finding (`load_balancer`, `listener`, `port`,
`policy`, `protocols`, `lowest_protocol`, `allows_tls10`, `allows_tls11`, `ciphers`;
risk 70 when it allows TLS 1.0, 50 for TLS 1.1, 10 otherwise) and one finding in the
crypto inventory (`GET /api/v1/cbom/assets`): a `host-config` fact at the listener with
the oldest version it allows, rated by the crypto policy. A listener whose policy allows
TLS 1.0 is therefore exactly one weak `TLSv1.0` finding, however many runs see it; when
the policy is tightened, the next run replaces that fact. A BIG-IP profile's cipher
string can narrow its versions further than its options do; a TLS scan of the virtual
address (CBOM scan) shows what actually negotiates. The calls never change the account
or the appliance, and BIG-IP's management certificate must be trusted by the host
(`SSL_CERT_FILE` or the system store).

### Unified NHI inventory — every credential kind, one denominator

`GET /api/v1/nhi/inventory` (`nhi:read`) is a read-side projection, not a new state
store, over identities, certificate inventory rows, API-token metadata, enrolled
agents, and discovery findings, normalized into one item shape spanning certificates,
SSH keys, secrets, API keys, OAuth apps, tokens/PATs, service accounts, IAM roles,
webhooks, workload IDs, and agents. Each item preserves its provenance (`identity`,
`certificate_inventory`, `access_api_token`, `agent_fleet`, or `discovery_finding`) plus
public metadata — owner, status, fingerprint, risk score, source system, external
reference — and never returns secret values, private keys, or raw API tokens. The
dashboard's NHI inventory summary consumes this API directly, so the first screen
counts all eleven kinds instead of only the managed `identities` table.

Managed NHI decommissioning rides the same denominator: `POST /api/v1/nhi/decommission`
selects tenant-local managed identities by departure, vendor-term, or inactivity signal
and drives the normal event-sourced revoke/retire lifecycle transitions.

### Ownership attribution — the canonical treatment

Every non-human identity needs an accountable owner, not a discovery note that says
"owner: unknown." `GET /api/v1/ownership/attribution` (`nhi:read`) resolves NHIs to an
owner two ways: managed identities resolve their stored `owner_id` directly, while
discovery-fed rows resolve the metadata-only owner, team, or vendor name captured at
discovery time against registered owners. Anything that doesn't resolve stays marked
`orphaned` rather than silently counted as accountable — that feeds tenant
governance reporting and the orphaned-owner signal risk scoring weighs. Each resolution
carries an evidence ref (such as `discovery.finding:<id>` or `inventory:<id>`) back to
the record that produced it, so an operator can trace an attribution to its source. The
same data is available via `trstctl-cli owners attribution` and the Owners console;
[Policy & governance](policy-and-governance.md) is the main consumer that turns this
into compliance posture.

### Discovery triage

Findings are immutable evidence, but their operator triage state is mutable and
event-sourced. `triage_status` starts as `unmanaged`; the state model also includes
`investigating`, `managed`, `dismissed`, and (A106) `remediated` and
`accepted_risk`. `POST
/api/v1/discovery/findings/{id}/claim` marks a finding managed, and `POST
/api/v1/discovery/findings/{id}/dismiss` dismisses it with a reason. Both are
tenant-scoped, idempotent mutations guarded by `discovery:write`.

`POST /api/v1/discovery/findings/{id}/resolution` (A106, `discovery:write`)
records a resolution with a `reason` and an `action`: `investigate` (an
`assignee` and an optional future `due_at`; repeating it reassigns),
`remediated` (an `evidence_ref` for the fix), `accept_risk` (an `expires_at`
within one year; the leader's lifecycle sweep reopens the finding when the
acceptance expires, as `system:risk-acceptance-expiry`), or `reopen` (from
remediated or accepted risk). Each action refuses the other actions' fields.
A finding reports `overdue` when its investigation is past due and `regressed`
when it was seen again after its fix was recorded. The NHI shadow and stale
posture leave a fix that held and an unexpired acceptance out of the open
posture and count them (`remediated`, `accepted_risk`, `resolved`); the CT and
drift dashboard summaries count every status (`triage_counts`), plus overdue
and regressed findings. On the Posture page each CT-log and drift row has a
Resolve action with these choices, limited to the moves its status allows.

`GET /api/v1/discovery/findings` filters on the server by `run_id`,
`source_kind` (the kind of the source a finding was recorded under, for
example `ct_log` or `drift`), `kind`, and `triage_status` (`unmanaged`
includes findings never triaged), and pages by `cursor`. The CT-log and drift
dashboards (`GET /api/v1/discovery/ct-monitoring` and
`GET /api/v1/discovery/drift-remediation`) take `triage_status`, `cursor`, and
`limit` (1-100, default 50): their `findings` are one page of their own source
kind with a `next_cursor`, and their `summary` counts every finding of that
kind on the server.

A finding produced without an explicit ID gets one deterministic ID from its exact
tenant, run, kind, reference, and fingerprint. This matters when the outbox retries a
partly completed scan: the retry records the same observation identity instead of a
new UUID that collides only after restart replay. Older histories can contain both
payload IDs for one natural observation. The projection keeps those IDs as aliases,
chooses the earliest immutable observation (then lexical ID for an exact-time tie) as
the canonical row, and resolves later triage events through either alias. A duplicate
whose source, provenance, risk, or metadata differs is not merged: replay fails with
the tenant, natural key, both IDs, and differing fields rather than silently changing
the evidence.

`GET /api/v1/nhi/posture/shadow` is the shadow posture view: it pages
through tenant-scoped discovery findings, excludes anything already claimed as managed
or dismissed, counts unmanaged and unregistered external NHIs by kind and surface, and
returns recommendation/evidence refs only — never credential values.
`trstctl-cli nhi posture shadow` reads the same view.

### In the console

The `/discovery` screen is named **Find unmanaged credentials** because that is the
operator's job, not the database feature underneath it. Its default reading order is:

1. **What needs attention** — unmanaged count, high-risk count, and credential types.
2. **Credentials to review** — one plain-language row action opens the finding.
3. **Claim** — the main next step turns a reviewed finding into managed inventory.

When creating an identity from a TLS finding with one distinct observed subject
alternative name, the console suggests that name rather than the certificate's
full distinguished name such as `CN=web.example.com`. This lets endpoint enrollment
reuse the requested identity for the same hostname and owner. The name remains
editable; when a certificate has multiple names, review which endpoint this
identity represents before creating it. Creation and claiming do not issue or
deploy a certificate.

Less-common rotate, revoke, decommission, remediate, and dismiss actions are grouped
under **More actions**. Exact fingerprints, internal finding/source/run IDs,
provenance, evidence references, raw kinds, the shadow-NHI projection, CT monitoring,
and drift details remain available through explicit evidence disclosures. This keeps
the first decision understandable while preserving the technical proof needed for an
audit or investigation. See [The web console](../web-console.md).

## Use it

The certificate inventory (F1) is live today. Drive it from the CLI:

```sh
# list certificates, newest first, paginated
trstctl-cli certificates list --limit 50

# list only certificates expiring within a window
trstctl-cli certificates list --expiring-before 720h

# show estate-wide expiry/source health, including imported and discovered certs
trstctl-cli certificates health

# ingest a certificate you already have (idempotent)
trstctl-cli certificates ingest -f ./server.pem
```

Those map to the served REST routes `GET /api/v1/certificates`,
`GET /api/v1/certificates/health`, and `POST /api/v1/certificates` (the latter
requires an `Idempotency-Key` header). For `certificates ingest`, `-f` accepts a
PEM certificate directly as shown above. To set an owner, deployment location,
or source during import, pass a JSON file with `pem`, `owner_id`,
`deployment_location`, and `source` fields instead. An import keeps the signed
certificate, recorded as an observation, so revocation health watches the CRL
and OCSP endpoints it names (including an AD CS LDAP distribution point covered
by an AD CS discovery source); importing a certificate trstctl issued updates its
provenance and never replaces the public chain trstctl retained. The CLI supplies a fresh
idempotency key for either form; repeat an exact request with the same explicit
key when recovering from an uncertain response.

Network discovery is live too:

```sh
cat > segment.json <<'JSON'
{"name":"edge","ranges":["10.0.0.0/24"],"staleness_hours":24,"excluded":false}
JSON
trstctl-cli discovery segments create -f segment.json

cat > source.json <<'JSON'
{"kind":"network","name":"edge-tls","config":{"segment":"edge","targets":["10.0.0.10:443"],"allow_rfc1918":true}}
JSON
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery sources list
trstctl-cli discovery sources preflight <source-id>

cat > run.json <<'JSON'
{"source_id":"<source-id>"}
JSON
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery runs get <run-id>
```

Copy the run ID from the start response. Read that exact run until its status is
`succeeded`. A `queued` or `running` response is still pending work; a `failed` run
requires inspecting its error and target results before retrying. Then read the
findings for that completed run:

```sh
trstctl-cli discovery findings list --run_id <run-id>
trstctl-cli nhi posture shadow
```

This example deliberately permits an owned RFC1918 target inside the declared
segment. Without `allow_rfc1918`, private IPv4 targets remain blocked. In the
console, select **Allow approved RFC1918 targets** for that same explicit scope.
This permission does not allow metadata, link-local, multicast, or other prohibited
addresses. A separate `allow_loopback` admits loopback targets (127.0.0.0/8, ::1)
for an authorized local diagnostic, such as a relay checking a listener on its own
host; it widens nothing else. Hostnames must be declared by their exact name; an IP-only segment does
not implicitly authorize a hostname that resolves into it. Preflight checks known
literal-address blockers without dialing; DNS and connectivity are checked by the
relay during the run.

The segment command maps to `POST /api/v1/discovery/segments`; declare that
bounded estate scope before creating any network or SSH source. The remaining
commands map to `POST|GET /api/v1/discovery/sources`,
`GET /api/v1/discovery/sources/{id}/preflight`,
`POST|GET /api/v1/discovery/schedules`, `POST|GET /api/v1/discovery/runs`,
`GET /api/v1/discovery/runs/{id}`, `POST /api/v1/discovery/runs/{id}/retry`,
`GET /api/v1/discovery/findings`,
`POST /api/v1/discovery/findings/{id}/claim`, and
`POST /api/v1/discovery/findings/{id}/dismiss`. The shadow posture command maps to
`GET /api/v1/nhi/posture/shadow`.

A discovery schedule name belongs to one schedule within a tenant. Retry a
lost create response with the same `Idempotency-Key` to recover that creation;
a separate create with the same name returns `409` before another event is
recorded. Use `GET /api/v1/discovery/schedules` to find the existing schedule.

Open **Discover → Schedules** to pause future scans, resume a paused schedule, or
retire it permanently after reviewing the exact schedule name. Pausing and retiring
leave prior runs and findings available. A stale scheduler decision is checked
again at run admission, so it cannot queue a new scheduled run after pause or
retirement. Retirement keeps the schedule visible as a tombstone and refuses
resume; create a new schedule with a new name if monitoring should start again.
The same controls are available through
`POST /api/v1/discovery/schedules/{id}/pause`, `/resume`, and `/retire` and the
`trstctl-cli discovery schedules` commands. `GET` on the schedule ID reads the
current state, including `retired_at`. Each mutation needs an `Idempotency-Key`;
retry the same key after a lost response to recover the original result.

To see enrolled agents that perform local discovery:

```sh
trstctl-cli agents list

# On an enrolled host, report public certificate files the agent can see.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:19443 \
  --server-name localhost \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs,/etc/pki/ca-trust/source/anchors \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-nss-trust-roots "$HOME/.pki/nssdb/exported-roots" \
  --inventory-browser-trust-roots "$HOME/.config/chromium/Default/exported-roots" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh

# Then read the projected discovery inventory and graph from the control plane.
trstctl-cli discovery findings list
trstctl-cli graph nodes
```

`--enroll-url` is the control-plane base URL, not `/enroll/bootstrap`; the agent
adds the endpoint. The console uses this same contract on Agents and in the setup
wizard. When the console itself is intentionally served from loopback HTTP for
local evaluation, its generated command adds
`--allow-insecure-loopback-enrollment`. The binary rechecks that the resolved
destination is loopback before every dial. Non-loopback HTTP remains refused.

When you find a credential you didn't expect, follow it into the
[credential graph](graph-query-ai.md) to see what it can reach, or into
[risk scoring](observability-and-risk.md) to see why it matters.

## Pitfalls & limits

Be precise about what runs in the server today versus what ships as tested library
code awaiting control-plane wiring (this matters for an honest evaluation — see also
[Current limitations](../limitations.md)):

| Capability                                                | Status today                                                                                                                                                                             |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Certificate inventory (F1)                                | **Served** — REST + CLI, event-sourced, with the `/api/v1/certificates/health` expiry/source dashboard                                                                                   |
| Network discovery (F2)                                    | **Served** — source/preview/preflight/schedule/run/finding APIs + CLI/UI; relay readiness is checked before admission, TLS scans execute through the outbox with reserved-IP SSRF filtering; runs report per-target outcomes, PostgreSQL listeners are negotiated (SSLRequest) before TLS, and repeat runs refresh findings instead of duplicating them |
| Agent-based discovery (F3)                                | **Served** — enrollment (`/enroll/bootstrap`, `/api/v1/agents`) and the mTLS `ReportInventory` path record source/run/finding rows and graph nodes                                       |
| SSH discovery (F42)                                       | **Served** — source/schedule/run/finding APIs + CLI/UI; host-key scans execute through the outbox, and on-host SSH/private-key inventory reports through the agent mTLS path             |
| Agentless cloud discovery (F49)                           | **Served** — AWS ACM, Azure Key Vault, and GCP Certificate Manager provider execution runs from the outbox with credential references; the shipped demo lab proves the AWS provider against its LocalStack emulator, and a run names each provider's outcome |
| Secret-store & API-key discovery (F35, F36)               | **Served for cloud secret managers** — AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and HashiCorp Vault KV imports; metadata-only references and fingerprints, never values; opt-in content inspection also finds the API keys, tokens, and private keys stored as secrets (masked, fingerprinted); the demo lab seeds a tagged certificate secret in LocalStack so the AWS collector is proven locally, and a partial run names the provider that failed |
| Cross-surface NHI discovery                               | **Served** — six-surface (IdP/cloud/SaaS/on-prem/code/CI) metadata-only findings                                                                                                         |
| Unified NHI inventory                                     | **Served** — `/api/v1/nhi/inventory` normalizes identities, certificates, tokens, agents, and findings across eleven kinds                                                               |
| Service-account discovery (CAP-NHI-03)                    | **Served** — AD/on-prem and cloud service-account findings                                                                                                                               |
| OAuth grant discovery + abuse detection (CAP-ITDR-03)     | **Served** — consent metadata findings, plus `oauth_grant_abuse` detections                                                                                                              |
| NHI behavior analytics                                    | **Served** — baseline and anomaly findings for IP, geo, user-agent, usage-spike, and off-hours signals                                                                                   |
| Compromised-credential detection (CAP-ITDR-02)            | **Served** — honeytoken/leak/replay signals normalized to findings tagged to OWASP NHI2                                                                                                  |
| Shadow/unmanaged NHI posture                              | **Served** — `/api/v1/nhi/posture/shadow`, `trstctl-cli nhi posture shadow`, and the Discovery console                                                                                   |
| Kubernetes Ingress/Gateway TLS auto-issuance (CAP-K8S-03) | **Served through an in-cluster agent** — bind a `k8s_ingress_gateway` source to the host-role agent running in the cluster (`cluster_agent_id`, `owner_id`, optional `verify_address`). Each run records every `Ingress`/`Gateway` TLS resource as a finding, keeps one `k8s_secret` destination and one certificate identity per TLS block, and queues the first issuance to that agent: it generates the key inside the cluster, sends only a CSR, writes the TLS Secret, reads it back and returns a signed receipt, so the control plane never generates the key. A resource reports `delivery_queued` until the agent's signed deploy receipt is recorded and `delivered` after; when the agent's latest attempt failed it reports `not_delivered` in the receipt's words while the job is retried. Renewals go to the same agent, and a TLS block with several hosts gets one certificate naming them all. A source without an agent, or with one that cannot deliver, reports each resource `not_delivered` with the reason and makes nothing ([Key custody](../custody.md), [Deliver into a Kubernetes Secret](deployment-connectors.md#deliver-into-a-kubernetes-secret-from-inside-the-cluster)) |

NHI policy compliance lives in [Policy & governance](policy-and-governance.md); CT-log
monitoring and drift detection live in [Observability & risk](observability-and-risk.md)
— all three read the same discovery projections, but they aren't this page's features.

Other gotchas: a network scan only sees what a host presents on a port at scan time —
pair it with agent-based discovery for the full picture. Cloud discovery needs
read-only credentials with list/get permission on the relevant service. Secret-store
discovery records _references_, so a finding tells you a secret exists and where, not
what it is.

## Reference

- **CLI groups:** the discovery-relevant commands live under `discovery`
  (`sources`, `schedules`, `runs`, `findings`, `ct-monitoring`, `drift-remediation`,
  `monitoring`), plus `certificates`, `agents`, and `nhi`. trstctl-cli has many more
  command groups outside discovery; `trstctl-cli <group> --help` lists the current
  subcommands for any of them.
- **Served routes:** `GET|POST /api/v1/certificates`, `GET /api/v1/certificates/{id}`,
  `GET|POST /api/v1/discovery/sources`, `GET /api/v1/discovery/sources/{id}/preflight`, `GET|POST /api/v1/discovery/schedules`,
  `GET /api/v1/discovery/schedules/{id}`, `POST /api/v1/discovery/schedules/{id}/pause|resume|retire`,
  `GET|POST /api/v1/discovery/runs`, `GET /api/v1/discovery/runs/{id}`,
  `POST /api/v1/discovery/runs/{id}/retry`,
  `GET /api/v1/discovery/findings`, `POST /api/v1/discovery/findings/{id}/claim`,
  `POST /api/v1/discovery/findings/{id}/dismiss`, `GET /api/v1/agents`,
  `GET /api/v1/nhi/posture/shadow`, `GET /api/v1/ownership/attribution`,
  `POST /api/v1/agents/enrollment-tokens`,
  `POST /api/v1/agents/{id}/offboard`,
  `GET /api/v1/graph`,
  `POST /enroll/bootstrap`.
- **Agent channel:** `AgentService.ReportInventory` over the mTLS agent gRPC listener
  when `agent_channel.enabled` is true.
- **Config:** `TRSTCTL_LIFECYCLE_RENEW_BEFORE` (default `720h`) sets the
  expiry window the inventory and lifecycle treat as "renew soon".
- **Served discovery source kinds:** `network`, `ssh_trust` (explicit agentless SSH trust through a pinned network relay; [setup and limits](ssh.md#agentless-trust-collection)), `cloud_certificate`,
  `cloud_secret`, `nhi_cross_surface`, `oauth_grant`, `service_account`,
  `nhi_behavior`, `credential_compromise`, `k8s_ingress_gateway`, `ct_log`, `drift`,
  `manual`, plus metadata-only `ssh`, `secret_store`, `api_key`, and `agent`.
- **Discovery source kinds (agent):** `filesystem`, `pkcs11`, `windows-store`,
  `k8s-secret`, `trust-store`, `private-key`.
- **Agent inventory flags:** `--inventory-cert-roots`, `--inventory-os-trust-roots`,
  `--inventory-java-trust-stores`, `--inventory-java-trust-store-password`,
  `--inventory-nss-trust-roots`, `--inventory-browser-trust-roots`,
  `--inventory-private-key-roots`, `--inventory-ssh-host-key-globs`,
  `--inventory-ssh-user-key-globs`, `--inventory-ssh-authorized-keys`,
  `--inventory-ssh-known-hosts`, `--inventory-ssh-sshd-configs`.
- **Audit events:** `certificate.recorded`, `discovery.source.upserted`,
  `discovery.schedule.upserted`, `discovery.schedule.paused`, `discovery.schedule.resumed`,
  `discovery.schedule.retired`, `discovery.run.queued`, `discovery.run.started`,
  `discovery.finding.recorded`, `discovery.run.completed`, `secretscan.finding`.

## See also

[Policy & governance](policy-and-governance.md) (ownership attribution's main consumer) ·
[Observability & risk](observability-and-risk.md) (scoring what you discover) ·
[Graph, query & AI](graph-query-ai.md) (what a credential can reach) ·
[Secrets](secrets.md) · [Current limitations](../limitations.md) ·
glossary: [certificate](../glossary.md), [fingerprint](../glossary.md),
[bulkhead](../glossary.md), [event sourcing](../glossary.md)

**Covers:** F1, F2, F3, F42, F49, F35, F36


### Read an AD CS CA database

The Posture page's AD CS certificate database panel shows each CA's
certificates by disposition: issued, pending a CA manager's approval, revoked,
denied and failed. **Read with certutil** asks one domain-joined network relay
to read a CA by certsrv's `HOST\CA-Name` identifier. The relay runs certutil as
its own domain identity and returns the counts and, for the requests the CA holds
for a manager's approval, each one's request id, template, requested name and
requester (the newest 500, N1-L2). No certificate, and no issued, revoked, denied or
failed row's subject or requester, leaves it. A database too large for one certutil
read (64 MiB of output) is read in pages of request ids and summarized the same way, up to
a million rows. The panel lists recent reads with their status (queued,
running, collected, failed) and a failed read's reason; a failed read keeps the
previous counts. Run the relay on a domain-joined Windows host with
`--relay-claim` (certutil is `certutil.exe` unless `--adcs-certutil` names
another path) and enable `adcs.ca_database` in
`agent_channel.claimable_job_kinds`. Automation uses `POST
/api/v1/adcs/ca-database/collect` with `ca_config` and `relay_agent_id`
(`discovery:write`) or `trstctl adcs ca-database collect -f read.json`, and
`GET /api/v1/adcs/ca-database` for the counts and reads.

### Modernize an AD CS template

Each row of the AD CS template grid has a **Modernize** action. Its effect-free
preview shows the trstctl profile the template becomes and every property it
leaves behind: names are confined to the template's DNS domain, so the requester
no longer supplies the subject (an ESC1-prone template stops being an
impersonation primitive), Any Purpose, Smart Card Logon, PKINIT and Certificate
Request Agent usages are removed, manager approval becomes the profile's dual
control, and certificates are valid for 90 days. **Create profile** makes it
through the normal profile path; a profile that already has the name is refused.
The domain comes from the publishing CA's observed DNS name unless you name a
`dns_suffix`. Automation uses `POST /api/v1/posture/adcs/templates/modernize/preview`
and `POST /api/v1/posture/adcs/templates/modernize` (`profiles:write`), or
`trstctl posture adcs modernize-preview -f req.json` and `... modernize -f req.json`.
To keep issuing at AD CS behind the new profile's checks, set the profile's
`upstream_external_ca` to an `adcs` external CA.

### Nested AD CS enrollment links

Discovery’s AD CS source wizard can opt into read-only nested group reads. Select
an upgraded network relay, enable **Read nested enrollment groups**, and provide
the explicit membership domain naming context. Preview checks both the server’s
job allowlist and that relay’s fresh enabled executor census. Posture displays
the observed users/computers, canonical SIDs, security-group paths, trustee,
observation time and completeness. An incomplete or refused read gives a recovery
action and no verified member list. This does not evaluate a full Windows token
or authorize issuance. The default direct-ACL reader stays available.

The [nested enrollment runbook](../guides/adcs-nested-enrollment.md) includes exact
source JSON, CLI operations, bounds, matching-rule verification and the Windows
forest proof boundary. The focused served journey exercises real Samba AD,
vaulted single-attempt credentials, mTLS signed results, immutable projections,
CLI readback, tenant isolation and replay. The final image/browser/restart
qualification follows the release replay.


### AD CS enrollment endpoint candidates

The AD CS source wizard can opt into fixed-path probes derived from directory
hostnames. Enable **Probe enrollment paths from directory hostnames**, select an
upgraded network relay and enter explicit DNS suffixes. Preview checks the relay
capability without contacting LDAP. Candidate counts become known during the
queued directory read; private destinations need an additional approved CIDR grant.

Posture shows configured, LDAP-derived and deduplicated combined origins, the
latest page's total and offsets, per-service coverage and unattempted outcomes.
The next run advances the retained cursor. Empty endpoints on a different page
mean unassessed, and unreachable endpoints remain unverified. Findings and
compliance evidence carry those limits; HTTP reachability does not prove IIS
Extended Protection or successful SCEP enrollment. The service-view ceiling is
visible when reached. The [endpoint probing runbook](../guides/adcs-endpoint-probing.md)
explains exact configuration, bounds and recovery. Windows IIS/NDES qualification
requires the Windows environment; a private Samba/HTTP/TLS fixture is separate proof.


### Switching from another certificate-management product (A265)

Moving to trstctl from another certificate-management product starts with that
product's inventory export, not with re-typing it. The switching kit reads the
export as data: CSV with a header row, or JSON (an array, or an object with a
`certificates` array), in the `trstctl.switching-export/v1` field set —
`certificate_pem` or `fingerprint_sha256`, `common_name`, `sans`, `serial`,
`issuer`, `not_after`, `folder` (a path such as `Root\Region\Team`),
`application`, `owner_email`, `owner_name`, `renewal_window_days`,
`key_algorithm` and `endpoints` (`host:port`, comma-separated). A column map
renames the export's own column names, so nothing about the other product is
ever needed: `{"Thumbprint": "fingerprint_sha256", "Valid To": "not_after"}`.

**Preview changes nothing.** Every row gets exactly one outcome — `mapped`,
`mapped_with_gaps` (each gap named: no owner, no application, no folder policy,
no endpoint, a folder with conflicting renewal settings), `duplicate` (naming
the first row with the same certificate), `unparseable` (with the reason) or
`expired`. Folders become profile proposals with their renewal window and key
algorithm; owners are matched per email in each application group (A244 groups
an owner's certificates by application) or proposed; rows whose certificate is
already in the inventory are marked. The report ends in a digest over every
row, the column map, the owners and the inventory as they were.

**Apply records exactly what was reviewed.** `POST /api/v1/switching/imports`
with the preview's digest refuses a changed export, column map, owner list or
inventory (409), records the import and every row's outcome, and the leader
then records each mapped row's certificate and owner in bounded batches of 500,
so a 50,000-row export (the limit, with 20 MiB) never holds one request open.
A certificate already in the inventory is linked to its row and left exactly as
it was. Imported certificates carry the source `switching:<import>` and no
issuance key, so they are watch-only: the other product keeps renewing them
and trstctl never queues their renewal. The import completes only when every
recorded row is applied; an apply retried with the same `Idempotency-Key`
resumes the same import rather than starting another.

```bash
trstctl-cli switching import preview --file export.csv --column-map map.json
trstctl-cli switching import apply --file export.csv --column-map map.json \
  --name "region rollout" --digest sha256:<digest from the preview>
trstctl-cli switching imports rows <import-id> --outcome unparseable
```

`GET /api/v1/switching/imports/{id}/rows` pages every row in export order with
its outcome, reason, gaps and the certificate and owner it became, so nothing
is dropped silently. A CSV row is numbered by the line it starts on (the header
is line 1); a JSON row by its position from 1.

**Side by side: every imported certificate is matched to its endpoint or
flagged.** `POST /api/v1/switching/imports/{id}/watch` (`trstctl-cli switching
imports watch <id> -f grant.json`) starts a watch round on a completed import.
The leader reads what each mapped row's endpoints serve with the same TLS
handshake discovery uses, from the control plane and under its egress rules:
public addresses only, unless the request grants private ranges
(`{"allow_private_endpoint": true, "private_egress_cidrs": ["10.20.0.0/16"]}`).
Every row ends the round with one status — `matched` (every endpoint serves the
imported certificate), `serves_other` (an endpoint serves another certificate;
its fingerprint is recorded, so a renewal the other product made shows up),
`unreachable` (with the reason) or `no_endpoint`. The import's `watch` block
counts them, `rows?watch_status=serves_other` lists them, and the leader starts
the next round itself a day after the last, with the same grant. Rounds run
eight handshakes at a time with a five-second timeout.

**Renewals move over in waves, each with its own rollback.** A wave assigns
imported rows to the deployment targets their replacements go to (a target
carries one active identity, as everywhere in trstctl). `POST
/api/v1/switching/imports/{id}/waves/preview` changes nothing: it lists the rows
the wave moves, the identity each gets — one per imported row, derived from the
import and the row, so no row ever has two — and every assigned row it leaves
out with the reason: not mapped, already in the inventory before the import, no
owner, already in a live wave, a target already carrying another identity, a
name trstctl already manages, or names the replacement would drop (trstctl
issues for the identity's name, so a certificate with more names is left to
the other product rather than narrowed). It also lists the fingerprints the
other product must stop renewing. `POST .../waves` with the preview's digest
binds each identity to its target and issues it through the ordinary
transition — its approval gate and profile policy included — and the deploy
and every later renewal follow the identity's lifecycle. Imported certificates
outside a wave are never renewal candidates; a wave row's endpoint serving a
certificate neither the export nor trstctl issued is flagged
`renewed_by_other_product` by the watch, and one serving trstctl's is
`serves_trstctl`. `POST /api/v1/switching/waves/{id}/rollback` refuses while
any issuance or renewal of the wave is in flight (nothing changes), then
withdraws its queued deploys, pauses each identity's renewal on its target and
returns the rows to watch-only; the receipt lists what trstctl issued. A later
wave that moves the row again finds the same identity and resumes it.

```bash
trstctl-cli switching waves preview <import-id> -f wave.json   # {"name": "...", "assignments": [{"row_number": 2, "target_id": "..."}]}
trstctl-cli switching waves cut-over <import-id> -f wave.json  # the same file with "preview_digest"
trstctl-cli switching waves rollback <wave-id> -f reason.json  # {"reason": "..."}
```

Status: served.

## Cloud machine entitlements

Use **Cloud machine entitlements** in Discover → Sources to inspect an AWS user
or role that a workload already uses. The source reads IAM policy and key
metadata, evaluates the exact action/resource/context you select, and compares
that check with explicitly scoped recorded activity. It serves read-only AWS
capture and advisory findings, plus the reviewed AWS changes below. Native
GCP/Azure collection is a separate capability.

An operator first approves an environment reference whose value is the absolute
path to an owner-only standard AWS STS JSON response file. Configure that reference
in the source, for example `env:TRSTCTL_AWS_READER_SESSION_PATH`. The environment
value is a path, and the file holds the short-lived credential. Refresh the file
atomically before expiration. Shared, expired, oversized or missing files fail the
run. The source never accepts a secret access key in its configuration.

Select the workload IAM name and exact principal ARN, permission action, resource
ARN and resource owner account. Leave condition-context completeness unchecked
when any relevant key is unknown. Review the server's exact plan, save the source,
and run it. The current console form configures one principal/check; the API and
CLI accept up to 256 selected principals and 128 exact checks. User group policies,
managed-policy versions, boundaries, role trust, key age and key last-use facts
come from IAM reads. An identity with a failed policy/group/key read is not
published as a complete capture.

Organization and resource policies unavailable from these IAM reads stay
unavailable. Optional recorded policy evidence carries a `recorded:` source
reference, exact principal/resource/account scope and explicit category coverage.
A verified absence differs from an unread category. Recorded activity specifies
its source, start/end window, exact covered principal/action/resource scopes and
normalized events. Its completeness is an operator declaration, not proof that
CloudTrail captured every action. Missing coverage cannot justify an unused
permission; a same-action event without resource identity also prevents that
claim. No raw CloudTrail request/response bodies enter the findings.

Each finding retains its scoped evaluation inputs and a source-input digest, so
later source edits cannot replace its recorded policy/activity evidence. Findings
report permission decisions with source/statement reasons, unused checks
within the declared covered window, and active keys unused for at least 90 days.
Keys at least 90 days old are separately marked long-lived. Self-escalation entries
are policy candidates requiring further trust, attachment and native authority
checks. None of these findings authorizes a cloud mutation.

The access graph uses the latest verified native-run snapshot per principal.
Allowed checks create `policy_model` evidence edges for active keys or a role's
policy authority, with the exact finding and check in their provenance. These are
conditional policy models, not proof that every requirement of a live AWS API
call is satisfied. A later denied check removes the previous modeled grant.
Models older than 24 hours contribute no grant edges. Manual findings cannot
manufacture native edges. Generated access reviews preserve this model provenance
and the graph's coverage statement.

The same workflow is available through the existing CLI commands:

```sh
trstctl discovery sources create -f source.json
trstctl discovery sources preflight SOURCE_ID
trstctl discovery runs start -f run.json
trstctl discovery findings list --run_id RUN_ID
```

`source.json` contains `kind`, `name` and `config`; `run.json` contains
`{"source_id":"SOURCE_ID"}`. Requests use the CLI's configured authentication and
idempotency key. The REST routes are `/api/v1/discovery/sources`,
`/api/v1/discovery/runs` and `/api/v1/discovery/findings?run_id=RUN_ID`.
Read the [capture and evaluation contract](../design/cloud-machine-entitlements.md)
for exact limits and the cached LocalStack lab runner. LocalStack native metadata
proof does not establish AWS permission enforcement or live cloud qualification.


### Propose and execute one reviewed AWS change

Open a native cloud machine finding in Discovery. Its permission table shows the
server's decision, policy reasons, activity coverage, and known limits. The change
wizard selects a captured key or one unused exact permission, records a writer STS
file reference and workload-impact reason, and shows the exact proposal. Open
Approvals to inspect the same intent and obtain distinct human reviews. Return to
the finding to queue the approved change and observe its native postcondition.

For automation, write a public proposal body to a file (never credential values):

```json
{"finding_id":"<finding UUID>","action":"revoke_key","access_key_id":"<captured key ID>","writer_session_file_ref":"env:TRSTCTL_AWS_WRITER_SESSION_PATH","reason":"Workload replacement verified; retire this exact key","required_approvals":2}
```

Use `trstctl access cloud changes propose --file proposal.json`,
`trstctl access cloud changes list`, and `trstctl access cloud changes get <id>`.
Approve the returned approval request and exact digest through the existing
approval commands or console. Then run
`trstctl access cloud changes execute <id>`. Execution queues an outbox command;
read the change again for its final result. A failed request can have an uncertain
native effect: rescan before proposing recovery. A verified deletion does not
supply replacement credentials or prove that a workload remains healthy.

To propose policy tightening, use `action: "tighten_policy"` and the zero-based
`evaluation_index` of a captured unused exact permission. Review the returned
public policy document (base64 in `intent.policy_document`) and SHA-256 before
approval. It adds an explicit Deny in all contexts and preserves existing policies.

### Bind temporary replacement to an authenticated consumer

The API and CLI also accept `replace_key`. Capture both the existing IAM user and
the intended IAM role, with an explicit permission check for each. The role must
be in the same AWS account and match an allowed role of an operator-configured
`aws-sts` provider. Seed the application secret under that provider role's friendly
name before proposing replacement. The proposal needs `access:write`,
`discovery:read`, permission to read and write that secret, and private-egress
permission for private sources.

```json
{"finding_id":"<user finding UUID>","action":"replace_key","access_key_id":"<captured key ID>","replacement_role_finding_id":"<role finding UUID>","replacement_provider_id":"workload-sts","replacement_role":"orders","ttl_seconds":900,"consumer":"orders-agent","consumer_subject":"<authenticated workload subject>","writer_session_file_ref":"env:TRSTCTL_AWS_WRITER_SESSION_PATH","reason":"Verify the temporary session before retiring this exact key","required_approvals":2}
```

Use `trstctl access cloud changes propose --file replacement.json`, inspect the
returned exact intent, approve its digest through the human approval queue, and
execute it with the same requester. The intent freezes both native identities,
role authority, source configurations, provider revision, current secret version,
consumer and actual authentication subject. Native role or policy drift blocks
retirement. A provider restart requires a new approval.

`preparing_replacement` means the durable child command is issuing, publishing and
checking the temporary session. `waiting_adoption` names the exact next secret
version that the named subject must report verified through
`POST /api/v1/secrets/deliveries`. Reading or injecting a value alone does not
satisfy that gate. Another subject or version cannot authorize retirement, and a
later injected report cannot change the author of an earlier verified receipt.
The public `adoption` receipt names its immutable source event. The existing agent
renderer can produce verified reports after its application probe succeeds.

Only then does the worker delete the captured old key and read its native absence
back. Expiry, missing adoption, failed publication or drift preserves retirement
and reports the failure. A receipt from an authenticated reporter is evidence of
that reporter's assertion; independently verify a real workload and its ongoing
refresh. The current API path does not itself prove workload continuity, automatic
renewal, live AWS enforcement or GCP/Azure qualification.


To replace a captured permanent AWS key in the console, select **Replace key
with temporary role credentials** in its finding. Choose a configured ready STS
provider, its role alias, and the captured native IAM role in the same account.
Set the consumer name and exact authenticated workload subject, session lifetime,
reference-only writer binding, reason, and approval count. The final review shows
the full request before it creates the approval. The server freezes and rechecks
the exact role, provider revision, source and key; selecting an alias does not
permit a different role to slip through.

The proposed change includes public agent renderer settings. Add them to the
workload's existing renderer configuration, set its private file destination and
resource-check probe, and use the token for the approved subject. The renderer
waits for approved publication, checks the exact session, and reports adoption
after the resource probe passes. The old key remains until that report is accepted
and native readback confirms deletion. Session refresh then follows the renderer
lease loop. The console loads at most 2,000 captured findings for this selector
and refuses a partial catalog; larger captures can use the documented API/CLI.
Native AWS authorization and revoked-signature rejection remain live-cloud proof.


### GCP workload identity inventory

Select **GCP workload identities** when creating a discovery source. Enter the
project ID, 1–64 selected service-account emails, and an operator-approved
`env:` reference to a private raw OAuth access-token file. Review the exact plan
before saving and running it. Optional audit lookback is 1–90 days; 0 disables
that read. Custom origins, public CA PEM and explicitly approved private CIDRs
are available for private endpoints and test environments. Token values and
arbitrary host paths cannot be supplied by a tenant.

The reader needs `iam.serviceAccounts.get`, `iam.serviceAccountKeys.list`,
`iam.serviceAccounts.getIamPolicy`, `resourcemanager.projects.getIamPolicy`, and
`iam.roles.get` on the selected scope. Audit observations also need the applicable
Cloud Logging read permission. Use a suitable OAuth scope such as
`cloud-platform` with those restricted IAM permissions; a broad OAuth scope does
not grant IAM permissions by itself. The operator refreshes the private token
file before it expires. An expired or unreadable token produces a failed/partial
run with explicit coverage gaps, rather than a successful empty inventory.

The collector requests only the required public metadata fields, excluding audit request/response contents and key material. It reads account identity and disabled state, user-managed key dates,
account trust/delegation policy, project role bindings and referenced role
permissions. CEL conditions remain visible and are not evaluated. A key at least
90 days old is marked long-lived. Audit reads retain successful observed use for
the exact account/key in the configured window. Service coverage, retention and
omitted key names prevent proof that an unobserved key was unused; actual last
use remains unknown where it cannot be observed.

The finding view shows dates, policy conditions, trust and coverage limits. NHI
inventory classifies the account as a service account; the graph shows native key
ownership and project role bindings. It creates no effective-access grant from
this partial policy scope. Organization/folder/resource inheritance, deny policies
and principal-access boundaries are not evaluated. The AWS effective-permission
evaluator and reviewed native changes remain separately identified.

These reads follow the official [service-account IAM policy API](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/getIamPolicy),
[project IAM policy API](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy),
[key metadata API](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list),
and [Cloud Logging entries API](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list).
Local API-shaped fixtures prove the product path and tenant/replay boundaries;
OAuth permissions and native behavior in a live GCP account remain Track B proof.

### Azure workload identity inventory

Select **Azure workload identities** in Discover → Sources, or create a discovery
source with kind `azure_machine_identity` through the existing API/CLI. Supply an
Azure tenant UUID, subscription UUID, 1–64 service-principal **object** UUIDs and
separate `graph_token_file_ref` / `arm_token_file_ref` values. Each is an
operator-approved `env:NAME` whose value names an owner-only file containing a raw
access token for that API's audience. Tokens are never source configuration values.
The operator refreshes these files before their short-lived tokens expire.

Graph needs organization ID visibility (`Organization.Read.All` for application
access), service-principal/application visibility (`Application.Read.All`) and
consent appropriate to the tenant. ARM needs subscription read plus
`Microsoft.Authorization/roleAssignments/read` and `roleDefinitions/read` on the
intended scopes. trstctl checks Graph's organization ID and ARM's native subscription
ID/tenant ID before collecting identities. Wrong or unreadable tenant bindings fail
closed. App-registration federation may be unreadable when the application belongs
to another tenant; that gap stays visible.

The collector reads public credential IDs and creation/expiry dates, app-role
assignments and referenced resource definitions, application federation and
subscription RBAC assignments/role definitions. It retains RBAC conditions and
`notActions`, `dataActions` and `notDataActions`. It discards password hints,
`secretText`, key bytes and unrecognized response fields. It never creates or
deletes credentials. A credential at least 90 days old is labeled long-lived;
absence of a recorded sign-in never means the credential is unused.

Graph principals with native type `ManagedIdentity` are captured explicitly. An
optional `managed_identity_resources` object maps selected principal UUIDs to exact
user-assigned identity ARM IDs. trstctl verifies the resource's principal, tenant
and client IDs before retaining its linkage and federation. Reading this path
requires `Microsoft.ManagedIdentity/userAssignedIdentities/read` and its
`federatedIdentityCredentials/read` operation. System-assigned resource linkage,
Windows/Azure runtime behavior and live tenant qualification remain outside this
capture proof.

Workload sign-in reads are off by default. To enable the **beta** Graph API, set
`read_beta_signins: true` and `activity_lookback_days: 1..30`; the console presents
this opt-in explicitly. Audit access requires the applicable Graph audit permissions
and tenant licensing/retention. The collector filters service-principal/managed
identity event types, verifies native principal/application IDs and successful
status, and binds observed use only to the exact credential key ID. Beta APIs are
subject to change. Missing events, permissions or key IDs leave last use unknown.

The setup form previews the exact selected scope. Findings show public dates,
roles, trust metadata and coverage. Graph/NHI retain observed ownership and role
bindings; they create no effective-access grant from Azure metadata. PIM activation,
deny assignments, inherited guards, resource constraints and conditional-access
evaluation remain unknown. The native AWS policy evaluator and reviewed AWS
remediation are separate workflows.

Origins default to `https://graph.microsoft.com` and
`https://management.azure.com`. Custom origins need the existing private-egress
permission/explicit CIDRs when private, with public CA PEM if needed; hostname
verification remains required. Plaintext is limited to explicitly approved loopback
fixtures. Redirects, cross-origin/path-changing cursors and cursor changes to the
original filter/selection are refused. Captures bound calls, identities, pages,
response bytes and event size. A partial read reports partial coverage rather than
asserting tenant-wide completeness. Local served proofs use native API-shaped
fixtures with real PostgreSQL/NATS; they do not qualify a live Azure tenant.

Native API references: [service principal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0),
[application federation](https://learn.microsoft.com/en-us/graph/api/application-list-federatedidentitycredentials?view=graph-rest-1.0),
[subscription](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01),
[RBAC assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-rest),
[beta workload sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta).
