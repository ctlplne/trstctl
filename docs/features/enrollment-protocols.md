# Enrollment protocols — how existing devices ask for certificates

## What it is

"Enrollment" is the moment a device asks a [CA](../glossary.md) for a
[certificate](../glossary.md) and gets one back. [ACME](acme-and-dns.md) is the modern
way, but the world is full of routers, switches, printers, phones, factory controllers,
and 5G base stations that already speak *older* protocols baked into their firmware.
trstctl serves those too — [EST](../glossary.md), [SCEP](../glossary.md), and
[CMP](../glossary.md) — plus a tiny client for constrained IoT devices and an
integration so mobile-device-management (MDM) platforms can enroll managed phones and
laptops.

The point: you shouldn't have to re-flash a million devices to bring them under
trstctl. If a device can already enroll over EST, SCEP, or CMP, it can enroll against
trstctl unchanged.

## Why it exists

Every certificate eventually expires, so every device needs a repeatable way to renew
without a human visiting it. Different industries standardized on different
protocols: enterprise/IoT gear speaks EST, network and mobile-device management speaks
SCEP, telecom and industrial systems speak CMP. Supporting all three lets trstctl
become the issuing authority for an existing fleet on day one, instead of being
limited to greenfield ACME-aware workloads.

## How it works

All three protocol servers share the same trstctl spine: each parses its protocol's
request format through the isolated cryptography path, authenticates the caller, then
hands the [CSR](../glossary.md) to the same issuance path every other feature uses —
with an `Idempotency-Key` so a retry never mints twice, the [outbox](../glossary.md)
delivering calls at-least-once, and an immutable audit event for every allow/deny/shed
decision. Each runs in its own bounded, bulkheaded [lane](../glossary.md) and sheds
load with HTTP 503 when saturated, so an enrollment storm can't starve the rest of
the system.

### EST (F22) — the modern enrollment protocol

EST (RFC 7030) is a small set of HTTPS endpoints under `/.well-known/est/...`: a client
fetches the CA chain from `/cacerts` (no auth, to bootstrap trust), then POSTs a CSR to
`/simpleenroll` (first time) or `/simplereenroll` (renewal) for a PKCS#7-wrapped
certificate. trstctl implements all four endpoints (including `/csrattrs`),
authenticates via an injected authenticator, caps request bodies, verifies the CSR's
self-signature, and honors an `Idempotency-Key` header (or one derived from the CSR)
so a retry never mints twice. The served tenant route accepts scoped API tokens and
answers an unauthenticated enrollment with `WWW-Authenticate: Bearer realm="est",
scope="certs:request"`. Invalid tokens receive RFC 6750 `invalid_token`; recognized
tokens without enrollment scope receive `insufficient_scope`. A Basic-authenticator
deployment still advertises Basic because the authenticator, not the EST handler,
owns the challenge.

#### Device TLS floor

The served listener negotiates TLS 1.3 only. Many device enrollment stacks cap at
TLS 1.2 — cisco libest's `estclient` does (`SSL_CTX_set_max_proto_version(TLS1_2_VERSION)`)
— and such a client fails the handshake with a `protocol version` alert before EST
starts. For those fleets set `TRSTCTL_SERVER_TLS_MIN_VERSION=1.2`; the listener then
offers TLS 1.2 with AEAD suites only and still prefers TLS 1.3 for capable clients.
Found by the cold design-partner run 20260906t143500z (DP2-036).

#### Check EST safely from the console

Open **Certificates → Enrollment methods**, expand **Set up and operate
methods**, and use **EST connection check** before connecting a real device.
The screen previews and then runs three same-origin checks:

1. `GET /.well-known/est/cacerts` must return a structurally valid, base64
   PKCS#7 CA chain.
2. `GET /.well-known/est/csrattrs` must return the server's CSR rules. trstctl's
   default “no extra attributes” answer is HTTP 204 and is valid.
3. `POST /.well-known/est/simpleenroll` deliberately sends no credentials and
   no body. It passes only when the server refuses it with HTTP 401 and the
   expected Bearer challenge.

The third request is a security negative control, not an enrollment attempt.
The browser omits session cookies, authorization, CSR bytes, and private-key
material. The workflow cannot issue a certificate. If any row fails, keep the
authentication requirement in place, repair the named responder, tenant, CA,
or signer configuration, and run the same check again. A real EST client still
creates and protects its private key locally, sends its CSR with a scoped
bootstrap token, and keeps the idempotency key for safe retries.

EST also serves the C3 parity extensions: EST `/serverkeygen` (when a profile opts in)
has the signer generate the key, returning the certificate plus encrypted private key
material as CMS EnvelopedData, with the raw key never entering logs or audit events.
RFC 9266 channel binding via `tls-server-end-point` binds a CSR to the server TLS
certificate so a relayed enrollment fails closed. Profiles can split by per-profile
PathID under `/.well-known/est/<PathID>/...`, with a separate mTLS sibling route under
`/.well-known/est-mtls/<PathID>/...` for 802.1X/Wi-Fi bootstrap, plus per-IP and
per-principal rate limits.

### SCEP (F23) — the one network and MDM gear still speaks

SCEP (RFC 8894) is ancient but ubiquitous in routers, printers, and mobile-device
management, wrapping requests in CMS (signed, encrypted ASN.1 envelopes). trstctl
advertises capabilities at `GetCACaps`, returns the chain at `GetCACert`, and on
`PKIOperation` decrypts the envelope and extracts the CSR — all through the isolated
cryptography path, with the SCEP transaction ID as the idempotency key. The SCEP
**RA transport key** is deliberately separate from the platform CA signing key and
never enters the isolated signing service: it's sealed at rest under
`protocols.ra_key_file` and shared across replicas, so a device that cached `GetCACert`
material can still enroll after a restart or rolling deploy.

When that RA is separate, `GetCACert` is an `application/x-x509-ca-ra-cert` bundle,
not one misleadingly named certificate. The required stock `sscep` gate accepts its
numbered output files in either order, identifies the exact public issuing CA by
certificate fingerprint and constraints, uses the remaining signing certificate as
the protocol RA for `PKIOperation`, and archives both public certificates beside the
request and response transcript.

SCEP also has per-profile SCEP RA material (distinct RA certificates and keys per
profile, same issuance path), a per-device rate limiter capping repeated attempts, and
a challenge hook that can require an MDM-issued challenge before any CSR is signed.
Routes `/scep`, `/scep/pkiclient.exe`.

#### Check SCEP safely from the console

Open **Certificates → Enrollment methods**, expand **Set up and operate
methods**, and use **SCEP connection check** before connecting a real device or
MDM profile. The screen shows the exact plan before it makes three same-origin
requests:

1. `GET /scep?operation=GetCACaps` must return HTTP 200, `text/plain`, and
   advertise `POSTPKIOperation`, `SHA-256`, and `SCEPStandard`.
2. `GET /scep?operation=GetCACert` must return HTTP 200 and a structurally valid
   DER CA certificate or CA/RA bundle with the matching SCEP media type.
3. `POST /scep?operation=PKIOperation` deliberately sends no body, browser
   session, authorization header, challenge, CSR, or private-key material. It
   passes only when the responder returns the exact fail-closed HTTP 400 empty
   message response.

The third request is a broken-input control, not an enrollment attempt. If it
ever succeeds, the whole check is red. The workflow cannot issue a certificate.
If a row fails, keep the MDM challenge gate and CMS validation strict, repair
the named responder, CA/RA, or signer configuration, and run the same check
again. A real SCEP device still creates and protects its private key locally,
then sends a CMS-wrapped CSR with an approved, short-lived MDM challenge.

### CMP (F55) — for telecom and industrial PKI

CMP (RFC 4210, over HTTP per RFC 6712) is common in 5G and industrial systems. trstctl
serves the `p10cr` flow at `POST /cmp`: it reads the DER PKIMessage, extracts the
transaction ID and CSR through the isolated cryptography path, and returns a signed
`pkixcmp` response. As with SCEP, the CMP protection key is the sealed
`protocols.ra_key_file` transport identity, distinct from the CA key in the isolated
signing service. The certificate that protects a client PKIMessage must chain to
`protocols.cmp_client_trust_anchor_file`. By default, the CSR may request only names
already asserted by that authenticated protection certificate. Third-party
registration-authority enrollment is possible only when
`protocols.cmp_allow_ra_enrollment` is explicitly enabled.

#### Check CMP safely before connecting a client

Open **Certificates → Enrollment methods**, expand **Set up and operate methods**,
then find **CMP readiness check**. Before any request, the page explains the four
groups it will inspect: endpoint and tenant, protection identity and trust, issuing
profile and isolated signer, and bounded worker capacity.

Choosing **Run safe CMP check** calls the authenticated, tenant-scoped
`POST /api/v1/protocols/cmp/qualification` endpoint. This is a read-only POST because
it asks the running process to assemble one answer from its in-memory mount state. It
does **not** query the database, call a network target or signer, append an event,
enqueue an outbox row, or create, parse, transmit, or retain a CSR, PKIMessage,
certificate, protection credential, or private key. The response contains eight
named gates, exact recovery for every red gate, and three empty effect lists. The
same check is available to automation:

```sh
trstctl protocols cmp qualify
```

A green readiness check is not a pretend enrollment. The final wire proof still
comes from a real CMP client that owns its private key. The console provides this
copy-safe OpenSSL `p10cr` handoff:

```sh
openssl cmp -config "" -cmd p10cr \
  -server https://trstctl.example.test -path /cmp \
  -csr device.csr \
  -cert cmp-client.pem -key cmp-client.key -extracerts cmp-client.pem \
  -srvcert cmp-ra.pem -ignore_keyusage -disable_confirm \
  -certout device.pem -reqout request.der -rspout response.der \
  -batch -verbosity 7
```

The client and RA files stay on the operator's machine; they are never pasted into
the browser. A refused request creates only a bounded, tenant-scoped diagnostic
receipt. When the server knows the exact branch, it distinguishes a rejected
protection certificate, a CSR/name binding violation, and a full local worker pool.
When it cannot safely tell whether policy, signer, persistence, parsing, or response
encoding failed, it says **unknown** instead of guessing. Repair the named gate and
run the identical safe check again before retrying the same CMP transaction.

### The embedded / IoT enrollment agent (F54)

The smallest devices can't run a Go agent, so trstctl ships two pieces: a
control-plane enrollment authority issuing single-use bootstrap tokens and signing the
device's first [mTLS](../glossary.md) certificate (the device keeps its own private
key, sending only a CSR), and a POSIX C client (`est_client.c`) needing only libc and
`openssl` — small enough for constrained hardware, compiled and run against a real EST
server by the test suite. A bootstrap token is checked-and-deleted atomically, so it
works exactly once.

**Status:** the running control plane mounts **`POST /enroll/bootstrap`** on the
control-plane HTTPS listener and, when `agent_channel.enabled`, serves
**`POST /enroll/renewal`** on a dedicated agent-CA mTLS HTTPS listener
(`agent_channel.http_renewal_addr`, default `:9444`). Bootstrap consumes the one-time
token. Renewal accepts only a verified client certificate from the current agent
identity, rejects missing or expired peer certificates, and signs a fresh CSR without
ever receiving the device's private key. The steady-state agent channel is also served
when `agent_channel.enabled`, so larger agents can renew over mTLS gRPC while embedded
clients use the HTTP renewal surface.

#### Enroll one machine from the console

Open **Workloads & Machines → Agents → Add agent**. The workflow is deliberately
split into two steps:

1. Choose the exact machine identity and certificate role, then select **Review exact
   enrollment plan**. This preview is effect-free: it creates no token and contacts no
   machine. It shows the public agent address, the TLS name the machine must verify,
   `POST /enroll/renewal`, and that renewal requires the machine's current verified
   certificate over mTLS.
2. Select **Mint one-time token** only when the preview says the whole lifecycle is
   ready. The server refuses this mutation too—not just the preview—if the public
   address, TLS name, or verified-mTLS renewal listener is unavailable. The token is
   shown once and is never saved in browser storage. The machine creates its private
   key locally; trstctl receives only its CSR.

If setup fails, dismiss the token, review the current plan again, and mint one
replacement. A lost, expired, or already-used token cannot be recovered. If a machine
that enrolled successfully is no longer trusted, revoke its current certificate or
offboard it from **Agents** before enrolling a replacement. Headless operators use
`trstctl agents enroll-token-preview` before `trstctl agents enroll-token`; the same
server-owned blockers protect both console and direct API mutation.

### Intune / MDM enrollment (F56)

When a mobile-device-management platform (Microsoft Intune, JAMF) pushes a SCEP
profile to a managed phone, you want only MDM-provisioned devices to enroll, not
anyone who can reach the SCEP endpoint. trstctl's MDM integration issues a stateless,
HMAC-signed challenge token the MDM embeds in the device's SCEP profile
`challengePassword`; the SCEP server validates it (constant-time MAC check, expiry)
before issuing, fail-closed on any defect. The HMAC key is the only shared secret — no
database lookup on the hot path — and is held in wipeable `[]byte` memory, zeroed
after use, never a copyable string.

For Microsoft Intune, trstctl validates the Intune JWS challenge against policy-backed
trust anchors, checks tenant and CSR subject/SAN binding, and consumes the nonce
through a single-use replay cache for the token TTL, so a captured challenge can't be
replayed. The gate wires into the served SCEP server's challenge hook.

The **Protocols → Intune / MDM SCEP policies** section handles the first policy as
well as later edits. Its three short steps ask: which MDM and certificate profile,
how the device proves it came from that MDM, and what the server will do. The last
step is not a browser estimate. It calls the effect-free server preview and shows
the normalized provider, profile, challenge check, reference **names**, planned
durable writes, blockers, and recovery steps. It never renders reference values,
certificates, keys, tokens, or other secret material. Save stays disabled unless the
server says the same plan used by the mutation is ready and effect-free.

Automation has the same safety rail. Preview a create with `POST
/api/v1/mdm/scep/policies/preview`, an update with `POST
/api/v1/mdm/scep/policies/{id}/preview`, and a challenge rotation with `POST
/api/v1/mdm/scep/policies/{id}/rotate-challenge/preview`. Those calls make zero
policy writes, event writes, outside calls, and signer calls. The matching CLI
commands are `trstctl mdm scep policies preview-create --file policy.json`,
`preview-update --id POLICY_ID --file policy.json`, and `preview-rotation --id
POLICY_ID`. Execute only after reviewing the plan with the existing `create`,
`update`, or `rotate-challenge` command. Mutations still require an idempotency key
and run the identical readiness planner again, so a caller cannot bypass the gate.

The other served operations are `POST/GET/PUT/DELETE
/api/v1/mdm/scep/policies`, `GET /api/v1/mdm/scep/status`, and their matching
`trstctl mdm scep ...` commands. They keep profile guidance, challenge mode,
trust-anchor references, rotation version, and telemetry visible without storing
raw MDM secrets. At runtime the validator resolves enabled policy
`trust_anchor_refs` from the served secret store (`secret://...`) per decision, so
anchor changes take effect without restarting the handler; the static
`protocols.scep.intune_challenge` anchors remain a bootstrap/fallback path.

If policy setup is blocked, fix the named prerequisite and run the preview again;
no partial policy exists to clean up. If a save is interrupted, retry with the same
idempotency key. If challenge rotation fails, the current challenge version remains
the only active version; keep the dialog open, review the refreshed plan, and retry.
After rotation, use the device trace to distinguish a challenge refusal from an
offline device. Repair the named refusal, or bring an offline device online and
trigger an MDM check-in. Do not weaken challenge, tenant, CSR, or replay validation
to make enrollment appear green.

The device-correlation surface is evidence-backed end to end. The SCEP handler
records an immutable request fact before challenge validation and a terminal
issuance fact for every success or refusal, keyed by tenant, CSR common-name
device serial, and transaction. A success includes the signer-minted certificate
serial, fingerprint, and expiry. The leader commits a durable `mdm.sync` intent;
a NETWORK relay redeems the `secret://` bearer for that attempt and reads
Intune's fixed `CertificatesByRAPolicy` report or Jamf's `CERTIFICATES`
inventory. Only its bounded typed, signed observation returns to the control
plane, which binds it to the exact job payload before correlation and completes
the claim plus outbox row atomically after projection. There is no control-plane
MDM HTTP/token fallback. Installation is successful only when the exact device
contains that exact serial with an active status. Device registration, a
correlation ID, or an identity row is never treated as proof. `GET /api/v1/mdm/devices` and
`GET /api/v1/mdm/{mdm}/devices/{id}/trace` expose requested, issued, installed,
and renewing evidence; the console opens the same trace from each device row and
keeps missing evidence `unknown`. A later SCEP transaction is renewal evidence;
an offline device inside the renewal window with no later attempt gets actionable
check-in guidance instead of a made-up failure or success.

## Use it

A device using a standard EST client enrolls like this:

```sh
# 1) fetch the CA chain (no auth) to establish trust
curl -s https://trstctl.example.com/.well-known/est/cacerts -o cacerts.p7

# 2) enroll: POST a base64 PKCS#10 CSR, get back a PKCS#7 cert
curl -s -H "Content-Type: application/pkcs10" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     --data-binary @request.b64 \
     https://trstctl.example.com/.well-known/est/simpleenroll
```

A constrained IoT device instead bootstraps with a one-time token:

```sh
curl -s -X POST https://trstctl.example.com/enroll/bootstrap \
     -d '{"token":"<one-time-token>","csr":"<base64-DER-CSR>"}'
# -> {"certificate":"<PEM chain>"}
```

## Pitfalls & limits

Be precise about what's mounted in the running server today:

| Surface | Status |
|---|---|
| Embedded bootstrap (`POST /enroll/bootstrap`, F54) | **Served** by the control plane |
| Embedded renewal (`POST /enroll/renewal`, F54) | **Served** on the dedicated agent-CA mTLS HTTPS listener when `agent_channel.enabled`; requires the current verified client certificate and rejects missing or expired peers |
| EST server (F22) | **Served** at `/.well-known/est/...` (`protocols.est.enabled` + `protocols.est.tenant_id`) — Bearer-token + TLS auth, orchestrator-backed, tenant-scoped |
| EST serverkeygen / channel binding / profile routes | **Served when configured** — `/serverkeygen`, RFC 9266 `tls-server-end-point`, per-profile PathID, and the mTLS sibling route |
| SCEP server (F23) | **Served** at `/scep` (`protocols.scep.enabled` + `protocols.scep.tenant_id`) — CMS transport, orchestrator-backed, tenant-scoped |
| SCEP per-profile RA and rate limits | **Served when configured** — per-profile SCEP RA cert/key plus per-device rate limiter |
| CMP server (F55) | **Served** at `/cmp` (`protocols.cmp.enabled` + `protocols.cmp.tenant_id`) — orchestrator-backed, tenant-scoped, client-anchor authenticated, subject-bound by default; safe qualification is served by API, CLI, and console |
| MDM challenge (F56) | **Served** — policy management (API/CLI/UI), challenge rotation, Intune JWS validation, tenant/CSR binding, single-use replay cache, and live trust-anchor resolution via `trust_anchor_refs` from the served secret store |

The protocol servers each expose a `Handler()` and mount on the control-plane TLS
listener at startup, behind the same issuance seam the API mint uses — backed by the
isolated signing service, scoped to one tenant, event-sourced, idempotent, and
profile-gated. Each is gated by `protocols.<name>.enabled` and binds a tenant via
`protocols.<name>.tenant_id`; toggles default off until an operator supplies that
binding, and startup validation fails when an enabled protocol has no tenant, so a
server can never come up serving an unscoped, cross-tenant path. They activate only
when an issuing CA is provisioned. EST and SCEP both rely on the device trusting the
`/cacerts`/`GetCACert` chain first; SCEP's security depends on the challenge gate (F56)
since the protocol itself is weakly authenticated. For SCEP/CMP, keep
`protocols.ra_key_file` on shared persistent storage in HA so all replicas use the same
transport identity. Disabled `/.well-known/est/`, `/scep`, and `/cmp` namespaces are
still reserved by the control-plane mux and return `404 application/problem+json`;
they never fall through to the browser SPA as HTTP 200. Unknown protocol children fail
the same machine-route boundary rather than becoming console routes.

An evaluation stack can instead select `protocols.profile=eval` with one
`eval_tenant_id`, assembling ACME, EST, SCEP, CMP, SSH, TSA, and SPIFFE but keeping
them unreachable until an authenticated first-run call to
`POST /api/v1/setup/protocols/activate` appends a tenant-scoped activation event and
opens the shared HTTP gate/SPIFFE UDS; event replay restores that state after restart.
KMIP stays a separately licensed, mTLS-configured listener the eval shortcut never
enables.

## Reference

- **EST:** `GET /.well-known/est/cacerts`, `POST /.well-known/est/simpleenroll`,
  `/simplereenroll`, `GET /.well-known/est/csrattrs`, `POST
  /.well-known/est/serverkeygen` (RFC 7030); profile PathID and mTLS sibling route
  variants mount under `/.well-known/est/<PathID>/...` and
  `/.well-known/est-mtls/<PathID>/...`.
- **SCEP:** `/scep?operation=GetCACaps|GetCACert|PKIOperation` (RFC 8894).
- **CMP:** `POST /cmp` (RFC 4210 / RFC 6712) for protected `p10cr` enrollment;
  authenticated read-only `POST /api/v1/protocols/cmp/qualification` and
  `trstctl protocols cmp qualify` for effect-free runtime qualification.
- **Embedded:** `POST /enroll/bootstrap` (one-time token) and `POST /enroll/renewal`
  (verified client certificate) are served by the running control plane.
- **Events:** `protocol.est.est-enroll`, `protocol.scep.*`, `protocol.cmp.enroll`,
  `mdm.scep_policy.*`, `mdm.scep_challenge.rotated`, and
  `mdm.intune_scep_challenge*`.

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (the shared issuance path) ·
[ACME & DNS](acme-and-dns.md) (the modern alternative) ·
[Current limitations](../limitations.md) ·
glossary: [EST/SCEP/CMP](../glossary.md), [CSR](../glossary.md), [mTLS](../glossary.md)

**Covers:** F22, F23, F55, F54, F56
