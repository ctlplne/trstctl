# Enrollment protocols — how existing devices ask for certificates

## What it is

"Enrollment" is the moment a device asks a [CA](../glossary.md) for a
[certificate](../glossary.md) and gets one back. [ACME](acme-and-dns.md) is the modern
way, but the world is full of routers, switches, printers, phones, factory controllers,
and 5G base stations that already speak *older* enrollment protocols baked into their
firmware. trstctl serves those protocols too — [EST](../glossary.md),
[SCEP](../glossary.md), and [CMP](../glossary.md) — plus a tiny enrollment client for
constrained IoT devices and an integration so mobile-device-management (MDM) platforms
can enroll managed phones and laptops.

The point: you should not have to re-flash a million devices to bring them under
trstctl. If a device can already enroll over EST, SCEP, or CMP, it can enroll against
trstctl unchanged.

## Why it exists

Every certificate eventually expires, so every device needs a *repeatable* way to get a
fresh one without a human visiting it. Different industries standardized on different
protocols years ago: enterprise and IoT gear tend to speak EST (RFC 7030); network
hardware and mobile-device management speak SCEP (RFC 8894); telecom and industrial
systems speak CMP (RFC 4210). Supporting all three means trstctl can become the issuing
authority for an existing fleet on day one, instead of being limited to greenfield
ACME-aware workloads.

## How it works

All three protocol servers share the same trstctl spine. Each one parses its protocol's
request format inside the single isolated cryptography path, authenticates the caller,
then hands the [CSR](../glossary.md) to the *same* issuance path every other feature uses
— with an `Idempotency-Key` so a retry never mints twice, the [outbox](../glossary.md)
that journals outbound calls and delivers them at-least-once, and an immutable audit event
for every allow/deny/shed decision. Each runs in its own bounded [lane](../glossary.md)
and sheds load with HTTP 503 when saturated, so an enrollment storm can't starve the rest
of the system.

### EST (F22) — the modern enrollment protocol

EST (Enrollment over Secure Transport, RFC 7030) is a small set of HTTPS endpoints. A
client fetches the CA chain from `/cacerts` (no auth, so it can bootstrap trust), then
POSTs a CSR to `/simpleenroll` (first time) or `/simplereenroll` (renewal) and gets back
a PKCS#7-wrapped certificate. trstctl implements all four endpoints (including
`/csrattrs`), authenticates via an injected authenticator, caps request bodies, verifies
the CSR's self-signature through the single isolated cryptography path, and honors an
`Idempotency-Key` header (or derives one from the CSR) so a retried enroll never mints
twice.

Routes under `/.well-known/est/...`.

### SCEP (F23) — the one network and MDM gear still speaks

SCEP (Simple Certificate Enrollment Protocol, RFC 8894) is ancient but ubiquitous in
routers, printers, and mobile-device management. It wraps requests in CMS (signed,
encrypted ASN.1 envelopes). trstctl advertises its capabilities at `GetCACaps`, returns
the chain at `GetCACert`, and on `PKIOperation` decrypts the CMS envelope and extracts
the CSR — all CMS handling inside the single isolated cryptography path. The SCEP
transaction ID becomes the idempotency key. Notably, the SCEP **RA transport key** is
deliberately separate from the platform CA signing key and never enters the isolated
signing service. It is sealed at rest under `protocols.ra_key_file` and shared across
replicas, so a device that cached `GetCACert` material can still complete enrollment after
a restart or rolling deploy.

Routes `/scep`, `/scep/pkiclient.exe`.

### CMP (F55) — for telecom and industrial PKI

CMP (Certificate Management Protocol, RFC 4210, over HTTP per RFC 6712) is common in 5G
and industrial systems. trstctl serves the `p10cr` flow: it reads the DER PKIMessage,
extracts the transaction ID and CSR through the single isolated cryptography path, issues,
and returns a signed `pkixcmp` response. As with SCEP, the CMP protection key is the
sealed `protocols.ra_key_file` transport identity, distinct from the CA key held in the
isolated signing service.

Route `POST /cmp`.

### The embedded / IoT enrollment agent (F54)

The smallest devices can't run a Go agent, so trstctl ships two cooperating pieces. On
the control-plane side, an **enrollment authority** issues single-use *bootstrap tokens*
and signs the device's first [mTLS](../glossary.md) certificate; the device generates its
own key, keeps the private half forever (it never crosses the wire), and sends only a
CSR. On the device side there's a **POSIX C client** (`est_client.c`) that depends only
on libc and the `openssl` CLI — small enough for constrained hardware — and the test
suite actually compiles and runs it against a real EST server. A bootstrap token is
checked-and-deleted atomically, so it works exactly once.

**Status:** the running control plane mounts **only `POST /enroll/bootstrap`**. Renewal is
**library-complete but not yet mounted**: an `EnrollRenewal` operation and a
`POST /enroll/renewal` handler exist in the codebase, but the served API does not register
that route, so a request to `/enroll/renewal` against the running binary returns **404**
today. This matches the served route set in
[discovery-and-inventory.md](discovery-and-inventory.md). Mounting renewal (and the agent
mTLS steady-state channel it pairs with) onto the served listener is tracked as future
work; until then, the served *agent* enrollment path is bootstrap-only. (The RFC issuance
protocols — ACME/EST/SCEP/CMP/SPIFFE/SSH — are now served; see the table below and
[limitations.md](../limitations.md).)

### Intune / MDM enrollment (F56)

When a mobile-device-management platform (Microsoft Intune, JAMF) pushes a SCEP profile
to a managed phone or laptop, you want *only* MDM-provisioned devices to enroll — not
anyone who can reach the SCEP endpoint. trstctl's MDM integration issues a stateless,
HMAC-signed **challenge token** that the MDM embeds in the device's SCEP profile
`challengePassword`. The SCEP server validates the token (constant-time MAC check,
expiry) before issuing — fail-closed on any defect. It's stateless: the HMAC key is the
only shared secret, so there's no database lookup on the hot path. The HMAC key is held in
wipeable `[]byte` memory and zeroed after use, never a copyable string.

Wires into the SCEP server's challenge hook.

## Use it

A device using a standard EST client enrolls like this (conceptually):

```sh
# 1) fetch the CA chain (no auth) to establish trust
curl -s https://trstctl.example.com/.well-known/est/cacerts -o cacerts.p7

# 2) enroll: POST a base64 PKCS#10 CSR, get back a PKCS#7 cert
curl -s -H "Content-Type: application/pkcs10" \
     -H "Idempotency-Key: $(uuidgen)" \
     --data-binary @request.b64 \
     https://trstctl.example.com/.well-known/est/simpleenroll
```

A constrained IoT device instead bootstraps with a one-time token over the served
endpoint:

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
| Embedded renewal (`POST /enroll/renewal`, F54) | **Library-complete, not yet mounted** — 404 on the running binary; mounting it (with the agent steady-state channel) is tracked as future work |
| EST server (F22) | **Served** at `/.well-known/est/...` (`protocols.est.enabled` + `protocols.est.tenant_id`) — Bearer-token + TLS auth, orchestrator-backed, tenant-scoped |
| SCEP server (F23) | **Served** at `/scep` (`protocols.scep.enabled` + `protocols.scep.tenant_id`) — CMS transport, orchestrator-backed, tenant-scoped |
| CMP server (F55) | **Served** at `/cmp` (`protocols.cmp.enabled` + `protocols.cmp.tenant_id`) — orchestrator-backed, tenant-scoped |
| MDM challenge (F56) | **Library-complete**, tested; the challenge-password gate activates when configured on the served SCEP endpoint |

The protocol servers each expose a `Handler()` and are mounted on the control-plane
TLS listener at startup, each behind the same issuance seam the API mint uses —
backed by the isolated signing service, scoped to one tenant, event-sourced, idempotent,
and profile-gated. Each is gated by `protocols.<name>.enabled` and binds a tenant via
`protocols.<name>.tenant_id`; all protocol toggles default off until an operator supplies
that tenant binding, and validation fails at startup when an enabled protocol has no
tenant — so a server can never come up serving an unscoped, cross-tenant path. They
activate only when an issuing CA is provisioned. Other notes: EST and SCEP
both rely on the device trusting the `/cacerts`/`GetCACert` chain first; SCEP's
security depends on the challenge gate (F56) since the protocol itself is weakly
authenticated. For SCEP/CMP, keep `protocols.ra_key_file` on shared persistent storage
in HA so all replicas use the same CMS transport identity.

## Reference

- **EST:** `GET /.well-known/est/cacerts`, `POST /.well-known/est/simpleenroll`,
  `/simplereenroll`, `GET /.well-known/est/csrattrs` (RFC 7030).
- **SCEP:** `/scep?operation=GetCACaps|GetCACert|PKIOperation` (RFC 8894).
- **CMP:** `POST /cmp` (RFC 4210 / RFC 6712).
- **Embedded:** `POST /enroll/bootstrap` (served). `POST /enroll/renewal` is
  library-complete but **not yet mounted** (404 on the running binary; mounting it,
  alongside the agent steady-state channel, is tracked as future work).
- **Events:** `protocol.est.est-enroll`, `protocol.scep.*`, `protocol.cmp.enroll`.
- **EST authoring guide:** [Device enrollment (EST)](../guides/est-enrollment.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (the shared issuance path) ·
[ACME & DNS](acme-and-dns.md) (the modern alternative) ·
[Device enrollment (EST) guide](../guides/est-enrollment.md) ·
[Current limitations](../limitations.md) ·
glossary: [EST/SCEP/CMP](../glossary.md), [CSR](../glossary.md), [mTLS](../glossary.md)

**Covers:** F22, F23, F55, F54, F56
