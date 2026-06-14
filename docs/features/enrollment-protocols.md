# Enrollment protocols — how existing devices ask for certificates

## What it is

"Enrollment" is the moment a device asks a [CA](../glossary.md) for a
[certificate](../glossary.md) and gets one back. [ACME](acme-and-dns.md) is the modern
way, but the world is full of routers, switches, printers, phones, factory controllers,
and 5G base stations that already speak *older* enrollment protocols baked into their
firmware. trustctl serves those protocols too — [EST](../glossary.md),
[SCEP](../glossary.md), and [CMP](../glossary.md) — plus a tiny enrollment client for
constrained IoT devices and an integration so mobile-device-management (MDM) platforms
can enroll managed phones and laptops.

The point: you should not have to re-flash a million devices to bring them under
trustctl. If a device can already enroll over EST, SCEP, or CMP, it can enroll against
trustctl unchanged.

## Why it exists

Every certificate eventually expires, so every device needs a *repeatable* way to get a
fresh one without a human visiting it. Different industries standardized on different
protocols years ago: enterprise and IoT gear tend to speak EST (RFC 7030); network
hardware and mobile-device management speak SCEP (RFC 8894); telecom and industrial
systems speak CMP (RFC 4210). Supporting all three means trustctl can become the issuing
authority for an existing fleet on day one, instead of being limited to greenfield
ACME-aware workloads.

## How it works

All three protocol servers share the same trustctl spine. Each one parses its protocol's
request format inside the crypto boundary `internal/crypto` (**AN-3**), authenticates the
caller, then hands the [CSR](../glossary.md) to the *same* issuance path every other
feature uses — with an idempotency key (**AN-5**), the [outbox](../glossary.md)
(**AN-6**), and an audit event for every allow/deny/shed decision (**AN-2**). Each runs
on its own [bulkhead](../glossary.md) and sheds load with HTTP 503 when saturated
(**AN-7**), so an enrollment storm can't starve the rest of the system.

### EST (F22) — the modern enrollment protocol

EST (Enrollment over Secure Transport, RFC 7030) is a small set of HTTPS endpoints. A
client fetches the CA chain from `/cacerts` (no auth, so it can bootstrap trust), then
POSTs a CSR to `/simpleenroll` (first time) or `/simplereenroll` (renewal) and gets back
a PKCS#7-wrapped certificate. trustctl implements all four endpoints (including
`/csrattrs`), authenticates via an injected authenticator, caps request bodies, verifies
the CSR's self-signature in `internal/crypto`, and honors an `Idempotency-Key` header (or
derives one from the CSR) so a retried enroll never mints twice.

*Code:* `internal/protocols/est`. Routes under `/.well-known/est/...`.

### SCEP (F23) — the one network and MDM gear still speaks

SCEP (Simple Certificate Enrollment Protocol, RFC 8894) is ancient but ubiquitous in
routers, printers, and mobile-device management. It wraps requests in CMS (signed,
encrypted ASN.1 envelopes). trustctl advertises its capabilities at `GetCACaps`, returns
the chain at `GetCACert`, and on `PKIOperation` decrypts the CMS envelope and extracts
the CSR — all CMS handling inside `internal/crypto` (**AN-3**). The SCEP transaction ID
becomes the idempotency key. Notably, the SCEP **RA transport key** is deliberately
separate from the platform CA signing key and never enters the isolated signer process.

*Code:* `internal/protocols/scep`, `internal/crypto/scep.go`. Routes `/scep`,
`/scep/pkiclient.exe`.

### CMP (F55) — for telecom and industrial PKI

CMP (Certificate Management Protocol, RFC 4210, over HTTP per RFC 6712) is common in 5G
and industrial systems. trustctl serves the `p10cr` flow: it reads the DER PKIMessage,
extracts the transaction ID and CSR inside `internal/crypto`, issues, and returns a
signed `pkixcmp` response. As with SCEP, the CMP protection key is a transport-layer key
distinct from the CA key in the signer.

*Code:* `internal/protocols/cmp`, `internal/crypto/cmp.go`. Route `POST /cmp`.

### The embedded / IoT enrollment agent (F54)

The smallest devices can't run a Go agent, so trustctl ships two cooperating pieces. On
the control-plane side, an **enrollment authority** issues single-use *bootstrap tokens*
and signs the device's first [mTLS](../glossary.md) certificate; the device generates its
own key, keeps the private half forever (it never crosses the wire), and sends only a
CSR. On the device side there's a **POSIX C client** (`est_client.c`) that depends only
on libc and the `openssl` CLI — small enough for constrained hardware — and the test
suite actually compiles and runs it against a real EST server. A bootstrap token is
checked-and-deleted atomically, so it works exactly once.

*Code:* `internal/agent/enroll` (`Authority`, `IssueBootstrapToken`, `EnrollBootstrap`,
`EnrollRenewal`), `internal/agent/httpenroll.go`, `clients/embedded/`. **Status:** the
bootstrap and renewal endpoints (`POST /enroll/bootstrap`, `POST /enroll/renewal`) **are
mounted and served** by the running control plane.

### Intune / MDM enrollment (F56)

When a mobile-device-management platform (Microsoft Intune, JAMF) pushes a SCEP profile
to a managed phone or laptop, you want *only* MDM-provisioned devices to enroll — not
anyone who can reach the SCEP endpoint. trustctl's MDM integration issues a stateless,
HMAC-signed **challenge token** that the MDM embeds in the device's SCEP profile
`challengePassword`. The SCEP server validates the token (constant-time MAC check,
expiry) before issuing — fail-closed on any defect. It's stateless: the HMAC key is the
only shared secret, so there's no database lookup on the hot path. The HMAC key is held
as `[]byte`, never a string (**AN-8**).

*Code:* `internal/mdm` (`Challenge`, `Issue`, `Validate`, `Validator`). Wires into the
SCEP server's challenge hook.

## Use it

A device using a standard EST client enrolls like this (conceptually):

```sh
# 1) fetch the CA chain (no auth) to establish trust
curl -s https://trustctl.example.com/.well-known/est/cacerts -o cacerts.p7

# 2) enroll: POST a base64 PKCS#10 CSR, get back a PKCS#7 cert
curl -s -H "Content-Type: application/pkcs10" \
     -H "Idempotency-Key: $(uuidgen)" \
     --data-binary @request.b64 \
     https://trustctl.example.com/.well-known/est/simpleenroll
```

A constrained IoT device instead bootstraps with a one-time token over the served
endpoint:

```sh
curl -s -X POST https://trustctl.example.com/enroll/bootstrap \
     -d '{"token":"<one-time-token>","csr":"<base64-DER-CSR>"}'
# -> {"certificate":"<PEM chain>"}
```

## Pitfalls & limits

Be precise about what's mounted in the running server today:

| Surface | Status |
|---|---|
| Embedded bootstrap/renewal (`/enroll/...`, F54) | **Served** by the control plane |
| EST server (F22) | **Library-complete**, tested (incl. differential tests); not yet mounted |
| SCEP server (F23) | **Library-complete**, tested; not yet mounted |
| CMP server (F55) | **Library-complete**, tested; not yet mounted |
| MDM challenge (F56) | **Library-complete**, tested; activates when SCEP is mounted |

The protocol servers each expose a `Handler()` and are attached through the composition
root (`internal/serving.Registry`); the production mount of that registry is the
remaining wiring step (see [Current limitations](../limitations.md)). Other notes: EST
and SCEP both rely on the device trusting the `/cacerts` chain first; SCEP's security
depends on the challenge gate (F56) since the protocol itself is weakly authenticated.

## Reference

- **EST:** `GET /.well-known/est/cacerts`, `POST /.well-known/est/simpleenroll`,
  `/simplereenroll`, `GET /.well-known/est/csrattrs` (RFC 7030).
- **SCEP:** `/scep?operation=GetCACaps|GetCACert|PKIOperation` (RFC 8894).
- **CMP:** `POST /cmp` (RFC 4210 / RFC 6712).
- **Embedded:** `POST /enroll/bootstrap`, `POST /enroll/renewal` (served).
- **Events:** `protocol.est.est-enroll`, `protocol.scep.*`, `protocol.cmp.enroll`.
- **EST authoring guide:** [Device enrollment (EST)](../guides/est-enrollment.md).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (the shared issuance path) ·
[ACME & DNS](acme-and-dns.md) (the modern alternative) ·
[Device enrollment (EST) guide](../guides/est-enrollment.md) ·
[Current limitations](../limitations.md) ·
glossary: [EST/SCEP/CMP](../glossary.md), [CSR](../glossary.md), [mTLS](../glossary.md)

**Covers:** F22, F23, F55, F54, F56
