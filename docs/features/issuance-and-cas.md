# Issuance & certificate authorities — how trstctl mints and governs certificates

## What it is

Issuance is the act of **creating a [certificate](../glossary.md)**: a machine asks
for one, an authority signs it, and the machine gets back a signed ID it can present.
This page covers everything around that act — issuing through *any* authority,
running your own [CA](../glossary.md) hierarchy, the rules that constrain what may be
issued, telling clients when to renew, taking certificates back early, and where the
all-important private key physically lives.

The mental model: trstctl is a **passport office**. A CA is the office that prints
and signs passports; a *profile* is the rulebook for what a valid passport may say; a
*registration authority* is the clerk who checks your paperwork but isn't allowed to
print the passport themselves; *revocation* is the bulletin of cancelled passports;
and the *HSM* is the locked vault holding the official seal.

## Why it exists

Certificates expire on purpose and must be re-minted constantly, so issuance has to be
automatic, governed, and auditable. Three things go wrong without a real issuance
layer: the wrong certificate gets minted (too-long validity, weak key, a name the
requester shouldn't control); the signing key leaks and forges everything; or a
compromised certificate keeps being trusted because nobody can pull it back. trstctl's
issuance layer is built to make each of those hard.

## How it works

### One issuance path, any CA (F4)

Every certificate trstctl issues goes through a single, uniform interface — a `CA`
with one real method, `Issue(request)` — no matter who actually signs. The built-in
in-process CA, a CA in your own [hierarchy](#running-your-own-ca-hierarchy-f48), and
third-party authorities (AWS Private CA, DigiCert, Sectigo, EJBCA, Microsoft ADCS,
Google CAS, Smallstep, Let's Encrypt) all implement that same interface, so switching
or adding a CA changes one wiring line, not your application.

That single path is where the guarantees live. Each issuance carries an
[`Idempotency-Key`](../glossary.md) (**AN-5**): the first call mints the certificate
*and* writes a `ca.issue` record to the [outbox](../glossary.md) in the same database
transaction (**AN-6**), and a retried call with the same key returns the *same*
certificate instead of minting a second one. The request's [CSR](../glossary.md) is
inspected through the crypto boundary `internal/crypto` (**AN-3**) — the issuance code
never imports `crypto/x509` — and the active [profile](#profiles-and-the-registration-authority-split-f53)
is enforced *before* anything is signed, with an `issuance.profile_evaluated` event
emitted either way (**AN-2**).

*Code:* `internal/ca/ca.go` (`CA`, `IssueRequest`), `internal/ca/issuance.go`
(`IssuanceService`), `internal/ca/builtin.go`, plus the per-vendor drivers under
`internal/ca/`.

### Running your own CA hierarchy (F48)

trstctl can *be* your private PKI: a root CA, intermediates beneath it, end-entity
certificates beneath those — the usual tree where the root is kept offline-precious and
the intermediates do the day-to-day signing.

The dangerous operations (creating a root or intermediate, rotating a CA, cross-signing)
are **each** gated by an **m-of-n key ceremony**: nothing happens until *m* of *n* named
custodians approve. You `StartCeremony(purpose, threshold)`, collect approvals with
`Approve(...)`, and every key operation consumes one pending ceremony whose purpose
matches the requested resource: `root:<sha256-of-ca-spec>`,
`intermediate:<parent-ca-id>:<sha256-of-ca-spec>`, `rotation:<ca-id>`, or
`cross-sign:<ca-id>:<sha256-of-target-cert-der>`. If approvals are short, the
operation returns `ErrQuorumNotMet`; if the ceremony was already used or opened for
a different resource/spec, it refuses before committing the CA mutation. Cross-signing
is gated for the same reason as creating an intermediate: it mints a CA certificate
under your signing CA and so extends trust. This is how you stop a single compromised
admin account from minting a rogue intermediate or cross-cert, and how you stop one
valid ceremony from being replayed against a different CA or a different CA request.
Every step (`ca.root.created`, `ca.intermediate.created`, `ca.rotated`,
`ca.cross_signed`) is a tenant-scoped event in the log carrying its `ceremony_id`
(**AN-1**, **AN-2**), and all the X.509 work happens inside `internal/crypto/ca`
(**AN-3**). Rotation atomically consumes the ceremony, supersedes the old authority,
and links the new one to it in one transaction. The full operator procedure is the
[CA key-ceremony runbook](../runbooks/key-ceremony.md).

> **Served status.** The CA-hierarchy + m-of-n ceremony (including the now
> quorum-gated cross-sign) is implemented and tested as **library code**
> (`internal/ca/hierarchy`), driven through the Go API; a served REST/UI ceremony
> flow is future work (see [limitations](../limitations.md)). Being library-only
> bounds the blast radius, but the quorum and purpose-bound single-use gate is
> enforced in code on every path, not assumed.

*Code:* `internal/ca/hierarchy/hierarchy.go` (`Manager`, `StartCeremony`, `Approve`,
`CreateRoot`, `CreateIntermediate`, `Rotate`, `CrossSign(ceremonyID, …)`,
`ErrQuorumNotMet`).

### Profiles and the registration-authority split (F53)

A **certificate profile** is a versioned, tenant-scoped rulebook: which key algorithms
and minimum sizes are allowed, which extended key usages, the maximum validity, which
DNS suffixes, which protocols. When you edit a profile you create a *new version*; old
versions stay queryable, so you always know which rules a past certificate was issued
under. On every issuance, `enforceProfile` fetches the active version, validates the
request, and emits an audit event for the allow-or-deny decision.

The **registration-authority (RA) model** is a role split that prevents the most
classic PKI abuse — the person who approves a request also fulfilling it. The built-in
`ra-officer` role can read and write profiles and *request* certificates, but it does
**not** hold the `certs:issue` permission. Only an operator/admin can issue. So an RA
officer cannot self-issue; the separation is enforced by [RBAC](policy-and-governance.md),
not by convention, and there's a test that asserts it. Authoring profiles is covered in
the [certificate-profile guide](../guides/profile-authoring.md).

*Code:* `internal/profile/profile.go` (`CertificateProfile`, `Validate`),
`internal/ca/issuance.go` (`enforceProfile`), `internal/authz/authz.go` (the
`ra-officer` role), `internal/api/profiles.go`.

### Telling clients when to renew: ARI (F46)

If thousands of clients all renew at the same fixed "30 days before expiry," they
stampede — and if a certificate must be replaced *early* (say a mass revocation),
there's no way to tell them. **ACME Renewal Information (ARI, RFC 9773)** fixes both:
the CA publishes a *suggested renewal window* per certificate, and clients renew within
it.

trstctl computes the window as the last third of the certificate's life and has each
client pick a deterministic, spread-out point inside it (so they don't bunch up). If
the CA flags a certificate for early renewal, the window jumps to "right now," and
compliant clients renew immediately. The certificate identifier is built inside the
crypto boundary (`certinfo.ARICertID`, **AN-3**).

*Code:* `internal/protocols/ari` (`SuggestWindow`, `RenewAt`, `Client`),
`internal/crypto/certinfo/ari.go`. Served by the ACME server at
`GET /acme/renewal-info/{certid}` (window state is currently in-memory — see
[ACME & DNS](acme-and-dns.md) and [limitations](../limitations.md)).

### Revocation: OCSP and CRLs (F47)

When a certificate must stop being trusted before it expires, you **revoke** it and
publish that fact two ways. A **[CRL](../glossary.md)** is a signed list of revoked
serial numbers, regenerated and published periodically. **[OCSP](../glossary.md)**
answers "is *this one* revoked?" live, one certificate at a time. trstctl does both
for certificates from its own hierarchy: `Revoke(serial, reason)` marks it and emits
`ca.certificate.revoked` (**AN-2**); `GenerateCRL` bumps the CRL number, signs a fresh
list inside `internal/crypto/ca` (**AN-3**), and emits `ca.crl.published`. The OCSP
responder runs on its own [bulkhead](../glossary.md) (**AN-7**) so an OCSP flood can't
starve the API.

*Code:* `internal/ca/revocation/revocation.go` (`Revoke`, `OCSP`, `GenerateCRL`,
`LatestCRL`), `internal/crypto/ca/revocation.go`. RFCs 6960 (OCSP), 5280 (CRL).

### Where the private key lives: HSM/KMS (F26)

A CA's private key is the single most valuable secret in the system — anyone who has it
can forge any certificate. So trstctl keeps it in hardware or a cloud key service that
**signs without ever revealing the key**. An [HSM/KMS](../glossary.md) backend
implements one interface (`Backend` → `GenerateKey` → a `Signer` that signs via the
device), and trstctl supports PKCS#11 HSMs, TPM 2.0, YubiHSM 2, AWS KMS, Azure Key
Vault, and GCP Cloud KMS. Adding one is a single package because *all* crypto goes
through `internal/crypto` (**AN-3**); the key material never crosses the boundary
(**AN-4**, **AN-8**) — only signatures and public keys do. Every backend must pass a
conformance harness (`ConformBackend`) before it's trusted: it signs a probe, verifies
it, and confirms a wrong message and a tampered signature both fail.

*Code:* `internal/crypto/backend.go` (`Backend`, `ConformBackend`),
`internal/kms/{pkcs11,tpm,yubihsm,awskms,azurekv,gcpkms}`. Note: several hardware
bindings ship against an injected interface with a software double on CI; the native
cgo/connector bindings are the documented follow-up.

## Use it

Issue and govern through the served API and CLI. Profiles are live today:

```sh
# create a versioned profile (RA officer or admin)
trstctl-cli profiles create -f tls-server-90d.json

# list active profiles
trstctl-cli profiles list
```

A profile spec looks like this — note the explicit, enforced constraints:

```json
{
  "name": "tls-server-90d",
  "spec": {
    "allowed_key_algorithms": ["ECDSA"],
    "min_ecdsa_bits": 256,
    "allowed_ekus": ["serverAuth"],
    "max_validity": "2160h"
  }
}
```

Issuance happens through the enrollment protocols ([ACME](acme-and-dns.md),
[EST/SCEP/CMP](enrollment-protocols.md)) and the API, each of which calls the one
issuance path with an `Idempotency-Key`. Revoke from the incident flow in
[Incident response](incident-and-jit.md).

## Pitfalls & limits

- **Private-key custody is your decision.** The in-process CA is the convenient
  reference path; for production, point the CA at an HSM/KMS backend so the key is
  never in the control-plane's memory. See [configuration](../configuration.md) for
  `TRSTCTL_SIGNER_MODE` and CA custody.
- **Hardware bindings vary in maturity.** The KMS/HSM backends are uniform behind the
  interface and tested against doubles; confirm the specific native binding you need is
  wired before relying on it ([limitations](../limitations.md)).
- **ARI window state is currently in-memory** in the ACME server; durable,
  event-sourced ARI is the documented integration step.
- **Revocation covers trstctl's own hierarchy.** Certificates from third-party CAs are
  revoked through those CAs.

## Reference

- **CLI groups:** `profiles`, `issuers`, `certificates`.
- **Served routes:** `POST|GET /api/v1/profiles`,
  `GET /api/v1/profiles/{name}/versions/{version}`, `POST /api/v1/certificates`.
- **Key ceremony:** `StartCeremony` → ≥`threshold` × `Approve` → `CreateRoot` /
  `CreateIntermediate`. See the [runbook](../runbooks/key-ceremony.md).
- **Events:** `ca.issue`, `issuance.profile_evaluated`, `ca.root.created`,
  `ca.intermediate.created`, `ca.rotated`, `ca.cross_signed`,
  `ca.certificate.revoked`, `ca.crl.published`.
- **RFCs:** 5280 (X.509/CRL), 6960 (OCSP), 9773 (ARI).

## See also

[ACME & DNS](acme-and-dns.md) · [Enrollment protocols](enrollment-protocols.md) ·
[Certificate-profile guide](../guides/profile-authoring.md) ·
[CA key-ceremony runbook](../runbooks/key-ceremony.md) ·
[Signing-service design](../design/signing-service.md) ·
glossary: [CA](../glossary.md), [CSR](../glossary.md), [OCSP](../glossary.md),
[CRL](../glossary.md), [HSM/KMS](../glossary.md)

**Covers:** F4, F48, F53, F46, F47, F26
