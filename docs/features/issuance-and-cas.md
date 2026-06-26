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
third-party authorities (Let's Encrypt/ACME, DigiCert, Sectigo, Microsoft AD CS,
AWS Private CA, Google CAS, EJBCA, Smallstep, Venafi TPP/TLS Protect) all implement
that same interface.
The running binary now exposes configured upstreams as a served registry at
`GET /api/v1/external-cas`; callers issue through one selected CA with
`POST /api/v1/external-cas/{id}/issue` using a PEM CSR, DNS names, and an
`Idempotency-Key`.

That single path is where the guarantees live. Each issuance carries an
[`Idempotency-Key`](../glossary.md): the first call mints the certificate *and* writes a
`ca.issue` record to the [outbox](../glossary.md) in the same database transaction
(journaled first so a crash can't silently drop it), and a retried call with the same key
returns the *same* certificate instead of minting a second one. The request's
[CSR](../glossary.md) is inspected through the single isolated cryptography path — the
issuance code never touches the low-level X.509 libraries directly — and the active
[profile](#profiles-and-the-registration-authority-split-f53) is enforced *before*
anything is signed, with an `issuance.profile_evaluated` event recorded either way in the
tamper-evident log.

Upstream CA credentials are configured by the control-plane operator, not written
through tenant JSON: API keys and provider handles stay in process configuration or
secret-backed plugin setup, then the API exposes only the non-secret registry row
(`id`, `type`, `name`, `status`). If a retry reuses the same idempotency key, the API
returns the cached certificate response and the upstream CA is not asked to sign again.
If the process crashes after recording the outbox intent, the outbox worker can resume
delivery without losing the fact that an external issuance happened.

### Kubernetes cert-manager external issuer

For Kubernetes-native issuance, trstctl ships cert-manager external issuer CRDs:
`Issuer` and `ClusterIssuer` in the `trstctl.com` API group. The Kubernetes agent
reconciles those resources, marks them Ready, and signs cert-manager
`CertificateRequest`s only when the request points at an existing trstctl issuer
resource. A cert-manager `Certificate` can therefore reference:

```yaml
issuerRef:
  name: trstctl
  kind: ClusterIssuer
  group: trstctl.com
```

The agent forwards only the CSR to the configured served trstctl issue endpoint,
adds a stable `Idempotency-Key`, and authenticates with an API token mounted from a
Kubernetes Secret file. cert-manager then writes the normal `kubernetes.io/tls`
Secret for the workload. CI proves this against a real `kind` cluster with real
cert-manager installed: `Certificate` -> `CertificateRequest` -> trstctl
`ClusterIssuer` -> TLS `Secret`.

### Running your own CA hierarchy (F48)

trstctl can *be* your private PKI: a root CA, intermediates beneath it, end-entity
certificates beneath those — the usual tree where the root is kept offline-precious and
the intermediates do the day-to-day signing.

The dangerous operations are gated by an **m-of-n key ceremony**: nothing happens
until *m* of *n* named custodians approve. Root and intermediate creation are served
today: open a ceremony, collect distinct custodian approvals, then create the CA.
Each operation consumes one pending ceremony whose purpose matches the reviewed
resource: `root:<sha256-of-ca-spec>` or
`intermediate:<parent-ca-id>:<sha256-of-ca-spec>`. If approvals are short, the
operation returns `ErrQuorumNotMet`; if the opener tries to approve their own
ceremony, or the ceremony was already used or opened for a different resource/spec, it
fails closed before committing the CA mutation. This is how you stop a single
compromised admin account from minting a rogue root or intermediate, and how you stop
one valid ceremony from being replayed against a different CA request.

The served hierarchy API lives at `/api/v1/ca/ceremonies`,
`/api/v1/ca/authorities`, and `/api/v1/ca/authorities/{id}/issue`. Root and
intermediate private keys are created in the isolated signing service and referenced
by signer handles; the control plane stores certificates, chains, metadata, and
ceremony state, but it never receives the CA private key. Every served step
(`ca.ceremony.started`, `ca.ceremony.approved`, `ca.root.created`,
`ca.intermediate.created`, `ca.endentity.issued`) is a tenant-scoped event carrying
the ceremony/authority context and is recorded immutably in the tamper-evident log.
Rotation and cross-signing remain purpose-bound library/operator workflows for now:
they use `rotation:<ca-id>` and `cross-sign:<ca-id>:<sha256-of-target-cert-der>`
ceremonies, with the same single-use quorum gate, until served rotation/cross-sign
routes ship. The full operator procedure is the
[CA key-ceremony runbook](../runbooks/key-ceremony.md).

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
single isolated cryptography path.

Served by the ACME server at `GET /acme/renewal-info/{certid}` and consumed by the
served lifecycle scheduler for trstctl-issued deployed X.509 identities. That means a
certificate can renew when its ARI window opens, even if it is not yet inside the fixed
`renew_before` fallback window.

### Revocation: OCSP and CRLs (F47)

When a certificate must stop being trusted before it expires, you **revoke** it and
publish that fact two ways. A **[CRL](../glossary.md)** is a signed list of revoked
serial numbers, regenerated and published periodically. **[OCSP](../glossary.md)**
answers "is *this one* revoked?" live, one certificate at a time. trstctl does both
for certificates from its own hierarchy: `Revoke(serial, reason)` marks it and emits
`ca.certificate.revoked` to the tamper-evident log; `GenerateCRL` bumps the CRL number,
signs a fresh list behind the single isolated cryptography path, and emits a v2
`ca.crl.published` event with the CRL DER and validity window so CRL serving state
rebuilds from the log. The OCSP responder runs in its own bounded
[lane](../glossary.md) so an OCSP flood can't starve the API.

RFCs 6960 (OCSP), 5280 (CRL).

### Where the private key lives: HSM/KMS (F26)

A CA's private key is the single most valuable secret in the system — anyone who has it
can forge any certificate. So trstctl keeps it in hardware or a cloud key service that
**signs without ever revealing the key**. An [HSM/KMS](../glossary.md) backend
implements one interface (`Backend` → `GenerateKey` → a `Signer` that signs via the
device), and trstctl supports PKCS#11 HSMs, TPM 2.0, YubiHSM 2, AWS KMS, Azure Key
Vault, and GCP Cloud KMS. Adding one is a single change because *all* cryptography goes
through one isolated path; the key material never leaves the device — private-key
operations run in a separate, isolated signing service, and the key bytes live only in
wipeable memory there — only signatures and public keys cross the wire. Every backend must
pass a conformance harness (`ConformBackend`) before it's trusted: it signs a probe,
verifies it, and confirms a wrong message and a tampered signature both fail.

The PKCS#11 backend now has a native module adapter as well as the fast injected
test double: an integration test initializes a real SoftHSM token in a container,
generates a non-extractable RSA-2048 key on that token, signs through the module,
and verifies the returned public key through the shared backend conformance harness.
Default release binaries stay static (`CGO_ENABLED=0`); deployments that need a
local PKCS#11 module build the signer/control-plane package with cgo enabled and
provide the module path, token label, and user PIN through operator-managed secret
configuration. Other hardware families still use the same backend contract, with
their own provider maturity and device setup requirements.

The managed-key lifecycle is now served for AWS KMS custody. When
`managed_keys.enabled` is true and the AWS KMS region/credentials are configured, the
running control plane exposes:

- `POST /api/v1/managed-keys` to create a KMS-resident signing key;
- `POST /api/v1/managed-keys/rotate` to mint a successor key;
- `POST /api/v1/managed-keys/revoke` to disable the current key at the provider;
- `POST /api/v1/managed-keys/zeroize` to schedule provider-side destruction.

The CLI mirrors those verbs under `trstctl managed-keys`. Every request is
tenant-scoped, idempotent, and recorded as a key-material-free lifecycle event. Rotate,
revoke, and zeroize require a distinct approval when four-eyes governance is enabled,
so one operator cannot silently destroy a tenant's signing key. CI proves the served
path against LocalStack AWS KMS through the official AWS SDK v2 KMS client, and the
same test runs against real AWS KMS when standard `AWS_*` credentials are present.

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

For a hybrid transition profile, allow the hybrid key label and bind it to the
protocols that should be able to request it:

```json
{
  "name": "hybrid-web-30d",
  "spec": {
    "allowed_key_algorithms": ["Hybrid-ML-DSA-44-ECDSA-P256"],
    "allowed_protocols": ["acme", "est", "scep", "cmp"],
    "allowed_ekus": ["serverAuth"],
    "max_validity": "720h"
  }
}
```

Issuance happens through the enrollment protocols ([ACME](acme-and-dns.md),
[EST/SCEP/CMP](enrollment-protocols.md)), the private-CA hierarchy API, and the
external CA registry API, each of which calls the one issuance path with an
`Idempotency-Key`. Revoke from the incident flow in [Incident response](incident-and-jit.md).

## Pitfalls & limits

- **Private-key custody is your decision.** The in-process CA is the convenient
  reference path; for production, point the CA at an HSM/KMS backend so the key is
  never in the control-plane's memory. See [configuration](../configuration.md) for
  `TRSTCTL_SIGNER_MODE` and CA custody.
- **Hardware bindings vary in maturity.** AWS KMS managed keys are served through the
  official AWS SDK v2 KMS client and LocalStack-proven; PKCS#11 has a real
  SoftHSM-backed native binding. Confirm the
  specific native binding you need is wired before relying on it
  ([limitations](../limitations.md)).
- **ARI-driven lifecycle scheduling is for trstctl-issued deployed X.509 identities.**
  Certificates discovered from another CA can still be inventoried and risk-scored, but
  renewing them requires a configured issuer path that can replace that outside
  certificate.
- **External CA registration is operator configuration.** Tenants can list and use
  configured upstream CAs, but provider credentials are not created through the tenant
  REST API.
- **Revocation covers trstctl's own hierarchy.** Certificates from third-party CAs are
  revoked through those CAs.

## Reference

- **CLI groups:** `profiles`, `issuers`, `external-cas`, `certificates`.
- **Served routes:** `POST|GET /api/v1/profiles`,
  `GET /api/v1/profiles/{name}/versions/{version}`, `POST /api/v1/certificates`,
  `GET /api/v1/external-cas`, `POST /api/v1/external-cas/{id}/issue`.
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
