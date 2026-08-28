# Authoring certificate profiles

Certificate **profiles** govern what a certificate may be: the allowed key
types and sizes, extended key usages, validity ceiling, name constraints, and which
enrollment protocols may use the profile. Every issuance path validates a request
against its bound profile **before anything is signed**, so a non-compliant request is
rejected with a clear reason rather than minting an out-of-policy certificate.

Profiles are **tenant-scoped**, **versioned**, and **event-sourced**:
editing a profile appends a full profile event, projects a new active read-model
version, and leaves prior versions resolvable for audit and for certificates issued
under them. A read-model rebuild restores profile versions from the event log. Every
create/update and every profile-gated issuance decision is recorded with the actor who
made it.

## The registration-authority (RA) separation

The RA role model separates **who may request** a certificate from **who may
approve/issue** it:

- the built-in **`ra-officer`** role may author profiles (`profiles:write`) and request
  certificates (`certs:request`), but **cannot** issue them (`certs:issue`);
- an **operator**/approver holds `certs:issue` and authorizes what a requester cannot
  self-issue.

This means a requester cannot self-issue: issuance requires the separate approval
permission.

## Profile fields

A profile spec is JSON:

| Field | Meaning |
| --- | --- |
| `allowed_key_algorithms` | permitted key algorithms, e.g. `["ECDSA","RSA"]` (empty = any) |
| `min_rsa_bits` / `min_ecdsa_bits` | minimum key strength floors |
| `allowed_ekus` | permitted extended key usages, e.g. `["serverAuth"]` (empty = any) |
| `max_validity` | validity ceiling as a duration, e.g. `"2160h"` (0 = no ceiling) |
| `allowed_protocols` | enrollment protocols that may use this profile, e.g. `["api","acme"]` |
| `allowed_dns_suffixes` | name constraint on SAN dNSNames (empty = unconstrained) |
| `acme_device_attestation` | explicit, default-off TPM `device-attest-01` policy: operator roots, device identifier allowlist, COSE algorithms, and maximum proof age |

## TPM device-attest-01

An ACME profile may add TPM-backed device identity as a fourth challenge without
removing or weakening `http-01`, `dns-01`, or `tls-alpn-01`. The feature is
default-off. Enabling it requires all of the following:

- `format: "tpm"` (the first and only supported attestation format);
- one or more operator-controlled X.509 trust roots in
  `attestation_roots_pem`;
- an explicit exact-name or `*.suffix` device identifier allowlist;
- allowed COSE signature algorithm numbers, such as ES256 `-7`; and
- a positive `max_age` no greater than 24 hours.

The device submits a fresh TPM WebAuthn attestation through `internal/crypto`.
trstctl binds that proof to
the tenant, ACME account, order, challenge, token, outer JWS nonce, device
identifier, CSR public key, and issuance time. The validated key digest is stored
in the ACME event stream and replayed after restart; finalization fails if the
CSR changes. Trust is entirely operator-supplied and no manufacturer metadata
service is contacted.

## Creating and listing profiles

Via the CLI (at parity with the REST API):

```bash
# Create (or version) a profile. Writing requires the profiles:write permission.
echo '{
  "name": "web-server",
  "spec": {
    "allowed_key_algorithms": ["ECDSA","RSA"],
    "min_rsa_bits": 3072,
    "min_ecdsa_bits": 256,
    "allowed_ekus": ["serverAuth"],
    "max_validity": "2160h",
    "allowed_protocols": ["api","acme"],
    "allowed_dns_suffixes": ["example.com"],
    "acme_device_attestation": {
      "enabled": true,
      "format": "tpm",
      "attestation_roots_pem": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"],
      "allowed_identifiers": ["*.devices.example.com"],
      "allowed_algorithms": [-7],
      "max_age": "5m"
    }
  }
}' | trstctl-cli profiles create -f -

# List the active profiles, and resolve a specific prior version.
trstctl-cli profiles list
trstctl-cli profiles get-version web-server 1
```

A re-create of the same `name` publishes a new version and activates it; the previous
version stays resolvable by number.

## Recovering a known-good version

Recovery is append-only. trstctl never edits an old row or flips an old version back
to active. Instead, it copies the reviewed historical spec into one new active
version. That keeps the full story readable: the bad version still exists for audit,
the recovered version says exactly where it came from, and certificates already
issued keep the profile-version evidence they originally used.

First create an effect-free review. The body pins the active version you saw and
records why recovery is needed:

```bash
cat > profile-restore.json <<'JSON'
{
  "expected_active_version": 2,
  "reason": "Recover the last known-good 24-hour web TLS rule"
}
JSON

trstctl-cli profiles restore-preview web-server 1 -f profile-restore.json
```

The preview reports the historical source, current active version, new version,
semantic spec digest, request fingerprint, risks, and verification steps. It writes
no event, creates no approval, changes no rule, and contacts no external system.
After checking that receipt, submit the same body:

```bash
trstctl-cli profiles restore web-server 1 \
  --idempotency-key profile-recovery-2026-08-28 \
  -f profile-restore.json
```

The server rechecks `expected_active_version` while holding the projection lock. If
another operator created a newer version after the preview, recovery returns `409`
and creates nothing; preview again instead of rolling over the newer decision. The
same idempotency key returns the original result and cannot create another version.
If either the current or historical rule requires approval, recovery is parked for
a different operator under the existing profile dual-control gate.

## What a profile rejects

An issuance bound to `web-server` above is rejected, with the reason, when it asks for a
disallowed key algorithm, an RSA key below 3072 bits, an EKU outside `serverAuth`, a
validity longer than 2160h, a protocol other than `api`/`acme`, or a SAN outside
`example.com`. A compliant request is signed normally.
