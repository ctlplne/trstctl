# Authoring certificate profiles

Certificate **profiles** (S8.1) govern what a certificate may be: the allowed key
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
    "allowed_dns_suffixes": ["example.com"]
  }
}' | trstctl-cli profiles create -f -

# List the active profiles, and resolve a specific prior version.
trstctl-cli profiles list
trstctl-cli profiles get-version web-server 1
```

A re-create of the same `name` publishes a new version and activates it; the previous
version stays resolvable by number.

## What a profile rejects

An issuance bound to `web-server` above is rejected, with the reason, when it asks for a
disallowed key algorithm, an RSA key below 3072 bits, an EKU outside `serverAuth`, a
validity longer than 2160h, a protocol other than `api`/`acme`, or a SAN outside
`example.com`. A compliant request is signed normally.
