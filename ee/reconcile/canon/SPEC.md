<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# XREC Canonicalization Specification

Version: `xrec.canon/v1`

This document is the normative XREC R-1..R-19 profile. XREC-01 implements R-1..R-10 only; R-11..R-19 are written here so later digest, witness, round, quarantine, and remediation cards bind to the same vocabulary.

## R-1 Record Model

A canonical record is a restricted-JSON object with mandatory members: `spec_version`, `record_key`, `record_type`, `tenant_id`, `algorithm`, `validity`, `status`, `provenance`, and `attributes`. The record carries identifiers, public parameters, and metadata only. Secret values, private keys, token values, passwords, and API keys are refused before serialization.

## R-2 Record Keys

The record key is `(tenant_id, record_type, stable_id)` and is the total leaf sort order for R-11. Stable IDs are derived as follows:

- X.509 certificate: lowercase-hex SHA-256 over `DER issuer name || serial bytes`.
- Key: durable logical key id, or lowercase-hex SHA-256 over SubjectPublicKeyInfo DER when no durable id exists.
- Secret reference: normalized `namespace:/path` reference, never the secret value.
- Workload identity: RFC-3986-normalized SPIFFE ID.

## R-3 Schema Mapping

Reducers map native authority fields into the canonical model only when the field has cross-plane meaning. Unmapped fields are dropped. Provider-specific policy facts feed R-13 posture, not opaque canonical attributes.

## R-4 Serialization Ordering

The reference encoding is restricted JSON: object member names sort by strict UTF-8 byte order; no insignificant whitespace is emitted; strings are NFC-normalized; numbers are integers only; duplicate object members after normalization are refused; arrays are used only when the specification defines their order. A length-prefixed binary tuple encoding is an equivalent embodiment, but JSON is the reference profile.

## R-5 Algorithm Registry

Native algorithm names reduce to a single `family-parameter` identifier. Aliases such as `RSA_2048`, `rsa-2048`, and RSA encryption OID spellings reduce to `rsa-2048`; `ECC_NIST_P256`, `ec-p256`, `secp256r1`, and `prime256v1` reduce to `ecdsa-p256`; Ed25519 JOSE/COSE/OID forms reduce to `ed25519`; ML-DSA forms reduce to `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87`. Unknown native identifiers reduce to `unknown-` plus lowercase-hex SHA-256 of the native string.

## R-6 Validity Bucketing

Creation and not-before instants floor to the configured granularity. Deletion and not-after instants ceil to the configured granularity. The v1 reference granularity is 300 seconds. Bucketed seconds enter the canonical record; raw instants remain in observed state for diagnosis.

## R-7 Value Normalization

Statuses reduce to `{active, disabled, revoked, expired, pending_deletion, unknown}`. Byte strings encode as lowercase hex. DNs, URIs, paths, booleans, and integers normalize under the package rules. Absent fields are omitted; `null` is not serialized.

## R-8 Tenant Scoping

Reduction runs for exactly one tenant at a time. Every record and record key carries `tenant_id`. A mixed-tenant reduction is refused.

## R-9 Secret Exclusion

Canonical records and digest-input bytes contain no secret values. Connectors must discard values before persistence; XREC carries only identifiers, public parameters, and provider-computed version/hash stand-ins.

## R-10 Determinism And Idempotence

Reduction is a pure function of `(observed_state, spec_version)`. The same observed substance reduces to byte-identical canonical bytes across runs. `spec_version` is serialized into every record so later digest comparison can refuse mixed versions.

## R-11 Leaves

Later digest code hashes each canonical record as `H(0x00 || "xrec/leaf/v1" || len(record_key_bytes) || record_key_bytes || canonical_record_bytes)`, where `H` is SHA-256 through `internal/crypto`. Leaves sort by R-2 record-key order.

## R-12 Tree

Interior nodes hash as `H(0x01 || "xrec/node/v1" || left || right)`. The domain byte and string separate leaves from nodes. Absence proofs use sorted-leaf bracketing record keys.

## R-13 Policy-Posture Summary

The policy set and per-rule satisfying/violating counts serialize canonically and commit into the signed state digest without enumerating every violating record.

## R-14 Digest

A signed state digest serializes `{version, spec_version, tenant_id, authority_id, merkle_root, policy_posture_summary, observation_watermark}` and is signed inside the isolated signing process.

## R-15 Witness Minimality

A divergence witness discloses only diverging canonical records. Remaining proof material is node hashes and bracketing record keys.

## R-16 Countersignature

In the mutual embodiment, the peer verifies the identical witness content and countersigns that content. Disputes are signed and recorded artifacts.

## R-17 Three-Or-More Plane Majority

Majority comparison is per record key. Minority planes conform to majority canonical content unless policy designates an authoritative plane override. This is tree-and-proof machinery, not abstract consensus.

## R-18 Drift Projections

Witness, remediation, refusal, quarantine, completion, and round-agreement events replay into deterministic metrics under a monotone replay watermark.

## R-19 Refusal

If signer-side plan verification fails, the isolated signer emits a signed refusal record naming the plan, witness hash, and failed check. Corrective operations do not dispatch on failed verification.
