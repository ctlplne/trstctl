<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# XREC R-3 Reducer Mapping Tables

These tables document the native fields this package maps into the R-1..R-10 canonical record model. Unlisted fields are dropped unless a later posture rule consumes them outside the canonical record.

## Vault

| Native shape | Native field | Canon target |
|--------------|--------------|--------------|
| secret ref | namespace + path | `record_key.stable_id` as normalized secret reference |
| secret ref | provider version id | `attributes.provider_version_id` |
| secret ref | provider-computed value hash | `attributes.value_sha256` |
| secret ref | returned value bytes | wiped and discarded before `canon.ObservedRecord` |
| PKI certificate | issuer DER + serial | X.509 stable id |
| PKI certificate | subject DN | `attributes.subject_dn` |
| key metadata | logical key id | key stable id |

## Cloud KMS

| Native field | Canon target |
|--------------|--------------|
| key id | key stable id |
| algorithm spec | R-5 algorithm registry |
| state | R-7 status |
| rotation enabled | `attributes.rotation_enabled` |

## trstctl Self

| Projection field | Canon target |
|------------------|--------------|
| issued/observed certs | X.509 canonical records |
| keys | key canonical records |
| workloads | workload-identity canonical records |
| projection checkpoint | observation watermark position |

Self queries are always tenant-filtered by passing the current `tenant_id` into the projection reader.
