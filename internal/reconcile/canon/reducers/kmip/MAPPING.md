<!-- SPDX-License-Identifier: BUSL-1.1 -->

# XREC KMIP R-3 Mapping

| KMIP observation field | Canon target |
|------------------------|--------------|
| Unique Identifier | key `stable_id` when present; secret reference path for secret objects |
| Object Type = PublicKey/PrivateKey/SymmetricKey | `record_type=key` |
| Object Type = Certificate | `record_type=x509_certificate` using issuer DER + serial |
| Object Type = SecretData/OpaqueObject | `record_type=secret_ref` |
| Cryptographic Algorithm + Cryptographic Length | R-5 algorithm registry input |
| State | R-7 status |
| Initial/Activation/Deactivation dates | R-6 bucketed validity |

The observation client performs Locate and Get-Attributes only. Key material and secret object values are never fetched.
