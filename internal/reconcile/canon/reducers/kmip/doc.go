// SPDX-License-Identifier: BUSL-1.1

// Package kmip maps read-only KMIP endpoint metadata into XREC canonical
// observed records. It reuses the served EE KMIP TTLV parser and keeps all XREC
// reducer logic under internal/reconcile; internal/kmip remains empty.
//
// KMIP is one of the heterogeneous authority types of XREC-claim-17.
package kmip
