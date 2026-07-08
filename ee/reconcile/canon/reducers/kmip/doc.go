// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package kmip maps read-only KMIP endpoint metadata into XREC canonical
// observed records. It reuses the served EE KMIP TTLV parser and keeps all XREC
// reducer logic under ee/reconcile; internal/kmip remains empty.
package kmip
