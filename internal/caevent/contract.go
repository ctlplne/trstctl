// SPDX-License-Identifier: BUSL-1.1

// Package caevent holds the CA event facts shared by the relational projector
// and the isolated signer's retirement gate. It deliberately depends on no
// database, message bus, or HTTP package.
package caevent

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	EventCAIssuedCertificate     = "ca.certificate.issued"
	EventCAAuthorityImported     = "ca.authority.imported"
	EventCAAuthorityRekeyed      = "ca.authority.rekeyed"
	EventCAIntermediateCreated   = "ca.intermediate.created"
	EventCAIntermediateCSRIssued = "ca.intermediate_csr.issued"
	EventCAEndEntityIssued       = "ca.endentity.issued"
	EventCACrossSigned           = "ca.cross_signed"
	// EventCACertificateInventoryRecovered gives a historical PKI-secret leaf
	// the inventory row its v1/v2 mint never projected (A111). It is not a
	// mint: the original event stays the issuance authority.
	EventCACertificateInventoryRecovered     = "ca.certificate.inventory_recovered"
	CAAuthorityCreatedEventSchemaVersion     = 2
	CAIssuedCertificateEvidenceSchemaVersion = 2
	CASecretInventorySchemaVersion           = 3
	CAEndEntityInventorySchemaVersion        = 3
)

var ErrUnknownSchemaVersion = errors.New("caevent: unknown event schema version")

// IsDependencyEvent is the closed event-family set that can add a CA key
// dependent. A new mint family must enter this list before the signer can
// safely decide that a predecessor has no dependents.
func IsDependencyEvent(eventType string) bool {
	switch eventType {
	case EventCAIssuedCertificate, EventCAAuthorityImported, EventCAAuthorityRekeyed,
		EventCAIntermediateCreated, EventCAIntermediateCSRIssued, EventCAEndEntityIssued, EventCACrossSigned:
		return true
	default:
		return false
	}
}

// ValidateSchemaVersion rejects future payload shapes before either consumer
// derives retirement authority from an old decoder. Version zero is the
// historical event-log spelling of version one.
func ValidateSchemaVersion(e eventspec.Event) error {
	version := e.SchemaVersion
	if version == 0 {
		version = eventspec.DefaultSchemaVersion
	}
	accepted := false
	switch e.Type {
	case EventCAIssuedCertificate, EventCAEndEntityIssued:
		accepted = version == 1 || version == CAIssuedCertificateEvidenceSchemaVersion ||
			version == CASecretInventorySchemaVersion
	case EventCAAuthorityImported, EventCAIntermediateCreated:
		accepted = version == 1 || version == CAAuthorityCreatedEventSchemaVersion
	case EventCAAuthorityRekeyed, EventCAIntermediateCSRIssued, EventCACrossSigned:
		accepted = version == 1
	default:
		return nil
	}
	if !accepted {
		return fmt.Errorf("%w: type %q v%d (seq %d)", ErrUnknownSchemaVersion,
			e.Type, version, e.Sequence)
	}
	return nil
}

// LegacyManagedCAInventoryID preserves the exact historical v2 leaf identity
// across read-model rebuilds. The input bytes must not change after release.
func LegacyManagedCAInventoryID(e eventspec.Event) string {
	return crypto.UUIDv5OID([]byte("managed-ca-legacy-inventory\x00" + e.TenantID + "\x00" + e.ID))
}

// SecretPKIInventoryID binds one PKI-secret leaf to its immutable mint event.
func SecretPKIInventoryID(e eventspec.Event) string {
	return crypto.UUIDv5OID([]byte("secret-pki-inventory\x00" + e.TenantID + "\x00" + e.ID))
}

// RecoveredSecretPKIInventoryID is the inventory identity of a historical
// PKI-secret leaf recovered later (A111): the identity its original mint
// event would have had, so recovery never invents a second one.
func RecoveredSecretPKIInventoryID(tenantID, originalEventID string) string {
	return SecretPKIInventoryID(eventspec.Event{TenantID: tenantID, ID: originalEventID})
}
