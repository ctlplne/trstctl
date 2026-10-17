// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

// CARegistrations derives dependencies from the original, immutable CA action.
// A second registration event would leave a crash window after signing and would
// miss leaves issued before VDEC was installed. The returned identity matches
// the certificate inventory when that event carries one; serial-only legacy
// events remain visible as conservative dependencies without inventing a leaf.
func CARegistrations(e eventspec.Event) ([]DependencyRegisteredV1, error) {
	var keyID, dependentID string
	switch e.Type {
	case projections.EventCAEndEntityIssued, projections.EventCAIssuedCertificate, projections.EventCAIntermediateCSRIssued:
		if err := projections.ValidateSchemaVersion(e); err != nil {
			return nil, err
		}
		var leaf struct {
			ID     string `json:"id"`
			CAID   string `json:"ca_id"`
			Serial string `json:"serial"`
		}
		if err := json.Unmarshal(e.Data, &leaf); err != nil {
			return nil, fmt.Errorf("depstate: decode %s: %w", e.Type, err)
		}
		if leaf.CAID == "" || leaf.Serial == "" {
			if e.Type == projections.EventCAIntermediateCSRIssued && leaf.Serial == "" {
				return nil, nil // Preparing an offline-parent CSR has not issued a certificate.
			}
			return nil, fmt.Errorf("depstate: %s requires ca_id and serial", e.Type)
		}
		keyID = leaf.CAID
		switch {
		case e.Type == projections.EventCAEndEntityIssued && e.SchemaVersion == projections.CAEndEntityInventorySchemaVersion:
			if leaf.ID == "" {
				return nil, fmt.Errorf("depstate: managed CA leaf requires inventory id")
			}
			dependentID = leaf.ID
		case e.Type == projections.EventCAEndEntityIssued && e.SchemaVersion == projections.CAIssuedCertificateEvidenceSchemaVersion:
			if e.ID == "" {
				return nil, fmt.Errorf("depstate: historical managed CA leaf requires event id")
			}
			dependentID = projections.LegacyManagedCAInventoryID(e)
		case e.Type == projections.EventCAIssuedCertificate && e.SchemaVersion == projections.CASecretInventorySchemaVersion:
			if e.ID == "" {
				return nil, fmt.Errorf("depstate: PKI secret leaf requires event id")
			}
			dependentID = projections.SecretPKIInventoryID(e)
		default:
			dependentID = "serial:" + leaf.Serial
		}
	case projections.EventCAIntermediateCreated, projections.EventCAAuthorityImported:
		if err := projections.ValidateSchemaVersion(e); err != nil {
			return nil, err
		}
		if e.SchemaVersion == 1 {
			return nil, nil // Audit-only legacy event lacks a recoverable authority.
		}
		var authority struct {
			CAID     string  `json:"ca_id"`
			ParentID *string `json:"parent_id"`
		}
		if err := json.Unmarshal(e.Data, &authority); err != nil {
			return nil, fmt.Errorf("depstate: decode %s: %w", e.Type, err)
		}
		if authority.ParentID == nil || *authority.ParentID == "" {
			return nil, nil
		}
		if authority.CAID == "" {
			return nil, fmt.Errorf("depstate: child CA requires ca_id")
		}
		keyID, dependentID = *authority.ParentID, authority.CAID
	case projections.EventCAAuthorityRekeyed:
		if err := projections.ValidateSchemaVersion(e); err != nil {
			return nil, err
		}
		var authority struct {
			ID                     string  `json:"id"`
			PredecessorID          string  `json:"predecessor_ca_id"`
			ParentID               *string `json:"parent_id"`
			NewSignedByPreviousDER []byte  `json:"new_signed_by_previous_der"`
		}
		if err := json.Unmarshal(e.Data, &authority); err != nil {
			return nil, fmt.Errorf("depstate: decode %s: %w", e.Type, err)
		}
		if authority.ID == "" || authority.PredecessorID == "" {
			return nil, fmt.Errorf("depstate: rekeyed CA requires successor and predecessor ids")
		}
		registrations := make([]DependencyRegisteredV1, 0, 2)
		if len(authority.NewSignedByPreviousDER) != 0 {
			registrations = append(registrations, DependencyRegisteredV1{
				TenantID: e.TenantID, KeyID: authority.PredecessorID,
				Dependent: Dependent{Class: DependentCredential, ID: "successor-cross-sign:" + authority.ID},
				Origin:    RegistrationOriginIssued,
			})
		}
		if authority.ParentID != nil && *authority.ParentID != "" && *authority.ParentID != authority.PredecessorID {
			registrations = append(registrations, DependencyRegisteredV1{
				TenantID: e.TenantID, KeyID: *authority.ParentID,
				Dependent: Dependent{Class: DependentCredential, ID: authority.ID},
				Origin:    RegistrationOriginIssued,
			})
		}
		return registrations, nil
	case projections.EventCACrossSigned:
		if err := projections.ValidateSchemaVersion(e); err != nil {
			return nil, err
		}
		var signed struct {
			CAID                string `json:"ca_id"`
			TargetSHA256        string `json:"target_sha256"`
			CrossCertificateDER []byte `json:"cross_certificate_der"`
		}
		if err := json.Unmarshal(e.Data, &signed); err != nil {
			return nil, fmt.Errorf("depstate: decode %s: %w", e.Type, err)
		}
		if len(signed.CrossCertificateDER) == 0 && signed.TargetSHA256 == "" {
			return nil, nil // Historical ceremony-only event has no public receipt.
		}
		if signed.CAID == "" || signed.TargetSHA256 == "" || len(signed.CrossCertificateDER) == 0 {
			return nil, fmt.Errorf("depstate: cross-sign requires exact issuer and public receipt")
		}
		keyID, dependentID = signed.CAID, "cross-sign:"+signed.TargetSHA256
	default:
		return nil, nil
	}
	return []DependencyRegisteredV1{{
		TenantID: e.TenantID, KeyID: keyID,
		Dependent: Dependent{Class: DependentCredential, ID: dependentID},
		Origin:    RegistrationOriginIssued,
	}}, nil
}

// CARegistrationEventTypes is the indexed event-family set that can add a CA
// key dependent after a frozen retirement command. Keep the cut check aligned
// with CARegistrations so a late mint cannot be omitted from the signer gate.
func CARegistrationEventTypes() []string {
	return []string{
		projections.EventCAEndEntityIssued,
		projections.EventCAIssuedCertificate,
		projections.EventCAIntermediateCSRIssued,
		projections.EventCAIntermediateCreated,
		projections.EventCAAuthorityImported,
		projections.EventCAAuthorityRekeyed,
		projections.EventCACrossSigned,
	}
}
