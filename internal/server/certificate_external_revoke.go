// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The retained batch authorizes this exact external effect. A changed payload,
// tenant, certificate or CA cannot turn an old command into new authority.
func (d *issuanceDispatcher) handleExternalCertificateRevocation(ctx context.Context, message orchestrator.Message, command store.ExternalCertificateRevocation) error {
	if command.EventID == "" || command.CertificateID == "" || command.ExternalCAID == "" || d.log == nil {
		return errors.New("server: exact external revocation has no retained command")
	}
	event, found, err := d.log.EventByID(ctx, command.EventID)
	if err != nil {
		return err
	}
	if !found || event.TenantID != message.TenantID || event.Type != projections.EventCertificateRevocationBatchApplied ||
		event.SchemaVersion != projections.CertificateExternalRevocationSchemaVersion {
		return errors.New("server: exact external revocation command is not retained for this tenant")
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		return err
	}
	var batch projections.CertificateRevocationBatchApplied
	if json.Unmarshal(event.Data, &batch) != nil || projections.ValidateCertificateRevocationBatch(batch) != nil || batch.Reason != command.Reason {
		return errors.New("server: invalid retained external revocation command")
	}
	matched := false
	for _, item := range batch.Items {
		if item.ID == command.CertificateID && item.Status == "queued" && item.ExternalCAID == command.ExternalCAID &&
			item.Fingerprint == command.Fingerprint && item.Serial == command.Serial {
			matched = true
		}
	}
	if !matched {
		return errors.New("server: external revocation differs from retained selection")
	}
	resultID := "certificate.external-revoked:" + crypto.SHA256Hex([]byte(message.TenantID+"\x00"+command.EventID+"\x00"+command.CertificateID))
	_, err = d.idem.Do(ctx, message.TenantID, "revoke-exact:"+resultID, func(ctx context.Context) ([]byte, error) {
		certificate, err := d.store.GetCertificate(ctx, message.TenantID, command.CertificateID)
		if err != nil {
			return nil, err
		}
		if certificate.Fingerprint != command.Fingerprint || certificate.Serial != command.Serial {
			return nil, errors.New("server: selected external certificate changed")
		}
		origins, err := d.certificateRevocationOrigins(ctx, message.TenantID, []store.Certificate{certificate})
		if err != nil {
			return nil, err
		}
		if origins[certificate.Fingerprint].ExternalID != command.ExternalCAID {
			return nil, errors.New("server: retained certificate authority differs from revocation command")
		}
		// Close crash-after-append and finite-cache expiry without calling the
		// issuer again. The orchestrator checks and reapplies the exact event.
		if prior, found, err := d.log.EventByID(ctx, resultID); err != nil {
			return nil, err
		} else if !found {
			if err := d.revokeExternalCertificate(ctx, message.TenantID, command.ExternalCAID, certificate, command.Reason); err != nil {
				return nil, err
			}
		} else if prior.TenantID != message.TenantID || prior.Type != projections.EventCertificateRevoked {
			return nil, errors.New("server: external revocation result identity conflicts")
		}
		if err := d.orch.RevokeCertificateForCAWithEventID(ctx, message.TenantID, resultID, certificate.Fingerprint,
			certificate.Serial, "", command.Reason, crypto.CRLReasonCode(crypto.RevocationReason(command.Reason))); err != nil {
			return nil, err
		}
		return []byte(`{"revoked":true}`), nil
	})
	return err
}
