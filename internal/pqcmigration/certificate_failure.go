// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
)

const EventCertificateFindingFailed = "pqc.migration.certificate_finding_failed"

type CertificateFindingFailure struct {
	RunID     string `json:"run_id"`
	AssetID   string `json:"asset_id"`
	Operation string `json:"operation"`
}

func init() {
	if err := events.RegisterPrivacyEventPolicy(EventCertificateFindingFailed, 1, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{
			{Path: "/run_id", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/asset_id", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/operation", Mode: events.PrivacyFieldOpaqueExact},
		},
		PayloadShape: events.PrivacyPayloadShapeOf[CertificateFindingFailure](), RejectSubjectData: true,
	}); err != nil {
		panic(err)
	}
}

func (h *outboxHandler) certificateTerminalFailure(ctx context.Context, m orchestrator.Message) error {
	var failed CertificateFindingFailure
	var expectedKey string
	switch m.Destination {
	case licensedCryptoMigrationReissueDestination:
		var payload pqcMigrationReissuePayload
		if err := json.Unmarshal(m.Payload, &payload); err != nil {
			return err
		}
		failed = CertificateFindingFailure{RunID: payload.RunID, AssetID: payload.AssetID, Operation: "issue"}
		expectedKey = "licensed-crypto-migration:" + payload.RunID + ":" + payload.AssetID
	case licensedCryptoMigrationRollbackDestination:
		var payload pqcMigrationRollbackPayload
		if err := json.Unmarshal(m.Payload, &payload); err != nil {
			return err
		}
		if payload.RunID != payload.Restore.RunID {
			return errors.New("pqcmigration: rollback failure run binding mismatch")
		}
		failed = CertificateFindingFailure{RunID: payload.RunID, AssetID: payload.Restore.AssetID, Operation: "rollback"}
		expectedKey = "licensed-crypto-migration-rollback:" + payload.RunID + ":" + payload.Restore.AssetID
	default:
		return errors.New("pqcmigration: unsupported certificate failure destination")
	}
	if strings.TrimSpace(m.TenantID) == "" || strings.TrimSpace(failed.RunID) == "" || strings.TrimSpace(failed.AssetID) == "" || m.IdempotencyKey != expectedKey {
		return errors.New("pqcmigration: certificate failure does not match its outbox binding")
	}
	if h.appendEvent == nil && (h.log == nil || h.store == nil) {
		return errors.New("pqcmigration: certificate failure requires event log and projection store")
	}
	// Receiver errors and the original payload may contain secrets or connection
	// details. Persist only bound IDs and this closed operation vocabulary.
	return h.appendProjected(ctx, m.TenantID, EventCertificateFindingFailed, failed)
}

func (p *ProgressProjection) applyCertificateFailure(ev eventspec.Event, failed CertificateFindingFailure) error {
	if ev.SchemaVersion != 0 && ev.SchemaVersion != 1 {
		return errors.New("pqcmigration: unsupported certificate failure schema")
	}
	if strings.TrimSpace(ev.TenantID) == "" || strings.TrimSpace(failed.RunID) == "" || strings.TrimSpace(failed.AssetID) == "" {
		return errors.New("pqcmigration: certificate failure requires tenant, run and asset")
	}
	status, reason := TLSFindingFailed, "Certificate issuance attempts exhausted"
	if failed.Operation == "rollback" {
		status, reason = TLSFindingRollbackFailed, "Certificate rollback attempts exhausted"
	} else if failed.Operation != "issue" {
		return errors.New("pqcmigration: unsupported certificate failure operation")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: failed.RunID, assetID: failed.AssetID}
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = failed.RunID, failed.AssetID, "certificate-key"
	item.Status, item.Failure, item.UpdatedAt = status, reason, eventTime(ev)
	p.items[key] = item
	return nil
}
