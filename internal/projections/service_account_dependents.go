// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const EventServiceDependentHostSaved = "pam.service_dependents.host_saved"
const EventServiceDependentScanQueued = "pam.service_dependents.scan_queued"
const EventServiceDependentScanObserved = "pam.service_dependents.scan_observed"
const EventServiceDependentScanFailed = "pam.service_dependents.scan_failed"

type ServiceDependentHostSaved struct {
	Account servicedependents.AccountBinding `json:"account"`
	AgentID string                           `json:"agent_id"`
	Enabled bool                             `json:"enabled"`
	Actor   string                           `json:"actor"`
	At      time.Time                        `json:"at"`
}
type ServiceDependentScanQueued struct {
	Intent servicedependents.InventoryIntent `json:"intent"`
	Actor  string                            `json:"actor"`
	At     time.Time                         `json:"at"`
}
type ServiceDependentScanObserved struct {
	JobID             int64                             `json:"job_id"`
	Attempt           int                               `json:"attempt"`
	Report            servicedependents.InventoryReport `json:"report"`
	EvidenceDigest    string                            `json:"evidence_digest"`
	ReceiptStatement  string                            `json:"receipt_statement"`
	ReceiptSignature  string                            `json:"receipt_signature_base64"`
	SignerFingerprint string                            `json:"signer_fingerprint"`
	At                time.Time                         `json:"at"`
}
type ServiceDependentScanFailed struct {
	RunID             string    `json:"run_id"`
	JobID             int64     `json:"job_id"`
	Attempt           int       `json:"attempt"`
	Reason            string    `json:"reason"`
	ReceiptStatement  string    `json:"receipt_statement"`
	ReceiptSignature  string    `json:"receipt_signature_base64"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	At                time.Time `json:"at"`
}

func validateServiceDependentReceipt(jobID int64, attempt int, statement, signature, fingerprint string, at time.Time) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if jobID <= 0 || attempt <= 0 || len(statement) == 0 || len(statement) > 32<<10 || err != nil || len(raw) == 0 || len(raw) > 16<<10 || !optionalSHA256Hex(fingerprint) || fingerprint == "" || at.IsZero() {
		return errors.New("service dependent receipt has incomplete signed peer evidence")
	}
	return nil
}
func (p *Projector) applyServiceDependentsTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventServiceDependentHostSaved:
		var value ServiceDependentHostSaved
		if err := decode(e, &value); err != nil {
			return true, err
		}
		if value.Actor == "" || value.At.IsZero() {
			return true, errors.New("service dependent host needs an authenticated actor and time")
		}
		return true, p.store.ApplyServiceDependentHostSavedTx(ctx, tx, e.TenantID, value.Account, value.AgentID, value.Enabled, value.Actor, value.At, e.Sequence)
	case EventServiceDependentScanQueued:
		var value ServiceDependentScanQueued
		if err := decode(e, &value); err != nil {
			return true, err
		}
		if value.Actor == "" || value.At.IsZero() || e.ID != value.Intent.RunID {
			return true, errors.New("service dependent scan source identity differs")
		}
		return true, p.store.ApplyServiceDependentScanQueuedTx(ctx, tx, e.TenantID, e.ID, value.Intent, value.Actor, value.At)
	case EventServiceDependentScanObserved:
		var value ServiceDependentScanObserved
		if err := decode(e, &value); err != nil {
			return true, err
		}
		if err := validateServiceDependentReceipt(value.JobID, value.Attempt, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At); err != nil {
			return true, err
		}
		raw, err := json.Marshal(value.Report)
		if err != nil {
			return true, err
		}
		if value.EvidenceDigest != crypto.SHA256Hex(raw) {
			return true, errors.New("service dependent native metadata digest differs")
		}
		return true, p.store.ApplyServiceDependentScanObservedTx(ctx, tx, e.TenantID, value.JobID, value.Attempt, value.Report, value.EvidenceDigest, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At, e.ID)
	case EventServiceDependentScanFailed:
		var value ServiceDependentScanFailed
		if err := decode(e, &value); err != nil {
			return true, err
		}
		if err := validateServiceDependentReceipt(value.JobID, value.Attempt, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At); err != nil {
			return true, err
		}
		if !canonicalUUID(value.RunID) {
			return true, errors.New("service dependent failed scan has no exact run")
		}
		switch value.Reason {
		case "agent_execution_failed", "invalid_native_report":
		default:
			return true, errors.New("service dependent failure reason is invalid")
		}
		return true, p.store.ApplyServiceDependentScanFailedTx(ctx, tx, e.TenantID, value.RunID, value.JobID, value.Attempt, value.Reason, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At)
	default:
		return false, nil
	}
}
