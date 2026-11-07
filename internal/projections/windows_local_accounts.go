// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostaccounts"
)

const EventWindowsLocalAccountScanQueued = "pam.windows_local_accounts.scan_queued"
const EventWindowsLocalAccountScanObserved = "pam.windows_local_accounts.scan_observed"
const EventWindowsLocalAccountScanFailed = "pam.windows_local_accounts.scan_failed"

type WindowsLocalAccountScanQueued struct {
	Intent hostaccounts.InventoryIntent `json:"intent"`
	Actor  string                       `json:"actor"`
	At     time.Time                    `json:"at"`
}
type WindowsLocalAccountScanObserved struct {
	JobID             int64                        `json:"job_id"`
	Attempt           int                          `json:"attempt"`
	Report            hostaccounts.InventoryReport `json:"report"`
	EvidenceDigest    string                       `json:"evidence_digest"`
	ReceiptStatement  string                       `json:"receipt_statement"`
	ReceiptSignature  string                       `json:"receipt_signature_base64"`
	SignerFingerprint string                       `json:"signer_fingerprint"`
	At                time.Time                    `json:"at"`
}
type WindowsLocalAccountScanFailed struct {
	RunID             string    `json:"run_id"`
	JobID             int64     `json:"job_id"`
	Attempt           int       `json:"attempt"`
	Reason            string    `json:"reason"`
	ReceiptStatement  string    `json:"receipt_statement"`
	ReceiptSignature  string    `json:"receipt_signature_base64"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	At                time.Time `json:"at"`
}

func (p *Projector) applyWindowsLocalAccountsTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventWindowsLocalAccountScanQueued:
		var v WindowsLocalAccountScanQueued
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if v.Intent.TenantID != e.TenantID || v.Intent.RunID != e.ID || v.Actor == "" || v.At.IsZero() {
			return true, errors.New("local account inventory source differs")
		}
		return true, p.store.ApplyWindowsLocalAccountScanQueuedTx(ctx, tx, e.TenantID, e.ID, v.Intent, v.Actor, v.At)
	case EventWindowsLocalAccountScanObserved:
		var v WindowsLocalAccountScanObserved
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if err := validateServiceDependentReceipt(v.JobID, v.Attempt, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At); err != nil {
			return true, err
		}
		raw, err := json.Marshal(v.Report)
		if err != nil || crypto.SHA256Hex(raw) != v.EvidenceDigest {
			return true, errors.New("local account inventory evidence digest differs")
		}
		return true, p.store.ApplyWindowsLocalAccountScanObservedTx(ctx, tx, e.TenantID, e.ID, v.JobID, v.Attempt, v.Report, v.EvidenceDigest, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At)
	case EventWindowsLocalAccountScanFailed:
		var v WindowsLocalAccountScanFailed
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if err := validateServiceDependentReceipt(v.JobID, v.Attempt, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At); err != nil {
			return true, err
		}
		if !canonicalUUID(v.RunID) || (v.Reason != "agent_execution_failed" && v.Reason != "invalid_native_report") {
			return true, errors.New("local account inventory failure identity differs")
		}
		return true, p.store.ApplyWindowsLocalAccountScanFailedTx(ctx, tx, e.TenantID, v.RunID, e.ID, v.JobID, v.Attempt, v.Reason, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At)
	default:
		return false, nil
	}
}
func addWindowsLocalAccountPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	exact := events.PrivacyFieldOpaqueExact
	policies[privacyEventPolicyKey{EventWindowsLocalAccountScanQueued, 1}] = privacyRules(privacyRule("/intent", exact), privacyRule("/actor", events.PrivacyFieldIdentityExact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventWindowsLocalAccountScanObserved, 1}] = privacyRules(privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/report", exact), privacyRule("/evidence_digest", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventWindowsLocalAccountScanFailed, 1}] = privacyRules(privacyRule("/run_id", exact), privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/reason", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
}
func addWindowsLocalAccountPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventWindowsLocalAccountScanQueued, 1}] = privacyPayloadShape[WindowsLocalAccountScanQueued]()
	shapes[privacyEventPolicyKey{EventWindowsLocalAccountScanObserved, 1}] = privacyPayloadShape[WindowsLocalAccountScanObserved]()
	shapes[privacyEventPolicyKey{EventWindowsLocalAccountScanFailed, 1}] = privacyPayloadShape[WindowsLocalAccountScanFailed]()
}
