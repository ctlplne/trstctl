// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// rollbackReceiptNamespace scopes the deterministic receipt ids for this
// surface, so they cannot collide with any other UUIDv5 the system derives.
var rollbackReceiptNamespace = uuid.MustParse("6f1d9a52-0f2a-4a5e-9a41-2f9c7f6b0d31")

// The rollback result receipt (epic D4).
//
// Queueing a rollback and executing one are different facts, and the evidence
// chain records both. The queue receipt says an operator asked; this one says an
// agent performed the family-specific rollback. Collapsing them into a single
// "rolled back" written at request time is exactly the memo-only receipt this
// epic replaced.

// rollbackVerificationDetail turns the agent's verification report (the same
// EndpointVerifyReport shape a deploy carries) into the sentence an operator
// needs when a restore ran but re-verification failed: what the listener
// served against what was expected, or why it could not be reached. B9-R1:
// without it the receipt said only "re-verification failed" and the cause
// was unrecoverable after the fact. Anything that does not decode is left
// out; the receipt never carries raw agent text.
// reportedChainMismatch reports whether a signed rollback verification
// observed the predecessor leaf with other issuers (B10-L1).
func reportedChainMismatch(agentDetail string) bool {
	var report relay.EndpointVerifyReport
	if err := decodeStrictJSON([]byte(agentDetail), &report); err != nil || len(report.Results) != 1 {
		return false
	}
	tr := report.Results[0].Transcript
	return tr.Reached && tr.Mismatch == certinfo.MismatchChain
}

func rollbackVerificationDetail(agentDetail string) string {
	var report relay.EndpointVerifyReport
	if err := decodeStrictJSON([]byte(agentDetail), &report); err != nil || len(report.Results) != 1 {
		return ""
	}
	result := report.Results[0]
	tr := result.Transcript
	short := func(fp string) string {
		fp = strings.TrimSpace(fp)
		if len(fp) > 12 {
			return fp[:12] + "…"
		}
		return fp
	}
	var out strings.Builder
	out.WriteString(" Listener " + strings.TrimSpace(tr.Address))
	if strings.TrimSpace(tr.ServerName) != "" {
		out.WriteString(" (SNI " + strings.TrimSpace(tr.ServerName) + ")")
	}
	switch {
	case !tr.Reached:
		out.WriteString(" could not be reached")
		if tr.Error != "" {
			out.WriteString(": " + tr.Error)
		}
		out.WriteString(".")
	case tr.Mismatch == certinfo.MismatchChain:
		out.WriteString(" served the expected predecessor " + short(tr.ObservedFingerprint) +
			" with other issuers than were restored (chain mismatch; set strict_chain on the target to fail on this).")
	case tr.Mismatch != "":
		out.WriteString(" served " + short(tr.ObservedFingerprint) + " where " + short(tr.ExpectedFingerprint) + " was expected (" + string(tr.Mismatch) + " mismatch).")
	default:
		out.WriteString(" served " + short(tr.ObservedFingerprint) + ", the expected predecessor.")
	}
	if d := strings.TrimSpace(result.Detail); d != "" {
		out.WriteString(" " + d)
	}
	return out.String()
}

// rollbackReceipt records what an agent reported for a connector.rollback job.
//
// outcome is the relay's own terminal outcome, already verified by the signed
// receipt gate (epic A1) before this runs — so what is recorded here is a claim
// the agent signed, not a claim the control plane invented about itself.
func (s *Server) rollbackReceipt(ctx context.Context, tenantID, agentName string, jobID int64, attempt int, idempotencyKey, payloadJSON, outcome, reason string) {
	if s.orch == nil {
		return
	}
	// The job payload names the connector, the target and the predecessor. It
	// carries no certificate and no key — that is the property that made the
	// rollback executable in the first place.
	var req struct {
		Connector              string `json:"connector"`
		Target                 string `json:"target"`
		IdentityID             string `json:"identity_id"`
		PredecessorFingerprint string `json:"predecessor_fingerprint"`
		PredecessorSerial      string `json:"predecessor_serial"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
		// An agent reporting something this cannot read is version skew, not a
		// rollback result. Recording it either way would be a guess.
		return
	}

	status := servedstatus.ConnectorRolledBack
	receiptReason := "rolled_back"
	detail := "agent " + agentName + " restored the predecessor certificate serial " + req.PredecessorSerial +
		" and completed the connector reload."
	switch outcome {
	case transport.JobOutcomeVerified:
		receiptReason = "rolled_back_and_reverified"
		if reportedChainMismatch(reason) {
			receiptReason = "rolled_back_and_reverified_chain_mismatch"
		}
		detail += " The same agent re-handshook the listener and verified the predecessor is serving."
		detail += rollbackVerificationDetail(reason)
	case transport.JobOutcomeExecuted:
		detail += " No listener verification address was configured, so this receipt does not claim what is serving."
		if reason == transport.RollbackExecutedLegacyObject {
			// A45: no fingerprint-named predecessor object existed; the relay
			// re-bound to the object installed under the target-derived name
			// from before fingerprint naming. Its contents were not re-read.
			receiptReason = "rolled_back_to_legacy_object"
			detail = "agent " + agentName + " found no fingerprint-named predecessor object and re-bound the target to the " +
				"object installed under its target-derived name from before fingerprint naming (expected to hold serial " +
				req.PredecessorSerial + "). That object's contents were not re-read: verify the listener independently."
		}
	case transport.JobOutcomeVerifyFailed:
		status = servedstatus.ConnectorRollbackFailed
		receiptReason = "rollback_restore_reverify_failed"
		detail += " The restore ran, but the same agent's listener re-verification failed." + rollbackVerificationDetail(reason)
	default:
		// Contact is classified from the agent's closed-set reason, never
		// assumed. Five of the failure reasons are refusals made before a socket
		// is opened, and recording those as "the attempt ran against the target"
		// would send an operator to check an appliance that never heard about
		// it. An unrecognized reason falls to refused — the fail-closed
		// direction, since we cannot substantiate contact we did not observe.
		if transport.RollbackReasonContactedTarget(reason) {
			status = servedstatus.ConnectorRollbackFailed
			receiptReason = "rollback_failed"
			detail = "the agent reached the target and the rollback operation did not succeed: " + reason
		} else {
			status = servedstatus.ConnectorRollbackRefused
			receiptReason = "rollback_refused"
			detail = "the agent declined before contacting the target: " + reason
		}
	}

	// A DETERMINISTIC id, so repeated attempts converge on one row instead of
	// appending a new one each time. RecordConnectorDelivery mints a fresh UUID
	// when none is supplied and the projector converges on id — so without this,
	// fail/fail/succeed leaves three rows for one rollback, distinguished only
	// by timestamp, and an evidence export would show conflicting outcomes for
	// the same operation.
	receiptID := uuid.NewSHA1(rollbackReceiptNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
	var identityID *string
	if value := strings.TrimSpace(req.IdentityID); value != "" {
		identityID = &value
	}
	if err := s.orch.RecordConnectorRollbackResult(ctx, tenantID, idempotencyKey, attempt, store.ConnectorDeliveryReceipt{
		ID: receiptID, OutboxID: outboxPtr(jobID), IdentityID: identityID,
		Destination: "connector.rollback", Connector: req.Connector, Target: req.Target,
		Fingerprint: req.PredecessorFingerprint,
		Status:      status, Attempts: attempt, Reason: receiptReason, Detail: detail,
		// A distinct key from the queueing receipt: "we asked" and "it
		// happened" are different facts and both belong in the chain.
		IdempotencyKey: idempotencyKey + ":rollback-result",
	}); err != nil {
		return
	}
}
