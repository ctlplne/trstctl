// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// retainLateReceipt runs under the store's attempt lock. Persistent lookup is
// necessary even after JetStream forgets a message ID. A failed SQL commit must
// never let a later report replace facts already accepted into the event log.
func (a *agentService) retainLateReceipt(ctx context.Context, proposed events.Event, receipt store.AgentJobReceipt) (store.AgentJobReceipt, error) {
	proposed.ID = fmt.Sprintf("agent-terminal-receipt/v1/%s/%d/%d", proposed.TenantID, receipt.JobID, receipt.Attempt)
	canonical, found, err := a.log.EventByID(ctx, proposed.ID)
	if err != nil {
		return receipt, err
	}
	if !found {
		canonical, err = a.log.Append(ctx, proposed)
		if err != nil {
			return receipt, err
		}
	}
	var payload struct {
		Agent       string `json:"agent"`
		JobID       int64  `json:"job_id"`
		Kind        string `json:"kind"`
		Attempt     int    `json:"attempt"`
		Outcome     string `json:"outcome"`
		Applied     *bool  `json:"current_state_applied"`
		Statement   string `json:"receipt_statement"`
		Signature   string `json:"receipt_signature"`
		Fingerprint string `json:"receipt_signer_fingerprint"`
	}
	if canonical.ID != proposed.ID || canonical.TenantID != proposed.TenantID || canonical.Type != proposed.Type ||
		canonical.SchemaVersion != events.DefaultSchemaVersion || canonical.Time.IsZero() || json.Unmarshal(canonical.Data, &payload) != nil ||
		payload.Applied == nil || *payload.Applied || payload.Statement == "" || payload.Signature == "" || payload.Fingerprint == "" {
		return receipt, errors.New("server: retained terminal receipt is invalid")
	}
	if payload.Agent != receipt.Agent || payload.JobID != receipt.JobID || payload.Attempt != receipt.Attempt ||
		payload.Kind != receipt.Kind || payload.Outcome != receipt.Outcome ||
		!store.SameAgentJobReceiptObservation(payload.Statement, receipt.Statement) {
		return receipt, store.ErrAgentJobReceiptConflict
	}
	// Restore the original signed bytes and signer together. Using the retry's
	// fresh signature with the retained statement would create invalid evidence.
	receipt.Statement, receipt.Signature = payload.Statement, payload.Signature
	receipt.SignerFingerprint, receipt.ObservedAt = payload.Fingerprint, canonical.Time
	return receipt, nil
}
