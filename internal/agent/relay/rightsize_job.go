// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rightsize"
)

// Right-size on the relay (A64). The queued intent is the control plane's own
// right-size operation record; the relay reads only the fields the
// conversation needs. The entitlement endpoint and the bearer token arrive
// through credential redemption for this attempt, never on the queue, so a
// claim envelope carries neither.

// RightSizeIntent is the subset of the queued operation the relay reads.
type RightSizeIntent struct {
	ID               string          `json:"id"`
	Action           string          `json:"action"`
	Connector        string          `json:"connector"`
	Target           string          `json:"target"`
	InventoryID      string          `json:"inventory_id,omitempty"`
	TargetIdentityID string          `json:"target_identity_id,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	ScopeDelta       json.RawMessage `json:"scope_delta"`
	IdempotencyKey   string          `json:"idempotency_key,omitempty"`
	OutboxKey        string          `json:"outbox_idempotency_key,omitempty"`
}

// RightSizeReport is what the relay signs after a verified mutation.
type RightSizeReport struct {
	OperationID    string `json:"operation_id"`
	Connector      string `json:"connector"`
	Target         string `json:"target"`
	MutationID     string `json:"mutation_id"`
	RollbackRef    string `json:"rollback_ref"`
	ReadbackDigest string `json:"readback_digest"`
}

// Redeemed material names for a right-size attempt.
const (
	RightSizeTokenRef    = "credential.right_size_token" // #nosec G101 -- a credential REFERENCE NAME, not a credential (CWE-798)
	RightSizeEndpointRef = "right_size.endpoint"
)

// Digest binds the report to its own fields for the signed evidence.
func (r RightSizeReport) Digest() string {
	var bytes []byte
	for _, part := range []string{"trstctl-right-size-report/v1", r.OperationID, r.Connector, r.Target,
		r.MutationID, r.RollbackRef, r.ReadbackDigest} {
		bytes = append(bytes, part...)
		bytes = append(bytes, 0)
	}
	return crypto.SHA256Hex(bytes)
}

// ValidateRightSizeReport checks that a signed report answers exactly the
// queued operation and that the signed digest is the report's own.
func ValidateRightSizeReport(intent RightSizeIntent, report RightSizeReport, digest string) error {
	if report.OperationID != intent.ID || report.Connector != intent.Connector || report.Target != intent.Target {
		return errors.New("right-size report does not answer the queued operation")
	}
	if !rightsize.ValidReceiptRef([]byte(report.MutationID)) || !rightsize.ValidReceiptRef([]byte(report.RollbackRef)) ||
		len(report.ReadbackDigest) != 64 || strings.ToLower(report.ReadbackDigest) != report.ReadbackDigest {
		return errors.New("right-size report carries invalid evidence references")
	}
	if digest == "" || digest != report.Digest() {
		return errors.New("right-size report digest does not match the signed evidence")
	}
	return nil
}

func validRightSizeIntent(intent RightSizeIntent) bool {
	return intent.Action == "right_size" && strings.TrimSpace(intent.ID) != "" &&
		strings.TrimSpace(intent.Connector) != "" && strings.TrimSpace(intent.Target) != "" &&
		len(intent.ScopeDelta) > 0 && strings.TrimSpace(intent.OutboxKey) != ""
}

func runRightSize(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent RightSizeIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || !validRightSizeIntent(intent) {
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeRefusedBadPayload)
		return false
	}
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeRefusedNoCredential)
		return false
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoLockedMemory)
		return false
	}
	defer destroy()
	token := material[RightSizeTokenRef]
	endpoint := strings.TrimSpace(string(material[RightSizeEndpointRef]))
	if len(token) == 0 {
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeRefusedNoCredential)
		return false
	}
	if endpoint == "" {
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeRefusedNoEndpoint)
		return false
	}
	tenantID := strings.TrimSpace(string(material["right_size.tenant_id"]))
	mutation, err := rightsize.Apply(ctx, client, rightsize.Input{
		Endpoint: endpoint, Token: token, TenantID: tenantID, IdempotencyKey: intent.OutboxKey,
		Connector: intent.Connector, Target: intent.Target, InventoryID: intent.InventoryID,
		TargetIdentityID: intent.TargetIdentityID, Reason: intent.Reason, ScopeDelta: intent.ScopeDelta,
	})
	if err != nil {
		// The conversation's errors never carry endpoint text or the token,
		// but a relay still reports only the closed phrase.
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeFailedAtEndpoint)
		return false
	}
	result := RightSizeReport{OperationID: intent.ID, Connector: intent.Connector, Target: intent.Target,
		MutationID: mutation.MutationID, RollbackRef: mutation.RollbackRef, ReadbackDigest: mutation.ReadbackDigest}
	encoded, err := json.Marshal(result)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RightSizeFailedAtEndpoint)
		return false
	}
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(encoded), result.Digest())
	return true
}
