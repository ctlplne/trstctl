// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
)

// RequestDestination is the outbox destination a control-plane API enqueues a
// "succeed identity X" request to (ee/succession/api). The SuccessionRequestWorker
// consumes it.
const RequestDestination = "pcas.succession-request"

// SuccessionRequestWorker is the outbox handler for pcas.succession-request messages
// (INT-03). It turns a queued request into a real minted, recorded, published
// succession: it resolves the identity's current algorithm-epoch and its per-epoch
// predecessor handle from the serving high-water, builds a MintRequest, and runs it
// idempotently through the orchestrator — mint over the signer transport, then record
// + rp-publish + high-water advance in one transaction. It is idempotent on the
// request id, so at-least-once outbox delivery yields exactly-once minting (claim 6).
type SuccessionRequestWorker struct {
	orch *Orchestrator
}

// NewSuccessionRequestWorker returns a worker that drives successions through orch.
func NewSuccessionRequestWorker(orch *Orchestrator) *SuccessionRequestWorker {
	return &SuccessionRequestWorker{orch: orch}
}

// requestPayload mirrors the ee/succession/api enqueued request (RequestID plus the
// RequestSuccessionRequest fields).
type requestPayload struct {
	RequestID       string `json:"request_id"`
	IdentityID      string `json:"identity_id"`
	CredentialType  string `json:"credential_type"`
	TargetAlgorithm string `json:"target_algorithm"`
	PolicyRef       string `json:"policy_ref"`
	DeploymentScope string `json:"deployment_scope"`
}

// Deliver implements the core outbox Handler (internal/orchestrator.Handler) for
// pcas.succession-request messages, so the worker can be registered on the outbox
// dispatcher. It must be idempotent on the message — it is, via the request id.
func (w *SuccessionRequestWorker) Deliver(ctx context.Context, m coreorch.Message) error {
	if m.Destination != RequestDestination {
		return fmt.Errorf("succession worker: unexpected destination %q", m.Destination)
	}
	return w.Handle(ctx, m.TenantID, m.Payload)
}

// Handle turns one succession-request payload for tenantID into a succession.
func (w *SuccessionRequestWorker) Handle(ctx context.Context, tenantID string, payload []byte) error {
	var p requestPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("succession worker: decode request: %w", err)
	}
	if p.IdentityID == "" || p.TargetAlgorithm == "" {
		return errors.New("succession worker: request missing identity or target algorithm")
	}

	// Resolve the identity's current epoch (0 => genesis, no succession yet) and the
	// deterministic predecessor handle the signer holds for it (KeyHandle(id, epoch)).
	epoch, err := w.currentEpoch(ctx, tenantID, p.IdentityID)
	if err != nil {
		return fmt.Errorf("succession worker: read current epoch: %w", err)
	}

	req := signing.MintRequest{
		IdentityID:               p.IdentityID,
		TenantID:                 tenantID,
		DeploymentScope:          p.DeploymentScope,
		PredecessorHandle:        succession.KeyHandle(p.IdentityID, epoch),
		AssertedPredecessorEpoch: epoch,
		TargetAlgorithm:          crypto.Algorithm(p.TargetAlgorithm),
		PolicyRef:                p.PolicyRef,
	}

	// Idempotency: the request id renders at-least-once delivery exactly-once. Fall
	// back to a deterministic per-(identity,epoch) key when a producer omitted one.
	idempotencyKey := p.RequestID
	if idempotencyKey == "" {
		idempotencyKey = "pcas-req:" + p.IdentityID + ":" + strconv.FormatUint(epoch, 10)
	}
	if _, err := w.orch.RunSuccession(ctx, tenantID, req, idempotencyKey); err != nil {
		return fmt.Errorf("succession worker: run succession: %w", err)
	}
	return nil
}

// currentEpoch returns the identity's serving algorithm-epoch high-water, or 0 when
// none is recorded yet (the identity is at genesis and its first succession advances
// it to epoch 1).
func (w *SuccessionRequestWorker) currentEpoch(ctx context.Context, tenantID, identityID string) (uint64, error) {
	var epoch uint64
	err := w.orch.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT epoch FROM identity_algorithm_epoch
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`, identityID).Scan(&epoch)
		if errors.Is(e, pgx.ErrNoRows) {
			epoch = 0
			return nil
		}
		return e
	})
	return epoch, err
}
