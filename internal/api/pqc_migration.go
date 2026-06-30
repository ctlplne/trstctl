package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/pqcmigration"
)

// PQCMigrationService is the served F57 orchestrator surface. Implementations read
// the CBOM projection, append migration events, and enqueue all re-issuance and
// rollback work through the outbox.
type PQCMigrationService interface {
	Start(ctx context.Context, tenantID string, req PQCMigrationRequest) (PQCMigrationResponse, error)
	Rollback(ctx context.Context, tenantID, runID string, req PQCMigrationRollbackRequest) (PQCMigrationRollbackResponse, error)
}

// WithPQCMigration wires the served PQC migration orchestrator. When nil, the
// routes fail closed so operators do not mistake a library-only build for a served
// migration system.
func WithPQCMigration(svc PQCMigrationService) Option {
	return func(c *config) { c.pqcMigration = svc }
}

// PQCMigrationRequest queues re-issuance for CBOM assets. TargetAlgorithm is the
// customer target from the CBOM inventory (for certificate keys, ML-DSA-65/FIPS
// 204); the served implementation may use a transition hybrid certificate where
// stock X.509 clients still require a classical subject key.
type PQCMigrationRequest struct {
	AssetIDs          []string `json:"asset_ids"`
	TargetAlgorithm   string   `json:"target_algorithm"`
	Protocol          string   `json:"protocol"`
	RollbackOnFailure bool     `json:"rollback_on_failure"`
}

type PQCMigrationResponse struct {
	RunID              string                 `json:"run_id"`
	Queued             int                    `json:"queued"`
	TargetAlgorithm    string                 `json:"target_algorithm"`
	EffectiveAlgorithm string                 `json:"effective_algorithm"`
	Protocol           string                 `json:"protocol"`
	RollbackConfigured bool                   `json:"rollback_configured"`
	MigrationProgress  cbom.MigrationProgress `json:"migration_progress"`
	QueuedAt           time.Time              `json:"queued_at"`
}

type PQCMigrationRollbackRequest struct {
	AssetIDs []string `json:"asset_ids"`
	Reason   string   `json:"reason"`
}

type PQCMigrationRollbackResponse struct {
	RunID             string                 `json:"run_id"`
	Queued            int                    `json:"queued"`
	Reason            string                 `json:"reason"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
	QueuedAt          time.Time              `json:"queued_at"`
}

//trstctl:mutation
func (a *API) startPQCMigration(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pqcMigration == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration orchestration is not configured")
		}
		var req PQCMigrationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.AssetIDs) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "asset_ids must contain at least one CBOM asset")
		}
		if req.TargetAlgorithm == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "target_algorithm is required")
		}
		if req.TargetAlgorithm != pqcmigration.TargetMLDSA65 {
			return 0, nil, errStatus(http.StatusBadRequest, "certificate-key PQC migration currently accepts target_algorithm "+pqcmigration.TargetMLDSA65)
		}
		if req.Protocol == "" {
			req.Protocol = pqcmigration.ProtocolACME
		}
		if req.Protocol != pqcmigration.ProtocolACME {
			return 0, nil, errStatus(http.StatusBadRequest, "protocol must be "+pqcmigration.ProtocolACME)
		}
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("pqc_migration", "start", start, opErr) }()
		resp, err := a.pqcMigration.Start(ctx, tenantID, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusAccepted, resp, nil
	})
}

//trstctl:mutation
func (a *API) rollbackPQCMigration(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pqcMigration == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration orchestration is not configured")
		}
		runID := r.PathValue("run_id")
		if runID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "run_id is required")
		}
		var req PQCMigrationRollbackRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.AssetIDs) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "asset_ids must contain at least one CBOM asset")
		}
		if req.Reason == "" {
			req.Reason = "operator rollback"
		}
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("pqc_migration", "rollback", start, opErr) }()
		resp, err := a.pqcMigration.Rollback(ctx, tenantID, runID, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusAccepted, resp, nil
	})
}
