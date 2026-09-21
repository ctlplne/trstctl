// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/editionseam"
)

const (
	pqcMigrationTargetMLDSA65 = "ML-DSA-65"
	pqcMigrationProtocolACME  = "acme"
)

type Service interface {
	Start(ctx context.Context, tenantID string, req APIRequest) (Response, error)
	// PlanPreview runs the same plan the start path would execute, without
	// queueing anything (B-3).
	PlanPreview(ctx context.Context, tenantID string, req APIRequest) (PlanPreviewResponse, error)
	Rollback(ctx context.Context, tenantID, runID string, req RollbackRequest) (RollbackResponse, error)
	Progress(ctx context.Context, tenantID, runID string) (RunProgressResponse, error)
}

type APIRequest struct {
	AssetIDs          []string        `json:"asset_ids"`
	TargetAlgorithm   string          `json:"target_algorithm"`
	Protocol          string          `json:"protocol"`
	RollbackOnFailure bool            `json:"rollback_on_failure"`
	TLSBindings       []APITLSBinding `json:"tls_bindings,omitempty"`
}

type APITLSBinding struct {
	AssetID  string               `json:"asset_id"`
	TargetID string               `json:"target_id"`
	Desired  connector.TLSPosture `json:"desired"`
}

type Response struct {
	RunID                     string                 `json:"run_id"`
	Queued                    int                    `json:"queued"`
	CertificateReissuesQueued int                    `json:"certificate_reissues_queued"`
	TLSFindingsQueued         int                    `json:"tls_findings_queued"`
	TargetAlgorithm           string                 `json:"target_algorithm"`
	EffectiveAlgorithm        string                 `json:"effective_algorithm"`
	Protocol                  string                 `json:"protocol"`
	RollbackConfigured        bool                   `json:"rollback_configured"`
	MigrationProgress         cbom.MigrationProgress `json:"migration_progress"`
	QueuedAt                  time.Time              `json:"queued_at"`
}

type RunProgressResponse struct {
	RunID      string            `json:"run_id"`
	Total      int               `json:"total"`
	Queued     int               `json:"queued"`
	Applied    int               `json:"applied"`
	Failed     int               `json:"failed"`
	RolledBack int               `json:"rolled_back"`
	Findings   []FindingProgress `json:"findings"`
}

type RollbackRequest struct {
	AssetIDs []string `json:"asset_ids"`
	Reason   string   `json:"reason"`
}

type RollbackResponse struct {
	RunID             string                 `json:"run_id"`
	Queued            int                    `json:"queued"`
	Reason            string                 `json:"reason"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
	QueuedAt          time.Time              `json:"queued_at"`
}

func NewAPIOptionsFactory(projection *ProgressProjection) editionseam.LicensedAPIOptionsFactory {
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		if projection == nil {
			return nil, errors.New("pqcmigration: API requires the shared runtime progress projection")
		}
		svc := &pqcMigrationService{
			store: d.Store, log: d.Log, outbox: d.Outbox,
			deployer: d.TLSPostureDeployer, progress: projection,
			integrityKey: d.OutboxIntegrityKey, tenantCrypto: d.TenantCrypto,
		}
		return []api.Option{
			api.WithCoreRoutes(routes(svc)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}

func routes(svc Service) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method: "GET", Path: "/api/v1/pqc/migrations/{run_id}", OperationID: "getPQCMigrationProgress",
			Summary:        "Read projected per-finding PQC TLS rollout progress and receiver evidence",
			Handler:        func(a *api.API) http.HandlerFunc { return progressHandler(a, svc) },
			PathParams:     []api.RouteParam{api.PathStringParam("run_id", "PQC migration run id")},
			ResponseSchema: "PQCMigrationProgress", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			// B-3: see the blast radius before authorizing it. Read-only: no
			// run id, no outbox row, no event.
			Method: "POST", Path: "/api/v1/pqc/migrations/plan", OperationID: "planPQCMigration",
			Summary:       "Preview the PQC migration plan without queueing it",
			Handler:       func(a *api.API) http.HandlerFunc { return planHandler(a, svc) },
			RequestSchema: "PQCMigrationRequest", ResponseSchema: "PQCMigrationPlan",
			SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "POST", Path: "/api/v1/pqc/migrations", OperationID: "startPQCMigration",
			Summary:       "Queue PQC re-issuance for CBOM assets through the served protocol path",
			Handler:       func(a *api.API) http.HandlerFunc { return startHandler(a, svc) },
			RequestSchema: "PQCMigrationRequest", ResponseSchema: "PQCMigration",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsIssue,
		},
		{
			Method: "POST", Path: "/api/v1/pqc/migrations/{run_id}/rollback", OperationID: "rollbackPQCMigration",
			Summary:       "Queue rollback for a PQC migration run",
			Handler:       func(a *api.API) http.HandlerFunc { return rollbackHandler(a, svc) },
			PathParams:    []api.RouteParam{api.PathStringParam("run_id", "PQC migration run id")},
			RequestSchema: "PQCMigrationRollbackRequest", ResponseSchema: "PQCMigrationRollback",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsIssue,
		},
	}
}

func progressHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProgressProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		runID := r.PathValue("run_id")
		if runID == "" {
			writeProgressProblem(w, http.StatusBadRequest, "run_id is required")
			return
		}
		start := time.Now()
		resp, err := svc.Progress(r.Context(), tenantID, runID)
		a.ObserveFeature("pqc_migration", "progress", start, err)
		if err != nil {
			writeProgressProblem(w, http.StatusNotFound, "PQC migration run not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func writeProgressProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "about:blank", "title": http.StatusText(status), "status": status, "detail": detail,
	})
}

func planHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			a.WriteProblemUnauthorized(w)
			return
		}
		var req APIRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			a.WriteError(w, api.ErrWithStatus(http.StatusBadRequest, err))
			return
		}
		if len(req.AssetIDs) == 0 {
			a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "asset_ids must contain at least one CBOM asset"))
			return
		}
		if req.TargetAlgorithm == "" {
			req.TargetAlgorithm = pqcMigrationTargetMLDSA65
		}
		if req.Protocol == "" {
			req.Protocol = pqcMigrationProtocolACME
		}
		plan, err := svc.PlanPreview(r.Context(), tenantID, req)
		if err != nil {
			a.WriteError(w, err)
			return
		}
		a.WriteJSON(w, http.StatusOK, plan)
	}
}

func startHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var req APIRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if len(req.AssetIDs) == 0 {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "asset_ids must contain at least one CBOM asset")
			}
			if req.TargetAlgorithm == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "target_algorithm is required")
			}
			if req.TargetAlgorithm != pqcMigrationTargetMLDSA65 {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "certificate-key PQC migration currently accepts target_algorithm "+pqcMigrationTargetMLDSA65)
			}
			if req.Protocol == "" {
				req.Protocol = pqcMigrationProtocolACME
			}
			if req.Protocol != pqcMigrationProtocolACME {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "protocol must be "+pqcMigrationProtocolACME)
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("pqc_migration", "start", start, opErr) }()
			resp, err := svc.Start(ctx, tenantID, req)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, resp, nil
		})
	}
}

func rollbackHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			runID := r.PathValue("run_id")
			if runID == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "run_id is required")
			}
			var req RollbackRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if len(req.AssetIDs) == 0 {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "asset_ids must contain at least one CBOM asset")
			}
			if req.Reason == "" {
				req.Reason = "operator rollback"
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("pqc_migration", "rollback", start, opErr) }()
			resp, err := svc.Rollback(ctx, tenantID, runID, req)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, resp, nil
		})
	}
}

func schemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"PQCMigrationRequest": api.ObjectSchema(map[string]*api.Schema{
			"asset_ids":           api.ArraySchema(api.StringSchema()),
			"target_algorithm":    api.StringSchema(),
			"protocol":            api.StringSchema(),
			"rollback_on_failure": api.BooleanSchema(),
			"tls_bindings":        api.ArraySchema(api.SchemaRef("PQCMigrationTLSBinding")),
		}, "asset_ids", "target_algorithm"),
		"PQCMigrationPlanReissue": api.ObjectSchema(map[string]*api.Schema{
			"asset_id": api.StringSchema(), "location": api.StringSchema(),
			"current_algorithm": api.StringSchema(), "target_algorithm": api.StringSchema(),
			"effective_algorithm": api.StringSchema(), "protocol": api.StringSchema(),
			"rollback_on_failure": api.BooleanSchema(),
		}, "asset_id", "target_algorithm", "protocol"),
		"PQCMigrationPlanTLSRollout": api.ObjectSchema(map[string]*api.Schema{
			"asset_id": api.StringSchema(), "location": api.StringSchema(),
			"finding_kind": api.StringSchema(), "target_id": api.StringSchema(),
			"rollback_on_failure": api.BooleanSchema(),
		}, "asset_id", "finding_kind", "target_id"),
		"PQCMigrationPlanResidual": api.ObjectSchema(map[string]*api.Schema{
			"id": api.StringSchema(), "status": api.StringSchema(), "reason": api.StringSchema(),
		}, "id", "status"),
		"PQCMigrationPlan": api.ObjectSchema(map[string]*api.Schema{
			"reissues":          api.ArraySchema(api.SchemaRef("PQCMigrationPlanReissue")),
			"tls_rollouts":      api.ArraySchema(api.SchemaRef("PQCMigrationPlanTLSRollout")),
			"residuals":         api.ArraySchema(api.SchemaRef("PQCMigrationPlanResidual")),
			"reissue_count":     api.IntegerSchema(),
			"tls_rollout_count": api.IntegerSchema(),
		}, "reissues", "tls_rollouts", "residuals", "reissue_count", "tls_rollout_count"),
		"PQCMigrationTLSPosture": api.ObjectSchema(map[string]*api.Schema{
			"minimum_version":     api.StringSchema(),
			"cipher_suites":       api.ArraySchema(api.StringSchema()),
			"key_exchange_groups": api.ArraySchema(api.StringSchema()),
		}, "minimum_version", "cipher_suites", "key_exchange_groups"),
		"PQCMigrationTLSBinding": api.ObjectSchema(map[string]*api.Schema{
			"asset_id": api.StringSchema(), "target_id": api.StringSchema(),
			"desired": api.SchemaRef("PQCMigrationTLSPosture"),
		}, "asset_id", "target_id", "desired"),
		"PQCMigration": api.ObjectSchema(map[string]*api.Schema{
			"run_id":                      api.StringSchema(),
			"queued":                      api.IntegerSchema(),
			"certificate_reissues_queued": api.IntegerSchema(),
			"tls_findings_queued":         api.IntegerSchema(),
			"target_algorithm":            api.StringSchema(),
			"effective_algorithm":         api.StringSchema(),
			"protocol":                    api.StringSchema(),
			"rollback_configured":         api.BooleanSchema(),
			"migration_progress":          api.SchemaRef("CBOMMigrationProgress"),
			"queued_at":                   api.TimestampSchema(),
		}, "run_id", "queued", "certificate_reissues_queued", "tls_findings_queued", "target_algorithm", "effective_algorithm", "protocol", "rollback_configured", "migration_progress", "queued_at"),
		"PQCMigrationFindingProgress": api.ObjectSchema(map[string]*api.Schema{
			"run_id": api.StringSchema(), "asset_id": api.StringSchema(), "finding_kind": api.StringSchema(),
			"target_id": api.StringSchema(), "target_revision": api.StringSchema(), "connector": api.StringSchema(),
			"desired": api.SchemaRef("PQCMigrationTLSPosture"), "previous": api.SchemaRef("PQCMigrationTLSPosture"),
			"observed": api.SchemaRef("PQCMigrationTLSPosture"), "status": api.StringSchema(),
			"failure": api.StringSchema(), "updated_at": api.TimestampSchema(),
		}, "run_id", "asset_id", "finding_kind", "target_id", "target_revision", "connector", "desired", "status", "updated_at"),
		"PQCMigrationProgress": api.ObjectSchema(map[string]*api.Schema{
			"run_id": api.StringSchema(), "total": api.IntegerSchema(), "queued": api.IntegerSchema(),
			"applied": api.IntegerSchema(), "failed": api.IntegerSchema(), "rolled_back": api.IntegerSchema(),
			"findings": api.ArraySchema(api.SchemaRef("PQCMigrationFindingProgress")),
		}, "run_id", "total", "queued", "applied", "failed", "rolled_back", "findings"),
		"PQCMigrationRollbackRequest": api.ObjectSchema(map[string]*api.Schema{
			"asset_ids": api.ArraySchema(api.StringSchema()),
			"reason":    api.StringSchema(),
		}, "asset_ids"),
		"PQCMigrationRollback": api.ObjectSchema(map[string]*api.Schema{
			"run_id":             api.StringSchema(),
			"queued":             api.IntegerSchema(),
			"reason":             api.StringSchema(),
			"migration_progress": api.SchemaRef("CBOMMigrationProgress"),
			"queued_at":          api.TimestampSchema(),
		}, "run_id", "queued", "reason", "migration_progress", "queued_at"),
	}
}

// B-3: the planner's served shape. It mirrors the plan the start path would
// execute — same BuildPlan, same assets — so a preview can never describe a
// different migration from the one that runs.
type PlanPreviewReissue struct {
	AssetID            string `json:"asset_id"`
	Location           string `json:"location"`
	CurrentAlgorithm   string `json:"current_algorithm"`
	TargetAlgorithm    string `json:"target_algorithm"`
	EffectiveAlgorithm string `json:"effective_algorithm"`
	Protocol           string `json:"protocol"`
	RollbackOnFailure  bool   `json:"rollback_on_failure"`
}

type PlanPreviewTLSRollout struct {
	AssetID           string `json:"asset_id"`
	Location          string `json:"location"`
	FindingKind       string `json:"finding_kind"`
	TargetID          string `json:"target_id"`
	RollbackOnFailure bool   `json:"rollback_on_failure"`
}

// PlanPreviewResidual names an asset the plan will NOT migrate, and why —
// the half of the answer a blast-radius review actually needs.
type PlanPreviewResidual struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type PlanPreviewResponse struct {
	Reissues        []PlanPreviewReissue    `json:"reissues"`
	TLSRollouts     []PlanPreviewTLSRollout `json:"tls_rollouts"`
	Residuals       []PlanPreviewResidual   `json:"residuals"`
	ReissueCount    int                     `json:"reissue_count"`
	TLSRolloutCount int                     `json:"tls_rollout_count"`
}
