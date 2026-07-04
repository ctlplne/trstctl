// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/editionseam"
)

const (
	pqcMigrationTargetMLDSA65 = "ML-DSA-65"
	pqcMigrationProtocolACME  = "acme"
)

type Service interface {
	Start(ctx context.Context, tenantID string, req APIRequest) (Response, error)
	Rollback(ctx context.Context, tenantID, runID string, req RollbackRequest) (RollbackResponse, error)
}

type APIRequest struct {
	AssetIDs          []string `json:"asset_ids"`
	TargetAlgorithm   string   `json:"target_algorithm"`
	Protocol          string   `json:"protocol"`
	RollbackOnFailure bool     `json:"rollback_on_failure"`
}

type Response struct {
	RunID              string                 `json:"run_id"`
	Queued             int                    `json:"queued"`
	TargetAlgorithm    string                 `json:"target_algorithm"`
	EffectiveAlgorithm string                 `json:"effective_algorithm"`
	Protocol           string                 `json:"protocol"`
	RollbackConfigured bool                   `json:"rollback_configured"`
	MigrationProgress  cbom.MigrationProgress `json:"migration_progress"`
	QueuedAt           time.Time              `json:"queued_at"`
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

func NewAPIOptionsFactory() editionseam.LicensedAPIOptionsFactory {
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		svc := &pqcMigrationService{store: d.Store, log: d.Log, outbox: d.Outbox}
		return []api.Option{
			api.WithLicensedRoutes(routes(svc)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}

func routes(svc Service) []api.LicensedRoute {
	return []api.LicensedRoute{
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
		}, "asset_ids", "target_algorithm"),
		"PQCMigration": api.ObjectSchema(map[string]*api.Schema{
			"run_id":              api.StringSchema(),
			"queued":              api.IntegerSchema(),
			"target_algorithm":    api.StringSchema(),
			"effective_algorithm": api.StringSchema(),
			"protocol":            api.StringSchema(),
			"rollback_configured": api.BooleanSchema(),
			"migration_progress":  api.SchemaRef("CBOMMigrationProgress"),
			"queued_at":           api.TimestampSchema(),
		}, "run_id", "queued", "target_algorithm", "effective_algorithm", "protocol", "rollback_configured", "migration_progress", "queued_at"),
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
