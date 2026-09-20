// SPDX-License-Identifier: BUSL-1.1

// Package api is the served H4 surface for verifiable decommission: the CA-key
// retirement checklist source behind core's GET /api/v1/ca/keys/{id}/retirement,
// the POST that starts re-protection, and the explicitly confirmed POST that
// freezes evidence for signer-local destruction.
//
// Both attach through the feature-neutral api.Option seam (the internal/succession
// precedent); no VDEC route, handler, or DTO lives in MPL core. Before this
// adapter existed the core route was registered and published in OpenAPI but its
// source had no production caller, so every deployment — licensed or not —
// answered 501 (AUD-3), and the re-protection pipeline behind the outbox handler
// had no producer at all (AUD-2). This package is the missing wiring, not new
// capability: the read model, the planner, and the executors all predate it.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/reprotect"
	"trstctl.com/trstctl/internal/decommission/retirement"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

// ChecklistSource answers the retirement checklist from the tenant-scoped VDEC
// dependency-state read model. It implements api.RetirementChecklistSource.
type ChecklistSource struct {
	repo       *decstore.Repo
	retirement *retirement.Projection
}

// NewChecklistSource builds the source over the VDEC read-model repository.
func NewChecklistSource(repo *decstore.Repo, retirementProjection *retirement.Projection) *ChecklistSource {
	return &ChecklistSource{repo: repo, retirement: retirementProjection}
}

// RetirementChecklist reports the dependents still standing between a key and
// destruction. A key the ledger has never recorded dependency state for returns
// an empty checklist with Total 0 — the truthful projection answer; enforcement
// of the destruction refusal itself lives in the isolated signer, not here.
// DestructionRecord stays empty while the key is alive. Once the outbox worker
// receives the signer's terminal decision, the immutable event projection makes
// the signed refusal or full destruction record readable here.
func (s *ChecklistSource) RetirementChecklist(r *http.Request, tenantID, keyID string) (api.RetirementChecklist, error) {
	state, found, err := s.repo.FetchKeyState(r.Context(), tenantID, keyID)
	if err != nil {
		return api.RetirementChecklist{}, err
	}
	if !found {
		return api.RetirementChecklist{Outstanding: []api.RetirementDependent{}}, nil
	}
	unaccounted := state.Unaccounted()
	outstanding := make([]api.RetirementDependent, 0, len(unaccounted))
	for _, dep := range unaccounted {
		outstanding = append(outstanding, api.RetirementDependent{
			Kind:   string(dep.Class),
			Ref:    dep.ID,
			Detail: resolutionDetail(dep.Class),
		})
	}
	checklist := api.RetirementChecklist{
		Outstanding: outstanding,
		Accounted:   len(state.Registered) - len(unaccounted),
		Total:       len(state.Registered),
	}
	if s.retirement != nil {
		retired, found, err := s.retirement.Fetch(r.Context(), tenantID, keyID)
		if err != nil {
			return api.RetirementChecklist{}, err
		}
		if found {
			checklist.RetirementStatus = retired.Status
			checklist.RefusalRecord = string(retired.RefusalRecord)
			checklist.DestructionRecord = string(retired.DestructionRecord)
		}
	}
	return checklist, nil
}

// resolutionDetail says what would resolve one outstanding dependent, in the
// operator's vocabulary, so the checklist reads as a to-do list.
func resolutionDetail(class depstate.DependentClass) string {
	switch class {
	case depstate.DependentCiphertext:
		return "re-encrypt this ciphertext under a successor key, or release it"
	case depstate.DependentWrappedKey:
		return "re-wrap this key under a successor, or release it"
	case depstate.DependentCredential:
		return "re-issue this credential under a successor, or release it"
	case depstate.DependentLeasedSecret:
		return "revoke this lease, or release it"
	case depstate.DependentDataSet:
		return "re-derive this data set under a successor, or release it"
	default:
		return "re-protect this dependent under a successor, or release it"
	}
}

// ReprotectionJobReceipt is one planned job in the start-re-protection answer.
type ReprotectionJobReceipt struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	DependentClass string `json:"dependent_class"`
	DependentRef   string `json:"dependent_ref"`
	// Enqueued false means an identical job was already queued (a replayed
	// start); the work happens once either way.
	Enqueued bool `json:"enqueued"`
}

// ReprotectionReceipt is the served answer to "start re-protection for this
// key's outstanding dependents".
type ReprotectionReceipt struct {
	KeyID string `json:"key_id"`
	// Planned is how many outstanding dependents produced a job this round.
	Planned int `json:"planned"`
	// Enqueued is how many of those were newly recorded; the rest were already
	// queued under the same stable idempotency key.
	Enqueued int                      `json:"enqueued"`
	Jobs     []ReprotectionJobReceipt `json:"jobs"`
}

func reprotectHandler(a *api.API, enq *reprotect.Enqueuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("vdec_reprotection", "start", start, opErr) }()
			keyID := r.PathValue("id")
			if keyID == "" {
				opErr = api.ErrStatus(http.StatusBadRequest, "key id is required")
				return 0, nil, opErr
			}
			jobs, found, err := enq.EnqueueOutstanding(ctx, tenantID, keyID)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			if !found {
				opErr = api.ErrStatus(http.StatusNotFound,
					"no dependency state is recorded for this key; register dependents before starting re-protection")
				return 0, nil, opErr
			}
			receipt := ReprotectionReceipt{KeyID: keyID, Planned: len(jobs), Jobs: make([]ReprotectionJobReceipt, 0, len(jobs))}
			for _, job := range jobs {
				if job.Enqueued {
					receipt.Enqueued++
				}
				receipt.Jobs = append(receipt.Jobs, ReprotectionJobReceipt{
					ID:             job.ID,
					Kind:           string(job.Kind),
					DependentClass: job.DependentClass,
					DependentRef:   job.DependentRef,
					Enqueued:       job.Enqueued,
				})
			}
			return http.StatusAccepted, receipt, nil
		})
	}
}

type RetirementRequest struct {
	FinalEpoch          uint64 `json:"final_epoch"`
	ConfirmIrreversible bool   `json:"confirm_irreversible"`
}

func retirementHandler(a *api.API, coordinator *retirement.Coordinator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.Mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("vdec_retirement", "request", start, opErr) }()
			keyID := r.PathValue("id")
			if keyID == "" {
				opErr = api.ErrStatus(http.StatusBadRequest, "key id is required")
				return 0, nil, opErr
			}
			var input RetirementRequest
			if err := api.DecodeJSONStrict(r, &input); err != nil {
				opErr = api.ErrWithStatus(http.StatusBadRequest, err)
				return 0, nil, opErr
			}
			principal, err := api.AuthenticatedPrincipalSubject(ctx)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			receipt, err := coordinator.Request(ctx, tenantID, keyID, retirement.Request{
				FinalEpoch: input.FinalEpoch, ConfirmIrreversible: input.ConfirmIrreversible,
				Approvals: []string{principal},
			})
			if err != nil {
				switch {
				case errors.Is(err, pgx.ErrNoRows):
					err = api.ErrStatus(http.StatusNotFound, "CA authority not found")
				case errors.Is(err, retirement.ErrCommandConflict):
					err = api.ErrStatus(http.StatusConflict, err.Error())
				case errors.Is(err, retirement.ErrInvalidCommand):
					err = api.ErrStatus(http.StatusBadRequest, err.Error())
				}
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, receipt, nil
		})
	}
}

// Routes declares the licensed VDEC REST surface. The start-re-protection route
// is a mutation with no request body: the key id in the path and the header
// idempotency key are the whole request (AN-5).
func Routes(enq *reprotect.Enqueuer, coordinator *retirement.Coordinator) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/reprotect", OperationID: "startCAKeyReprotection",
			Summary:        "Queue re-protection jobs for a CA key's outstanding dependents",
			Handler:        func(a *api.API) http.HandlerFunc { return reprotectHandler(a, enq) },
			PathParams:     []api.RouteParam{api.PathStringParam("id", "stable key identifier")},
			ResponseSchema: "VDECReprotectionReceipt", SuccessCode: "202", Mutation: true,
			Permission: authz.KeysWrite,
		},
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement", OperationID: "retireCAKey",
			Summary:       "Irreversibly retire a superseded CA key through the isolated signer",
			Handler:       func(a *api.API) http.HandlerFunc { return retirementHandler(a, coordinator) },
			PathParams:    []api.RouteParam{api.PathStringParam("id", "stable CA authority identifier")},
			RequestSchema: "VDECRetirementRequest", ResponseSchema: "VDECRetirementReceipt", SuccessCode: "202",
			Mutation: true, Permission: authz.KeysWrite,
		},
	}
}

func schemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"VDECReprotectionJob": api.ObjectSchema(map[string]*api.Schema{
			"id":              api.StringSchema(),
			"kind":            api.StringSchema(),
			"dependent_class": api.StringSchema(),
			"dependent_ref":   api.StringSchema(),
			"enqueued":        api.BooleanSchema(),
		}, "id", "kind", "dependent_class", "dependent_ref", "enqueued"),
		"VDECReprotectionReceipt": api.ObjectSchema(map[string]*api.Schema{
			"key_id":   api.StringSchema(),
			"planned":  api.IntegerSchema(),
			"enqueued": api.IntegerSchema(),
			"jobs":     api.ArraySchema(api.SchemaRef("VDECReprotectionJob")),
		}, "key_id", "planned", "enqueued", "jobs"),
		"VDECRetirementRequest": api.ObjectSchema(map[string]*api.Schema{
			"final_epoch":          api.IntegerSchema(),
			"confirm_irreversible": api.BooleanSchema(),
		}, "final_epoch", "confirm_irreversible"),
		"VDECRetirementReceipt": api.ObjectSchema(map[string]*api.Schema{
			"key_id":           api.StringSchema(),
			"command_event_id": api.StringSchema(),
			"status":           api.StringSchema(),
			"ledger_position":  api.IntegerSchema(),
			"final_epoch":      api.IntegerSchema(),
		}, "key_id", "command_event_id", "status", "ledger_position", "final_epoch"),
	}
}

// NewAPIOptionsFactory returns the licensed-route factory that attaches the VDEC
// H4 surface under the FeatureVerifiableDecommission block (ee_attach). The
// checklist source and the re-protection producer are built from the
// server-provided store and outbox, so the route serves the same read model and
// the same outbox the dispatcher drains.
func NewAPIOptionsFactory(retirementProjections ...*retirement.Projection) editionseam.LicensedAPIOptionsFactory {
	var retirementProjection *retirement.Projection
	if len(retirementProjections) != 0 {
		retirementProjection = retirementProjections[0]
	}
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		repo := decstore.New(d.Store)
		outbox := d.Outbox
		if outbox == nil {
			outbox = orchestrator.NewOutbox(d.Store)
		}
		enq := reprotect.NewEnqueuer(d.Store, repo, outbox)
		coordinator := retirement.NewCoordinator(d.Store, d.Log, retirementProjection)
		return []api.Option{
			api.WithRetirementChecklist(NewChecklistSource(repo, retirementProjection)),
			api.WithLicensedRoutes(Routes(enq, coordinator)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}
