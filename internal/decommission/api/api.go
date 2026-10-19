// SPDX-License-Identifier: BUSL-1.1

// Package api is the served H4 surface for verifiable decommission: the CA-key
// retirement checklist source behind core's GET /api/v1/ca/keys/{id}/retirement,
// the POST that starts re-protection, and the explicitly confirmed POST that
// freezes evidence for signer-local destruction.
//
// Both attach through the feature-neutral api.Option seam (the internal/succession
// precedent); no VDEC route, handler, or DTO lives in the static API package. Before this
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
	"trstctl.com/trstctl/internal/decommission/release"
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
// destruction. Missing tenant dependency state returns 404: absent evidence is
// not evidence that every dependent is accounted for. Enforcement of the
// destruction refusal itself lives in the isolated signer, not here.
// DestructionRecord stays empty while the key is alive. Once the outbox worker
// receives the signer's terminal decision, the immutable event projection makes
// the signed refusal or full destruction record readable here.
func (s *ChecklistSource) RetirementChecklist(r *http.Request, tenantID, keyID string) (api.RetirementChecklist, error) {
	state, found, err := s.repo.FetchKeyState(r.Context(), tenantID, keyID)
	if err != nil {
		return api.RetirementChecklist{}, err
	}
	if !found {
		return api.RetirementChecklist{}, api.ErrStatus(http.StatusNotFound,
			"no dependency state is recorded for this key in this tenant; verify the key ID and collect its dependency evidence before assessing retirement")
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
			checklist.FinalEpoch = retired.FinalEpoch
			checklist.RefusalRecord = string(retired.RefusalRecord)
			checklist.DestructionRecord = string(retired.DestructionRecord)
			checklist.CommandEventID = retired.CommandEventID
			delivery, delivered, err := s.retirement.FetchDelivery(r.Context(), tenantID, retired.CommandEventID)
			if err != nil {
				return api.RetirementChecklist{}, err
			}
			if delivered {
				checklist.DeliveryStatus = delivery.Status
				checklist.DeliveryAttempts = delivery.Attempts
				checklist.DeliveryAttemptLimit = delivery.AttemptLimit
				checklist.RecoveryAction = retirementRecoveryAction(state.LedgerPosition, retired.LedgerPosition, retired.Status, delivery)
			}
		}
	}
	return checklist, nil
}

// retirementRecoveryAction is read-only guidance. The coordinator repeats all
// checks under the command fence at mutation time; this hint cannot authorize
// a stale retry or make a destruction decision for the isolated signer.
func retirementRecoveryAction(statePosition, frozenPosition uint64, status string, delivery retirement.DeliveryState) string {
	if status != retirement.StatusPending || delivery.Status != "failed" {
		return "none"
	}
	if statePosition > frozenPosition {
		return "fresh_command"
	}
	if delivery.Attempts > 0 && delivery.AttemptLimit <= delivery.Attempts {
		return "retry_delivery"
	}
	return "none"
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

// CredentialPlanReceipt is a public readback of the immutable command the
// worker will enforce. It contains no subject private key or agent credential.
type CredentialPlanReceipt struct {
	JobID                  string `json:"job_id"`
	IdentityID             string `json:"identity_id"`
	CertificateID          string `json:"certificate_id"`
	SuccessorAuthorityID   string `json:"successor_authority_id"`
	PredecessorFingerprint string `json:"predecessor_fingerprint"`
	PredecessorSPKISHA256  string `json:"predecessor_spki_sha256"`
	TargetID               string `json:"target_id"`
	TargetRevisionID       string `json:"target_revision_id"`
	RequiredAgentID        string `json:"required_agent_id"`
	Connector              string `json:"connector"`
	VerifyAddress          string `json:"verify_address"`
	VerifyServerName       string `json:"verify_server_name"`
	TTLSeconds             int64  `json:"ttl_seconds"`
	Recorded               bool   `json:"recorded"`
}

func credentialPlanHandler(a *api.API, enq *reprotect.Enqueuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.Mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("vdec_reprotection", "record_plan", start, opErr) }()
			var input reprotect.CredentialPlanSelection
			if err := api.DecodeJSONStrict(r, &input); err != nil {
				opErr = api.ErrWithStatus(http.StatusBadRequest, err)
				return 0, nil, opErr
			}
			plan, recorded, err := enq.RegisterCredentialPlan(ctx, tenantID, r.PathValue("id"), input)
			if err != nil {
				switch {
				case errors.Is(err, reprotect.ErrCredentialPlanNotFound):
					err = api.ErrWithStatus(http.StatusNotFound, err)
				case errors.Is(err, reprotect.ErrCredentialPlanTargetChanged),
					errors.Is(err, reprotect.ErrCredentialPlanNotReady),
					errors.Is(err, reprotect.ErrCompletionConflict):
					err = api.ErrWithStatus(http.StatusConflict, err)
				case errors.Is(err, reprotect.ErrInvalidState):
					err = api.ErrWithStatus(http.StatusBadRequest, err)
				}
				opErr = err
				return 0, nil, err
			}
			receipt := CredentialPlanReceipt{
				JobID: plan.Job.ID, IdentityID: plan.IdentityID, CertificateID: plan.Job.Dependent.ID,
				SuccessorAuthorityID:   plan.SuccessorAuthorityID,
				PredecessorFingerprint: plan.PredecessorFingerprint,
				PredecessorSPKISHA256:  plan.PredecessorSPKISHA256,
				TargetID:               plan.TargetID, TargetRevisionID: plan.TargetRevisionID,
				RequiredAgentID: plan.RequiredAgentID, Connector: plan.Connector,
				VerifyAddress: plan.VerifyAddress, VerifyServerName: plan.VerifyServerName,
				TTLSeconds: plan.TTLSeconds, Recorded: recorded,
			}
			if !recorded {
				return http.StatusOK, receipt, nil
			}
			return http.StatusCreated, receipt, nil
		})
	}
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
				if errors.Is(err, reprotect.ErrCredentialPlanRequired) {
					err = api.ErrStatus(http.StatusConflict, err.Error())
				}
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

type RetirementRetryRequest struct {
	CommandEventID      string `json:"command_event_id"`
	ExpectedAttempts    int    `json:"expected_attempts"`
	Reason              string `json:"reason"`
	ConfirmIrreversible bool   `json:"confirm_irreversible"`
}

type DependentReleaseRequest struct {
	CertificateID             string `json:"certificate_id"`
	ExpectedCertificateSHA256 string `json:"expected_certificate_sha256"`
	CeremonyID                string `json:"ceremony_id"`
	Reason                    string `json:"reason"`
	RiskAccepted              bool   `json:"risk_accepted"`
}

func dependentReleaseHandler(a *api.API, coordinator *release.Coordinator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.Mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("vdec_retirement", "release_dependent", start, opErr) }()
			var input DependentReleaseRequest
			if err := api.DecodeJSONStrict(r, &input); err != nil {
				opErr = api.ErrWithStatus(http.StatusBadRequest, err)
				return 0, nil, opErr
			}
			receipt, err := coordinator.Execute(ctx, tenantID, r.PathValue("id"), input.CeremonyID,
				release.Request{CertificateID: input.CertificateID,
					ExpectedCertificateSHA256: input.ExpectedCertificateSHA256,
					Reason:                    input.Reason, RiskAccepted: input.RiskAccepted})
			if err != nil {
				switch {
				case errors.Is(err, pgx.ErrNoRows):
					err = api.ErrStatus(http.StatusNotFound, "CA authority, certificate, or ceremony not found")
				case errors.Is(err, release.ErrInvalid):
					err = api.ErrStatus(http.StatusBadRequest, err.Error())
				case errors.Is(err, release.ErrConflict):
					err = api.ErrStatus(http.StatusConflict, err.Error())
				}
				opErr = err
				return 0, nil, err
			}
			return http.StatusOK, receipt, nil
		})
	}
}

func retirementRetryHandler(a *api.API, coordinator *retirement.Coordinator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("vdec_retirement", "retry", start, opErr) }()
			keyID := r.PathValue("id")
			var input RetirementRetryRequest
			if keyID == "" {
				opErr = api.ErrStatus(http.StatusBadRequest, "key id is required")
				return 0, nil, opErr
			}
			if err := api.DecodeJSONStrict(r, &input); err != nil {
				opErr = api.ErrWithStatus(http.StatusBadRequest, err)
				return 0, nil, opErr
			}
			receipt, err := coordinator.Retry(ctx, tenantID, keyID, retirement.RetryRequest{
				CommandEventID: input.CommandEventID, ExpectedAttempts: input.ExpectedAttempts,
				Reason: input.Reason, RequestKey: idempotencyKey,
				ConfirmIrreversible: input.ConfirmIrreversible,
			})
			if err != nil {
				switch {
				case errors.Is(err, pgx.ErrNoRows):
					err = api.ErrStatus(http.StatusNotFound, "CA authority or exact retirement command not found")
				case errors.Is(err, retirement.ErrRetryUnavailable), errors.Is(err, retirement.ErrCommandConflict):
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
func Routes(enq *reprotect.Enqueuer, coordinator *retirement.Coordinator, releaser *release.Coordinator) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/reprotect/plans", OperationID: "registerCAKeyReprotectionPlan",
			Summary:       "Record one reviewed certificate, successor CA and exact host route before re-protection",
			Handler:       func(a *api.API) http.HandlerFunc { return credentialPlanHandler(a, enq) },
			PathParams:    []api.RouteParam{api.PathStringParam("id", "superseded managed CA authority identifier")},
			RequestSchema: "VDECCredentialPlanSelection", ResponseSchema: "VDECCredentialPlanReceipt",
			SuccessCode: "201", Mutation: true, Permission: authz.KeysWrite,
		},
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/reprotect", OperationID: "startCAKeyReprotection",
			Summary:        "Queue re-protection jobs for a CA key's outstanding dependents",
			Handler:        func(a *api.API) http.HandlerFunc { return reprotectHandler(a, enq) },
			PathParams:     []api.RouteParam{api.PathStringParam("id", "stable key identifier")},
			ResponseSchema: "VDECReprotectionReceipt", SuccessCode: "202", Mutation: true,
			Permission: authz.KeysWrite,
		},
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/dependencies/release", OperationID: "releaseCAKeyDependent",
			Summary:       "Release one exact expired requester-custody CA leaf after distinct custodian approval and explicit external-use risk acceptance",
			Handler:       func(a *api.API) http.HandlerFunc { return dependentReleaseHandler(a, releaser) },
			PathParams:    []api.RouteParam{api.PathStringParam("id", "managed CA authority identifier")},
			RequestSchema: "VDECDependentReleaseRequest", ResponseSchema: "VDECDependentReleaseReceipt", SuccessCode: "200",
			Mutation: true, Permission: authz.KeysWrite,
		},
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement", OperationID: "retireCAKey",
			Summary:       "Irreversibly retire a superseded CA key through the isolated signer",
			Handler:       func(a *api.API) http.HandlerFunc { return retirementHandler(a, coordinator) },
			PathParams:    []api.RouteParam{api.PathStringParam("id", "stable CA authority identifier")},
			RequestSchema: "VDECRetirementRequest", ResponseSchema: "VDECRetirementReceipt", SuccessCode: "202",
			Mutation: true, Permission: authz.KeysWrite,
		},
		{
			Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement/retry", OperationID: "retryCAKeyRetirement",
			Summary:       "Grant one bounded retry to an exact failed CA-key destruction command",
			Handler:       func(a *api.API) http.HandlerFunc { return retirementRetryHandler(a, coordinator) },
			PathParams:    []api.RouteParam{api.PathStringParam("id", "stable CA authority identifier")},
			RequestSchema: "VDECRetirementRetryRequest", ResponseSchema: "VDECRetirementRetryReceipt", SuccessCode: "202",
			Mutation: true, Permission: authz.KeysWrite,
		},
	}
}

func schemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"VDECCredentialPlanSelection": api.ObjectSchema(map[string]*api.Schema{
			"certificate_id": api.StringSchema(), "successor_authority_id": api.StringSchema(),
			"target_id": api.StringSchema(), "expected_target_revision": api.StringSchema(),
			"expected_fingerprint": api.StringSchema(), "ttl_seconds": api.IntegerSchema(),
		}, "certificate_id", "successor_authority_id", "target_id", "expected_target_revision", "expected_fingerprint", "ttl_seconds"),
		"VDECCredentialPlanReceipt": api.ObjectSchema(map[string]*api.Schema{
			"job_id": api.StringSchema(), "identity_id": api.StringSchema(), "certificate_id": api.StringSchema(),
			"successor_authority_id": api.StringSchema(), "predecessor_fingerprint": api.StringSchema(),
			"predecessor_spki_sha256": api.StringSchema(), "target_id": api.StringSchema(),
			"target_revision_id": api.StringSchema(), "required_agent_id": api.StringSchema(),
			"connector": api.StringSchema(), "verify_address": api.StringSchema(),
			"verify_server_name": api.StringSchema(), "ttl_seconds": api.IntegerSchema(),
			"recorded": api.BooleanSchema(),
		}, "job_id", "identity_id", "certificate_id", "successor_authority_id", "predecessor_fingerprint",
			"predecessor_spki_sha256", "target_id", "target_revision_id", "required_agent_id",
			"connector", "verify_address", "verify_server_name", "ttl_seconds", "recorded"),
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
		"VDECRetirementRetryRequest": api.ObjectSchema(map[string]*api.Schema{
			"command_event_id":     api.StringSchema(),
			"expected_attempts":    api.IntegerSchema(),
			"reason":               api.StringSchema(),
			"confirm_irreversible": api.BooleanSchema(),
		}, "command_event_id", "expected_attempts", "reason", "confirm_irreversible"),
		"VDECRetirementRetryReceipt": api.ObjectSchema(map[string]*api.Schema{
			"key_id":           api.StringSchema(),
			"command_event_id": api.StringSchema(),
			"grant_event_id":   api.StringSchema(),
			"outbox_id":        api.IntegerSchema(),
			"attempts_before":  api.IntegerSchema(),
			"attempt_limit":    api.IntegerSchema(),
			"status":           api.StringSchema(),
		}, "key_id", "command_event_id", "grant_event_id", "outbox_id", "attempts_before", "attempt_limit", "status"),
		"VDECDependentReleaseRequest": api.ObjectSchema(map[string]*api.Schema{
			"certificate_id": api.StringSchema(), "expected_certificate_sha256": api.StringSchema(),
			"ceremony_id": api.StringSchema(), "reason": api.StringSchema(), "risk_accepted": api.BooleanSchema(),
		}, "certificate_id", "expected_certificate_sha256", "ceremony_id", "reason", "risk_accepted"),
		"VDECDependentReleaseReceipt": api.ObjectSchema(map[string]*api.Schema{
			"key_id": api.StringSchema(), "certificate_id": api.StringSchema(),
			"ceremony_id": api.StringSchema(), "release_event_id": api.StringSchema(),
			"certificate_sha256": api.StringSchema(), "status": api.StringSchema(),
		}, "key_id", "certificate_id", "ceremony_id", "release_event_id", "certificate_sha256", "status"),
	}
}

// NewAPIOptionsFactory returns the composition factory that attaches the Core
// VDEC H4 surface. The
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
		enq := reprotect.NewEnqueuer(d.Store, repo, outbox, reprotect.NewCredentialPlanLedger(d.Log, d.Store))
		coordinator := retirement.NewCoordinator(d.Store, d.Log, retirementProjection)
		releaser := release.NewCoordinator(d.Store, d.Log)
		return []api.Option{
			api.WithRetirementChecklist(NewChecklistSource(repo, retirementProjection)),
			api.WithCoreRoutes(Routes(enq, coordinator, releaser)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}
