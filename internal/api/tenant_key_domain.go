// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const legacyDeploymentKEKMode = "legacy_deployment_kek"

// TenantKeyDomainLifecycle is the API-facing view of the CORE tenant custody
// coordinator. It deliberately returns projection records, never transient key
// material or wrapper paths.
type TenantKeyDomainLifecycle interface {
	Status(context.Context, string) (store.TenantKeyDomain, error)
	Migrate(context.Context, string, tenantseal.WrapperRef) (store.TenantKeyDomain, error)
	RequestSeal(context.Context, string, string, string) (store.TenantKeyDomain, error)
	CompleteSeal(context.Context, string, string) (store.TenantKeyDomain, error)
	FailSeal(context.Context, string, string) (store.TenantKeyDomain, error)
	Unseal(context.Context, string) (store.TenantKeyDomain, error)
}

type tenantKeyDomainMigrateRequest struct {
	WrapperKind string `json:"wrapper_kind"`
	WrapperID   string `json:"wrapper_id"`
}

// TenantKeyDomainSealReceipt is deliberately small and stable. It contains no
// tenant ciphertext or result data, so the seal endpoint can reconstruct the
// exact accepted response after the tenant key becomes unavailable while still
// proving the encrypted idempotency row reached completed first.
type TenantKeyDomainSealReceipt struct {
	Accepted    bool   `json:"accepted"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	StatusURL   string `json:"status_url"`
}

// TenantKeyDomainStatus is safe operator metadata. WrappedDomainKEK and local
// wrapper paths never cross the API boundary.
type TenantKeyDomainStatus struct {
	Served                    bool       `json:"served"`
	ProtectionMode            string     `json:"protection_mode"`
	State                     string     `json:"state"`
	DomainID                  string     `json:"domain_id,omitempty"`
	Generation                int64      `json:"generation,omitempty"`
	WrapperKind               string     `json:"wrapper_kind,omitempty"`
	WrapperID                 string     `json:"wrapper_id,omitempty"`
	OperationID               string     `json:"operation_id,omitempty"`
	OperationKind             string     `json:"operation_kind,omitempty"`
	OperationStatus           string     `json:"operation_status,omitempty"`
	MigrationStage            string     `json:"migration_stage,omitempty"`
	ProgressCompleted         int64      `json:"progress_completed"`
	ProgressTotal             int64      `json:"progress_total"`
	Retryable                 bool       `json:"retryable"`
	FailureCode               string     `json:"failure_code,omitempty"`
	Failure                   string     `json:"failure,omitempty"`
	LegacyHistoryExposure     string     `json:"legacy_history_exposure"`
	LastTransitionType        string     `json:"last_transition_type,omitempty"`
	LastTransitionActor       string     `json:"last_transition_actor,omitempty"`
	LastTransitionAt          *time.Time `json:"last_transition_at,omitempty"`
	LastTransitionEvidenceRef []string   `json:"last_transition_evidence_refs"`
	LocalWrapperZeroEgress    bool       `json:"local_wrapper_zero_egress"`
	RemoteWrapperState        string     `json:"remote_wrapper_state"`
	Recovery                  string     `json:"recovery"`
}

func (a *API) getTenantKeyDomain(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.tenantKeyDomains == nil {
		a.writeJSON(w, http.StatusOK, unavailableTenantKeyDomainStatus())
		return
	}
	domain, err := a.tenantKeyDomains.Status(r.Context(), tenantID)
	if errors.Is(err, store.ErrTenantKeyDomainNotFound) {
		a.writeJSON(w, http.StatusOK, legacyTenantKeyDomainStatus())
		return
	}
	if err != nil {
		a.writeJSON(w, http.StatusOK, TenantKeyDomainStatus{
			Served: true, ProtectionMode: "unavailable", State: "failed",
			Retryable: true, FailureCode: "tenant_key_domain_status_unavailable",
			LastTransitionEvidenceRef: []string{}, LocalWrapperZeroEgress: true,
			RemoteWrapperState: "disabled_in_core_local_custody",
			Failure:            "Tenant key-domain status could not be read.",
			Recovery:           "Check PostgreSQL readiness and retry this tenant-scoped status read.",
		})
		return
	}
	a.writeJSON(w, http.StatusOK, tenantKeyDomainStatusFromStore(domain))
}

//trstctl:mutation
func (a *API) migrateTenantKeyDomain(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.tenantKeyDomains == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "tenant key-domain lifecycle is not configured")
		}
		var req tenantKeyDomainMigrateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.WrapperKind = strings.TrimSpace(req.WrapperKind)
		req.WrapperID = strings.TrimSpace(req.WrapperID)
		if req.WrapperKind == "" {
			req.WrapperKind = tenantseal.WrapperKindLocalFile
		}
		if req.WrapperKind != tenantseal.WrapperKindLocalFile || req.WrapperID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "wrapper_kind must be local_file and wrapper_id is required")
		}
		domain, err := a.tenantKeyDomains.Migrate(ctx, tenantID, tenantseal.WrapperRef{
			Kind: req.WrapperKind, ID: req.WrapperID,
		})
		if err != nil {
			return 0, nil, mapTenantKeyDomainError(err)
		}
		return http.StatusOK, tenantKeyDomainStatusFromStore(domain), nil
	})
}

//trstctl:mutation
func (a *API) unsealTenantKeyDomain(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.tenantKeyDomains == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "tenant key-domain lifecycle is not configured")
		}
		domain, err := a.tenantKeyDomains.Unseal(ctx, tenantID)
		if err != nil {
			return 0, nil, mapTenantKeyDomainError(err)
		}
		return http.StatusOK, tenantKeyDomainStatusFromStore(domain), nil
	})
}

//trstctl:mutation
func (a *API) sealTenantKeyDomain(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := mutationRouteBinding(principal, r.Method, r.URL.EscapedPath())
	if err != nil {
		a.writeError(w, err)
		return
	}
	if a.tenantKeyDomains == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "tenant key-domain lifecycle is not configured"))
		return
	}

	recordResult := func(ctx context.Context) ([]byte, error) {
		domain, err := a.tenantKeyDomains.RequestSeal(ctx, tenantID, idempotencyKey, binding)
		if err != nil {
			return nil, mapTenantKeyDomainError(err)
		}
		if domain.OperationID == nil || domain.OperationKind != store.TenantKeyOperationSeal {
			return nil, errStatus(http.StatusInternalServerError, "tenant key-domain seal request returned no operation identity")
		}
		body, err := json.Marshal(tenantKeyDomainSealReceipt(*domain.OperationID))
		if err != nil {
			return nil, err
		}
		return json.Marshal(cachedResponse{Status: http.StatusAccepted, Body: body, Binding: binding})
	}
	raw, err := a.idem.DoDurableEffectBound(
		r.Context(), tenantID, idempotencyKey, binding, recordResult,
	)
	if err != nil {
		if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
			err = errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
		} else if recovered, recoveryErr := a.recoverSealedTenantKeyDomainReceipt(
			r.Context(), tenantID, idempotencyKey, binding, err,
		); recoveryErr == nil {
			raw = recovered
			err = nil
		} else if !errors.Is(recoveryErr, err) {
			err = recoveryErr
		}
	}
	if err != nil {
		a.writeError(w, err)
		return
	}

	var cached cachedResponse
	if err := json.Unmarshal(raw, &cached); err != nil {
		a.writeError(w, err)
		return
	}
	if !crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(binding)) {
		a.writeError(w, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(cached.Status)
	_, _ = w.Write(cached.Body)
}

func (a *API) recoverSealedTenantKeyDomainReceipt(
	ctx context.Context,
	tenantID, idempotencyKey, binding string,
	openErr error,
) ([]byte, error) {
	status, ok := tenantseal.StatusOf(openErr)
	if !ok || (status != tenantseal.StatusSealed && status != tenantseal.StatusSealing) {
		return nil, openErr
	}
	completed, err := a.idem.BoundResultCompleted(ctx, tenantID, idempotencyKey, binding)
	if err != nil || !completed {
		if err != nil {
			return nil, err
		}
		return nil, orchestrator.ErrInProgress
	}
	domain, err := a.tenantKeyDomains.Status(ctx, tenantID)
	if err != nil {
		return nil, mapTenantKeyDomainError(err)
	}
	expectedID, err := tenantseal.SealOperationID(tenantID, idempotencyKey, binding)
	if err != nil {
		return nil, err
	}
	if domain.OperationID == nil || *domain.OperationID != expectedID ||
		domain.OperationKind != store.TenantKeyOperationSeal ||
		(domain.State != store.TenantKeyDomainStateSealed && domain.State != store.TenantKeyDomainStateSealing) {
		return nil, errStatus(http.StatusConflict, "the completed seal receipt does not match the tenant's current seal operation")
	}
	body, err := json.Marshal(tenantKeyDomainSealReceipt(expectedID))
	if err != nil {
		return nil, err
	}
	return json.Marshal(cachedResponse{Status: http.StatusAccepted, Body: body, Binding: binding})
}

func tenantKeyDomainSealReceipt(operationID string) TenantKeyDomainSealReceipt {
	return TenantKeyDomainSealReceipt{
		Accepted: true, OperationID: operationID,
		State:     store.TenantKeyDomainStateSealQueued,
		StatusURL: "/api/v1/platform/tenant-key-domain",
	}
}

func tenantKeyDomainStatusFromStore(domain store.TenantKeyDomain) TenantKeyDomainStatus {
	operationID := ""
	if domain.OperationID != nil {
		operationID = *domain.OperationID
	}
	status := TenantKeyDomainStatus{
		Served: true, ProtectionMode: domain.ProtectionMode, State: domain.State,
		DomainID: domain.DomainID, Generation: domain.Generation,
		WrapperKind: domain.WrapperKind, WrapperID: domain.WrapperID,
		OperationID: operationID, OperationKind: domain.OperationKind,
		OperationStatus: domain.OperationStatus, MigrationStage: domain.MigrationStage,
		ProgressCompleted: domain.ProgressCompleted, ProgressTotal: domain.ProgressTotal,
		Retryable: domain.Retryable, FailureCode: domain.LastErrorCode,
		Failure: domain.LastError, LegacyHistoryExposure: domain.LegacyHistoryExposure,
		LastTransitionType:        domain.LastTransitionType,
		LastTransitionActor:       domain.LastTransitionActor,
		LastTransitionEvidenceRef: append([]string(nil), domain.LastTransitionEvidenceRefs...),
		LocalWrapperZeroEgress:    true,
		RemoteWrapperState:        "disabled_in_core_local_custody",
	}
	if status.LastTransitionEvidenceRef == nil {
		status.LastTransitionEvidenceRef = []string{}
	}
	if !domain.LastTransitionAt.IsZero() {
		transitionAt := domain.LastTransitionAt
		status.LastTransitionAt = &transitionAt
	}
	status.Recovery = tenantKeyDomainRecovery(domain)
	return status
}

func unavailableTenantKeyDomainStatus() TenantKeyDomainStatus {
	return TenantKeyDomainStatus{
		Served: false, ProtectionMode: "unavailable", State: "unavailable",
		LastTransitionEvidenceRef: []string{}, LocalWrapperZeroEgress: true,
		RemoteWrapperState: "disabled_in_core_local_custody",
		Failure:            "Tenant key-domain lifecycle is not wired.",
		Recovery:           "Run the default control-plane binary with PostgreSQL, JetStream, the audit signing key, and tenant wrapper configuration.",
	}
}

func legacyTenantKeyDomainStatus() TenantKeyDomainStatus {
	return TenantKeyDomainStatus{
		Served: true, ProtectionMode: legacyDeploymentKEKMode, State: "legacy",
		LegacyHistoryExposure:     store.TenantKeyLegacyHotHistoryPending,
		LastTransitionEvidenceRef: []string{}, LocalWrapperZeroEgress: true,
		RemoteWrapperState: "disabled_in_core_local_custody",
		Recovery:           "Provision an existing local tenant wrapper and start migration; trstctl will not create the wrapper or fall back to the deployment KEK after opt-in.",
	}
}

func tenantKeyDomainRecovery(domain store.TenantKeyDomain) string {
	if domain.OperationKind == store.TenantKeyOperationSeal &&
		domain.OperationStatus == store.TenantKeyOperationFailed {
		return "The seal did not commit and tenant crypto remains available. Fix the worker failure, then retry with a new Idempotency-Key; the exhausted key continues replaying its original accepted receipt."
	}
	switch domain.State {
	case store.TenantKeyDomainStateMigrating:
		return "Migration is resumable. Retry with the same wrapper kind and ID after the current operation stops progressing."
	case store.TenantKeyDomainStatePartial:
		if domain.OperationStatus == store.TenantKeyOperationFailed {
			return "Fix the reported local custody or history prerequisite, then retry migration with the same wrapper kind and ID."
		}
		return "Hot state is tenant-domain protected. Retire or re-encrypt pre-migration archives, exports, and backups before asserting no legacy exposure."
	case store.TenantKeyDomainStateSealQueued:
		return "The seal request is durable. The bounded worker will commit it only after the accepted idempotency result is complete; poll this tenant-scoped status."
	case store.TenantKeyDomainStateSealed:
		return "Use the configured operator-controlled wrapper and the unseal mutation to restore tenant cryptographic access."
	case store.TenantKeyDomainStateWrapperUnavailable:
		return "Restore the exact configured local wrapper file and retry; no deployment-key fallback is attempted."
	case store.TenantKeyDomainStateWrongWrapper:
		return "Restore the wrapper key that originally protected this tenant domain; trstctl cannot distinguish a wrong key from authenticated unwrap failure."
	case store.TenantKeyDomainStateCorrupt:
		return "Stop mutation attempts and restore the tenant-domain record plus wrapper from verified recovery evidence."
	case store.TenantKeyDomainStateSealing, store.TenantKeyDomainStateUnsealing:
		return "Retry the same idempotent lifecycle operation so the event-projected transition can resume."
	default:
		return "Tenant-domain protection is available. Keep the operator wrapper and pre-migration archive evidence in the recovery plan."
	}
}

func mapTenantKeyDomainError(err error) error {
	if errors.Is(err, tenantseal.ErrLifecycleConflict) || errors.Is(err, tenantseal.ErrMigrationAlreadyDone) {
		return errStatus(http.StatusConflict, "tenant key-domain lifecycle state conflicts with this operation")
	}
	if errors.Is(err, tenantseal.ErrWrapperNotConfigured) {
		return errStatus(http.StatusServiceUnavailable, "the requested tenant wrapper is not configured")
	}
	if status, ok := tenantseal.StatusOf(err); ok {
		switch status {
		case tenantseal.StatusWrapperUnavailable:
			return errStatus(http.StatusServiceUnavailable, "the configured tenant wrapper is unavailable")
		case tenantseal.StatusSealed:
			return errStatus(http.StatusLocked, "the tenant cryptographic domain is sealed")
		default:
			return errStatus(http.StatusConflict, "tenant cryptographic access failed closed: "+string(status))
		}
	}
	return errStatus(http.StatusInternalServerError, "tenant key-domain lifecycle operation failed")
}
