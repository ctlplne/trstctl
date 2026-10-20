// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// SecretSyncReconcileOutcome is what the served reconciliation returns to the
// API: the resulting job and receiver authority, and one closed outcome word.
type SecretSyncReconcileOutcome struct {
	Outcome   string
	Detail    string
	Job       store.SecretSyncJob
	Authority store.SecretSyncReceiverAuthority
}

// Closed reconciliation outcomes. The first three change state; the others
// explain why nothing changed and map to 409 so a client never mistakes a
// refused reconciliation for progress.
const (
	SecretSyncReconcileDelivered  = "delivered"
	SecretSyncReconcileFailed     = "failed"
	SecretSyncReconcileSettled    = "settled"
	SecretSyncReconcileUnknown    = "unknown"
	SecretSyncReconcileDiverged   = "diverged"
	SecretSyncReconcileNotStarted = "not_started"
	SecretSyncReconcileTerminal   = "terminal"
)

type secretSyncReconcileRequest struct {
	OperatorVerified bool   `json:"operator_verified"`
	Observed         string `json:"observed"`
}

type secretSyncReconcileResponse struct {
	Outcome string                `json:"outcome"`
	Detail  string                `json:"detail"`
	Job     secretSyncJobResponse `json:"job"`
}

// secretSyncJobResponseFor reads the receiver authority beside the projected
// job so the console and CLI can see why a version is still queued and whether
// its target can read itself back.
func (a *API) secretSyncJobResponseFor(ctx context.Context, tenantID string, job store.SecretSyncJob) secretSyncJobResponse {
	response := secretSyncJobResponse{
		JobID: job.ID, Name: job.SecretName, SecretVersion: job.SecretVersion,
		Target: job.Target, RemoteKey: job.RemoteKey, Status: string(job.Status),
		Attempts: job.Attempts, RequestedAt: job.RequestedAt.UTC().Format(time.RFC3339),
		UpdatedAt: job.UpdatedAt.UTC().Format(time.RFC3339), LastError: job.LastError,
	}
	if job.DeliveredAt != nil {
		response.DeliveredAt = job.DeliveredAt.UTC().Format(time.RFC3339)
	}
	if authority, err := a.secrets.be.Store.SecretSyncReceiverAuthority(ctx, tenantID, job.ID); err == nil {
		response.ReceiverEffectState = string(authority.EffectState)
		response.ReceiverIOStarts = authority.ReceiverIOStarts
	}
	if job.Status == store.SecretSyncJobPending {
		if predecessor, found, err := a.secrets.be.Store.SecretSyncBlockingPredecessor(ctx, tenantID, job.ID); err == nil && found {
			response.BlockedByJobID = predecessor
		}
	}
	if a.secrets.be.SecretSyncTargetsForTenant != nil {
		if target := a.secrets.be.SecretSyncTargetsForTenant(tenantID)[job.Target]; target != nil {
			response.Reconcilable = target.CanReconcile()
		}
	} else if target := a.secrets.be.SecretSyncTargets[job.Target]; target != nil {
		response.Reconcilable = target.CanReconcile()
	}
	return response
}

// reconcileSecretSync resolves one command whose receiver outcome was lost. It
// reads the receiver back where the target can, or records an operator's
// attestation where it cannot, and never sends the value again.
//
//trstctl:mutation
func (a *API) reconcileSecretSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	var request secretSyncReconcileRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	request.Observed = strings.TrimSpace(request.Observed)
	switch request.Observed {
	case "", "value_present", "value_absent":
	default:
		a.writeError(w, errStatus(http.StatusBadRequest, "observed must be value_present or value_absent"))
		return
	}
	if request.OperatorVerified != (request.Observed != "") {
		a.writeError(w, errStatus(http.StatusBadRequest, "operator_verified and observed go together: say what you saw at the destination, or omit both"))
		return
	}
	jobID := r.PathValue("id")
	key := r.Header.Get("Idempotency-Key")
	bindingBody, err := json.Marshal(struct {
		Domain    string                     `json:"domain"`
		Principal string                     `json:"principal"`
		JobID     string                     `json:"job_id"`
		Request   secretSyncReconcileRequest `json:"request"`
	}{"trstctl.secret-sync-reconcile.v1", principal.Subject, jobID, request})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, key, crypto.SHA256Hex(bindingBody),
		func(ctx context.Context, tenantID string) (int, any, error) {
			if a.secrets.be.ReconcileSecretSync == nil {
				return 0, nil, errStatus(http.StatusServiceUnavailable, "secret-sync reconciliation is not configured on this control plane")
			}
			out, err := a.secrets.be.ReconcileSecretSync(ctx, tenantID, jobID, request.OperatorVerified, request.Observed, principal.Subject)
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusNotFound, "secret sync job not found")
			}
			if err != nil {
				return 0, nil, err
			}
			switch out.Outcome {
			case SecretSyncReconcileUnknown, SecretSyncReconcileDiverged, SecretSyncReconcileNotStarted:
				return 0, nil, errStatus(http.StatusConflict, out.Outcome+": "+out.Detail)
			}
			return http.StatusOK, secretSyncReconcileResponse{
				Outcome: out.Outcome, Detail: out.Detail,
				Job: a.secretSyncJobResponseFor(ctx, tenantID, out.Job),
			}, nil
		})
}

var _ = errors.New
