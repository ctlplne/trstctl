// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// A210: after containment stopped a listener, a replacement preview asks the
// host, through a read-only agent job, whether its profile pins an action that
// brings the listener back and what the listener serves now.

type endpointRecoveryCheckRequest struct {
	IdentityID string `json:"identity_id"`
}

type endpointRecoveryCheckResponse struct {
	CheckID            string     `json:"check_id"`
	TargetID           string     `json:"target_id"`
	TargetRevision     string     `json:"target_revision"`
	AgentID            string     `json:"agent_id"`
	RequestedBy        string     `json:"requested_by,omitempty"`
	RequestedAt        time.Time  `json:"requested_at"`
	Status             string     `json:"status"`
	Recovery           string     `json:"recovery,omitempty"`
	RecoveryAction     string     `json:"recovery_action,omitempty"`
	ExecutableSHA256   string     `json:"executable_sha256,omitempty"`
	ArgvSHA256         string     `json:"argv_sha256,omitempty"`
	Listener           string     `json:"listener,omitempty"`
	ServingFingerprint string     `json:"serving_fingerprint,omitempty"`
	Failure            string     `json:"failure,omitempty"`
	JobID              *int64     `json:"job_id,omitempty"`
	EvidenceDigest     string     `json:"evidence_digest,omitempty"`
	CheckedAt          *time.Time `json:"checked_at,omitempty"`
}

func toEndpointRecoveryCheckResponse(c store.EndpointRecoveryCheck) endpointRecoveryCheckResponse {
	return endpointRecoveryCheckResponse{
		CheckID: c.CheckID, TargetID: c.TargetID, TargetRevision: c.TargetRevision, AgentID: c.AgentID,
		RequestedBy: c.RequestedBy, RequestedAt: c.RequestedAt, Status: c.Status, Recovery: c.Recovery,
		RecoveryAction: c.RecoveryAction, ExecutableSHA256: c.ExecutableSHA256, ArgvSHA256: c.ArgvSHA256,
		Listener: c.Listener, ServingFingerprint: c.ServingFingerprint, Failure: c.Failure, JobID: c.JobID,
		EvidenceDigest: c.EvidenceDigest, CheckedAt: c.CheckedAt,
	}
}

// Recovery readiness states in a replacement preview.
const (
	recoveryReady     = "ready"
	recoveryNotReady  = "not_ready"
	recoveryUnchecked = "unchecked"
	recoveryQueued    = "queued"
	recoveryStale     = "stale"
	recoveryFailed    = "failed"
)

// endpointRecoveryReadiness is what a replacement preview knows about bringing
// a contained listener back.
type endpointRecoveryReadiness struct {
	State                string                         `json:"state"`
	Reasons              []string                       `json:"reasons"`
	ContainedAt          time.Time                      `json:"contained_at"`
	ContainedFingerprint string                         `json:"contained_fingerprint"`
	DeployActions        []string                       `json:"deploy_actions,omitempty"`
	Check                *endpointRecoveryCheckResponse `json:"check,omitempty"`
}

// maxContainmentReceiptsRead bounds the receipts read to find a target's
// latest containment of one identity.
const maxContainmentReceiptsRead = 64

// targetContainments returns an identity's containment receipts for one
// target, newest first. A receipt's id derives from its target id and request
// key, which survives the outbox row that carried the command.
func (a *API) targetContainments(ctx context.Context, tenantID, identityID, targetID string) ([]store.EndpointContainmentReceipt, error) {
	receipts, err := a.store.EndpointContainmentReceipts(ctx, tenantID, identityID, maxContainmentReceiptsRead)
	if err != nil {
		return nil, err
	}
	out := receipts[:0]
	for _, receipt := range receipts {
		if receipt.ID == orchestrator.EndpointContainmentReceiptID(tenantID, targetID, receipt.IdempotencyKey) {
			out = append(out, receipt)
		}
	}
	return out, nil
}

// endpointRecoveryReadiness reads whether a replacement for an identity whose
// listener containment stopped can bring that listener back. It is nil when
// the identity's latest containment of this target did not stop a listener;
// the preview then claims nothing about recovery.
func (a *API) endpointRecoveryReadiness(ctx context.Context, tenantID, identityID string,
	target endpointBindingTargetSummary) (*endpointRecoveryReadiness, error) {
	if target.ID == "" {
		return nil, nil
	}
	contained, err := a.targetContainments(ctx, tenantID, identityID, target.ID)
	if err != nil || len(contained) == 0 || contained[0].Status != servedstatus.ConnectorContainmentStopped {
		return nil, err
	}
	stop := contained[0]
	out := &endpointRecoveryReadiness{State: recoveryUnchecked, Reasons: []string{},
		ContainedAt: stop.UpdatedAt, ContainedFingerprint: stop.Fingerprint}
	out.DeployActions, err = relay.HostDeployActionNames(target.Connector, target.Config)
	if err != nil {
		out.State = recoveryNotReady
		out.Reasons = append(out.Reasons, "the "+target.Connector+" connector's deploy actions could not be read for this target: "+err.Error())
		return out, nil
	}
	check, found, err := a.store.GetEndpointRecoveryCheck(ctx, tenantID, target.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		out.Reasons = append(out.Reasons, "no host recovery check has run since containment stopped this listener")
		return out, nil
	}
	response := toEndpointRecoveryCheckResponse(check)
	out.Check = &response
	agent, _ := connector.TargetHostAgentID(target.Config)
	switch {
	case !checkFollowsContainment(check, stop):
		out.State = recoveryStale
		out.Reasons = append(out.Reasons, "the last recovery check ran before containment stopped this listener")
	case check.TargetRevision != target.Revision || check.AgentID != agent:
		out.State = recoveryStale
		out.Reasons = append(out.Reasons, "the target or its enrolled host changed after the last recovery check")
	case check.Status == store.EndpointRecoveryCheckQueued:
		out.State = recoveryQueued
		out.Reasons = append(out.Reasons, "the recovery check is queued for the enrolled host; preview again once it answers")
	case check.Status == store.EndpointRecoveryCheckFailed:
		out.State = recoveryFailed
		out.Reasons = append(out.Reasons, "the recovery check failed: "+check.Failure)
	default:
		out.State, out.Reasons = recoveryVerdict(check, stop, out.DeployActions, target.Connector)
	}
	return out, nil
}

// checkFollowsContainment orders the check's request after the containment
// result by event sequence, or by time for a receipt projected before
// receipts carried one.
func checkFollowsContainment(check store.EndpointRecoveryCheck, stop store.EndpointContainmentReceipt) bool {
	if stop.EventSequence > 0 {
		return check.RequestSequence > stop.EventSequence
	}
	return check.RequestedAt.After(stop.UpdatedAt)
}

// recoveryVerdict reads a host's answer: ready only when the profile pins a
// recovery action the connector runs while deploying and the listener is not
// serving the contained leaf.
func recoveryVerdict(check store.EndpointRecoveryCheck, stop store.EndpointContainmentReceipt,
	deployActions []string, connectorName string) (string, []string) {
	var reasons []string
	switch check.Recovery {
	case relay.RecoveryCheckNoBinding:
		reasons = append(reasons, "the host profile has no containment binding for this target")
	case relay.RecoveryCheckNoRecoveryAction:
		reasons = append(reasons, "the host profile pins no recovery action for this listener; set containments[].recovery_action in the host profile")
	case relay.RecoveryCheckPinned:
		if !slices.Contains(deployActions, check.RecoveryAction) {
			reasons = append(reasons, "recovery action "+check.RecoveryAction+" is not one the "+connectorName+
				" connector runs while deploying ("+strings.Join(deployActions, ", ")+"); a replacement deploy would not run it")
		}
	default:
		reasons = append(reasons, "the recovery check reported an unknown state")
	}
	switch check.Listener {
	case relay.RecoveryListenerServingRevoke:
		reasons = append(reasons, "the listener is serving the contained certificate again; contain it again first")
	case relay.RecoveryListenerUnverified:
		reasons = append(reasons, "the host could not tell what the listener serves")
	case relay.RecoveryListenerServing:
		if strings.EqualFold(check.ServingFingerprint, stop.Fingerprint) {
			reasons = append(reasons, "the listener is serving the contained certificate again; contain it again first")
		}
	}
	if len(reasons) != 0 {
		return recoveryNotReady, reasons
	}
	return recoveryReady, []string{}
}

func (a *API) getEndpointRecoveryCheck(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	targetID, err := recoveryTargetID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	check, found, err := a.store.GetEndpointRecoveryCheck(r.Context(), tenantID, targetID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if !found {
		a.writeError(w, errStatus(http.StatusNotFound, "no recovery check of this target"))
		return
	}
	a.writeJSON(w, http.StatusOK, toEndpointRecoveryCheckResponse(check))
}

//trstctl:mutation
func (a *API) requestEndpointRecoveryCheck(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("recovery check orchestrator is unavailable")
		}
		targetID, err := recoveryTargetID(r)
		if err != nil {
			return 0, nil, err
		}
		var request endpointRecoveryCheckRequest
		if err := decodeJSON(r, &request); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if parsed, err := googleuuid.Parse(request.IdentityID); err != nil || parsed.String() != request.IdentityID {
			return 0, nil, errStatus(http.StatusBadRequest, "identity_id must name the contained identity by its canonical UUID")
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if err != nil {
			return 0, nil, err
		}
		if !connector.CanRollbackOnHost(target.Type) {
			return 0, nil, errStatus(http.StatusConflict, "this connector is not an enrolled host target with a containment path")
		}
		agent, err := connector.TargetHostAgentID(target.Config)
		if err != nil || agent == "" {
			return 0, nil, errStatus(http.StatusConflict, "the target names no enrolled host agent to ask")
		}
		contained, err := a.targetContainments(ctx, tenantID, request.IdentityID, target.ID)
		if err != nil {
			return 0, nil, err
		}
		if len(contained) == 0 {
			return 0, nil, errStatus(http.StatusConflict,
				"this identity has no containment of this target; a recovery check follows a containment")
		}
		var revoked []string
		for _, receipt := range contained {
			fp := strings.ToLower(receipt.Fingerprint)
			if fp != "" && !slices.Contains(revoked, fp) && len(revoked) < 16 {
				revoked = append(revoked, fp)
			}
		}
		principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
		requested, err := a.orch.RequestEndpointRecoveryCheck(ctx, tenantID, orchestrator.EndpointRecoveryCheckRequest{
			TargetID: target.ID, TargetRevision: target.RevisionID, RequiredAgentID: agent,
			RevokedFingerprints: revoked, RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		check, found, err := a.store.GetEndpointRecoveryCheck(ctx, tenantID, target.ID)
		if err != nil {
			return 0, nil, err
		}
		if !found || check.CheckID != requested.CheckID {
			return 0, nil, errStatus(http.StatusConflict, "a newer recovery check of this target replaced this one")
		}
		return http.StatusAccepted, toEndpointRecoveryCheckResponse(check), nil
	})
}

func recoveryTargetID(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.PathValue("id"))
	parsed, err := googleuuid.Parse(id)
	if err != nil || parsed == googleuuid.Nil || parsed.String() != id {
		return "", errStatus(http.StatusBadRequest, "target id must be a canonical non-zero UUID")
	}
	return id, nil
}

// withRecoveryReadiness puts a contained listener's recovery readiness on a
// replacement preview. The preview is ready only when recovery is.
func withRecoveryReadiness(preview endpointBindingPreviewResponse, recovery *endpointRecoveryReadiness,
	identityID string) endpointBindingPreviewResponse {
	if recovery == nil {
		return preview
	}
	preview.RecoveryReadiness = recovery
	if recovery.State != recoveryReady {
		preview.Ready = false
		preview.RecoverySteps = append([]string{"Check host recovery readiness: POST /api/v1/connectors/targets/" +
			preview.Target.ID + "/recovery-check with identity_id " + identityID + ", then preview again."},
			preview.RecoverySteps...)
	}
	return preview
}

// recoveryNotReadyError refuses to authorize a replacement whose contained
// listener has no confirmed way back.
func recoveryNotReadyError(recovery *endpointRecoveryReadiness) error {
	if recovery == nil || recovery.State == recoveryReady {
		return nil
	}
	return errStatus(http.StatusConflict, "the contained listener's recovery is "+recovery.State+": "+
		strings.Join(recovery.Reasons, "; ")+"; check host recovery readiness and preview again; nothing was queued or changed")
}
