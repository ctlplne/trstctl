// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"net/http"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentRecoveryReview struct {
	Digest               string                         `json:"recovery_digest"`
	IntentDigest         string                         `json:"intent_digest"`
	Previous             servicedependents.RotationStep `json:"previous_step"`
	PreviousStatus       string                         `json:"previous_status"`
	PreviousReportDigest string                         `json:"previous_report_digest,omitempty"`
	CurrentVersion       int                            `json:"current_vault_version"`
	RetainedVersion      int                            `json:"retained_generation_version"`
}
type dependentRecoveryRequest struct {
	StepID       string `json:"step_id"`
	IntentDigest string `json:"intent_digest"`
	Digest       string `json:"recovery_digest"`
	Reason       string `json:"reason"`
	Acknowledge  bool   `json:"acknowledge_original_outcome"`
}
type dependentRecoveryQueued struct {
	Step   servicedependents.RotationStep `json:"step"`
	Digest string                         `json:"recovery_digest"`
}

func (a *API) dependentRecoveryParent(ctx context.Context, r *http.Request, tenantID, id string) (store.ServiceDependentRotation, store.SecretStaticRotationCommand, error) {
	parent, err := a.store.GetServiceDependentRotation(ctx, tenantID, id)
	if errors.Is(err, store.ErrServiceDependentRotationNotFound) {
		return parent, store.SecretStaticRotationCommand{}, errStatus(http.StatusNotFound, "service-account rotation not found")
	}
	if err != nil {
		return parent, store.SecretStaticRotationCommand{}, err
	}
	if err := a.dependentRotationPermission(ctx, r, tenantID, parent.Intent.Plan.SecretName); err != nil {
		return parent, store.SecretStaticRotationCommand{}, err
	}
	cmd, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, parent.CommandID)
	if err != nil {
		return parent, cmd, err
	}
	if cmd.ID != id || parent.ID != cmd.ID {
		return parent, cmd, errDependentCanonicalEvidence
	}
	canonical, err := a.dependentRotationParent(ctx, cmd)
	if err != nil {
		return parent, cmd, err
	}
	if canonical.ID != id || canonical.IntentDigest != parent.IntentDigest {
		return parent, cmd, errDependentCanonicalEvidence
	}
	return canonical, cmd, nil
}
func (a *API) dependentRecoveryReview(ctx context.Context, parent store.ServiceDependentRotation, cmd store.SecretStaticRotationCommand, stepID string) (dependentRecoveryReview, error) {
	refused := errStatus(http.StatusConflict, "only the next failed, uncertain or expired inverse step can receive explicit recovery")
	if cmd.Terminal() || parent.Direction != servicedependents.Inverse || !parent.DirectoryRestored {
		return dependentRecoveryReview{}, refused
	}
	next, err := a.nextDependentStep(ctx, parent, false)
	if err != nil && !errors.Is(err, store.ErrServiceDependentStepFailed) {
		return dependentRecoveryReview{}, err
	}
	if next == nil || next.ID != stepID {
		return dependentRecoveryReview{}, refused
	}
	previous, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, stepID)
	if err != nil {
		return dependentRecoveryReview{}, err
	}
	if previous.Status != "failed" && previous.Status != "uncertain" && (previous.Status != "queued" || !time.Now().After(previous.Intent.Deadline.Add(time.Minute))) {
		return dependentRecoveryReview{}, refused
	}
	if previous.Intent.Recovery != nil && previous.Intent.Recovery.Depth >= servicedependents.MaxInverseRecoveryDepth-1 {
		return dependentRecoveryReview{}, errStatus(http.StatusConflict, "retained recovery history is full; preserve its evidence before further recovery")
	}
	if _, err := a.dependentIntentProvider(parent.TenantID, parent.Intent); err != nil {
		return dependentRecoveryReview{}, err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, parent.TenantID, cmd.Key)
	if err != nil {
		return dependentRecoveryReview{}, err
	}
	reportDigest := projections.ServiceDependentReportDigest(previous.Report)
	digest, err := projections.ServiceDependentRecoveryReviewDigest(previous.Intent, previous.Status, reportDigest, current.Version)
	if err != nil {
		return dependentRecoveryReview{}, err
	}
	return dependentRecoveryReview{Digest: digest, IntentDigest: parent.IntentDigest, Previous: previous.Intent, PreviousStatus: previous.Status, PreviousReportDigest: reportDigest, CurrentVersion: current.Version, RetainedVersion: cmd.ExpectedVersion}, nil
}
func validDependentRecoveryStepID(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && value == strings.ToLower(value)
}
func (a *API) previewPAMServiceDependentRecovery(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.secrets == nil {
		a.writeError(w, ErrPAMUnavailable)
		return
	}
	stepID := r.URL.Query().Get("step_id")
	if !validDependentRecoveryStepID(stepID) {
		a.writeError(w, errStatus(http.StatusBadRequest, "exact canonical step ID required"))
		return
	}
	parent, cmd, err := a.dependentRecoveryParent(r.Context(), r, tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	review, err := a.dependentRecoveryReview(r.Context(), parent, cmd, stepID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, review)
}

//trstctl:mutation
func (a *API) queuePAMServiceDependentRecovery(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var req dependentRecoveryRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if !validDependentRecoveryStepID(req.StepID) || !req.Acknowledge || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 4096 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "exact inverse step, bounded reason and original-outcome acknowledgement required")
		}
		actor, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		var result dependentRecoveryQueued
		err = a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			parent, cmd, err := a.dependentRecoveryParent(ctx, r, tenantID, r.PathValue("id"))
			if err != nil {
				return err
			}
			if parent.IntentDigest != req.IntentDigest {
				return store.ErrIdempotencyConflict
			}
			sourceID := servicedependents.RecoverySourceID(parent.ID, req.StepID)
			if source, found, err := a.log.EventByID(ctx, sourceID); err != nil {
				return err
			} else if found {
				var existing projections.ServiceDependentStepRecoveryQueued
				if source.TenantID != tenantID || json.Unmarshal(source.Data, &existing) != nil || projections.ValidateServiceDependentStepRecovery(source, existing) != nil || existing.Actor != actor || existing.Reason != strings.TrimSpace(req.Reason) || existing.ReviewDigest != req.Digest {
					return store.ErrIdempotencyConflict
				}
				if err := projections.New(a.store).Apply(ctx, source); err != nil {
					return err
				}
				result = dependentRecoveryQueued{existing.Step, existing.ReviewDigest}
				return nil
			}
			review, err := a.dependentRecoveryReview(ctx, parent, cmd, req.StepID)
			if err != nil {
				return err
			}
			if req.Digest != review.Digest {
				return errStatus(http.StatusConflict, "inverse recovery review changed; reopen the exact effect before queuing")
			}
			now := time.Now().UTC()
			challenge := googleuuid.NewString()
			next, err := servicedependents.NewInverseRecoveryStep(review.Previous, challenge, now)
			if err != nil {
				return err
			}
			value := projections.ServiceDependentStepRecoveryQueued{Previous: review.Previous, Step: next, PreviousStatus: review.PreviousStatus, PreviousReportDigest: review.PreviousReportDigest, CurrentVersion: review.CurrentVersion, ReviewDigest: review.Digest, Actor: actor, Reason: strings.TrimSpace(req.Reason), At: now}
			raw, err := json.Marshal(value)
			if err != nil {
				return err
			}
			event := events.Event{ID: sourceID, TenantID: tenantID, Type: projections.EventServiceDependentStepRecoveryQueued, SchemaVersion: 1, Time: now, Data: raw}
			if requester, ok := events.ActorFromContext(ctx); ok {
				event.Actor = &requester
			}
			if err := projections.ValidateServiceDependentStepRecovery(event, value); err != nil {
				return err
			}
			canonical, err := a.log.Append(ctx, event)
			if err != nil {
				return err
			}
			if canonical.ID != event.ID || canonical.TenantID != tenantID || canonical.Type != event.Type || !bytes.Equal(canonical.Data, event.Data) {
				return store.ErrIdempotencyConflict
			}
			if err := projections.New(a.store).Apply(ctx, canonical); err != nil {
				return err
			}
			result = dependentRecoveryQueued{next, review.Digest}
			return nil
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, result, nil
	})
}
func (a *API) dependentRecoveryRoutes() []route {
	root := "/api/v1/access/discovery/dependent-rotations/{id}/recoveries"
	return []route{
		{method: "GET", path: root + "/preview", opID: "previewPAMServiceDependentRecovery", summary: "Review one exact inverse recovery while retaining its original failed or uncertain evidence", handler: a.previewPAMServiceDependentRecovery, pathParams: []param{pathUUID("id")}, query: []param{{name: "step_id", typ: "string", required: true}}, resSchema: "PAMServiceDependentRecoveryReview", successCode: "200", perm: authz.AccessTargetsWrite},
		{method: "POST", path: root, opID: "queuePAMServiceDependentRecovery", summary: "Explicitly queue a fresh inverse lease for the unchanged retained effect", handler: a.queuePAMServiceDependentRecovery, pathParams: []param{pathUUID("id")}, reqSchema: "PAMServiceDependentRecoveryRequest", resSchema: "PAMServiceDependentRecoveryQueued", successCode: "202", mutation: true, perm: authz.AccessTargetsWrite},
	}
}
