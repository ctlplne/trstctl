// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"net/http"
	"strconv"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentRotationPreviewRequest struct {
	SecretName string                           `json:"secret_name"`
	Order      []servicedependents.DependentRef `json:"order"`
	Probes     []servicedependents.ProbeBinding `json:"probes"`
}
type dependentRotationRequest struct {
	Intent                 servicedependents.RotationIntent `json:"intent"`
	IntentDigest           string                           `json:"intent_digest"`
	AcknowledgeSinglePhase bool                             `json:"acknowledge_single_phase"`
}
type dependentRotationView struct {
	Rotation store.ServiceDependentRotation `json:"rotation"`
	Command  secretStaticRotationView       `json:"command"`
}

func (a *API) pamServiceDependentRotationRoutes() []route {
	root := "/api/v1/access/discovery/accounts/{account_id}/dependents/rotations"
	return []route{
		{method: "POST", path: root + "/preview", opID: "previewPAMServiceDependentRotation", summary: "Review complete native dependent inventory, restart order and useful-work bindings before AD rotation", handler: a.previewPAMServiceDependentRotation, pathParams: []param{pathUUID("account_id")}, reqSchema: "PAMServiceDependentRotationPreviewRequest", resSchema: "PAMServiceDependentRotationPreview", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: root, opID: "queuePAMServiceDependentRotation", summary: "Queue the exact reviewed AD rotation and all native dependent effects", handler: a.queuePAMServiceDependentRotation, pathParams: []param{pathUUID("account_id")}, reqSchema: "PAMServiceDependentRotationRequest", resSchema: "PAMServiceDependentRotationView", successCode: "202", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/discovery/dependent-rotations/{id}/steps", opID: "listPAMServiceDependentRotationSteps", summary: "Page exact native step evidence and independent delivery state", handler: a.listPAMServiceDependentRotationSteps, pathParams: []param{pathUUID("id")}, query: []param{{name: "after", typ: "string", desc: "the last step ID from the previous page"}, {name: "limit", typ: "integer", desc: "1-256 steps, default 50"}}, resSchema: "PAMServiceDependentRotationStepList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/discovery/dependent-rotations/{id}", opID: "getPAMServiceDependentRotation", summary: "Read directory rotation and dependent rollback progress", handler: a.getPAMServiceDependentRotation, pathParams: []param{pathUUID("id")}, resSchema: "PAMServiceDependentRotationView", successCode: "200", perm: authz.AccessRead},
	}
}
func (a *API) dependentRotationPermission(ctx context.Context, r *http.Request, tenantID, key string) error {
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if !principal.Can(authz.SecretsWrite, authz.Scope{TenantID: tenantID}) {
		return errStatus(http.StatusForbidden, "service-account rotation also requires secrets:write")
	}
	if e := a.checkABAC(ctx, r, principal, authz.SecretsWrite, authz.Scope{TenantID: tenantID}); e != nil {
		return e
	}
	return a.requireSecretWrite(ctx, tenantID, key)
}
func (a *API) dependentRotationInputs(ctx context.Context, tenantID, accountID string) ([]servicedependents.RotationHostInput, error) {
	svc, e := a.serviceDependentDiscovery()
	if e != nil {
		return nil, e
	}
	after := ""
	var inputs []servicedependents.RotationHostInput
	for {
		page, e := svc.ListPAMServiceDependentHosts(ctx, tenantID, accountID, after, 256)
		if e != nil {
			return nil, e
		}
		for _, host := range page.Items {
			if !host.Binding.Enabled {
				continue
			}
			if host.LatestScan == nil || host.LatestScan.Status != "complete" || !host.LatestScan.Current {
				return nil, errStatus(http.StatusConflict, "every enabled host needs a current complete signed native inventory")
			}
			scan, e := svc.GetPAMServiceDependentScan(ctx, tenantID, host.LatestScan.ID)
			if e != nil {
				return nil, e
			}
			if scan.Report == nil || scan.Status != "complete" || scan.Intent.Binding != host.Binding {
				return nil, errStatus(http.StatusConflict, "current signed host inventory differs")
			}
			if e := a.validateDependentScanSource(ctx, tenantID, scan); e != nil {
				return nil, e
			}
			inputs = append(inputs, servicedependents.RotationHostInput{Binding: host.Binding, Inventory: *scan.Report, InventoryDigest: scan.ReportDigest})
			// The final event is bounded. Stop collecting when even references exceed
			// that wire bound, rather than imposing a permanent host-count ceiling.
			refs, e := json.Marshal(inputsHostReferences(inputs))
			if e != nil {
				return nil, e
			}
			if len(refs) > servicedependents.MaxRotationPlanBytes {
				return nil, errStatus(http.StatusRequestEntityTooLarge, "complete account review exceeds the current bound; no directory reset was queued")
			}
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == after {
			return nil, errors.New("api: dependent host cursor did not advance")
		}
		after = page.NextCursor
	}
	if len(inputs) == 0 {
		return nil, errStatus(http.StatusConflict, "select and scan the account's enrolled member hosts first")
	}
	return inputs, nil
}
func inputsHostReferences(inputs []servicedependents.RotationHostInput) []servicedependents.HostBinding {
	out := make([]servicedependents.HostBinding, 0, len(inputs))
	for _, v := range inputs {
		out = append(out, v.Binding)
	}
	return out
}

//trstctl:mutation
func (a *API) previewPAMServiceDependentRotation(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var req dependentRotationPreviewRequest
		if e := decodeJSON(r, &req); e != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, e)
		}
		if e := a.dependentRotationPermission(ctx, r, tenantID, req.SecretName); e != nil {
			return 0, nil, e
		}
		inputs, e := a.dependentRotationInputs(ctx, tenantID, r.PathValue("account_id"))
		if e != nil {
			return 0, nil, e
		}
		account := inputs[0].Binding.Account
		provider, _, e := a.staticRotationProvider(tenantID, account.ProviderID, req.SecretName)
		if e != nil {
			return 0, nil, e
		}
		prepared, ok := provider.(dynsecret.PreparedStaticRotationProvider)
		if !ok || staticRotationPhase(provider, req.SecretName) != dynsecret.RotationSinglePhase {
			return 0, nil, errStatus(http.StatusConflict, "a prepared native AD provider is required")
		}
		if _, ok := provider.(dynsecret.StaticCredentialRestorer); !ok {
			return 0, nil, errStatus(http.StatusConflict, "a native AD inverse is required")
		}
		current, e := a.secrets.be.Store.GetSecret(ctx, tenantID, req.SecretName)
		if e != nil {
			return 0, nil, e
		}
		plan, e := servicedependents.NewRotationPlan(googleuuid.NewString(), account, req.SecretName, inputs, req.Order, time.Now().UTC())
		if e != nil {
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, e)
		}
		intent := servicedependents.RotationIntent{Plan: plan, ExpectedVersion: current.Version, ProviderBinding: prepared.StaticRotationBinding(req.SecretName), Probes: req.Probes}
		if e = intent.Validate(inputs); e != nil {
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, e)
		}
		digest, e := intent.Digest()
		if e != nil {
			return 0, nil, e
		}
		return http.StatusOK, struct {
			Intent servicedependents.RotationIntent `json:"intent"`
			Digest string                           `json:"intent_digest"`
		}{intent, digest}, nil
	})
}

//trstctl:mutation
func (a *API) queuePAMServiceDependentRotation(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var req dependentRotationRequest
		if e := decodeJSON(r, &req); e != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, e)
		}
		if e := a.dependentRotationPermission(ctx, r, tenantID, req.Intent.Plan.SecretName); e != nil {
			return 0, nil, e
		}
		digest, e := req.Intent.Digest()
		if e != nil || digest != req.IntentDigest || req.Intent.Plan.Account.AccountID != r.PathValue("account_id") || !req.AcknowledgeSinglePhase {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "exact reviewed plan and single-phase acknowledgement required")
		}
		var parent store.ServiceDependentRotation
		e = a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			// Recover the first source even when the response or SQL projection was lost.
			if source, found, e := a.log.EventByID(ctx, req.Intent.Plan.ID); e != nil {
				return e
			} else if found {
				var queued projections.ServiceDependentRotationQueued
				if source.Type != projections.EventServiceDependentRotationQueued || source.TenantID != tenantID || json.Unmarshal(source.Data, &queued) != nil {
					return store.ErrIdempotencyConflict
				}
				retained, e := queued.Intent.Digest()
				if e != nil || retained != digest {
					return store.ErrIdempotencyConflict
				}
				if e := projections.New(a.store).Apply(ctx, source); e != nil {
					return e
				}
				parent, e = a.store.GetServiceDependentRotation(ctx, tenantID, source.ID)
				return e
			}
			now := time.Now().UTC()
			if !now.Before(req.Intent.Plan.ExpiresAt) || req.Intent.Plan.CreatedAt.After(now.Add(time.Minute)) {
				return errStatus(http.StatusConflict, "reviewed native inventory expired; rescan before resetting AD")
			}
			inputs, e := a.dependentRotationInputs(ctx, tenantID, r.PathValue("account_id"))
			if e != nil {
				return e
			}
			if e = req.Intent.Validate(inputs); e != nil {
				return errWithStatus(http.StatusConflict, e)
			}
			current, e := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Intent.Plan.SecretName)
			if e != nil {
				return e
			}
			if current.Version != req.Intent.ExpectedVersion {
				return errStatus(http.StatusConflict, staticRotationVersionMovedDetail)
			}
			provider, _, e := a.staticRotationProvider(tenantID, req.Intent.Plan.Account.ProviderID, req.Intent.Plan.SecretName)
			if e != nil {
				return e
			}
			prep, ok := provider.(dynsecret.PreparedStaticRotationProvider)
			if !ok || prep.StaticRotationBinding(req.Intent.Plan.SecretName) != req.Intent.ProviderBinding || staticRotationPhase(provider, req.Intent.Plan.SecretName) != dynsecret.RotationSinglePhase {
				return errStatus(http.StatusConflict, "native AD provider changed after review")
			}
			if latest, found, e := a.store.LatestSecretStaticRotationCommandForKey(ctx, tenantID, req.Intent.Plan.SecretName); e != nil {
				return e
			} else if found && !latest.Terminal() {
				return errStatus(http.StatusConflict, staticRotationInFlightDetail)
			}
			epoch, e := a.applicationSecretTenantEpoch(ctx, tenantID)
			if e != nil {
				return e
			}
			keyDigest := crypto.SHA256Hex([]byte("service-dependent-rotation:" + req.Intent.Plan.ID))
			// One canonical operation identity lets the worker find the parent
			// source even if its projected child-parent column is removed.
			childID := req.Intent.Plan.ID
			child := projections.SecretStaticRotationQueued{ID: childID, TenantEpoch: epoch, Provider: req.Intent.Plan.Account.ProviderID, Key: req.Intent.Plan.SecretName, OldRef: req.Intent.Plan.Account.DN, ProviderBinding: req.Intent.ProviderBinding, ExpectedVersion: req.Intent.ExpectedVersion, IdempotencyKeyDigest: keyDigest, RequestBinding: digest, DependentChangeID: req.Intent.Plan.ID, SinglePhaseAcknowledged: true}
			actor, e := requestPrincipalSubject(ctx)
			if e != nil {
				return e
			}
			queued := projections.ServiceDependentRotationQueued{Intent: req.Intent, Child: child, Actor: actor, At: now}
			if e := a.appendAndProjectStaticRotation(ctx, tenantID, req.Intent.Plan.ID, projections.EventServiceDependentRotationQueued, queued); e != nil {
				return e
			}
			parent, e = a.store.GetServiceDependentRotation(ctx, tenantID, req.Intent.Plan.ID)
			return e
		})
		if e != nil {
			return 0, nil, e
		}
		view, e := a.dependentRotationView(ctx, parent)
		return http.StatusAccepted, view, e
	})
}
func (a *API) dependentRotationView(ctx context.Context, parent store.ServiceDependentRotation) (dependentRotationView, error) {
	child, e := a.store.GetSecretStaticRotationCommand(ctx, parent.TenantID, parent.CommandID)
	if e != nil {
		return dependentRotationView{}, e
	}
	return dependentRotationView{Rotation: parent, Command: toSecretStaticRotationView(child)}, nil
}
func (a *API) getPAMServiceDependentRotation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	parent, e := a.store.GetServiceDependentRotation(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(e, store.ErrServiceDependentRotationNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "service-account rotation not found"))
		return
	}
	if e != nil {
		a.writeError(w, e)
		return
	}
	if e := a.requireSecretRead(r.Context(), tenantID, parent.Intent.Plan.SecretName); e != nil {
		a.writeError(w, e)
		return
	}
	view, e := a.dependentRotationView(r.Context(), parent)
	if e != nil {
		a.writeError(w, e)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// Every publication gate reads the exact canonical queued and observed source
// before using a projected status to advance the native sequence.
func (a *API) nextDependentStep(ctx context.Context, parent store.ServiceDependentRotation, preflight bool) (*servicedependents.RotationStep, error) {
	inputs, err := a.dependentRotationStoredInputs(ctx, parent)
	if err != nil {
		return nil, err
	}
	steps, err := parent.Intent.Steps(inputs, parent.Direction)
	if err != nil {
		return nil, err
	}
	for _, step := range steps {
		if preflight && step.Action != servicedependents.Preflight {
			return nil, nil
		}
		saved, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, step.ID)
		if errors.Is(err, store.ErrServiceDependentStepNotFound) {
			return &step, nil
		}
		if err != nil {
			return nil, err
		}
		if saved.Status == "failed" || saved.Status == "uncertain" {
			return &saved.Intent, store.ErrServiceDependentStepFailed
		}
		if saved.Status != "succeeded" {
			return &saved.Intent, nil
		}
	}
	return nil, nil
}

func (a *API) validateDependentScanSource(ctx context.Context, tenantID string, scan store.ServiceDependentScan) error {
	queued, found, e := a.log.EventByID(ctx, scan.QueuedEventID)
	if e != nil {
		return e
	}
	var source projections.ServiceDependentScanQueued
	if !found || queued.Type != projections.EventServiceDependentScanQueued || queued.TenantID != tenantID || json.Unmarshal(queued.Data, &source) != nil || source.Intent.RunID != scan.ID || source.Intent.BindingDigest != scan.Intent.BindingDigest {
		return errStatus(http.StatusConflict, "native inventory queued source differs; rescan this host before rotation")
	}
	if scan.ObservedEventID == "" {
		return errStatus(http.StatusConflict, "rescan this host to bind the signed native observation")
	}
	observed, found, e := a.log.EventByID(ctx, scan.ObservedEventID)
	if e != nil {
		return e
	}
	var report projections.ServiceDependentScanObserved
	if !found || observed.Type != projections.EventServiceDependentScanObserved || observed.TenantID != tenantID || json.Unmarshal(observed.Data, &report) != nil || report.Report.Validate(source.Intent) != nil || report.EvidenceDigest != scan.ReportDigest || report.JobID <= 0 || report.Attempt <= 0 || report.ReceiptSignature == "" {
		return errStatus(http.StatusConflict, "native inventory has no exact retained signed observation; rescan this host before rotation")
	}
	raw, e := json.Marshal(report.Report)
	if e != nil {
		return e
	}
	if crypto.SHA256Hex(raw) != scan.ReportDigest {
		return errStatus(http.StatusConflict, "native inventory differs from canonical signed metadata; rescan this host before rotation")
	}
	return nil
}

func (a *API) listPAMServiceDependentRotationSteps(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	parent, e := a.store.GetServiceDependentRotation(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(e, store.ErrServiceDependentRotationNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "service-account rotation not found"))
		return
	}
	if e != nil {
		a.writeError(w, e)
		return
	}
	if e := a.requireSecretRead(r.Context(), tenantID, parent.Intent.Plan.SecretName); e != nil {
		a.writeError(w, e)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 256 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-256"))
			return
		}
		limit = n
	}
	after := r.URL.Query().Get("after")
	if after != "" {
		value, e := hex.DecodeString(after)
		if e != nil || len(value) != 16 || after != strings.ToLower(after) {
			a.writeError(w, errStatus(http.StatusBadRequest, "after must be a canonical step ID"))
			return
		}
	}
	steps, e := a.store.ListServiceDependentSteps(r.Context(), tenantID, parent.ID, after, limit)
	if e != nil {
		a.writeError(w, e)
		return
	}
	result := struct {
		Items      []store.ServiceDependentStep `json:"items"`
		NextCursor string                       `json:"next_cursor,omitempty"`
	}{Items: []store.ServiceDependentStep{}}
	if len(steps) > limit {
		steps = steps[:limit]
		result.NextCursor = steps[len(steps)-1].Intent.ID
	}
	for _, step := range steps {
		verified, err := a.canonicalDependentStep(r.Context(), tenantID, parent.ID, step.Intent.ID)
		if err != nil {
			if errors.Is(err, errDependentCanonicalEvidence) {
				err = errStatus(http.StatusConflict, "native step evidence differs from its retained source; rebuild projections before continuing")
			}
			a.writeError(w, err)
			return
		}
		verified.DeliveryStatus = step.DeliveryStatus
		result.Items = append(result.Items, verified)
	}
	a.writeJSON(w, http.StatusOK, result)
}
