// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Renewal waves of a switching import (A265). A wave moves the renewal of a
// bounded set of imported certificates from the other product to trstctl:
// each row gets the one identity trstctl keeps for it, bound to the
// deployment target the wave assigns it (a target carries one active
// identity) and issued through the same transition, approval and profile
// policy as any issuance; the deploy and later renewals follow the identity's
// ordinary lifecycle. The preview names every selected row it
// leaves out and why, and the certificates the other product must stop
// renewing. Rolling a wave back — refused while an issuance or renewal of it
// is in flight — withdraws its queued deploys, pauses each identity's renewal
// on its target and returns the rows to watch-only.

// maxSwitchingWaveRows bounds one wave: waves exist to move renewals over a
// few at a time, each with its own rollback.
const maxSwitchingWaveRows = 100

func (a *API) switchingWaveRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/switching/imports/{id}/waves/preview", opID: "previewSwitchingWave", summary: "Plan a renewal wave without changing state: the imported rows it moves to trstctl, each with the deployment target it is assigned and the identity it gets, every assigned row it leaves out and why, and the certificates the other product must stop renewing", handler: a.previewSwitchingWave, pathParams: idPath, reqSchema: "SwitchingWaveRequest", resSchema: "SwitchingWavePreview", successCode: "200", readOnly: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/switching/imports/{id}/waves", opID: "cutOverSwitchingWave", summary: "Cut over a previewed renewal wave: each row's identity is bound to its deployment target and issued through the ordinary issuance policy, and trstctl renews it from then on; a changed plan refuses the stale digest", handler: a.cutOverSwitchingWave, pathParams: idPath, reqSchema: "SwitchingWaveRequest", resSchema: "SwitchingWave", successCode: "201", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/switching/imports/{id}/waves", opID: "listSwitchingWaves", summary: "List an import's renewal waves, newest first", handler: a.listSwitchingWaves, pathParams: idPath, resSchema: "SwitchingWaveList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/switching/waves/{id}", opID: "getSwitchingWave", summary: "Get a renewal wave: each row's identity and its state, the certificates trstctl issued for it and what its endpoint serves", handler: a.getSwitchingWave, pathParams: idPath, resSchema: "SwitchingWave", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/switching/waves/{id}/rollback", opID: "rollbackSwitchingWave", summary: "Roll a renewal wave back once no issuance or renewal of it is in flight: withdraw its queued deploys, pause each identity's renewal on its target and return the rows to watch-only, with a receipt of what trstctl issued", handler: a.rollbackSwitchingWave, pathParams: idPath, reqSchema: "SwitchingWaveRollbackRequest", resSchema: "SwitchingWave", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
	}
}

// switchingWaveAssignment assigns an imported row the deployment target its
// replacement goes to.
type switchingWaveAssignment struct {
	Row      int    `json:"row_number"`
	TargetID string `json:"target_id"`
}

type switchingWaveRequest struct {
	Name          string                    `json:"name"`
	Assignments   []switchingWaveAssignment `json:"assignments"`
	IssuerID      string                    `json:"issuer_id,omitempty"`
	PreviewDigest string                    `json:"preview_digest,omitempty"`
}

type switchingWaveRowPlan struct {
	Row                 int                 `json:"row_number"`
	CommonName          string              `json:"common_name"`
	OwnerID             string              `json:"owner_id"`
	IdentityID          string              `json:"identity_id"`
	IdentityExists      bool                `json:"identity_exists"`
	Target              switchingWaveTarget `json:"target"`
	IssuerID            string              `json:"issuer_id,omitempty"`
	ImportedFingerprint string              `json:"imported_fingerprint_sha256"`
	Folder              string              `json:"folder,omitempty"`
	Application         string              `json:"application,omitempty"`
	WatchStatus         string              `json:"watch_status,omitempty"`
}

type switchingWaveExcluded struct {
	Row    int    `json:"row_number"`
	Reason string `json:"reason"`
}

type switchingWaveTarget struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Connector string `json:"connector"`
}

type switchingWavePreview struct {
	ImportID     string                  `json:"import_id"`
	Name         string                  `json:"name"`
	IssuerID     string                  `json:"issuer_id,omitempty"`
	Rows         []switchingWaveRowPlan  `json:"rows"`
	Excluded     []switchingWaveExcluded `json:"excluded"`
	StopRenewing []string                `json:"stop_renewing"`
	Digest       string                  `json:"digest"`
}

func decodeSwitchingWaveRequest(r *http.Request) (switchingWaveRequest, error) {
	var req switchingWaveRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, errWithStatus(http.StatusBadRequest, err)
	}
	req.Name, req.IssuerID = strings.TrimSpace(req.Name), strings.TrimSpace(req.IssuerID)
	if req.Name == "" || len(req.Name) > 200 {
		return req, errStatus(http.StatusBadRequest, "name is required (at most 200 characters)")
	}
	if len(req.Assignments) == 0 {
		return req, errStatus(http.StatusBadRequest,
			"assignments are required: each row the wave moves, with the deployment target its replacement goes to")
	}
	if len(req.Assignments) > maxSwitchingWaveRows {
		return req, errStatus(http.StatusBadRequest, fmt.Sprintf("a wave moves at most %d rows", maxSwitchingWaveRows))
	}
	for i := range req.Assignments {
		req.Assignments[i].TargetID = strings.TrimSpace(req.Assignments[i].TargetID)
		if req.Assignments[i].Row <= 0 || req.Assignments[i].TargetID == "" {
			return req, errStatus(http.StatusBadRequest, "each assignment names a row_number and a target_id")
		}
	}
	return req, nil
}

// planSwitchingWave works out what a wave would move, against the import, the
// live waves, the inventory, the targets and trstctl's identities as they are
// now.
func (a *API) planSwitchingWave(ctx context.Context, tenantID, importID string, req switchingWaveRequest) (switchingWavePreview, map[string]store.DeploymentTarget, error) {
	imp, err := a.store.GetSwitchingImport(ctx, tenantID, importID)
	if err != nil {
		return switchingWavePreview{}, nil, switchingImportNotFound(err)
	}
	if imp.Status != "completed" {
		return switchingWavePreview{}, nil, errStatus(http.StatusConflict, "the import is still being applied; plan a wave once it completes")
	}
	if req.IssuerID != "" {
		if _, err := a.store.GetIssuer(ctx, tenantID, req.IssuerID); err != nil {
			return switchingWavePreview{}, nil, errStatus(http.StatusBadRequest, "issuer_id names no issuer of this tenant")
		}
	}
	numbers := make([]int, 0, len(req.Assignments))
	for _, as := range req.Assignments {
		numbers = append(numbers, as.Row)
	}
	rows, err := a.store.SwitchingImportRowsForWave(ctx, tenantID, importID, numbers, "", "", "", len(numbers)+1)
	if err != nil {
		return switchingWavePreview{}, nil, err
	}
	byNumber := make(map[int]store.SwitchingImportRow, len(rows))
	for _, row := range rows {
		byNumber[row.Row] = row
	}
	live, err := a.store.LiveSwitchingWaveRows(ctx, tenantID, importID)
	if err != nil {
		return switchingWavePreview{}, nil, err
	}
	out := switchingWavePreview{ImportID: importID, Name: req.Name, IssuerID: req.IssuerID,
		Rows: []switchingWaveRowPlan{}, Excluded: []switchingWaveExcluded{}, StopRenewing: []string{}}
	targets := map[string]store.DeploymentTarget{}
	seenRow, seenTarget := map[int]bool{}, map[string]int{}
	for _, as := range req.Assignments {
		exclude := func(reason string) {
			out.Excluded = append(out.Excluded, switchingWaveExcluded{Row: as.Row, Reason: reason})
		}
		row, ok := byNumber[as.Row]
		switch {
		case seenRow[as.Row]:
			exclude("the row is assigned twice in this wave")
			continue
		case !ok:
			exclude("the import has no such row")
			continue
		}
		seenRow[as.Row] = true
		switch {
		case row.Outcome != "mapped" && row.Outcome != "mapped_with_gaps":
			exclude("the row is " + row.Outcome + ": " + row.Reason)
			continue
		case row.AppliedAt == nil:
			exclude("the row is not applied yet")
			continue
		case row.Linked:
			exclude("the certificate was already in the inventory before the import; manage it where it is")
			continue
		case row.CommonName == "":
			exclude("the export names no common name for the replacement")
			continue
		case row.OwnerID == "":
			exclude("the row has no owner; assign one before moving its renewal")
			continue
		}
		if w, ok := live[row.Row]; ok {
			exclude("the row is already in live wave " + w.WaveID)
			continue
		}
		extra := 0
		for _, san := range row.SANs {
			if !strings.EqualFold(san, row.CommonName) {
				extra++
			}
		}
		if extra > 0 {
			exclude(fmt.Sprintf("the replacement would cover only %s; the export lists %d more names", row.CommonName, extra))
			continue
		}
		target, ok := targets[as.TargetID]
		if !ok {
			target, err = a.store.GetDeploymentTarget(ctx, tenantID, as.TargetID)
			if store.IsNotFound(err) {
				exclude("target " + as.TargetID + " is no deployment target of this tenant")
				continue
			} else if err != nil {
				return switchingWavePreview{}, nil, err
			}
			targets[as.TargetID] = target
		}
		if !target.Enabled {
			exclude("target " + target.Name + " is disabled")
			continue
		}
		if first, used := seenTarget[target.ID]; used {
			exclude(fmt.Sprintf("target %s is assigned to row %d in this wave; a target carries one identity", target.Name, first))
			continue
		}
		identityID := orchestrator.SwitchingRowIdentityID(tenantID, importID, row.Row)
		if others, err := a.store.OtherActiveIdentitiesOnTarget(ctx, tenantID, target.ID, identityID); err != nil {
			return switchingWavePreview{}, nil, err
		} else if len(others) > 0 {
			exclude("target " + target.Name + " already carries active identity " + others[0])
			continue
		}
		plan := switchingWaveRowPlan{Row: row.Row, CommonName: row.CommonName, OwnerID: row.OwnerID, IdentityID: identityID,
			Target:   switchingWaveTarget{ID: target.ID, Name: target.Name, Connector: target.Type},
			IssuerID: req.IssuerID, ImportedFingerprint: row.Fingerprint, Folder: row.Folder, Application: row.Application,
			WatchStatus: row.WatchStatus}
		if existing, ok, err := a.store.FindIdentityByName(ctx, tenantID, row.CommonName); err != nil {
			return switchingWavePreview{}, nil, err
		} else if ok && existing.ID != identityID {
			exclude("trstctl already manages " + row.CommonName + " as identity " + existing.ID)
			continue
		}
		if ident, err := a.store.GetIdentity(ctx, tenantID, identityID); err == nil {
			// A row moved before keeps its identity and that identity's issuer.
			plan.IdentityExists = true
			plan.IssuerID = ""
			if ident.IssuerID != nil {
				plan.IssuerID = *ident.IssuerID
			}
			if ident.OwnerID != row.OwnerID {
				exclude("trstctl's identity for this row belongs to another owner now")
				continue
			}
		} else if !store.IsNotFound(err) {
			return switchingWavePreview{}, nil, err
		}
		seenTarget[target.ID] = row.Row
		out.Rows = append(out.Rows, plan)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].Row < out.Rows[j].Row })
	sort.Slice(out.Excluded, func(i, j int) bool { return out.Excluded[i].Row < out.Excluded[j].Row })
	for _, p := range out.Rows {
		out.StopRenewing = append(out.StopRenewing, p.ImportedFingerprint)
	}
	h := []string{importID, req.IssuerID, req.Name}
	for _, p := range out.Rows {
		h = append(h, strconv.Itoa(p.Row), p.IdentityID, p.Target.ID, targets[p.Target.ID].RevisionID, p.ImportedFingerprint,
			p.CommonName, p.OwnerID, p.IssuerID)
	}
	out.Digest = "sha256:" + crypto.SHA256Hex([]byte(strings.Join(h, "\x00")))
	return out, targets, nil
}

func (a *API) previewSwitchingWave(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	req, err := decodeSwitchingWaveRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan, _, err := a.planSwitchingWave(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) cutOverSwitchingWave(w http.ResponseWriter, r *http.Request) {
	importID, key := r.PathValue("id"), r.Header.Get("Idempotency-Key")
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if err := requireEndpointIssuancePermission(ctx, tenantID); err != nil {
			return 0, nil, err
		}
		req, err := decodeSwitchingWaveRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if req.PreviewDigest == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "preview_digest is required: preview the wave, review it, then cut over that digest")
		}
		plan, targets, err := a.planSwitchingWave(ctx, tenantID, importID, req)
		if err != nil {
			return 0, nil, err
		}
		if plan.Digest != req.PreviewDigest {
			return 0, nil, errStatus(http.StatusConflict, "the rows, live waves, identities, targets or issuer changed since the preview; preview again")
		}
		if len(plan.Rows) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "the wave moves no rows; every selected row is excluded")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		waveID := orchestrator.SwitchingWaveID(tenantID, importID, key+"\x00"+plan.Digest)
		rows := make([]store.SwitchingWaveRow, 0, len(plan.Rows))
		for _, p := range plan.Rows {
			rows = append(rows, store.SwitchingWaveRow{Row: p.Row, IdentityID: p.IdentityID, TargetID: p.Target.ID,
				ImportedFingerprint: p.ImportedFingerprint})
		}
		if err := a.orch.RecordSwitchingWaveCutOver(ctx, tenantID, projections.SwitchingWaveCutOver{WaveID: waveID, ImportID: importID,
			Name: req.Name, IssuerID: req.IssuerID, PreviewDigest: plan.Digest, Rows: rows, CreatedBy: principal.Subject}); err != nil {
			return 0, nil, err
		}
		reason := "switching wave " + req.Name
		for _, p := range plan.Rows {
			target := targets[p.Target.ID]
			var issuer *string
			if p.IssuerID != "" {
				id := p.IssuerID
				issuer = &id
			}
			attributes, err := json.Marshal(map[string]any{"switching_import_id": importID, "switching_row": p.Row})
			if err != nil {
				return 0, nil, err
			}
			ident, err := a.orch.EnsureIdentity(ctx, tenantID, p.IdentityID, store.Identity{Kind: store.KindX509Certificate,
				Name: p.CommonName, OwnerID: p.OwnerID, IssuerID: issuer, Attributes: attributes})
			if err != nil {
				return 0, nil, err
			}
			if boundTargetID(ident) != target.ID {
				if ident, err = a.orch.BindIdentityDeploymentTarget(ctx, tenantID, ident.ID, target); err != nil {
					return 0, nil, err
				}
			}
			if _, paused := store.IdentityRenewalPauses(ident.Attributes)[target.ID]; paused {
				if err := a.orch.ResumeIdentityRenewal(ctx, tenantID, ident.ID, target.ID); err != nil {
					return 0, nil, err
				}
			}
			if ident.Status == string(orchestrator.StateRequested) {
				// The ordinary issuance command: its approval gate and profile
				// policy apply to a wave exactly as to any other issuance.
				status, body, err := a.executeIdentityTransition(ctx, tenantID, principal, ident.ID,
					transitionRequest{To: string(orchestrator.StateIssued), Reason: reason}, key+":row:"+strconv.Itoa(p.Row))
				if err != nil {
					return 0, nil, err
				}
				if status >= http.StatusBadRequest {
					return status, body, nil
				}
			}
		}
		view, err := a.switchingWaveDetail(ctx, tenantID, waveID)
		return http.StatusCreated, view, err
	})
}

// boundTargetID is the deployment target an identity is bound to.
func boundTargetID(ident store.Identity) string {
	var attrs map[string]any
	if len(ident.Attributes) == 0 || json.Unmarshal(ident.Attributes, &attrs) != nil {
		return ""
	}
	id, _ := attrs["deployment_target_id"].(string)
	return strings.TrimSpace(id)
}

type switchingWaveRowView struct {
	Row                 int      `json:"row_number"`
	IdentityID          string   `json:"identity_id"`
	IdentityStatus      string   `json:"identity_status"`
	TargetID            string   `json:"target_id"`
	RenewalPaused       bool     `json:"renewal_paused"`
	ImportedFingerprint string   `json:"imported_fingerprint_sha256"`
	TrstctlFingerprints []string `json:"trstctl_fingerprints_sha256"`
	WatchStatus         string   `json:"watch_status,omitempty"`
	Live                bool     `json:"live"`
}

type switchingWaveView struct {
	ID             string                 `json:"id"`
	ImportID       string                 `json:"import_id"`
	Name           string                 `json:"name"`
	Status         string                 `json:"status"`
	IssuerID       string                 `json:"issuer_id,omitempty"`
	PreviewDigest  string                 `json:"preview_digest"`
	CreatedBy      string                 `json:"created_by"`
	CreatedAt      time.Time              `json:"created_at"`
	RolledBackAt   *time.Time             `json:"rolled_back_at,omitempty"`
	RolledBackBy   string                 `json:"rolled_back_by,omitempty"`
	RollbackReason string                 `json:"rollback_reason,omitempty"`
	Rows           []switchingWaveRowView `json:"rows"`
	// Withdrawn counts the queued deploys a rollback withdrew or recalled.
	Withdrawn int `json:"withdrawn,omitempty"`
}

func switchingWaveNotFound(err error) error {
	if errors.Is(err, store.ErrSwitchingWaveNotFound) {
		return errStatus(http.StatusNotFound, "switching wave not found")
	}
	return err
}

func (a *API) switchingWaveDetail(ctx context.Context, tenantID, waveID string) (switchingWaveView, error) {
	wave, err := a.store.GetSwitchingWave(ctx, tenantID, waveID)
	if err != nil {
		return switchingWaveView{}, switchingWaveNotFound(err)
	}
	rows, err := a.store.ListSwitchingWaveRows(ctx, tenantID, waveID)
	if err != nil {
		return switchingWaveView{}, err
	}
	ids := make([]string, 0, len(rows))
	numbers := make([]int, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.IdentityID)
		numbers = append(numbers, r.Row)
	}
	issued, err := a.store.TrstctlFingerprintsForIdentities(ctx, tenantID, ids)
	if err != nil {
		return switchingWaveView{}, err
	}
	imported, err := a.store.SwitchingImportRowsForWave(ctx, tenantID, wave.ImportID, numbers, "", "", "", len(numbers)+1)
	if err != nil {
		return switchingWaveView{}, err
	}
	watch := map[int]string{}
	for _, r := range imported {
		watch[r.Row] = r.WatchStatus
	}
	view := switchingWaveView{ID: wave.ID, ImportID: wave.ImportID, Name: wave.Name, Status: wave.Status,
		IssuerID: wave.IssuerID, PreviewDigest: wave.PreviewDigest, CreatedBy: wave.CreatedBy, CreatedAt: wave.CreatedAt,
		RolledBackAt: wave.RolledBackAt, RolledBackBy: wave.RolledBackBy, RollbackReason: wave.RollbackReason,
		Rows: make([]switchingWaveRowView, 0, len(rows))}
	for _, r := range rows {
		row := switchingWaveRowView{Row: r.Row, IdentityID: r.IdentityID, TargetID: r.TargetID, ImportedFingerprint: r.ImportedFingerprint,
			TrstctlFingerprints: issued[r.IdentityID], WatchStatus: watch[r.Row], Live: r.Live}
		if row.TrstctlFingerprints == nil {
			row.TrstctlFingerprints = []string{}
		}
		if ident, err := a.store.GetIdentity(ctx, tenantID, r.IdentityID); err == nil {
			row.IdentityStatus = ident.Status
			_, row.RenewalPaused = store.IdentityRenewalPauses(ident.Attributes)[r.TargetID]
		} else if !store.IsNotFound(err) {
			return switchingWaveView{}, err
		}
		view.Rows = append(view.Rows, row)
	}
	return view, nil
}

func (a *API) listSwitchingWaves(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	importID := r.PathValue("id")
	if _, err := a.store.GetSwitchingImport(r.Context(), tenantID, importID); err != nil {
		a.writeError(w, switchingImportNotFound(err))
		return
	}
	waves, err := a.store.ListSwitchingWaves(r.Context(), tenantID, importID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]switchingWaveView, 0, len(waves))
	for _, wave := range waves {
		view, err := a.switchingWaveDetail(r.Context(), tenantID, wave.ID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		items = append(items, view)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getSwitchingWave(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	view, err := a.switchingWaveDetail(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

type switchingWaveRollbackRequest struct {
	Reason string `json:"reason"`
}

//trstctl:mutation
func (a *API) rollbackSwitchingWave(w http.ResponseWriter, r *http.Request) {
	waveID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req switchingWaveRollbackRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Reason == "" || len(req.Reason) > 200 {
			return 0, nil, errStatus(http.StatusBadRequest, "reason is required (at most 200 characters)")
		}
		wave, err := a.store.GetSwitchingWave(ctx, tenantID, waveID)
		if err != nil {
			return 0, nil, switchingWaveNotFound(err)
		}
		if wave.Status != "cut_over" {
			return 0, nil, errStatus(http.StatusConflict, "the wave is already rolled back")
		}
		rows, err := a.store.ListSwitchingWaveRows(ctx, tenantID, waveID)
		if err != nil {
			return 0, nil, err
		}
		// Nothing is touched while an issuance or a renewal is in flight: its
		// certificate would land after the rollback and deploy on its own.
		identities := make([]string, 0, len(rows))
		for _, row := range rows {
			identities = append(identities, row.IdentityID)
		}
		busy, err := a.store.IdentitiesWithIssuanceOrRenewalInFlight(ctx, tenantID, identities)
		if err != nil {
			return 0, nil, err
		}
		if len(busy) > 0 {
			return 0, nil, errStatus(http.StatusConflict, fmt.Sprintf(
				"identity %s has an issuance or renewal in flight; roll the wave back once it settles (nothing was changed)", busy[0]))
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		reason := "switching wave " + wave.Name + " rolled back: " + req.Reason
		withdrawn := 0
		for _, row := range rows {
			cancelled, err := a.orch.CancelConnectorTargetWork(ctx, tenantID, orchestrator.CancelConnectorWorkRequest{
				TargetID: row.TargetID, IdentityID: row.IdentityID, Reason: reason, RequestedBy: principal.Subject})
			if err != nil {
				return 0, nil, err
			}
			withdrawn += len(cancelled.Withdrawn) + len(cancelled.Recalled)
			if err := a.orch.PauseIdentityRenewal(ctx, tenantID, row.IdentityID, row.TargetID, reason); err != nil {
				return 0, nil, err
			}
		}
		// The scheduler queues no renewal of a paused identity; one it queued
		// while the pauses were being recorded holds the rollback, with the
		// renewals now paused, until it settles.
		if busy, err = a.store.IdentitiesWithIssuanceOrRenewalInFlight(ctx, tenantID, identities); err != nil {
			return 0, nil, err
		} else if len(busy) > 0 {
			return 0, nil, errStatus(http.StatusConflict, fmt.Sprintf(
				"a renewal of identity %s started while the wave was rolling back; its renewals are paused now, so retry the rollback once it settles", busy[0]))
		}
		if err := a.orch.RecordSwitchingWaveRolledBack(ctx, tenantID, projections.SwitchingWaveRolledBack{WaveID: waveID,
			Reason: req.Reason, RolledBackBy: principal.Subject}); err != nil {
			return 0, nil, err
		}
		view, err := a.switchingWaveDetail(ctx, tenantID, waveID)
		view.Withdrawn = withdrawn
		return http.StatusOK, view, err
	})
}

func switchingWaveSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	target := object(map[string]*Schema{"id": str(), "name": str(), "connector": str()}, "id", "name", "connector")
	plan := object(map[string]*Schema{"row_number": integer(), "common_name": str(), "owner_id": str(), "identity_id": str(),
		"identity_exists": boolean(), "target": target, "issuer_id": str(), "imported_fingerprint_sha256": str(), "folder": str(),
		"application": str(), "watch_status": str()},
		"row_number", "common_name", "owner_id", "identity_id", "identity_exists", "target", "imported_fingerprint_sha256")
	excluded := object(map[string]*Schema{"row_number": integer(), "reason": str()}, "row_number", "reason")
	row := object(map[string]*Schema{"row_number": integer(), "identity_id": str(), "target_id": str(), "identity_status": str(),
		"renewal_paused":              boolean(),
		"imported_fingerprint_sha256": str(), "trstctl_fingerprints_sha256": list(str()), "watch_status": str(), "live": boolean()},
		"row_number", "identity_id", "target_id", "identity_status", "renewal_paused", "imported_fingerprint_sha256",
		"trstctl_fingerprints_sha256", "live")
	wave := object(map[string]*Schema{"id": str(), "import_id": str(), "name": str(),
		"status": {Type: "string", Enum: []string{"cut_over", "rolled_back"}}, "issuer_id": str(),
		"preview_digest": str(), "created_by": str(), "created_at": ts(), "rolled_back_at": ts(), "rolled_back_by": str(),
		"rollback_reason": str(), "rows": list(row), "withdrawn": integer()},
		"id", "import_id", "name", "status", "preview_digest", "created_by", "created_at", "rows")
	return map[string]*Schema{
		"SwitchingWaveRequest": object(map[string]*Schema{"name": str(),
			"assignments": list(object(map[string]*Schema{"row_number": integer(), "target_id": str()}, "row_number", "target_id")),
			"issuer_id":   str(), "preview_digest": str()}, "name", "assignments"),
		"SwitchingWavePreview": object(map[string]*Schema{"import_id": str(), "name": str(), "issuer_id": str(),
			"rows": list(plan), "excluded": list(excluded), "stop_renewing": list(str()), "digest": str()},
			"import_id", "name", "rows", "excluded", "stop_renewing", "digest"),
		"SwitchingWave":                wave,
		"SwitchingWaveList":            object(map[string]*Schema{"items": list(wave)}, "items"),
		"SwitchingWaveRollbackRequest": object(map[string]*Schema{"reason": str()}, "reason"),
	}
}
