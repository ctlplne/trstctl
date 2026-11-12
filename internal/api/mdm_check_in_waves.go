// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/store"
)

// N9-L2: a check-in wave asks the MDM to have every device of a renewal wave
// check in under one approval. The requester names the devices (each one
// trstctl has read from that MDM), other reviewers approve exactly that set,
// and the requester then executes it, which queues one check-in and one relay
// job per device, each recorded from the MDM's answer as N9's check-ins.

// MaxMDMCheckInWaveDevices bounds one wave.
const MaxMDMCheckInWaveDevices = 200

// MDMCheckInWaveService runs a wave's approval and execution. The server
// implements it beside MDMCheckInService.
type MDMCheckInWaveService interface {
	RequestMDMCheckInWaveApproval(ctx context.Context, tenantID, requester, provider string, input MDMCheckInWaveRequest) (MDMCheckInWaveApproval, error)
	QueueMDMCheckInWave(ctx context.Context, tenantID, requester, provider string, input MDMCheckInWaveStart) (store.MDMCheckInWave, error)
}

// MDMCheckInWaveRequest asks for approval of one wave.
type MDMCheckInWaveRequest struct {
	DeviceIDs []string `json:"device_ids"`
	Reason    string   `json:"reason"`
}

// MDMCheckInWaveDevice is one device a wave names.
type MDMCheckInWaveDevice struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
}

// MDMCheckInWaveApproval is the approval request a wave waits on.
type MDMCheckInWaveApproval struct {
	MDM                  string                 `json:"mdm"`
	Devices              []MDMCheckInWaveDevice `json:"devices"`
	Reason               string                 `json:"reason"`
	ApprovalRequestID    string                 `json:"approval_request_id"`
	ApprovalIntentDigest string                 `json:"approval_intent_digest"`
	Status               string                 `json:"status"`
	RequiredApprovals    int                    `json:"required_approvals"`
	ApprovalCount        int                    `json:"approval_count"`
	ExpiresAt            time.Time              `json:"expires_at"`
}

// MDMCheckInWaveStart executes an approved wave: the same devices the
// approval names.
type MDMCheckInWaveStart struct {
	ApprovalRequestID    string   `json:"approval_request_id"`
	ApprovalIntentDigest string   `json:"approval_intent_digest"`
	DeviceIDs            []string `json:"device_ids"`
}

// CanonicalMDMWaveDevices is a wave's device set: trimmed, unique, sorted,
// 1 to MaxMDMCheckInWaveDevices ids of at most 64 characters.
func CanonicalMDMWaveDevices(ids []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > 64 {
			return nil, errStatus(http.StatusBadRequest, "device_ids must name MDM device ids of at most 64 characters")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 || len(out) > MaxMDMCheckInWaveDevices {
		return nil, errStatus(http.StatusBadRequest, "a check-in wave names 1 to 200 devices")
	}
	sort.Strings(out)
	return out, nil
}

func (a *API) mdmCheckInWaveRoutes() []route {
	mdmPath := []param{pathString("mdm", "intune or jamf")}
	return []route{
		{method: "POST", path: "/api/v1/mdm/{mdm}/check-in-waves/approval-requests", opID: "requestMDMCheckInWaveApproval", summary: "Ask for approval to have every device of a renewal wave check in with its MDM now; other reviewers approve exactly that set of devices before anything reaches the MDM", handler: a.requestMDMCheckInWaveApproval, pathParams: mdmPath, reqSchema: "MDMCheckInWaveRequest", resSchema: "MDMCheckInWaveApproval", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "POST", path: "/api/v1/mdm/{mdm}/check-in-waves", opID: "executeMDMCheckInWave", summary: "Execute an approved check-in wave: one check-in, through the MDM schedule's relay, for each device the approval names", handler: a.executeMDMCheckInWave, pathParams: mdmPath, reqSchema: "MDMCheckInWaveStart", resSchema: "MDMCheckInWave", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/mdm/{mdm}/check-in-waves", opID: "listMDMCheckInWaves", summary: "List an MDM's check-in waves, newest first, with how many devices checked in, failed or wait", handler: a.listMDMCheckInWaves, pathParams: mdmPath, resSchema: "MDMCheckInWaveList", successCode: "200", perm: authz.CertsRead},
	}
}

func mdmFromPath(r *http.Request) (string, error) {
	provider := strings.TrimSpace(r.PathValue("mdm"))
	if provider != mdm.MDMIntune && provider != mdm.MDMJamf {
		return "", errStatus(http.StatusBadRequest, "mdm must be intune or jamf")
	}
	return provider, nil
}

func (a *API) mdmCheckInWaves() (MDMCheckInWaveService, error) {
	svc, ok := a.mdmCheckIns.(MDMCheckInWaveService)
	if a.mdmCheckIns == nil || !ok {
		return nil, errStatus(http.StatusServiceUnavailable, "MDM check-ins are not configured")
	}
	return svc, nil
}

//trstctl:mutation
func (a *API) requestMDMCheckInWaveApproval(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	provider, err := mdmFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input MDMCheckInWaveRequest
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Reason == "" || len(input.Reason) > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "reason is required (at most 200 characters)"))
		return
	}
	devices, err := CanonicalMDMWaveDevices(input.DeviceIDs)
	if err != nil {
		a.writeError(w, err)
		return
	}
	input.DeviceIDs = devices
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("mdm-check-in-wave-approval\x00" + subject + "\x00" + provider + "\x00" +
		strings.Join(devices, "\x00") + "\x00" + input.Reason))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.mdmCheckInWaves()
		if err != nil {
			return 0, nil, err
		}
		approval, err := svc.RequestMDMCheckInWaveApproval(ctx, tenantID, subject, provider, input)
		return http.StatusCreated, approval, mdmCheckInAPIError(err)
	})
}

//trstctl:mutation
func (a *API) executeMDMCheckInWave(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	provider, err := mdmFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input MDMCheckInWaveStart
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	devices, err := CanonicalMDMWaveDevices(input.DeviceIDs)
	if err != nil {
		a.writeError(w, err)
		return
	}
	input.DeviceIDs = devices
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("mdm-check-in-wave-execute\x00" + subject + "\x00" + provider + "\x00" +
		strings.Join(devices, "\x00") + "\x00" + input.ApprovalRequestID + "\x00" + input.ApprovalIntentDigest))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.mdmCheckInWaves()
		if err != nil {
			return 0, nil, err
		}
		wave, err := svc.QueueMDMCheckInWave(ctx, tenantID, subject, provider, input)
		if err != nil {
			return 0, nil, mdmCheckInAPIError(err)
		}
		return http.StatusCreated, mdmCheckInWaveResponse(wave), nil
	})
}

type mdmCheckInWaveView struct {
	ID                string    `json:"id"`
	MDM               string    `json:"mdm"`
	Reason            string    `json:"reason"`
	ApprovalRequestID string    `json:"approval_request_id"`
	RequestedBy       string    `json:"requested_by"`
	DeviceCount       int       `json:"device_count"`
	CheckedIn         int       `json:"checked_in"`
	Failed            int       `json:"failed"`
	Queued            int       `json:"queued"`
	QueuedAt          time.Time `json:"queued_at"`
}

func mdmCheckInWaveResponse(w store.MDMCheckInWave) mdmCheckInWaveView {
	return mdmCheckInWaveView{ID: w.ID, MDM: w.MDM, Reason: w.Reason, ApprovalRequestID: w.ApprovalRequestID, RequestedBy: w.RequestedBy,
		DeviceCount: w.DeviceCount, CheckedIn: w.CheckedIn, Failed: w.Failed, Queued: w.Queued, QueuedAt: w.QueuedAt}
}

func (a *API) listMDMCheckInWaves(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	provider, err := mdmFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	waves, err := a.store.ListMDMCheckInWaves(r.Context(), tenantID, provider, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]mdmCheckInWaveView, 0, len(waves))
	for _, wave := range waves {
		items = append(items, mdmCheckInWaveResponse(wave))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func mdmCheckInWaveSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	mdmEnum := &Schema{Type: "string", Enum: []string{mdm.MDMIntune, mdm.MDMJamf}}
	ids := &Schema{Type: "array", Items: str(), Description: "The MDM's own device ids, 1 to 200; each must be a device trstctl has read from that MDM."}
	wave := object(map[string]*Schema{"id": str(), "mdm": mdmEnum, "reason": str(), "approval_request_id": str(), "requested_by": str(),
		"device_count": integer(), "checked_in": integer(), "failed": integer(), "queued": integer(), "queued_at": ts()},
		"id", "mdm", "reason", "approval_request_id", "requested_by", "device_count", "checked_in", "failed", "queued", "queued_at")
	return map[string]*Schema{
		"MDMCheckInWaveRequest": object(map[string]*Schema{"device_ids": ids, "reason": str()}, "device_ids", "reason"),
		"MDMCheckInWaveApproval": object(map[string]*Schema{"mdm": mdmEnum,
			"devices": {Type: "array", Items: object(map[string]*Schema{"device_id": str(), "device_name": str()}, "device_id")},
			"reason":  str(), "approval_request_id": str(), "approval_intent_digest": str(), "status": str(), "required_approvals": integer(),
			"approval_count": integer(), "expires_at": ts()},
			"mdm", "devices", "reason", "approval_request_id", "approval_intent_digest", "status", "required_approvals", "approval_count", "expires_at"),
		"MDMCheckInWaveStart": object(map[string]*Schema{"approval_request_id": str(), "approval_intent_digest": str(), "device_ids": ids},
			"approval_request_id", "approval_intent_digest", "device_ids"),
		"MDMCheckInWave":     wave,
		"MDMCheckInWaveList": object(map[string]*Schema{"items": {Type: "array", Items: wave}}, "items"),
	}
}
