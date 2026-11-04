// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/store"
)

// MDM device check-ins (N9). A check-in asks the MDM to have one device check
// in now — Intune's syncDevice action, or a Jamf Pro blank push to one
// computer — so it fetches a new or renewed SCEP profile without waiting for
// its next scheduled check-in. It is the only write trstctl makes to an MDM:
// the requester asks for one exact device, other reviewers approve it, and
// the requester then executes exactly what they approved, which queues one job
// for the MDM schedule's relay. The check-in is recorded from the relay's
// checked report of the MDM's answer.

// MDMCheckInService runs the approval and execution against the MDM schedule's
// relay.
type MDMCheckInService interface {
	RequestMDMCheckInApproval(ctx context.Context, tenantID, requester, provider, deviceID string,
		input MDMCheckInRequest) (MDMCheckInApproval, error)
	QueueMDMCheckIn(ctx context.Context, tenantID, requester, provider, deviceID string,
		input MDMCheckInStart) (store.MDMCheckIn, error)
}

// WithMDMCheckIns serves N9's routes.
func WithMDMCheckIns(service MDMCheckInService) Option {
	return func(c *config) { c.mdmCheckIns = service }
}

var (
	// ErrMDMCheckInUnavailable is an MDM whose schedule names no relay or no
	// https base URL.
	ErrMDMCheckInUnavailable = errors.New("this MDM has no check-in route: its poll schedule needs an https base URL and one exact network relay")
	// ErrMDMDeviceUnknown is a device trstctl has not read from that MDM.
	ErrMDMDeviceUnknown = errors.New("trstctl has not read this device from that MDM")
)

// MDMCheckInRequest asks for approval of one device check-in.
type MDMCheckInRequest struct {
	Reason string `json:"reason"`
}

// MDMCheckInApproval is the approval request a check-in waits on.
type MDMCheckInApproval struct {
	MDM                  string    `json:"mdm"`
	DeviceID             string    `json:"device_id"`
	DeviceName           string    `json:"device_name,omitempty"`
	Reason               string    `json:"reason"`
	ApprovalRequestID    string    `json:"approval_request_id"`
	ApprovalIntentDigest string    `json:"approval_intent_digest"`
	Status               string    `json:"status"`
	RequiredApprovals    int       `json:"required_approvals"`
	ApprovalCount        int       `json:"approval_count"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// MDMCheckInStart executes an approved check-in.
type MDMCheckInStart struct {
	ApprovalRequestID    string `json:"approval_request_id"`
	ApprovalIntentDigest string `json:"approval_intent_digest"`
}

func (a *API) mdmCheckInRoutes() []route {
	devicePath := []param{pathString("mdm", "intune or jamf"), pathString("id", "the MDM's own device id, as shown in its console")}
	return []route{
		{method: "POST", path: "/api/v1/mdm/{mdm}/devices/{id}/check-in/approval-requests", opID: "requestMDMCheckInApproval", summary: "Ask for approval to have one device check in with its MDM now (Intune syncDevice or a Jamf blank push); other reviewers decide it before anything reaches the MDM", handler: a.requestMDMCheckInApproval, pathParams: devicePath, reqSchema: "MDMCheckInRequest", resSchema: "MDMCheckInApproval", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "POST", path: "/api/v1/mdm/{mdm}/devices/{id}/check-ins", opID: "executeMDMCheckIn", summary: "Execute an approved check-in: the MDM schedule's relay asks the MDM to have the device check in, and records the MDM's answer", handler: a.executeMDMCheckIn, pathParams: devicePath, reqSchema: "MDMCheckInStart", resSchema: "MDMCheckIn", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/mdm/{mdm}/check-ins", opID: "listMDMCheckIns", summary: "List an MDM's device check-ins, newest first: queued, checked in with the MDM's answer, or failed with the relay's reason", handler: a.listMDMCheckIns, pathParams: []param{pathString("mdm", "intune or jamf")}, resSchema: "MDMCheckInList", successCode: "200", perm: authz.CertsRead},
	}
}

func mdmDeviceFromPath(r *http.Request) (string, string, error) {
	provider, deviceID := strings.TrimSpace(r.PathValue("mdm")), strings.TrimSpace(r.PathValue("id"))
	if (provider != mdm.MDMIntune && provider != mdm.MDMJamf) || deviceID == "" || len(deviceID) > 64 {
		return "", "", errStatus(http.StatusBadRequest, "name intune or jamf and the MDM's device id")
	}
	return provider, deviceID, nil
}

func mdmCheckInAPIError(err error) error {
	switch {
	case errors.Is(err, ErrMDMCheckInUnavailable):
		return errStatusFrom(http.StatusConflict, err)
	case errors.Is(err, ErrMDMDeviceUnknown):
		return errStatusFrom(http.StatusNotFound, err)
	case errors.Is(err, store.ErrApprovalRequestNotFound):
		return errStatus(http.StatusNotFound, "approval request not found")
	case errors.Is(err, store.ErrApprovalDigestMismatch):
		return errStatus(http.StatusConflict, "the approval request names a different device, MDM or requester")
	}
	return approvalAPIError(err)
}

//trstctl:mutation
func (a *API) requestMDMCheckInApproval(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	provider, deviceID, err := mdmDeviceFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input MDMCheckInRequest
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Reason == "" || len(input.Reason) > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "reason is required (at most 200 characters)"))
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("mdm-check-in-approval\x00" + subject + "\x00" + provider + "\x00" + deviceID + "\x00" + input.Reason))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.mdmCheckIns == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "MDM check-ins are not configured")
		}
		approval, err := a.mdmCheckIns.RequestMDMCheckInApproval(ctx, tenantID, subject, provider, deviceID, input)
		return http.StatusCreated, approval, mdmCheckInAPIError(err)
	})
}

//trstctl:mutation
func (a *API) executeMDMCheckIn(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	provider, deviceID, err := mdmDeviceFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input MDMCheckInStart
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("mdm-check-in-execute\x00" + subject + "\x00" + provider + "\x00" + deviceID +
		"\x00" + input.ApprovalRequestID + "\x00" + input.ApprovalIntentDigest))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.mdmCheckIns == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "MDM check-ins are not configured")
		}
		checkIn, err := a.mdmCheckIns.QueueMDMCheckIn(ctx, tenantID, subject, provider, deviceID, input)
		if err != nil {
			return 0, nil, mdmCheckInAPIError(err)
		}
		return http.StatusCreated, mdmCheckInResponse(checkIn), nil
	})
}

type mdmCheckInView struct {
	ID                string     `json:"id"`
	MDM               string     `json:"mdm"`
	DeviceID          string     `json:"device_id"`
	DeviceName        string     `json:"device_name,omitempty"`
	Reason            string     `json:"reason"`
	ApprovalRequestID string     `json:"approval_request_id"`
	RequestedBy       string     `json:"requested_by"`
	Status            string     `json:"status"`
	ProviderStatus    int        `json:"provider_status,omitempty"`
	Failure           string     `json:"failure,omitempty"`
	QueuedAt          time.Time  `json:"queued_at"`
	CheckedInAt       *time.Time `json:"checked_in_at,omitempty"`
}

// mdmCheckInResponse reads a check-in's status: checked_in from the relay's
// checked report of the MDM's answer, failed when its relay job ended without
// one, queued until then.
func mdmCheckInResponse(c store.MDMCheckIn) mdmCheckInView {
	view := mdmCheckInView{ID: c.ID, MDM: c.MDM, DeviceID: c.DeviceID, DeviceName: c.DeviceName, Reason: c.Reason,
		ApprovalRequestID: c.ApprovalRequestID, RequestedBy: c.RequestedBy, Status: "queued", QueuedAt: c.QueuedAt,
		CheckedInAt: c.CheckedInAt}
	switch {
	case c.CheckedIn:
		view.Status, view.ProviderStatus = "checked_in", c.ProviderStatus
	case c.JobStatus == "failed" || c.JobStatus == "dead_letter" || c.JobStatus == "cancelled":
		view.Status, view.Failure = "failed", c.JobError
	}
	return view
}

func (a *API) listMDMCheckIns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	provider := strings.TrimSpace(r.PathValue("mdm"))
	if provider != mdm.MDMIntune && provider != mdm.MDMJamf {
		a.writeError(w, errStatus(http.StatusBadRequest, "mdm must be intune or jamf"))
		return
	}
	checkIns, err := a.store.ListMDMCheckIns(r.Context(), tenantID, provider, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]mdmCheckInView, 0, len(checkIns))
	for _, c := range checkIns {
		items = append(items, mdmCheckInResponse(c))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func mdmCheckInSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	mdmEnum := &Schema{Type: "string", Enum: []string{mdm.MDMIntune, mdm.MDMJamf}}
	checkIn := object(map[string]*Schema{"id": str(), "mdm": mdmEnum, "device_id": str(), "device_name": str(), "reason": str(),
		"approval_request_id": str(), "requested_by": str(),
		"status":          {Type: "string", Enum: []string{"queued", "checked_in", "failed"}},
		"provider_status": integer(), "failure": str(), "queued_at": ts(), "checked_in_at": ts()},
		"id", "mdm", "device_id", "reason", "approval_request_id", "requested_by", "status", "queued_at")
	return map[string]*Schema{
		"MDMCheckInRequest": object(map[string]*Schema{"reason": str()}, "reason"),
		"MDMCheckInApproval": object(map[string]*Schema{"mdm": mdmEnum, "device_id": str(), "device_name": str(), "reason": str(),
			"approval_request_id": str(), "approval_intent_digest": str(), "status": str(), "required_approvals": integer(),
			"approval_count": integer(), "expires_at": ts()},
			"mdm", "device_id", "reason", "approval_request_id", "approval_intent_digest", "status", "required_approvals",
			"approval_count", "expires_at"),
		"MDMCheckInStart": object(map[string]*Schema{"approval_request_id": str(), "approval_intent_digest": str()},
			"approval_request_id", "approval_intent_digest"),
		"MDMCheckIn":     checkIn,
		"MDMCheckInList": object(map[string]*Schema{"items": {Type: "array", Items: checkIn}}, "items"),
	}
}
