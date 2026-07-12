// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
)

var (
	// ErrProtocolProfileUnavailable means this deployment did not select the
	// explicit evaluation profile. Production protocol toggles remain config-only.
	ErrProtocolProfileUnavailable = errors.New("protocol eval profile is not configured")
	// ErrProtocolProfileTenantMismatch prevents a caller from activating a profile
	// bound to any tenant other than the authenticated one (AN-1).
	ErrProtocolProfileTenantMismatch = errors.New("protocol eval profile belongs to another tenant")
)

// ProtocolProfileStatus is the non-secret, tenant-scoped setup state shown by the
// first-run wizard. Protocols contains only the closed set assembled into the
// shipped server; no credentials, keys, or configuration file paths are exposed.
type ProtocolProfileStatus struct {
	Profile   string   `json:"profile"`
	Active    bool     `json:"active"`
	Protocols []string `json:"protocols"`
}

// ProtocolProfileControl is implemented by the assembled server. Activating the
// eval profile appends a tenant-bound event before opening its route/UDS gate; a
// restart replays that event, so the wizard action is a real state change rather
// than a cosmetic client toggle (AN-1/AN-2).
type ProtocolProfileControl interface {
	Status(ctx context.Context, tenantID string) (ProtocolProfileStatus, error)
	Activate(ctx context.Context, tenantID, idempotencyKey string) (ProtocolProfileStatus, error)
}

// WithProtocolProfileControl wires the explicit eval-profile activation/status
// service. Nil leaves the setup routes fail-closed.
func WithProtocolProfileControl(control ProtocolProfileControl) Option {
	return func(c *config) { c.protocolProfile = control }
}

// AttachProtocolProfileControl completes the cyclic assembly seam after the
// signer-backed protocol servers exist. Server.Build calls it exactly once before
// exposing Handler; it is not a hot-reconfiguration API.
func (a *API) AttachProtocolProfileControl(control ProtocolProfileControl) {
	a.protocolProfile = control
}

func (a *API) getProtocolProfile(w http.ResponseWriter, r *http.Request) {
	if a.protocolProfile == nil {
		a.writeError(w, errStatus(http.StatusNotFound, ErrProtocolProfileUnavailable.Error()))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	status, err := a.protocolProfile.Status(r.Context(), tenantID)
	if err != nil {
		a.writeProtocolProfileError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, status)
}

//trstctl:mutation
func (a *API) activateProtocolProfile(w http.ResponseWriter, r *http.Request) {
	if a.protocolProfile == nil {
		a.writeError(w, errStatus(http.StatusNotFound, ErrProtocolProfileUnavailable.Error()))
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutateDurable(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		status, err := a.protocolProfile.Activate(ctx, tenantID, idempotencyKey)
		if errors.Is(err, ErrProtocolProfileUnavailable) {
			return 0, nil, errStatus(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, ErrProtocolProfileTenantMismatch) {
			return 0, nil, errStatus(http.StatusForbidden, err.Error())
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, status, nil
	})
}

func (a *API) writeProtocolProfileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrProtocolProfileUnavailable):
		a.writeError(w, errStatus(http.StatusNotFound, err.Error()))
	case errors.Is(err, ErrProtocolProfileTenantMismatch):
		a.writeError(w, errStatus(http.StatusForbidden, err.Error()))
	default:
		a.writeError(w, err)
	}
}
