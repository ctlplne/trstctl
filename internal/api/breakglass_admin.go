package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/breakglass"
)

const maxBreakglassAdminLoginBytes = 16 << 10

type breakglassAdminLoginRequest struct {
	ActorID  string       `json:"actor_id"`
	Password ldapPassword `json:"password"`
}

func (a *API) authBreakglassAdminLogin(w http.ResponseWriter, r *http.Request) {
	if a.breakglassAdmin == nil || !a.breakglassAdmin.Enabled() {
		a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
		return
	}
	if a.auth == nil || a.auth.Sessions == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "break-glass admin login is not configured"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBreakglassAdminLoginBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req breakglassAdminLoginRequest
	if err := dec.Decode(&req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid break-glass admin login request"))
		return
	}
	defer req.Password.wipe()
	if req.ActorID == "" || len(req.Password) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "actor_id and password are required"))
		return
	}
	token, err := a.breakglassAdmin.Authenticate(r.Context(), req.ActorID, []byte(req.Password), requestClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, breakglass.ErrAdminDisabled):
			a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
		case errors.Is(err, breakglass.ErrAdminInvalidCredentials):
			a.writeProblem(w, problem.New(http.StatusUnauthorized, "invalid credentials"))
		case errors.Is(err, breakglass.ErrAdminLocked):
			a.writeProblem(w, problem.New(http.StatusTooManyRequests, "break-glass admin login is locked"))
		default:
			a.writeError(w, err)
		}
		return
	}
	a.setSessionCookie(w, token)
	csrf, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setCSRFCookie(w, csrf)
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
