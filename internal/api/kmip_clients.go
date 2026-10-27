// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A197: tenant self-service KMIP clients. A tenant registers a client and
// gets a one-time enrollment: the client's first KMIP request presents its TLS
// certificate with the enrollment's username and password, which binds that
// certificate to the tenant on the shared KMIP listener.

// WithKMIPClientRegistrations reports whether the KMIP listener serves
// tenants' registered clients; the registration routes answer 503 otherwise.
// It is read per request: the listener is assembled after the API.
func WithKMIPClientRegistrations(served func() bool) Option {
	return func(c *config) { c.kmipClientRegistrations = served }
}

// kmipClientRoutes are the tenant self-service KMIP client registrations.
// They live beside their handlers for the served-surface file budget.
func (a *API) kmipClientRoutes(idPath []param) []route {
	return []route{
		{method: "GET", path: "/api/v1/kmip/clients", opID: "listKMIPClients", summary: "List this tenant's registered KMIP clients", handler: a.listKMIPClients, resSchema: "KMIPClientList", successCode: "200", perm: authz.KeysRead},
		{method: "POST", path: "/api/v1/kmip/clients", opID: "registerKMIPClient", summary: "Register a KMIP client and issue its one-time enrollment", handler: a.registerKMIPClient, reqSchema: "KMIPClientRegisterRequest", resSchema: "KMIPClientEnrollment", successCode: "201", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/kmip/clients/{id}/enrollment", opID: "issueKMIPClientEnrollment", summary: "Issue a KMIP client a new one-time enrollment, for a move to a new certificate", handler: a.issueKMIPClientEnrollment, pathParams: idPath, resSchema: "KMIPClientEnrollment", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "DELETE", path: "/api/v1/kmip/clients/{id}", opID: "removeKMIPClient", summary: "Remove a KMIP client; its certificate is refused from its next request", handler: a.removeKMIPClient, pathParams: idPath, successCode: "204", mutation: true, perm: authz.KeysWrite},
	}
}

type kmipClientRegisterRequest struct {
	Name string `json:"name"`
}

const (
	kmipClientAwaitingEnrollment = "awaiting_enrollment"
	kmipClientEnrollmentExpired  = "enrollment_expired"
	kmipClientEnrolled           = "enrolled"
	kmipClientReenrolling        = "enrolled_reenrolling"
)

type kmipClientResponse struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	State               string  `json:"state"`
	Fingerprint         string  `json:"fingerprint,omitempty"`
	Subject             string  `json:"subject,omitempty"`
	NotAfter            *string `json:"not_after,omitempty"`
	EnrolledAt          *string `json:"enrolled_at,omitempty"`
	EnrollmentExpiresAt *string `json:"enrollment_expires_at,omitempty"`
	CreatedAt           string  `json:"created_at"`
	Detail              string  `json:"detail"`
}

type kmipClientListResponse struct {
	Items []kmipClientResponse `json:"items"`
}

// kmipEnrollmentCredential is shown once: the server keeps only the
// password's SHA-256.
type kmipEnrollmentCredential struct {
	Username  string          `json:"username"`
	Password  secretJSONBytes `json:"password"`
	ExpiresAt string          `json:"expires_at"`
}

type kmipClientEnrollmentResponse struct {
	Client     kmipClientResponse       `json:"client"`
	Enrollment kmipEnrollmentCredential `json:"enrollment"`
}

func (r *kmipClientEnrollmentResponse) wipeSecrets() { r.Enrollment.Password.wipe() }

func optionalTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func kmipClientResponseFor(c store.KMIPClient, now time.Time) kmipClientResponse {
	out := kmipClientResponse{
		ID: c.ID, Name: c.Name, Fingerprint: c.Fingerprint, Subject: c.Subject,
		NotAfter: optionalTime(c.NotAfter), EnrolledAt: optionalTime(c.EnrolledAt),
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
	}
	pending := c.EnrollmentHash != "" && c.EnrollmentExpiresAt != nil && now.Before(*c.EnrollmentExpiresAt)
	if pending {
		out.EnrollmentExpiresAt = optionalTime(c.EnrollmentExpiresAt)
	}
	switch {
	case c.Fingerprint != "" && pending:
		out.State = kmipClientReenrolling
		out.Detail = "The bound certificate keeps working; the next KMIP request that presents the new enrollment binds the certificate it comes with instead."
	case c.Fingerprint != "":
		out.State = kmipClientEnrolled
		out.Detail = "KMIP requests that present this certificate are served for this tenant. Issue a new enrollment when the client moves to a new certificate."
	case pending:
		out.State = kmipClientAwaitingEnrollment
		out.Detail = "Configure the client with the enrollment's username and password; its first KMIP request binds the certificate it presents."
	default:
		out.State = kmipClientEnrollmentExpired
		out.Detail = "The enrollment expired before the client used it. Issue a new enrollment."
	}
	return out
}

// kmipClientsServed reports whether the KMIP listener serves tenants'
// registered clients; the routes answer 503 when it does not.
func (a *API) kmipClientsServed() bool {
	return a.kmipClientRegistrations != nil && a.kmipClientRegistrations()
}

func kmipClientsUnavailable() error {
	return errStatus(http.StatusServiceUnavailable,
		"KMIP client registrations are not served: the licensed KMIP listener is not running, or protocols.kmip.client_registrations is off")
}

func kmipClientError(err error) error {
	switch {
	case errors.Is(err, orchestrator.ErrKMIPClientInvalid):
		return errStatus(http.StatusBadRequest, strings.TrimPrefix(err.Error(), "orchestrator: "))
	case errors.Is(err, orchestrator.ErrKMIPClientNotFound):
		return errStatus(http.StatusNotFound, "no such KMIP client")
	}
	return err
}

func (a *API) listKMIPClients(w http.ResponseWriter, r *http.Request) {
	if !a.kmipClientsServed() {
		a.writeError(w, kmipClientsUnavailable())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	clients, err := a.store.KMIPClients(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	out := kmipClientListResponse{Items: make([]kmipClientResponse, 0, len(clients))}
	for _, c := range clients {
		out.Items = append(out.Items, kmipClientResponseFor(c, now))
	}
	a.writeJSON(w, http.StatusOK, out)
}

// registerKMIPClient records a KMIP client and returns its one-time
// enrollment.
//
//trstctl:mutation
func (a *API) registerKMIPClient(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if !a.kmipClientsServed() {
			return 0, nil, kmipClientsUnavailable()
		}
		var req kmipClientRegisterRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		enrollment, err := a.orch.RegisterKMIPClient(ctx, tenantID, req.Name)
		if err != nil {
			return 0, nil, kmipClientError(err)
		}
		return http.StatusCreated, kmipEnrollmentResponse(enrollment), nil
	})
}

// issueKMIPClientEnrollment issues a client a new enrollment, for a move to
// a new certificate.
//
//trstctl:mutation
func (a *API) issueKMIPClientEnrollment(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if !a.kmipClientsServed() {
			return 0, nil, kmipClientsUnavailable()
		}
		if _, err := googleuuid.Parse(id); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "KMIP client id must be a UUID")
		}
		enrollment, err := a.orch.IssueKMIPClientEnrollment(ctx, tenantID, id)
		if err != nil {
			return 0, nil, kmipClientError(err)
		}
		return http.StatusOK, kmipEnrollmentResponse(enrollment), nil
	})
}

// removeKMIPClient removes a registration; its certificate is refused from
// its next KMIP request.
//
//trstctl:mutation
func (a *API) removeKMIPClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if !a.kmipClientsServed() {
			return 0, nil, kmipClientsUnavailable()
		}
		if _, err := googleuuid.Parse(id); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "KMIP client id must be a UUID")
		}
		if err := a.orch.RemoveKMIPClient(ctx, tenantID, id); err != nil {
			return 0, nil, kmipClientError(err)
		}
		return http.StatusNoContent, nil, nil
	})
}

func kmipEnrollmentResponse(e orchestrator.KMIPClientEnrollment) *kmipClientEnrollmentResponse {
	return &kmipClientEnrollmentResponse{
		Client: kmipClientResponseFor(e.Client, time.Now().UTC()),
		Enrollment: kmipEnrollmentCredential{
			Username: e.Client.ID, Password: secretJSONBytes(e.Secret), ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
}
