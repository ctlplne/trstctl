// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/breakglass"
)

// ErrBreakglassInvalidBundle marks a signed emergency bundle that did not verify
// against the deployment-pinned break-glass trust anchors.
var ErrBreakglassInvalidBundle = errors.New("api: invalid break-glass bundle")

// BreakglassReconciler verifies offline emergency bundles and reconciles the
// verified facts into the tenant audit chain. The API owns only the HTTP shape;
// the server composition injects verifier material from trusted deployment config.
type BreakglassReconciler interface {
	ReconcileBreakglass(ctx context.Context, tenantID string, bundles []breakglass.Bundle) (int, error)
}

// BreakglassIssuer performs the online m-of-n emergency issuance workflow. The
// implementation is injected by server composition so the API never sees private
// key material; it only enforces request shape, idempotency, RBAC, and response
// semantics.
type BreakglassIssuer interface {
	IssueBreakglass(ctx context.Context, tenantID string, req breakglass.EmergencyRequest, ttl time.Duration) (breakglass.Bundle, int, error)
}

// WithBreakglass wires the served recovery-side break-glass reconciliation
// endpoint. When unset, POST /api/v1/breakglass/reconcile fails closed.
func WithBreakglass(r BreakglassReconciler) Option {
	return func(c *config) { c.breakglass = r }
}

// WithBreakglassIssuer wires the served online m-of-n emergency issuance route.
// When unset, POST /api/v1/breakglass/issue fails closed. The issuer must sign
// through the configured signing boundary and reconcile the resulting bundle into
// audit before returning it.
func WithBreakglassIssuer(i BreakglassIssuer) Option {
	return func(c *config) { c.breakglassIssuer = i }
}

// WithBreakglassAdmin wires the disabled-by-default local-admin recovery login.
// It is intentionally separate from the certificate break-glass reconciler:
// this route mints an admin browser session for IdP-outage recovery, while
// /api/v1/breakglass/reconcile only absorbs offline emergency issuance bundles.
func WithBreakglassAdmin(svc *breakglass.AdminService) Option {
	return func(c *config) {
		c.breakglassAdmin = svc
		if svc == nil || svc.SessionIssuer() == nil {
			return
		}
		if c.auth == nil {
			c.auth = &AuthConfig{Sessions: svc.SessionIssuer()}
			return
		}
		if c.auth.Sessions == nil {
			c.auth.Sessions = svc.SessionIssuer()
		}
	}
}

type breakglassReconcileRequest struct {
	Bundles []breakglass.Bundle `json:"bundles"`
}

type breakglassReconcileResponse struct {
	Reconciled int `json:"reconciled"`
}

type breakglassIssueRequest struct {
	RequestID  string   `json:"request_id"`
	Subject    string   `json:"subject"`
	CSRDer     []byte   `json:"csr_der"`
	Reason     string   `json:"reason"`
	Approvals  []string `json:"approvals"`
	TTLSeconds int      `json:"ttl_seconds"`
}

type breakglassIssueResponse struct {
	Bundle         breakglass.Bundle `json:"bundle"`
	Reconciled     int               `json:"reconciled"`
	AuditEventType string            `json:"audit_event_type"`
}

// issueBreakglass is the online version of the break-glass ceremony: the
// running control plane accepts a CSR plus a distinct m-of-n operator quorum,
// asks the configured break-glass issuer to sign through the crypto boundary,
// and returns only after the resulting bundle is reconciled into audit.
//
//trstctl:mutation
func (a *API) issueBreakglass(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassIssuer == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "online break-glass issuance is not configured")
		}
		var req breakglassIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		emergency, ttl, err := validateBreakglassIssueRequest(req)
		if err != nil {
			return 0, nil, err
		}
		bundle, reconciled, err := a.breakglassIssuer.IssueBreakglass(ctx, tenantID, emergency, ttl)
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		return http.StatusCreated, breakglassIssueResponse{
			Bundle: bundle, Reconciled: reconciled, AuditEventType: "breakglass.issued",
		}, nil
	})
}

// reconcileBreakglass accepts already-issued offline break-glass bundles and
// reconciles them into the audit log. It does not issue new credentials online:
// issuance remains the m-of-n offline ceremony in internal/breakglass.
//
//trstctl:mutation
func (a *API) reconcileBreakglass(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglass == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "break-glass reconciliation is not configured")
		}
		var req breakglassReconcileRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.Bundles) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "bundles must contain at least one break-glass bundle")
		}
		if len(req.Bundles) > 100 {
			return 0, nil, errStatus(http.StatusRequestEntityTooLarge, "a reconcile request may contain at most 100 bundles")
		}
		for i, b := range req.Bundles {
			if err := validateBreakglassBundle(i, b); err != nil {
				return 0, nil, err
			}
		}
		reconciled, err := a.breakglass.ReconcileBreakglass(ctx, tenantID, req.Bundles)
		if err != nil {
			if errors.Is(err, ErrBreakglassInvalidBundle) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
			}
			return 0, nil, err
		}
		return http.StatusOK, breakglassReconcileResponse{Reconciled: reconciled}, nil
	})
}

func validateBreakglassIssueRequest(req breakglassIssueRequest) (breakglass.EmergencyRequest, time.Duration, error) {
	id := strings.TrimSpace(req.RequestID)
	if id == "" {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "request_id is required")
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "subject is required")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "reason is required")
	}
	if len(req.CSRDer) == 0 {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "csr_der is required")
	}
	approvals := compactNonEmptyStrings(req.Approvals)
	if len(approvals) == 0 {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "approvals must contain at least one approval")
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if ttl > 24*time.Hour {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "ttl_seconds may not exceed 86400")
	}
	return breakglass.EmergencyRequest{
		ID: id, Subject: subject, CSRDer: append([]byte(nil), req.CSRDer...),
		Reason: reason, Approvals: approvals,
	}, ttl, nil
}

func compactNonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validateBreakglassBundle(i int, b breakglass.Bundle) error {
	if strings.TrimSpace(b.RequestID) == "" {
		return breakglassBundleError(i, "request_id is required")
	}
	if strings.TrimSpace(b.Subject) == "" {
		return breakglassBundleError(i, "subject is required")
	}
	if strings.TrimSpace(b.Reason) == "" {
		return breakglassBundleError(i, "reason is required")
	}
	if len(b.Approvals) == 0 {
		return breakglassBundleError(i, "approvals must contain at least one approval")
	}
	if len(b.CertDER) == 0 {
		return breakglassBundleError(i, "cert_der is required")
	}
	if len(b.Signature) == 0 {
		return breakglassBundleError(i, "signature is required")
	}
	if b.IssuedAt.IsZero() {
		return breakglassBundleError(i, "issued_at is required")
	}
	return nil
}

func breakglassBundleError(i int, detail string) error {
	return errStatus(http.StatusBadRequest, fmt.Sprintf("bundles[%d].%s", i, detail))
}
