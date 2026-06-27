package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

// WithBreakglass wires the served recovery-side break-glass reconciliation
// endpoint. When unset, POST /api/v1/breakglass/reconcile fails closed.
func WithBreakglass(r BreakglassReconciler) Option {
	return func(c *config) { c.breakglass = r }
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
