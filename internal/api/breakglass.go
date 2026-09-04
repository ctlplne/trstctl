// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/crypto"
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

// BreakglassCeremonyService starts request-bound ceremonies using the configured
// operator threshold. Approvals are still recorded by the shared CA ceremony
// approval route, which attributes ca.ceremony.approved to the authenticated
// principal.
type BreakglassCeremonyService interface {
	BreakglassConfiguration() BreakglassConfiguration
	StartBreakglassIssueCeremony(ctx context.Context, tenantID string, req breakglass.EmergencyRequest, ttl time.Duration) (BreakglassCeremony, error)
}

// BreakglassConfiguration is the non-secret part of deployment-owned emergency
// custody configuration. Operator identities, signer handles, certificate bytes,
// and file paths never cross this boundary.
type BreakglassConfiguration struct {
	ApprovalThreshold       int
	ConfiguredOperatorCount int
}

// BreakglassRotationService performs signer-backed emergency-CA rotation and
// cross-signing. All private operations stay behind the isolated signer; the API
// carries certificates and ceremony ids only.
type BreakglassRotationService interface {
	StartBreakglassRotationCeremony(ctx context.Context, tenantID string, req BreakglassRotationIntent) (BreakglassCeremony, error)
	RotateBreakglass(ctx context.Context, tenantID string, req BreakglassRotationRequest) (BreakglassRotation, error)
	StartBreakglassCrossSignCeremony(ctx context.Context, tenantID string, targetCertDER []byte) (BreakglassCeremony, error)
	CrossSignBreakglass(ctx context.Context, tenantID string, req BreakglassCrossSignRequest) (BreakglassCrossSign, error)
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

func WithBreakglassCeremonies(s BreakglassCeremonyService) Option {
	return func(c *config) { c.breakglassCeremonies = s }
}

func WithBreakglassRotation(s BreakglassRotationService) Option {
	return func(c *config) { c.breakglassRotation = s }
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
	CeremonyID      string          `json:"ceremony_id"`
	RequestID       string          `json:"request_id"`
	Subject         string          `json:"subject"`
	CSRDer          []byte          `json:"csr_der"`
	Reason          string          `json:"reason"`
	TTLSeconds      int             `json:"ttl_seconds"`
	CallerApprovals json.RawMessage `json:"approvals,omitempty"` // rejection sentinel for the retired caller-authored field
}

type BreakglassCeremony struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Purpose   string    `json:"purpose"`
	Threshold int       `json:"threshold"`
	Status    string    `json:"status"`
	Approvals int       `json:"approvals"`
	Opener    string    `json:"opener,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type BreakglassRotationIntent struct {
	Reason     string `json:"reason"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type BreakglassRotationRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Reason     string `json:"reason"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type BreakglassRotation struct {
	PreviousSignerHandle   string `json:"previous_signer_handle"`
	ActiveSignerHandle     string `json:"active_signer_handle"`
	PreviousCertificatePEM string `json:"previous_certificate_pem"`
	ActiveCertificatePEM   string `json:"active_certificate_pem"`
	NewSignedByPreviousPEM string `json:"new_signed_by_previous_pem"`
	PreviousSignedByNewPEM string `json:"previous_signed_by_new_pem"`
	CeremonyID             string `json:"ceremony_id"`
	RequestDigest          string `json:"request_digest"`
}

type BreakglassCrossSignRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
}

type BreakglassCrossSign struct {
	IssuerSignerHandle string `json:"issuer_signer_handle"`
	TargetSHA256       string `json:"target_sha256"`
	CertificatePEM     string `json:"certificate_pem"`
	CeremonyID         string `json:"ceremony_id"`
}

type breakglassIssueResponse struct {
	Bundle         breakglass.Bundle `json:"bundle"`
	Reconciled     int               `json:"reconciled"`
	AuditEventType string            `json:"audit_event_type"`
}

type BreakglassPrerequisite struct {
	ID          string `json:"id"`
	Ready       bool   `json:"ready"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

// BreakglassIssuePlanPreview is the read-only answer to "is this exact
// emergency request safe and runnable?" It reports deployment readiness without
// disclosing the operator roster or signer custody details. Execution revalidates
// the same request when it opens and consumes the request-bound ceremony.
type BreakglassIssuePlanPreview struct {
	Capability               string                   `json:"capability"`
	Operation                string                   `json:"operation"`
	Ready                    bool                     `json:"ready"`
	EffectFree               bool                     `json:"effect_free"`
	RequestID                string                   `json:"request_id"`
	Subject                  string                   `json:"subject"`
	Reason                   string                   `json:"reason"`
	RequestedTTLSeconds      int                      `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds      int64                    `json:"effective_ttl_seconds"`
	CSRSHA256                string                   `json:"csr_sha256"`
	RequestFingerprint       string                   `json:"request_fingerprint"`
	ApprovalThreshold        int                      `json:"approval_threshold"`
	ConfiguredOperatorCount  int                      `json:"configured_operator_count"`
	RequiredPermission       string                   `json:"required_permission"`
	Prerequisites            []BreakglassPrerequisite `json:"prerequisites"`
	Blockers                 []string                 `json:"blockers"`
	PreviewWrites            []string                 `json:"preview_writes"`
	PreviewExternalEffects   []string                 `json:"preview_external_effects"`
	PreviewSignerCalls       []string                 `json:"preview_signer_calls"`
	ExecutionWrites          []string                 `json:"execution_writes"`
	ExecutionExternalEffects []string                 `json:"execution_external_effects"`
	ExecutionSignerCalls     []string                 `json:"execution_signer_calls"`
	RecoverySteps            []string                 `json:"recovery_steps"`
	VerificationSteps        []string                 `json:"verification_steps"`
}

// previewBreakglassIssue validates and explains one exact online emergency
// request. It opens no ceremony, records no idempotency key, appends no event,
// calls no signer, and contacts no external system.
func (a *API) previewBreakglassIssue(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req breakglassIssueRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(req.CeremonyID) != "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "ceremony_id must be omitted during preview"))
		return
	}
	emergency, ttl, err := validateBreakglassIssueRequest(req, false)
	if err != nil {
		a.writeError(w, err)
		return
	}
	configuration := BreakglassConfiguration{}
	if a.breakglassCeremonies != nil {
		configuration = a.breakglassCeremonies.BreakglassConfiguration()
	}
	onlineReady := a.breakglassCeremonies != nil && a.breakglassIssuer != nil
	rosterReady := configuration.ApprovalThreshold >= 2 && configuration.ConfiguredOperatorCount >= configuration.ApprovalThreshold
	blockers := make([]string, 0, 2)
	if !onlineReady {
		blockers = append(blockers, "Online break-glass custody is not configured; enable the purpose-constrained signer and ceremony runtime at startup.")
	}
	if !rosterReady {
		blockers = append(blockers, "The deployment needs at least two distinct configured operators and a satisfiable approval threshold.")
	}
	fingerprint := strings.TrimPrefix(breakglass.IssuePurpose(tenantID, emergency, ttl), "breakglass-issue:")
	preview := BreakglassIssuePlanPreview{
		Capability: "F34", Operation: "issue_breakglass", Ready: onlineReady && rosterReady, EffectFree: true,
		RequestID: emergency.ID, Subject: emergency.Subject, Reason: emergency.Reason,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int64(ttl / time.Second),
		CSRSHA256: crypto.SHA256Hex(emergency.CSRDer), RequestFingerprint: "sha256:" + fingerprint,
		ApprovalThreshold: configuration.ApprovalThreshold, ConfiguredOperatorCount: configuration.ConfiguredOperatorCount,
		RequiredPermission: "certs:issue",
		Prerequisites: []BreakglassPrerequisite{
			{ID: "online_signer", Ready: onlineReady, Detail: "A purpose-constrained signer, pinned emergency CA, event log, and ceremony runtime must be configured at startup.", Remediation: "Set break-glass custody configuration, then restart and rerun this preview."},
			{ID: "operator_roster", Ready: rosterReady, Detail: fmt.Sprintf("%d configured operators can satisfy a %d-person quorum.", configuration.ConfiguredOperatorCount, configuration.ApprovalThreshold), Remediation: "Configure at least two distinct operator subjects and a threshold the roster can satisfy."},
			{ID: "request_binding", Ready: true, Detail: "The ceremony will be bound to this tenant, request, CSR digest, reason, and lifetime."},
		},
		Blockers: blockers, PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		ExecutionWrites:          []string{"Append and project one exact ceremony record.", "Consume the approved ceremony and append breakglass.issued before returning."},
		ExecutionExternalEffects: []string{},
		ExecutionSignerCalls:     []string{"Ask the isolated signer to issue one short-lived certificate only after quorum."},
		RecoverySteps:            []string{"Do not execute if the request fingerprint no longer matches the incident.", "If quorum cannot be reached, leave the ceremony unconsumed and use the documented offline procedure.", "After recovery, reconcile and audit every offline-issued bundle."},
		VerificationSteps:        []string{"Verify the returned signed bundle against the pinned emergency CA.", "Confirm breakglass.issued is present in the tenant audit chain.", "Retire emergency access before its short lifetime ends and complete the post-incident review."},
	}
	a.writeJSON(w, http.StatusOK, preview)
}

// issueBreakglass is the online execution half of the break-glass ceremony. The
// request carries no approver names: the configured issuer derives the m-of-n
// quorum from authenticated, immutable CA-ceremony approval events, signs
// through the isolated crypto boundary, and consumes that exact ceremony once.
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
		emergency, ttl, err := validateBreakglassIssueRequest(req, true)
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

//trstctl:mutation
func (a *API) startBreakglassIssueCeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassCeremonies == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "online break-glass ceremonies are not configured")
		}
		var req breakglassIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.CeremonyID) != "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ceremony_id must be omitted when starting a ceremony")
		}
		emergency, ttl, err := validateBreakglassIssueRequest(req, false)
		if err != nil {
			return 0, nil, err
		}
		ceremony, err := a.breakglassCeremonies.StartBreakglassIssueCeremony(ctx, tenantID, emergency, ttl)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ceremony, nil
	})
}

//trstctl:mutation
func (a *API) startBreakglassRotationCeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassRotation == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "break-glass rotation is not configured")
		}
		var req BreakglassRotationIntent
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := validateBreakglassRotationIntent(req); err != nil {
			return 0, nil, err
		}
		ceremony, err := a.breakglassRotation.StartBreakglassRotationCeremony(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ceremony, nil
	})
}

//trstctl:mutation
func (a *API) rotateBreakglass(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassRotation == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "break-glass rotation is not configured")
		}
		var req BreakglassRotationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.CeremonyID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ceremony_id is required")
		}
		if err := validateBreakglassRotationIntent(BreakglassRotationIntent{Reason: req.Reason, TTLSeconds: req.TTLSeconds}); err != nil {
			return 0, nil, err
		}
		result, err := a.breakglassRotation.RotateBreakglass(ctx, tenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusConflict, err.Error())
		}
		return http.StatusCreated, result, nil
	})
}

//trstctl:mutation
func (a *API) startBreakglassCrossSignCeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassRotation == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "break-glass cross-signing is not configured")
		}
		var req BreakglassCrossSignRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.CeremonyID) != "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ceremony_id must be omitted when starting a ceremony")
		}
		der, err := breakglassCertificateDER(req.CertificatePEM)
		if err != nil {
			return 0, nil, err
		}
		ceremony, err := a.breakglassRotation.StartBreakglassCrossSignCeremony(ctx, tenantID, der)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ceremony, nil
	})
}

//trstctl:mutation
func (a *API) crossSignBreakglass(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.breakglassRotation == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "break-glass cross-signing is not configured")
		}
		var req BreakglassCrossSignRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.CeremonyID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ceremony_id is required")
		}
		if _, err := breakglassCertificateDER(req.CertificatePEM); err != nil {
			return 0, nil, err
		}
		result, err := a.breakglassRotation.CrossSignBreakglass(ctx, tenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusConflict, err.Error())
		}
		return http.StatusCreated, result, nil
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

func validateBreakglassIssueRequest(req breakglassIssueRequest, requireCeremony bool) (breakglass.EmergencyRequest, time.Duration, error) {
	if len(req.CallerApprovals) != 0 {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "approvals must be omitted; authenticated ceremony events supply the operator quorum")
	}
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if requireCeremony && ceremonyID == "" {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "ceremony_id is required")
	}
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
	if err := crypto.VerifyCertificateRequest(req.CSRDer); err != nil {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "csr_der must be a signed PKCS#10 certificate request")
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if ttl > 24*time.Hour {
		return breakglass.EmergencyRequest{}, 0, errStatus(http.StatusBadRequest, "ttl_seconds may not exceed 86400")
	}
	return breakglass.EmergencyRequest{
		CeremonyID: ceremonyID, ID: id, Subject: subject, CSRDer: append([]byte(nil), req.CSRDer...),
		Reason: reason,
	}, ttl, nil
}

func validateBreakglassRotationIntent(req BreakglassRotationIntent) error {
	if strings.TrimSpace(req.Reason) == "" {
		return errStatus(http.StatusBadRequest, "reason is required")
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > int64((10*365*24*time.Hour)/time.Second) {
		return errStatus(http.StatusBadRequest, "ttl_seconds must be between 1 and 315360000")
	}
	return nil
}

func breakglassCertificateDER(value string) ([]byte, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errStatus(http.StatusBadRequest, "certificate_pem must contain exactly one CERTIFICATE PEM block")
	}
	return append([]byte(nil), block.Bytes...), nil
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
