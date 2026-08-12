// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

// Constrained edge sub-CA surface (epic B6): per-segment opt-in, the
// attestation-gated mint, revocation from the brain, and reconciliation of
// locally-issued leaves. The service lives in internal/server because minting
// needs the isolated signer; these routes hold the HTTP shape and the refusal
// semantics.

var (
	ErrEdgeDelegationUnavailable = errors.New("api: edge delegation surface is not enabled")
	ErrEdgeDelegationInvalid     = errors.New("api: invalid edge delegation request")
	ErrEdgeDelegationRefused     = errors.New("api: edge delegation refused")
	ErrEdgeDelegationNotFound    = errors.New("api: edge delegation not found")
)

// EdgeDelegationService is implemented by internal/server.
type EdgeDelegationService interface {
	SetSegmentPolicy(ctx context.Context, tenantID string, req EdgeSegmentPolicyRequest) (EdgeSegmentPolicy, error)
	ListSegmentPolicies(ctx context.Context, tenantID string) ([]EdgeSegmentPolicy, error)
	MintDelegation(ctx context.Context, tenantID string, req EdgeDelegationMintRequest) (EdgeDelegation, error)
	ListDelegations(ctx context.Context, tenantID string) ([]EdgeDelegation, error)
	GetDelegation(ctx context.Context, tenantID, id string) (EdgeDelegationDetail, error)
	RevokeDelegation(ctx context.Context, tenantID, id, reason string) (EdgeDelegation, error)
	Reconcile(ctx context.Context, tenantID, id string, req EdgeReconcileRequest) (EdgeReconcileResult, error)
}

// WithEdgeDelegations wires the served edge delegation surface. When unset,
// the routes answer that the surface is not enabled — the default-off posture
// of the one exception to the signing boundary.
func WithEdgeDelegations(svc EdgeDelegationService) Option {
	return func(c *config) { c.edgeDelegations = svc }
}

type EdgeSegmentPolicyRequest struct {
	SegmentID string `json:"segment_id"`
	Enabled   bool   `json:"enabled"`
	// AttestationRootsPEM are the TPM attestation roots that may vouch for
	// hosts in this segment. Required to enable: without one, any key that
	// asks would be vouched for.
	AttestationRootsPEM []string `json:"attestation_roots_pem,omitempty"`
	// PermittedDNSDomains become the name constraints of every delegation
	// minted for this segment. The mint request cannot widen them.
	PermittedDNSDomains []string `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains  []string `json:"excluded_dns_domains,omitempty"`
	// AllowedKeyProviders is a closed, explicit custody allowlist. Empty means
	// TPM2 only; adding software is a visible policy exception, never a fallback.
	AllowedKeyProviders []string `json:"allowed_key_providers,omitempty"`
}

type EdgeSegmentPolicy struct {
	SegmentID   string `json:"segment_id"`
	SegmentName string `json:"segment_name,omitempty"`
	Enabled     bool   `json:"enabled"`
	// AttestationRoots is a COUNT. The roots themselves are certificates, not
	// secrets, but echoing them back adds nothing an operator needs here.
	AttestationRoots    int       `json:"attestation_roots"`
	PermittedDNSDomains []string  `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains  []string  `json:"excluded_dns_domains,omitempty"`
	AllowedKeyProviders []string  `json:"allowed_key_providers"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type EdgeSegmentPolicyList struct {
	Items    []EdgeSegmentPolicy `json:"items"`
	Guidance string              `json:"guidance"`
}

type EdgeDelegationMintRequest struct {
	SegmentID  string `json:"segment_id"`
	CAID       string `json:"ca_id"`
	Host       string `json:"host"`
	CommonName string `json:"common_name,omitempty"`
	// TTLSeconds is bounded by the 30-day ceiling; longer is refused, not
	// clamped. Zero takes the 7-day default.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// CSRDER is the CSR over the key the edge host generated locally; the key
	// itself never travels.
	CSRDER []byte `json:"csr_der"`
	// AttestationCredentialJSON is the WebAuthn-format TPM attestation over
	// the challenge binding tenant, segment and this CSR.
	AttestationCredentialJSON []byte `json:"attestation_credential_json"`
	// KeyProvider describes the shipping agent custody path that made the CSR:
	// tpm2 (default), pkcs11, or software. The server derives storage and
	// exportability from this closed value and the segment must allow it.
	KeyProvider string `json:"key_provider,omitempty"`
}

type EdgeDelegation struct {
	ID                  string     `json:"id"`
	SegmentID           string     `json:"segment_id"`
	CAID                string     `json:"ca_id"`
	Host                string     `json:"host"`
	CommonName          string     `json:"common_name"`
	Serial              string     `json:"serial"`
	CertificatePEM      string     `json:"certificate_pem,omitempty"`
	PermittedDNSDomains []string   `json:"permitted_dns_domains"`
	ExcludedDNSDomains  []string   `json:"excluded_dns_domains,omitempty"`
	AttestedKeySHA256   string     `json:"attested_key_sha256,omitempty"`
	CSRKeySHA256        string     `json:"csr_key_sha256"`
	KeyProvider         string     `json:"key_provider"`
	KeyStorage          string     `json:"key_storage"`
	KeyExportable       bool       `json:"key_exportable"`
	CustodyAssurance    string     `json:"custody_assurance"`
	Status              string     `json:"status"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevokeReason        string     `json:"revoke_reason,omitempty"`
}

type EdgeDelegationList struct {
	Items    []EdgeDelegation `json:"items"`
	Guidance string           `json:"guidance"`
}

type EdgeIssuance struct {
	Serial            string    `json:"serial"`
	Subject           string    `json:"subject"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IssuedAt          time.Time `json:"issued_at"`
	ReconciledAt      time.Time `json:"reconciled_at"`
	WithinConstraints bool      `json:"within_constraints"`
	Violation         string    `json:"violation,omitempty"`
}

type EdgeDelegationDetail struct {
	Delegation EdgeDelegation `json:"delegation"`
	Issuances  []EdgeIssuance `json:"issuances,omitempty"`
}

type EdgeDelegationRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

type EdgeReconcileRequest struct {
	Host string `json:"host,omitempty"`
	// CertificatesPEM are the leaves the edge host issued while unreachable.
	CertificatesPEM []string `json:"certificates_pem"`
}

type EdgeReconcileResult struct {
	Reconciled int `json:"reconciled"`
	// Violations counts leaves recorded OUTSIDE the delegation's constraints —
	// recorded and flagged, never silently dropped or silently accepted.
	Violations int `json:"violations"`
	Already    int `json:"already"`
	// Rejected counts reports that did not chain to this delegated CA at all.
	Rejected int    `json:"rejected"`
	Guidance string `json:"guidance,omitempty"`
}

const edgeDelegationGuidance = "A delegated edge CA is the one deliberate exception to signing " +
	"living only in the isolated signer, bounded hard: minted centrally with name constraints from " +
	"the segment's policy, path length zero, a 30-day ceiling on life, per-segment opt-in, and TPM " +
	"attestation. TPM2 requires the attested key to equal the CSR key; PKCS#11 or exportable software " +
	"custody requires an explicit policy exception and is labeled with its weaker assurance. Revoking " +
	"here also revokes the delegation's serial in the parent " +
	"CA's ledger, so OCSP and the CRL answer for it. Local issuances must reconcile back; a leaf " +
	"outside the constraints is recorded as a violation, visibly."

func (a *API) putEdgeSegmentPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.edgeDelegations == nil {
			return 0, nil, ErrEdgeDelegationUnavailable
		}
		var body EdgeSegmentPolicyRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		body.SegmentID = r.PathValue("segmentID")
		policy, err := a.edgeDelegations.SetSegmentPolicy(ctx, tenantID, body)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, policy, nil
	})
}

func (a *API) listEdgeSegmentPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.edgeDelegations == nil {
		a.writeError(w, ErrEdgeDelegationUnavailable)
		return
	}
	items, err := a.edgeDelegations.ListSegmentPolicies(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items == nil {
		items = []EdgeSegmentPolicy{}
	}
	a.writeJSON(w, http.StatusOK, EdgeSegmentPolicyList{Items: items, Guidance: edgeDelegationGuidance})
}

func (a *API) mintEdgeDelegation(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.edgeDelegations == nil {
			return 0, nil, ErrEdgeDelegationUnavailable
		}
		var body EdgeDelegationMintRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		delegation, err := a.edgeDelegations.MintDelegation(ctx, tenantID, body)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, delegation, nil
	})
}

func (a *API) listEdgeDelegations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.edgeDelegations == nil {
		a.writeError(w, ErrEdgeDelegationUnavailable)
		return
	}
	items, err := a.edgeDelegations.ListDelegations(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items == nil {
		items = []EdgeDelegation{}
	}
	a.writeJSON(w, http.StatusOK, EdgeDelegationList{Items: items, Guidance: edgeDelegationGuidance})
}

func (a *API) getEdgeDelegation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.edgeDelegations == nil {
		a.writeError(w, ErrEdgeDelegationUnavailable)
		return
	}
	detail, err := a.edgeDelegations.GetDelegation(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, detail)
}

func (a *API) revokeEdgeDelegation(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.edgeDelegations == nil {
			return 0, nil, ErrEdgeDelegationUnavailable
		}
		var body EdgeDelegationRevokeRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		delegation, err := a.edgeDelegations.RevokeDelegation(ctx, tenantID, r.PathValue("id"), body.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, delegation, nil
	})
}

func (a *API) reconcileEdgeDelegation(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.edgeDelegations == nil {
			return 0, nil, ErrEdgeDelegationUnavailable
		}
		var body EdgeReconcileRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(body.CertificatesPEM) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "certificates_pem is required: reconciliation reports the leaves the edge host issued")
		}
		result, err := a.edgeDelegations.Reconcile(ctx, tenantID, r.PathValue("id"), body)
		if err != nil {
			return 0, nil, err
		}
		result.Guidance = edgeDelegationGuidance
		return http.StatusOK, result, nil
	})
}

// writeEdgeDelegationError maps the surface's sentinel errors; reports whether
// it handled the error.
func (a *API) writeEdgeDelegationError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrEdgeDelegationUnavailable):
		a.writeProblem(w, problem.New(http.StatusNotImplemented,
			"edge delegation surface is not enabled on this deployment"))
	case errors.Is(err, ErrEdgeDelegationNotFound):
		a.writeProblem(w, problem.New(http.StatusNotFound, "edge delegation not found"))
	case errors.Is(err, ErrEdgeDelegationRefused):
		a.writeProblem(w, problem.New(http.StatusForbidden, edgeErrDetail(err)))
	case errors.Is(err, ErrEdgeDelegationInvalid):
		a.writeProblem(w, problem.New(http.StatusBadRequest, edgeErrDetail(err)))
	default:
		return false
	}
	return true
}

func edgeErrDetail(err error) string {
	return strings.TrimPrefix(err.Error(), "api: ")
}
