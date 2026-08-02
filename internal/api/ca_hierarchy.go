// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

var (
	ErrCAHierarchyUnavailable = errors.New("api: CA hierarchy surface is not enabled")
	ErrCAHierarchyInvalid     = errors.New("api: invalid CA hierarchy request")
	ErrCAHierarchyConflict    = errors.New("api: CA hierarchy request conflicts with current ceremony state")
)

// CAHierarchyService is the served private-CA hierarchy backend (F48). The
// implementation lives in internal/server so it can bind to the isolated signer;
// the API owns only the JSON contract and RBAC/idempotency wrapper.
type CAHierarchyService interface {
	StartCeremony(ctx context.Context, tenantID string, req CACeremonyStartRequest) (CAKeyCeremony, error)
	GetCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	ApproveCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	ListAuthorities(ctx context.Context, tenantID string) ([]CAAuthority, error)
	CreateRoot(ctx context.Context, tenantID string, req CACreateRootRequest) (CAAuthority, error)
	ImportOfflineRoot(ctx context.Context, tenantID string, req CAImportOfflineRootRequest) (CAAuthority, error)
	ImportExisting(ctx context.Context, tenantID string, req CAImportExistingRequest) (CAAuthority, error)
	CreateIntermediate(ctx context.Context, tenantID string, req CACreateIntermediateRequest) (CAAuthority, error)
	CreateOfflineIntermediateCSR(ctx context.Context, tenantID, caID string, req CACreateOfflineIntermediateCSRRequest) (CAIntermediateCSR, error)
	ImportOfflineIntermediate(ctx context.Context, tenantID, caID string, req CAImportOfflineIntermediateRequest) (CAAuthority, error)
	IssueIntermediateCSR(ctx context.Context, tenantID, caID string, req CAIssueIntermediateRequest) (CAIssuedIntermediate, error)
	IssueLeaf(ctx context.Context, tenantID, caID string, req CAIssueLeafRequest) (CAIssuedLeaf, error)
	RotateAuthority(ctx context.Context, tenantID, caID string, req CAAuthorityRotationRequest) (CAAuthorityRotation, error)
	RekeyAuthority(ctx context.Context, tenantID, caID string, req CAAuthorityRekeyRequest) (CAAuthorityRotation, error)
	CrossSignAuthority(ctx context.Context, tenantID, caID string, req CACrossSignRequest) (CACrossSign, error)
	ImportOfflineRootCrossSign(ctx context.Context, tenantID, caID string, req CAOfflineCrossSignImportRequest) (CACrossSign, error)
	RekeyOfflineRoot(ctx context.Context, tenantID, caID string, req CAOfflineRootRekeyRequest) (CAOfflineRootRekey, error)
}

// WithCAHierarchy wires the served CA hierarchy surface. When unset, the routes
// fail closed with 503 instead of pretending CA creation is available.
func WithCAHierarchy(svc CAHierarchyService) Option {
	return func(c *config) { c.caHierarchy = svc }
}

type CASpec struct {
	CommonName          string   `json:"common_name"`
	PermittedDNSDomains []string `json:"permitted_dns_domains"`
	MaxPathLen          int      `json:"max_path_len"`
	ExtendedKeyUsages   []string `json:"extended_key_usages"`
	TTLSeconds          int64    `json:"ttl_seconds"`
	SignatureAlgorithm  string   `json:"signature_algorithm"`
}

type CACeremonyStartRequest struct {
	Operation                  string `json:"operation"`
	ParentID                   string `json:"parent_id"`
	AuthorityID                string `json:"authority_id,omitempty"`
	CSRPem                     string `json:"csr_pem,omitempty"`
	CertificatePEM             string `json:"certificate_pem,omitempty"`
	TargetCertificatePEM       string `json:"target_certificate_pem,omitempty"`
	CrossCertificatePEM        string `json:"cross_certificate_pem,omitempty"`
	ReverseCrossCertificatePEM string `json:"reverse_cross_certificate_pem,omitempty"`
	Reason                     string `json:"reason,omitempty"`
	SignerHandle               string `json:"signer_handle,omitempty"`
	Threshold                  int    `json:"threshold"`
	Spec                       CASpec `json:"spec"`
}

type CACreateRootRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Spec       CASpec `json:"spec"`
}

type CAImportOfflineRootRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	Spec           CASpec `json:"spec"`
}

type CAImportExistingRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	SignerHandle   string `json:"signer_handle"`
	Spec           CASpec `json:"spec"`
}

type CACreateIntermediateRequest struct {
	CeremonyID string `json:"ceremony_id"`
	ParentID   string `json:"parent_id"`
	Spec       CASpec `json:"spec"`
}

type CACreateOfflineIntermediateCSRRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Spec       CASpec `json:"spec"`
}

type CAImportOfflineIntermediateRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	Spec           CASpec `json:"spec"`
}

type CAIssueLeafRequest struct {
	CSRDER     []byte
	TTLSeconds int64
}

type CAAuthorityRotationRequest struct {
	SuccessorID string `json:"successor_id"`
	Reason      string `json:"reason,omitempty"`
}

type CAAuthorityRekeyRequest struct {
	CeremonyID string `json:"ceremony_id"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type CACrossSignRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
}

type CAOfflineCrossSignImportRequest struct {
	CeremonyID           string `json:"ceremony_id"`
	TargetCertificatePEM string `json:"target_certificate_pem"`
	CrossCertificatePEM  string `json:"cross_certificate_pem"`
}

type CAOfflineRootRekeyRequest struct {
	CeremonyID              string `json:"ceremony_id"`
	SuccessorCertificatePEM string `json:"successor_certificate_pem"`
	NewSignedByPreviousPEM  string `json:"new_signed_by_previous_pem"`
	PreviousSignedByNewPEM  string `json:"previous_signed_by_new_pem"`
	Reason                  string `json:"reason"`
	Spec                    CASpec `json:"spec"`
}

type CAIssueIntermediateRequest struct {
	CeremonyID string
	CSRDER     []byte
	Spec       CASpec
}

type caIssueLeafJSON struct {
	CSRPem     string `json:"csr_pem"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type caIssueIntermediateJSON struct {
	CeremonyID string `json:"ceremony_id"`
	CSRPem     string `json:"csr_pem"`
	Spec       CASpec `json:"spec"`
}

type CAIntermediateCSR struct {
	CeremonyID   string `json:"ceremony_id"`
	ParentID     string `json:"parent_id"`
	CSRPem       string `json:"csr_pem"`
	SignerHandle string `json:"signer_handle"`
}

type CAKeyCeremony struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Purpose   string    `json:"purpose"`
	Threshold int       `json:"threshold"`
	Status    string    `json:"status"`
	Approvals int       `json:"approvals"`
	Opener    string    `json:"opener,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type CAAuthority struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	ParentID          *string    `json:"parent_id,omitempty"`
	CommonName        string     `json:"common_name"`
	Kind              string     `json:"kind"`
	Status            string     `json:"status"`
	CertificatePEM    string     `json:"certificate_pem"`
	SignerHandle      string     `json:"signer_handle"`
	Serial            string     `json:"serial"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	MaxPathLen        int        `json:"max_path_len"`
	PermittedDNSNames []string   `json:"permitted_dns_names"`
	ExtendedKeyUsages []string   `json:"extended_key_usages"`
	ReplacesID        *string    `json:"replaces_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

type CAAuthorityRotationIssuer struct {
	AuthorityID string `json:"authority_id"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	IssuePath   string `json:"issue_path"`
}

type CAAuthorityRotation struct {
	Predecessor     CAAuthority                 `json:"predecessor"`
	Successor       CAAuthority                 `json:"successor"`
	IssuePath       string                      `json:"issue_path"`
	ActiveIssuePath string                      `json:"active_issue_path"`
	OverlapIssuers  []CAAuthorityRotationIssuer `json:"overlap_issuers"`
}

type CACrossSign struct {
	IssuerAuthorityID string `json:"issuer_authority_id"`
	TargetSHA256      string `json:"target_sha256"`
	CertificatePEM    string `json:"certificate_pem"`
	CeremonyID        string `json:"ceremony_id"`
	Imported          bool   `json:"imported"`
}

type CAOfflineRootRekey struct {
	Rotation               CAAuthorityRotation `json:"rotation"`
	NewSignedByPreviousPEM string              `json:"new_signed_by_previous_pem"`
	PreviousSignedByNewPEM string              `json:"previous_signed_by_new_pem"`
	CeremonyID             string              `json:"ceremony_id"`
}

type CAIssuedLeaf struct {
	CertificatePEM string    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
}

type CAIssuedIntermediate struct {
	CertificatePEM string    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
}

//trstctl:mutation
func (a *API) createCACeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACeremonyStartRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		c, err := a.caHierarchy.StartCeremony(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, c, nil
	})
}

func (a *API) getCACeremony(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	c, err := a.caHierarchy.GetCeremony(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, c)
}

//trstctl:mutation
func (a *API) approveCACeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		c, err := a.caHierarchy.ApproveCeremony(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, c, nil
	})
}

func (a *API) listCAAuthorities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	items, err := a.caHierarchy.ListAuthorities(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	// Every authority carries its year-scale horizon (H5), so the console never
	// has to decide for itself whether a not_after two years out is fine.
	now := time.Now().UTC()
	out := make([]caAuthorityResponse, 0, len(items))
	for _, item := range items {
		out = append(out, a.toCAAuthorityResponse(item, now))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: out})
}

//trstctl:mutation
func (a *API) createRootCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACreateRootRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.CreateRoot(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) importOfflineRootCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAImportOfflineRootRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.ImportOfflineRoot(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) importExistingCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAImportExistingRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.ImportExisting(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) createIntermediateCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACreateIntermediateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.CreateIntermediate(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) createOfflineIntermediateCSR(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACreateOfflineIntermediateCSRRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		csr, err := a.caHierarchy.CreateOfflineIntermediateCSR(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, csr, nil
	})
}

//trstctl:mutation
func (a *API) importOfflineIntermediateCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAImportOfflineIntermediateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.ImportOfflineIntermediate(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) issueHierarchyIntermediateCSR(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req caIssueIntermediateJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		block, _ := pem.Decode([]byte(req.CSRPem))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return 0, nil, errStatus(http.StatusBadRequest, "csr_pem must contain one CERTIFICATE REQUEST PEM block")
		}
		issued, err := a.caHierarchy.IssueIntermediateCSR(ctx, tenantID, id, CAIssueIntermediateRequest{
			CeremonyID: req.CeremonyID,
			CSRDER:     block.Bytes,
			Spec:       req.Spec,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

//trstctl:mutation
func (a *API) issueHierarchyLeaf(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req caIssueLeafJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		block, _ := pem.Decode([]byte(req.CSRPem))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return 0, nil, errStatus(http.StatusBadRequest, "csr_pem must contain one CERTIFICATE REQUEST PEM block")
		}
		issued, err := a.caHierarchy.IssueLeaf(ctx, tenantID, id, CAIssueLeafRequest{
			CSRDER:     block.Bytes,
			TTLSeconds: req.TTLSeconds,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

//trstctl:mutation
func (a *API) rotateCAAuthority(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAAuthorityRotationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.SuccessorID = strings.TrimSpace(req.SuccessorID)
		if req.SuccessorID == "" {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "successor_id is required")
		}
		if err := authorizeCARotationSuccessor(ctx, tenantID, req.SuccessorID); err != nil {
			return 0, nil, err
		}
		rotation, err := a.caHierarchy.RotateAuthority(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, rotation, nil
	})
}

//trstctl:mutation
func (a *API) rekeyCAAuthority(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAAuthorityRekeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		rotation, err := a.caHierarchy.RekeyAuthority(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, rotation, nil
	})
}

//trstctl:mutation
func (a *API) crossSignCAAuthority(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACrossSignRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := a.caHierarchy.CrossSignAuthority(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, result, nil
	})
}

//trstctl:mutation
func (a *API) importOfflineRootCrossSign(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAOfflineCrossSignImportRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := a.caHierarchy.ImportOfflineRootCrossSign(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, result, nil
	})
}

//trstctl:mutation
func (a *API) rekeyOfflineRoot(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAOfflineRootRekeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := a.caHierarchy.RekeyOfflineRoot(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, result, nil
	})
}

func authorizeCARotationSuccessor(ctx context.Context, tenantID, successorID string) error {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok {
		return errStatus(http.StatusUnauthorized, "missing authenticated principal")
	}
	target := authz.Scope{TenantID: tenantID, Issuer: successorID}
	if !principal.Can(authz.IssuersWrite, target) {
		return errStatus(http.StatusForbidden, "forbidden: requires issuers:write on successor authority")
	}
	return nil
}

func (a *API) writeCAHierarchyError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrCAHierarchyUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "CA hierarchy surface is not enabled"))
	case errors.Is(err, ErrCAHierarchyInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrCAHierarchyInvalid.Error()+": ")))
	case errors.Is(err, ErrCAHierarchyConflict),
		errors.Is(err, store.ErrSelfApproval),
		errors.Is(err, store.ErrKeyCeremonyNotPending),
		errors.Is(err, store.ErrKeyCeremonyPurposeMismatch),
		errors.Is(err, store.ErrKeyCeremonyQuorumNotMet):
		a.writeProblem(w, problem.New(http.StatusConflict, err.Error()))
	default:
		return false
	}
	return true
}
