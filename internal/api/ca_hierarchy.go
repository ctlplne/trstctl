// SPDX-License-Identifier: BUSL-1.1

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
	"trstctl.com/trstctl/internal/events"
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
	PreviewCeremony(ctx context.Context, tenantID string, req CACeremonyStartRequest) (CACeremonyPlanPreview, error)
	StartCeremony(ctx context.Context, tenantID string, req CACeremonyStartRequest) (CAKeyCeremony, error)
	GetCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	ApproveCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	CancelCeremony(ctx context.Context, tenantID, id, reason string) (CAKeyCeremony, error)
	ListAuthorities(ctx context.Context, tenantID string) ([]CAAuthority, error)
	CreateRoot(ctx context.Context, tenantID string, req CACreateRootRequest) (CAAuthority, error)
	ImportOfflineRoot(ctx context.Context, tenantID string, req CAImportOfflineRootRequest) (CAAuthority, error)
	ImportExisting(ctx context.Context, tenantID string, req CAImportExistingRequest) (CAAuthority, error)
	PrepareKeyImport(ctx context.Context, tenantID string, req CAKeyImportOfferRequest) (CAKeyImportOffer, error)
	ImportKey(ctx context.Context, tenantID string, req CAImportKeyRequest) (CAAuthority, error)
	PrepareExistingImportCSR(ctx context.Context, tenantID string, req CAPrepareExistingImportCSRRequest) (CAExistingImportCSR, error)
	GetExistingImportCSR(ctx context.Context, tenantID, ceremonyID string) (CAExistingImportCSR, error)
	CreateIntermediate(ctx context.Context, tenantID string, req CACreateIntermediateRequest) (CAAuthority, error)
	CreateOfflineIntermediateCSR(ctx context.Context, tenantID, caID string, req CACreateOfflineIntermediateCSRRequest) (CAIntermediateCSR, error)
	ImportOfflineIntermediate(ctx context.Context, tenantID, caID string, req CAImportOfflineIntermediateRequest) (CAAuthority, error)
	IssueIntermediateCSR(ctx context.Context, tenantID, caID string, req CAIssueIntermediateRequest) (CAIssuedIntermediate, error)
	IssueLeaf(ctx context.Context, tenantID, caID string, req CAIssueLeafRequest) (CAIssuedLeaf, error)
	PreviewRotation(ctx context.Context, tenantID, caID string, req CAAuthorityRotationRequest) (CAAuthorityRotationPlanPreview, error)
	RotateAuthority(ctx context.Context, tenantID, caID string, req CAAuthorityRotationRequest) (CAAuthorityRotation, error)
	RekeyAuthority(ctx context.Context, tenantID, caID string, req CAAuthorityRekeyRequest) (CAAuthorityRotation, error)
	RevokeAuthority(ctx context.Context, tenantID, caID string, req CAAuthorityRevokeRequest) (CAAuthorityRevocation, error)
	CrossSignAuthority(ctx context.Context, tenantID, caID string, req CACrossSignRequest) (CACrossSign, error)
	GetCrossSignReceipt(ctx context.Context, tenantID, ceremonyID string) (CACrossSign, error)
	ImportOfflineRootCrossSign(ctx context.Context, tenantID, caID string, req CAOfflineCrossSignImportRequest) (CACrossSign, error)
	RekeyOfflineRoot(ctx context.Context, tenantID, caID string, req CAOfflineRootRekeyRequest) (CAOfflineRootRekey, error)
	GetOfflineRootRekeyReceipt(ctx context.Context, tenantID, ceremonyID string) (CAOfflineRootRekey, error)
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
	DependentID                string `json:"dependent_id,omitempty"`
	ExpectedCertificateSHA256  string `json:"expected_certificate_sha256,omitempty"`
	RiskAccepted               bool   `json:"risk_accepted,omitempty"`
	CSRPem                     string `json:"csr_pem,omitempty"`
	CertificatePEM             string `json:"certificate_pem,omitempty"`
	TargetCertificatePEM       string `json:"target_certificate_pem,omitempty"`
	CrossCertificatePEM        string `json:"cross_certificate_pem,omitempty"`
	ReverseCrossCertificatePEM string `json:"reverse_cross_certificate_pem,omitempty"`
	Reason                     string `json:"reason,omitempty"`
	SignerHandle               string `json:"signer_handle,omitempty"`
	Threshold                  int    `json:"threshold"`
	Spec                       CASpec `json:"spec,omitempty"`
}

// CACeremonyPlanAuthority is the non-secret identity of one existing authority
// referenced by an effect-free ceremony review. Certificate PEM and signer
// handles deliberately never cross this preview boundary.
type CACeremonyPlanAuthority struct {
	ID         string `json:"id"`
	CommonName string `json:"common_name"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
}

// CACeremonyPlanPreview is the server-owned answer to "what exactly will this
// CA ceremony prepare?" It is intentionally not durable state: successful
// preview writes no event, opens no ceremony, creates no signer handle, and
// contacts no external authority. The mutation still rechecks every condition.
type CACeremonyPlanPreview struct {
	Capability             string                   `json:"capability"`
	Operation              string                   `json:"operation"`
	Ready                  bool                     `json:"ready"`
	RequestFingerprint     string                   `json:"request_fingerprint"`
	ApprovalThreshold      int                      `json:"approval_threshold"`
	RequiredPermission     string                   `json:"required_permission"`
	NormalizedSpec         CASpec                   `json:"normalized_spec"`
	Parent                 *CACeremonyPlanAuthority `json:"parent,omitempty"`
	Authority              *CACeremonyPlanAuthority `json:"authority,omitempty"`
	ReleaseReview          *CAReleaseCeremonyReview `json:"release_review,omitempty"`
	Changes                []string                 `json:"changes"`
	Risks                  []string                 `json:"risks"`
	VerificationSteps      []string                 `json:"verification_steps"`
	SensitiveInputs        []string                 `json:"sensitive_inputs"`
	PreviewWrites          []string                 `json:"preview_writes"`
	PreviewExternalEffects []string                 `json:"preview_external_effects"`
}

// CAReleaseCeremonyReview is the public evidence a custodian sees before
// approving a historical managed-certificate disposition. A digest without
// these fields would not provide an informed two-person decision.
type CAReleaseCeremonyReview struct {
	KeyID              string     `json:"key_id"`
	CertificateID      string     `json:"certificate_id"`
	SourceEventID      string     `json:"source_event_id"`
	SourceSequence     uint64     `json:"source_sequence"`
	RevocationEventID  string     `json:"revocation_event_id,omitempty"`
	RevocationSequence uint64     `json:"revocation_sequence,omitempty"`
	Serial             string     `json:"serial"`
	CertificateSHA256  string     `json:"certificate_sha256"`
	Subject            string     `json:"subject,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	Reason             string     `json:"reason"`
	RiskAccepted       bool       `json:"risk_accepted"`
}

type CACreateRootRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Spec       CASpec `json:"spec"`
}

type CAImportOfflineRootRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	Spec           CASpec `json:"spec"`
	// PossessionSignature is the offline root's signature, base64, over
	// crypto.OfflinePossessionMessage(CeremonyID), made where the root key
	// lives during the import ceremony. Without it the import records that
	// possession was not proven (eMudhra, Part 4).
	PossessionSignature string `json:"possession_signature,omitempty"`
}

type CAImportExistingRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	SignerHandle   string `json:"signer_handle"`
	ParentID       string `json:"parent_id,omitempty"`
	Spec           CASpec `json:"spec"`
}

// CAPrepareExistingImportCSRRequest binds a new signer-held CA key to one
// reviewed external issuer chain before returning public signing material.
type CAPrepareExistingImportCSRRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	ParentID       string `json:"parent_id,omitempty"`
	Spec           CASpec `json:"spec"`
}

type CAExistingImportCSR struct {
	CeremonyID   string `json:"ceremony_id"`
	ParentID     string `json:"parent_id,omitempty"`
	IssuerSHA256 string `json:"issuer_sha256"`
	CSRPem       string `json:"csr_pem"`
	SignerHandle string `json:"signer_handle"`
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

// CAAuthorityRotationPlanPreview is the effect-free answer to "what will this
// rotation change?" It deliberately contains only public authority identity,
// never certificate PEM or signer handles. The mutation rechecks the same
// eligibility rules while holding both authority rows for update.
type CAAuthorityRotationPlanPreview struct {
	Capability             string                  `json:"capability"`
	Operation              string                  `json:"operation"`
	Ready                  bool                    `json:"ready"`
	RequestFingerprint     string                  `json:"request_fingerprint"`
	RequiredPermission     string                  `json:"required_permission"`
	Reason                 string                  `json:"reason"`
	Predecessor            CACeremonyPlanAuthority `json:"predecessor"`
	Successor              CACeremonyPlanAuthority `json:"successor"`
	Changes                []string                `json:"changes"`
	Risks                  []string                `json:"risks"`
	VerificationSteps      []string                `json:"verification_steps"`
	PreviewWrites          []string                `json:"preview_writes"`
	PreviewExternalEffects []string                `json:"preview_external_effects"`
}

type CAAuthorityRekeyRequest struct {
	CeremonyID string `json:"ceremony_id"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// CAKeyImportOfferRequest asks for the signer's one-time import key for an
// import_ca_key ceremony that reached quorum (A128): the same chain, profile and
// parent the ceremony approved.
type CAKeyImportOfferRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	ParentID       string `json:"parent_id,omitempty"`
	Spec           CASpec `json:"spec"`
}

// CAKeyImportOffer is what an operator seals the CA's private key to, on their
// own machine: the import key's public half under Suite, bound by TenantID,
// OperationID and ExpectedPublicKey (the certificate's key). The signer keeps
// the key under SignerHandle.
type CAKeyImportOffer struct {
	CeremonyID        string `json:"ceremony_id"`
	TenantID          string `json:"tenant_id"`
	OperationID       string `json:"operation_id"`
	Suite             string `json:"suite"`
	PublicKey         []byte `json:"public_key"`
	ExpectedPublicKey []byte `json:"expected_public_key"`
	SignerHandle      string `json:"signer_handle"`
}

// CAImportKeyRequest carries the sealed private key for an import_ca_key
// ceremony, with the chain, profile and parent it approved.
type CAImportKeyRequest struct {
	CeremonyID     string `json:"ceremony_id"`
	CertificatePEM string `json:"certificate_pem"`
	ParentID       string `json:"parent_id,omitempty"`
	Spec           CASpec `json:"spec"`
	SealedKey      []byte `json:"sealed_key"`
}

// CAAuthorityRevokeRequest executes a revoke_ca ceremony that reached quorum
// (A128). The reason must be the one the ceremony approved.
type CAAuthorityRevokeRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Reason     string `json:"reason"`
}

// CAAuthorityRevocation is the result of revoking an authority's key: the
// authority as now recorded, the revocation, whether the signer itself reports
// the key revoked, and whether the authority's certificate was revoked on a
// managed parent's CRL. FollowUp names what remains outside trstctl's reach.
type CAAuthorityRevocation struct {
	Authority          CAAuthority `json:"authority"`
	Reason             string      `json:"reason"`
	RevokedAt          time.Time   `json:"revoked_at"`
	SignerRevoked      bool        `json:"signer_revoked"`
	ParentID           *string     `json:"parent_id,omitempty"`
	RevokedOnParentCRL bool        `json:"revoked_on_parent_crl"`
	CeremonyID         string      `json:"ceremony_id"`
	FollowUp           []string    `json:"follow_up"`
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
	ID            string                   `json:"id"`
	TenantID      string                   `json:"tenant_id"`
	Purpose       string                   `json:"purpose"`
	Threshold     int                      `json:"threshold"`
	Status        string                   `json:"status"`
	Approvals     int                      `json:"approvals"`
	Opener        string                   `json:"opener,omitempty"`
	CreatedAt     time.Time                `json:"created_at"`
	ClosedAt      *time.Time               `json:"closed_at,omitempty"`
	ClosedBy      string                   `json:"closed_by,omitempty"`
	CloseReason   string                   `json:"close_reason,omitempty"`
	ReleaseReview *CAReleaseCeremonyReview `json:"release_review,omitempty"`
}

type caCeremonyCancelJSON struct {
	Reason string `json:"reason"`
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
	// KeyAlgorithm is the authority certificate's public-key family as the
	// platform labels it (ecdsa-p256, ml-dsa-65, ...), read from the
	// certificate itself.
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// PossessionProof is how possession of the authority's key was
	// established by the call that created or imported it: one of the
	// CAPossession* values. That call's response and the creation event
	// carry it; listings omit it.
	PossessionProof string `json:"possession_proof,omitempty"`
	// RevokedAt and RevocationReason are set once the authority's key was
	// administratively revoked (status "revoked").
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

// How possession of a CA key was established when an authority was created
// or imported (eMudhra, Part 4).
const (
	// CAPossessionSelfSignature: a root trstctl created; its self-signature,
	// made by the signer-held key, verifies under the certified key.
	CAPossessionSelfSignature = "self_signature"
	// CAPossessionSignerChallenge: the signer-held key signed a fresh
	// challenge that verified against the certified public key.
	CAPossessionSignerChallenge = "signer_challenge"
	// CAPossessionOfflineSignature: the offline root signed the import
	// ceremony's challenge where its key lives.
	CAPossessionOfflineSignature = "offline_signature"
	// CAPossessionNotProven: no proof was made, and the record says so
	// rather than claim possession.
	CAPossessionNotProven = "not_proven"
)

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

func (a *API) previewCACeremony(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	var req CACeremonyStartRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	preview, err := a.caHierarchy.PreviewCeremony(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

func (a *API) previewCAAuthorityRotation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	var req CAAuthorityRotationRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.SuccessorID = strings.TrimSpace(req.SuccessorID)
	if req.SuccessorID == "" {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "successor_id is required"))
		return
	}
	if err := authorizeCARotationSuccessor(r.Context(), tenantID, req.SuccessorID); err != nil {
		a.writeError(w, err)
		return
	}
	preview, err := a.caHierarchy.PreviewRotation(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
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

//trstctl:mutation
func (a *API) cancelCACeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req caCeremonyCancelJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" || len(reason) > 512 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "reason must be 1-512 characters")
		}
		c, err := a.caHierarchy.CancelCeremony(ctx, tenantID, id, reason)
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
		resp := a.toCAAuthorityResponse(item, now)
		a.attachTruncatedLeaves(r.Context(), tenantID, &resp)
		out = append(out, resp)
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
func (a *API) prepareExistingImportCSR(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAPrepareExistingImportCSRRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		csr, err := a.caHierarchy.PrepareExistingImportCSR(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, csr, nil
	})
}

func (a *API) getExistingImportCSR(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	csr, err := a.caHierarchy.GetExistingImportCSR(r.Context(), tenantID, r.PathValue("ceremony_id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, csr)
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

// prepareCAKeyImport offers the signer's one-time import key for an approved
// import_ca_key ceremony (A128).
//
//trstctl:mutation
func (a *API) prepareCAKeyImport(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAKeyImportOfferRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		offer, err := a.caHierarchy.PrepareKeyImport(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, offer, nil
	})
}

// importCAKey takes a sealed CA private key into signer custody and binds the
// approved chain to it (A128).
//
//trstctl:mutation
func (a *API) importCAKey(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAImportKeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		authority, err := a.caHierarchy.ImportKey(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, authority, nil
	})
}

// revokeCAAuthority revokes a signer-backed authority's key after a revoke_ca
// ceremony reached quorum (A128).
//
//trstctl:mutation
func (a *API) revokeCAAuthority(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CAAuthorityRevokeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := a.caHierarchy.RevokeAuthority(ctx, tenantID, id, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, result, nil
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

func (a *API) getCACrossSignReceipt(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	receipt, err := a.caHierarchy.GetCrossSignReceipt(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, ok := r.Context().Value(principalCtxKey).(authz.Principal)
	if !ok || !principal.Can(authz.IssuersRead, authz.Scope{TenantID: tenantID, Issuer: receipt.IssuerAuthorityID}) {
		a.writeProblem(w, problem.New(http.StatusForbidden, "forbidden: requires issuers:read on cross-sign issuer"))
		return
	}
	a.writeJSON(w, http.StatusOK, receipt)
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

func (a *API) getOfflineRootRekeyReceipt(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	receipt, err := a.caHierarchy.GetOfflineRootRekeyReceipt(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, ok := r.Context().Value(principalCtxKey).(authz.Principal)
	if !ok || !principal.Can(authz.IssuersRead, authz.Scope{TenantID: tenantID, Issuer: receipt.Rotation.Predecessor.ID}) ||
		!principal.Can(authz.IssuersRead, authz.Scope{TenantID: tenantID, Issuer: receipt.Rotation.Successor.ID}) {
		a.writeProblem(w, problem.New(http.StatusForbidden, "forbidden: requires issuers:read on both re-key authorities"))
		return
	}
	a.writeJSON(w, http.StatusOK, receipt)
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
	case errors.Is(err, events.ErrEventIDIndexBehind):
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable,
			"CA history is catching up; retry with the same Idempotency-Key"))
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
