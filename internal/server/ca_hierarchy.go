// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	libhierarchy "trstctl.com/trstctl/internal/ca/hierarchy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

const hierarchySignerHandlePrefix = "ca-hierarchy-"

type caCrossSignedEvent struct {
	CAID                 string `json:"ca_id"`
	CeremonyID           string `json:"ceremony_id"`
	OfflineRoot          bool   `json:"offline_root,omitempty"`
	TargetCertificateDER []byte `json:"target_certificate_der"`
	CrossCertificateDER  []byte `json:"cross_certificate_der"`
	TargetSHA256         string `json:"target_sha256"`
}

type caHierarchyService struct {
	parseSubjectCSR           LicensedCSRParser
	inspectHybridSubjectCSR   LicensedCSRInspector
	preparedSubjectLeafSigner PreparedSubjectLeafSigner
	store                     *store.Store
	log                       *events.Log
	signer                    SignerProvider
	signAuthz                 signing.SignTokenProvider
	leafProfile               crypto.LeafProfile
	revocationBaseURL         string
	requireRevocationPointers bool
	// minApprovals is the configured ceremony threshold floor (F264).
	minApprovals int

	mu      sync.Mutex
	signers map[string]*signing.RemoteSigner
}

func (s *Server) buildCAHierarchyService(d Deps) api.CAHierarchyService {
	if d.Signer == nil || d.Signer.Client() == nil || s.signAuthz == nil {
		return nil
	}
	return &caHierarchyService{
		parseSubjectCSR: d.LicensedCSRParser, inspectHybridSubjectCSR: d.LicensedCSRInspector,
		preparedSubjectLeafSigner: d.PreparedSubjectLeafSigner,
		store:                     d.Store, log: d.Log, signer: d.Signer, signAuthz: s.signAuthz,
		leafProfile: d.LeafProfile, revocationBaseURL: d.HierarchyRevocationBaseURL,
		requireRevocationPointers: d.CAHierarchyRequireRevocationPointers,
		signers:                   map[string]*signing.RemoteSigner{},
		minApprovals:              d.CACeremonyMinApprovals,
	}
}

// ceremonyThresholdFloor refuses a threshold below the configured floor, so a
// requester cannot choose how many other people must agree (F264).
func (h *caHierarchyService) ceremonyThresholdFloor(threshold int) error {
	floor := h.minApprovals
	if floor < 1 {
		floor = 1
	}
	if threshold < floor {
		return fmt.Errorf("%w: threshold must be at least %d (ca.ceremony_min_approvals)", api.ErrCAHierarchyInvalid, floor)
	}
	return nil
}

func (h *caHierarchyService) PreviewCeremony(ctx context.Context, tenantID string, req api.CACeremonyStartRequest) (api.CACeremonyPlanPreview, error) {
	if err := h.ceremonyThresholdFloor(req.Threshold); err != nil {
		return api.CACeremonyPlanPreview{}, err
	}
	purpose, normalizedSpec, err := h.ceremonyPurposeAndSpec(ctx, tenantID, req)
	if err != nil {
		return api.CACeremonyPlanPreview{}, err
	}
	fingerprintPayload, err := json.Marshal(struct {
		Purpose   string `json:"purpose"`
		Threshold int    `json:"threshold"`
	}{Purpose: purpose, Threshold: req.Threshold})
	if err != nil {
		return api.CACeremonyPlanPreview{}, err
	}
	preview := api.CACeremonyPlanPreview{
		Capability:             "F48",
		Operation:              req.Operation,
		Ready:                  true,
		RequestFingerprint:     crypto.SHA256Hex(fingerprintPayload),
		ApprovalThreshold:      req.Threshold,
		RequiredPermission:     "issuers:write",
		NormalizedSpec:         normalizedSpec,
		Changes:                ceremonyPreviewChanges(req.Operation),
		Risks:                  ceremonyPreviewRisks(req.Operation),
		VerificationSteps:      ceremonyPreviewVerification(req.Operation),
		SensitiveInputs:        ceremonySensitiveInputs(req),
		PreviewWrites:          []string{},
		PreviewExternalEffects: []string{},
	}
	if req.Operation == "release_managed_ca_leaf" {
		if err := h.fillManagedLeafReleasePreview(ctx, tenantID, req, purpose, &preview); err != nil {
			return api.CACeremonyPlanPreview{}, err
		}
	}
	if req.Operation == "rekey_ca" {
		preview.Changes = append(preview.Changes, "Re-key reason: "+strings.TrimSpace(req.Reason))
	}
	if req.Operation == "revoke_ca" {
		preview.Changes = append(preview.Changes, "Revocation reason: "+strings.TrimSpace(req.Reason))
	}
	if req.ParentID != "" {
		parent, loadErr := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.ParentID))
		if loadErr != nil {
			return api.CACeremonyPlanPreview{}, loadErr
		}
		preview.Parent = caCeremonyPlanAuthority(parent)
	}
	if req.AuthorityID != "" {
		authority, loadErr := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.AuthorityID))
		if loadErr != nil {
			return api.CACeremonyPlanPreview{}, loadErr
		}
		if err := validateOfflineCeremonyPackage(authority, req); err != nil {
			return api.CACeremonyPlanPreview{}, err
		}
		preview.Authority = caCeremonyPlanAuthority(authority)
	}
	return preview, nil
}

func caCeremonyPlanAuthority(authority store.CAAuthority) *api.CACeremonyPlanAuthority {
	return &api.CACeremonyPlanAuthority{
		ID: authority.ID, CommonName: authority.CommonName, Kind: authority.Kind, Status: authority.Status,
	}
}

func ceremonySensitiveInputs(req api.CACeremonyStartRequest) []string {
	inputs := make([]string, 0, 6)
	for field, present := range map[string]bool{
		"certificate_pem":               strings.TrimSpace(req.CertificatePEM) != "",
		"csr_pem":                       strings.TrimSpace(req.CSRPem) != "",
		"signer_handle":                 strings.TrimSpace(req.SignerHandle) != "",
		"target_certificate_pem":        strings.TrimSpace(req.TargetCertificatePEM) != "",
		"cross_certificate_pem":         strings.TrimSpace(req.CrossCertificatePEM) != "",
		"reverse_cross_certificate_pem": strings.TrimSpace(req.ReverseCrossCertificatePEM) != "",
	} {
		if present {
			inputs = append(inputs, field)
		}
	}
	slices.Sort(inputs)
	return inputs
}

func ceremonyPreviewChanges(operation string) []string {
	switch operation {
	case "create_root":
		return []string{"Prepare an m-of-n ceremony for a new signer-backed root CA. No key or authority is created by this preview."}
	case "import_offline_root":
		return []string{"Prepare an m-of-n ceremony to trust the supplied public offline-root certificate. The offline private key stays outside trstctl."}
	case "import_existing_ca":
		return []string{"Prepare an m-of-n ceremony to bind the supplied public CA chain to an existing signer-held key handle."}
	case "import_ca_key":
		return []string{"Prepare an m-of-n ceremony to take the CA's existing private key into signer custody for the supplied public chain and profile. After quorum the signer offers a one-time import key; you seal the private key to it on your own machine, and only the sealed key reaches trstctl. No key is created or contacted by this preview."}
	case "prepare_existing_ca":
		return []string{"Prepare an m-of-n ceremony to create a tenant-bound signer-held CA key and public CSR for the reviewed external issuer chain. No key is created by this preview."}
	case "create_intermediate":
		return []string{"Prepare an m-of-n ceremony for a new signer-backed intermediate under the reviewed parent authority."}
	case "create_offline_intermediate":
		return []string{"Prepare an m-of-n ceremony for a signer-held intermediate CSR that an offline parent will sign."}
	case "issue_intermediate_csr":
		return []string{"Prepare an m-of-n ceremony to sign the reviewed external intermediate CSR with the reviewed parent authority."}
	case "rekey_ca":
		return []string{"Prepare an m-of-n ceremony to replace the reviewed authority key while retaining an auditable predecessor-to-successor lineage."}
	case "cross_sign_ca":
		return []string{"Prepare an m-of-n ceremony to cross-sign the reviewed public CA certificate with the reviewed signer-backed authority."}
	case "import_offline_cross_sign":
		return []string{"Prepare an m-of-n ceremony to verify and import the supplied public cross-certificate from the reviewed offline root."}
	case "rekey_offline_root":
		return []string{"Prepare an m-of-n ceremony to activate the supplied offline-root successor and its bidirectional public cross-signatures."}
	case "release_managed_ca_leaf":
		return []string{"Prepare a two-custodian disposition of the exact expired managed CA leaf, its original mint event and the operator's explicit external-use risk decision. The preview writes nothing."}
	case "revoke_ca":
		return []string{"Prepare an m-of-n ceremony to revoke the reviewed authority's key for the reviewed reason. Executing it makes the isolated signer refuse every signature with that key, stops the authority issuing, and revokes its certificate on a managed parent's CRL. The preview writes nothing and contacts no signer."}
	default:
		return []string{"Prepare the reviewed CA hierarchy ceremony without creating a ceremony, key, certificate, or external request during preview."}
	}
}

func ceremonyPreviewRisks(operation string) []string {
	if operation == "revoke_ca" {
		return []string{
			"Revocation is permanent: the key signs no certificate, CRL or OCSP response again, and its last published CRL stays until its next-update time.",
			"Certificates this authority issued stop validating only where relying parties check its parent's CRL; a root has no issuer, so it must be removed from trust stores.",
			"The server will require distinct custodian approvals and revalidate the exact authority, certificate, signer handle and reason before execution.",
		}
	}
	if operation == "release_managed_ca_leaf" {
		return []string{
			"The requester held this leaf's private key. Expiry and a local inventory record cannot prove it was never used outside this deployment.",
			"Releasing this exact dependency after two distinct custodian approvals permits a later retirement request; it does not revoke the certificate or destroy the CA key.",
		}
	}
	risks := []string{
		"A completed ceremony can authorize a later change to certificate trust or signing authority.",
		"The server will require distinct custodian approvals and revalidate the exact ceremony purpose before execution.",
	}
	if strings.Contains(operation, "offline") {
		risks = append(risks, "Only public certificate material is accepted; private-key material is rejected at the server boundary.")
	}
	if operation == "import_ca_key" {
		risks = append(risks, "The private key existed outside trstctl before this import and may still exist there; trstctl cannot prove other copies were destroyed.")
	}
	return risks
}

func ceremonyPreviewVerification(operation string) []string {
	if operation == "revoke_ca" {
		return []string{
			"Confirm the authority, its status and the reason match the intended revocation before opening the ceremony.",
			"After execution, verify the authority reads revoked, the signer reports its key revoked, and a managed parent's CRL lists its serial.",
			"Reissue what the authority issued from another active authority.",
		}
	}
	if operation == "release_managed_ca_leaf" {
		return []string{
			"Match the exact certificate ID, public DER digest, original mint event, CA key and explicit external-use risk decision before opening the ceremony.",
			"Verify two distinct custodian approval events authorize this exact disposition before executing the release.",
			"After release, read the retirement checklist for this CA key and verify the exact certificate is accounted for; retain the immutable release receipt and audit event.",
		}
	}
	steps := []string{
		"Confirm the operation, authority identity, CA profile, and required approval threshold match the intended change.",
		"After the ceremony starts, verify each distinct approval and the immutable ceremony event before executing the CA change.",
		"After execution, verify authority status, chain, expiry, signer custody, and the matching immutable audit event.",
	}
	if operation == "rekey_ca" || operation == "rekey_offline_root" || operation == "cross_sign_ca" || operation == "import_offline_cross_sign" {
		steps = append(steps, "Verify both predecessor and successor trust paths before retiring any old trust material.")
	}
	return steps
}

// issueLeafForExactAuthorityWithValidity mints through the active signer-backed authority
// frozen into a migration member. Unlike the public hierarchy issue route, it
// deliberately does not follow a later rotation: changing authorities under a
// reviewed run would make the installed trust anchor and issued leaf disagree.
func (h *caHierarchyService) issueLeafForExactAuthorityWithValidity(
	ctx context.Context,
	tenantID, authorityID string,
	csrDER []byte,
	ttl time.Duration,
	profile crypto.LeafProfile,
	keyOrigin custody.KeyOrigin,
) (crypto.IssuedLeaf, []byte, string, error) {
	return h.issueLeafForExactAuthority(ctx, tenantID, authorityID, csrDER, ttl, profile, keyOrigin,
		exactAuthorityLeafOptions{migration: true})
}

type exactAuthorityLeafOptions struct {
	expectedSignerHandle string
	expectedCACertDER    []byte
	migration            bool
}

// IssuePCASLeaf reuses the managed-CA profile, dual-control signer binding,
// source event and revocation inventory for a PCAS extension. It never selects
// a successor authority implicitly: the PCAS registration pins one handle and
// public certificate until its own epoch and authority are re-registered.
func (h *caHierarchyService) IssuePCASLeaf(ctx context.Context, tenantID, caHandle string,
	expectedCACertDER, csrDER []byte, ttl time.Duration, extension crypto.CertificateExtension) ([]byte, error) {
	if h == nil || h.store == nil || h.signer == nil || h.signAuthz == nil {
		return nil, api.ErrCAHierarchyUnavailable
	}
	ca, err := h.store.GetCAAuthorityBySignerHandle(ctx, tenantID, caHandle)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: PCAS signer handle is not a tenant-managed CA", api.ErrCAHierarchyConflict)
	}
	if err != nil {
		return nil, err
	}
	profile := h.leafProfile
	profile.ExtraExtensions = append(append([]crypto.CertificateExtension(nil), profile.ExtraExtensions...), extension)
	issued, _, _, err := h.issueLeafForExactAuthority(ctx, tenantID, ca.ID, csrDER, ttl,
		profile, custody.OriginRequester, exactAuthorityLeafOptions{
			expectedSignerHandle: caHandle, expectedCACertDER: expectedCACertDER,
		})
	if err != nil {
		return nil, err
	}
	return issued.DER, nil
}

func (h *caHierarchyService) issueLeafForExactAuthority(
	ctx context.Context, tenantID, authorityID string, csrDER []byte, ttl time.Duration,
	profile crypto.LeafProfile, keyOrigin custody.KeyOrigin, opts exactAuthorityLeafOptions,
) (crypto.IssuedLeaf, []byte, string, error) {
	if len(csrDER) == 0 || ttl <= 0 {
		return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: CSR and positive TTL are required", api.ErrCAHierarchyInvalid)
	}
	if keyOrigin != custody.OriginRequester && keyOrigin != custody.OriginHostAgent &&
		keyOrigin != custody.OriginAppliance && keyOrigin != custody.OriginControlPlane {
		return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: exact-authority issuance requires a known subject-key origin", api.ErrCAHierarchyInvalid)
	}
	if err := refuseCompromisedCSRKey(ctx, h.store, tenantID, csrDER); err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	authority, err := h.store.GetCAAuthority(ctx, tenantID, authorityID)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	if authority.Status != "active" {
		return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: exact authority %s is no longer active", api.ErrCAHierarchyConflict, authority.ID)
	}
	if opts.expectedSignerHandle != "" && authority.SignerHandle != opts.expectedSignerHandle {
		return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: PCAS signer handle changed", api.ErrCAHierarchyConflict)
	}
	signer, err := h.signerForAuthority(ctx, authority)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	caDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	if len(opts.expectedCACertDER) != 0 && !bytes.Equal(caDER, opts.expectedCACertDER) {
		return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: PCAS issuer certificate changed", api.ErrCAHierarchyConflict)
	}
	profile, err = h.leafProfileForAuthority(tenantID, authority, profile)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	// A migration member is pinned to this exact authority, so it cannot follow a
	// later rotation. It still must stop when that pinned authority expires.
	profile.ClampTTLToIssuer = true
	issued, err := signSubjectLifecycleLeaf(ctx, caDER, signer, csrDER, ttl, profile, h.parseSubjectCSR, h.inspectHybridSubjectCSR, h.preparedSubjectLeafSigner)
	if err != nil {
		if crypto.IsLeafProfileViolation(err) {
			return crypto.IssuedLeaf{}, nil, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return crypto.IssuedLeaf{}, nil, "", err
	}
	info, err := certinfo.Inspect(issued.DER)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	evidence := managedCALeafEvent(authority.ID, issued.DER, info)
	evidence.MigrationExactAuthority = opts.migration
	evidence.KeyOrigin = string(keyOrigin)
	ev, err := h.appendVersionedEvent(ctx, tenantID, projections.EventCAEndEntityIssued, projections.CAEndEntityInventorySchemaVersion, evidence)
	if err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		return crypto.IssuedLeaf{}, nil, "", err
	}
	return issued, []byte(authority.CertificatePEM), authority.ID, nil
}

func (h *caHierarchyService) StartCeremony(ctx context.Context, tenantID string, req api.CACeremonyStartRequest) (api.CAKeyCeremony, error) {
	if err := h.ceremonyThresholdFloor(req.Threshold); err != nil {
		return api.CAKeyCeremony{}, err
	}
	purpose, _, err := h.ceremonyPurposeAndSpec(ctx, tenantID, req)
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if req.Operation == "import_offline_cross_sign" || req.Operation == "rekey_offline_root" {
		authority, err := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.AuthorityID))
		if err != nil {
			return api.CAKeyCeremony{}, err
		}
		if err := validateOfflineCeremonyPackage(authority, req); err != nil {
			return api.CAKeyCeremony{}, err
		}
	}
	opener := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		opener = a.Subject
	}
	id := uuid.NewString()
	ev, err := h.appendEvent(ctx, tenantID, projections.EventCACeremonyStarted, projections.CACeremonyStarted{
		CeremonyID: id,
		Purpose:    purpose,
		Threshold:  req.Threshold,
		Opener:     opener,
	})
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		return api.CAKeyCeremony{}, err
	}
	return h.GetCeremony(ctx, tenantID, id)
}

func (h *caHierarchyService) GetCeremony(ctx context.Context, tenantID, id string) (api.CAKeyCeremony, error) {
	c, err := h.store.GetKeyCeremony(ctx, tenantID, id)
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if c.Status == "pending" {
		status, err := h.store.CACeremonyCancelCommandStatus(ctx, tenantID, id)
		if err != nil {
			return api.CAKeyCeremony{}, err
		}
		if status != "" {
			c.Status = "cancellation_pending"
		}
	}
	return h.enrichManagedLeafReleaseCeremony(ctx, tenantID, ceremonyResponse(c), c.Purpose)
}

func (h *caHierarchyService) ApproveCeremony(ctx context.Context, tenantID, id string) (api.CAKeyCeremony, error) {
	custodian := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		custodian = a.Subject
	}
	if custodian == "" {
		return api.CAKeyCeremony{}, store.ErrAnonymousApproval
	}
	err := h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Hold the same ceremony row lock as the cancellation claim through the
		// append. A late approval cannot slip between the fence check and source.
		if err := h.store.LockPendingKeyCeremonyTx(ctx, tx, tenantID, id); err != nil {
			return err
		}
		var opener string
		var approvals int
		var evidenced bool
		if err := tx.QueryRow(ctx, `SELECT opener, (SELECT count(*) FROM ca_ceremony_approvals a
			WHERE a.tenant_id=c.tenant_id AND a.ceremony_id=c.id AND a.approval_event_id IS NOT NULL)
			FROM ca_key_ceremonies c WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&opener, &approvals); err != nil {
			return err
		}
		if opener != "" && opener == custodian {
			return store.ErrSelfApproval
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ca_ceremony_approvals
			WHERE tenant_id=$1 AND ceremony_id=$2 AND custodian=$3 AND approval_event_id IS NOT NULL)`,
			tenantID, id, custodian).Scan(&evidenced); err != nil {
			return err
		}
		if evidenced {
			return nil
		}
		ev, err := h.appendEvent(ctx, tenantID, projections.EventCACeremonyApproved, projections.CACeremonyApproved{
			CeremonyID: id, Custodian: custodian, Approvals: approvals + 1,
		})
		if err != nil {
			return err
		}
		return projections.New(h.store).ApplyTx(ctx, tx, ev)
	})
	if err != nil {
		return api.CAKeyCeremony{}, caHierarchyConflict(err)
	}
	return h.GetCeremony(ctx, tenantID, id)
}

func (h *caHierarchyService) ListAuthorities(ctx context.Context, tenantID string) ([]api.CAAuthority, error) {
	rows, err := h.store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.CAAuthority, 0, len(rows))
	for _, row := range rows {
		out = append(out, authorityResponse(row))
	}
	return out, nil
}

func (h *caHierarchyService) CreateRoot(ctx context.Context, tenantID string, req api.CACreateRootRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	if err := validateSignerBackedCASpec(req.Spec); err != nil {
		return api.CAAuthority{}, err
	}
	purpose, err := hierarchyPurpose("create_root", "", req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	if err := h.claimCeremonyCASigner(ctx, tenantID, req.CeremonyID, purpose, handle); err != nil {
		return api.CAAuthority{}, err
	}
	authorityID := uuid.NewString()
	var created store.CAAuthority
	var signer *signing.RemoteSigner
	var signerCreated bool
	var appended events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		var err error
		keyAlgorithm, err := crypto.SignerBackedCAKeyAlgorithm(req.Spec.SignatureAlgorithm)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		signer, signerCreated, err = h.createOrBindSigner(ctx, handle, keyAlgorithm)
		if err != nil {
			return err
		}
		issued, err := crypto.SelfSignedHierarchyCA(signer, cryptoProfile(req.Spec))
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		notAfter := issued.NotAfter
		created = store.CAAuthority{
			ID: authorityID, TenantID: tenantID, CommonName: req.Spec.CommonName, Kind: "root", Status: "active",
			CertificatePEM: string(issued.CertificatePEM), SignerHandle: handle, Serial: issued.Serial,
			NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendAuthorityCreatedEventTx(ctx, tx, tenantID, projections.EventCARootCreated, created, req.CeremonyID, false, "", api.CAPossessionSelfSignature)
		appended = ev
		if err != nil {
			return err
		}
		created.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if signerCreated && appended.ID == "" && signer != nil {
			_ = signer.Destroy(ctx)
		}
		if appended.ID == "" {
			return api.CAAuthority{}, caHierarchyConflict(err)
		}
		created, err = h.reconcileAppendedAuthority(ctx, tenantID, req.CeremonyID, created, appended, err)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	h.rememberSigner(created.ID, signer)
	return withPossession(authorityResponse(created), api.CAPossessionSelfSignature), nil
}

func (h *caHierarchyService) ImportOfflineRoot(ctx context.Context, tenantID string, req api.CAImportOfflineRootRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	rootDER, rootPEM, err := singleCertificatePEM(req.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	issued, err := crypto.VerifyImportedOfflineRoot(rootDER, cryptoProfile(req.Spec))
	if err != nil {
		return api.CAAuthority{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	possession, err := offlineRootPossession(rootDER, req)
	if err != nil {
		return api.CAAuthority{}, err
	}
	purpose, err := offlineRootPurpose(rootDER, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	authorityID := uuid.NewString()
	var created store.CAAuthority
	var appended events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		notAfter := issued.NotAfter
		created = store.CAAuthority{
			ID: authorityID, TenantID: tenantID, CommonName: issued.CommonName, Kind: "root", Status: "active",
			CertificatePEM: rootPEM, Serial: issued.Serial, NotAfter: &notAfter,
			MaxPathLen: issued.MaxPathLen, PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendAuthorityCreatedEventTx(ctx, tx, tenantID, projections.EventCARootCreated, created, req.CeremonyID, true, "", possession)
		appended = ev
		if err != nil {
			return err
		}
		created.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if appended.ID == "" {
			return api.CAAuthority{}, caHierarchyConflict(err)
		}
		created, err = h.reconcileAppendedAuthority(ctx, tenantID, req.CeremonyID, created, appended, err)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	return withPossession(authorityResponse(created), possession), nil
}

func (h *caHierarchyService) ImportExisting(ctx context.Context, tenantID string, req api.CAImportExistingRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" || req.SignerHandle == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id and signer_handle are required", api.ErrCAHierarchyInvalid)
	}
	chainDER, chainPEM, err := certificateChainPEM(req.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	ceremony, err := h.store.GetKeyCeremony(ctx, tenantID, req.CeremonyID)
	if err != nil {
		return api.CAAuthority{}, err
	}
	preparedImport := strings.HasPrefix(ceremony.Purpose, "prepare-existing-ca:")
	importedKey := strings.HasPrefix(ceremony.Purpose, "import-ca-key:")
	if importedKey {
		// A128: the operator's key was imported under this ceremony's own handle.
		if req.SignerHandle != hierarchySignerHandle(req.CeremonyID) {
			return api.CAAuthority{}, fmt.Errorf("%w: an imported CA key is held under its ceremony's signer handle", api.ErrCAHierarchyInvalid)
		}
		purpose, err := importCAKeyPurpose(chainDER, req.Spec, req.ParentID)
		if err != nil {
			return api.CAAuthority{}, err
		}
		if ceremony.Purpose != purpose {
			return api.CAAuthority{}, fmt.Errorf("%w: CA chain differs from the approved chain, parent or profile", api.ErrCAHierarchyConflict)
		}
	}
	var preparation store.CASignerPreparation
	if preparedImport {
		if len(chainDER) < 2 || req.SignerHandle != hierarchySignerHandle(req.CeremonyID) {
			return api.CAAuthority{}, fmt.Errorf("%w: prepared import requires its signer handle and complete child-to-issuer chain", api.ErrCAHierarchyInvalid)
		}
		preparation, err = h.store.GetCASignerPreparation(ctx, tenantID, req.CeremonyID, req.SignerHandle)
		if err != nil {
			return api.CAAuthority{}, fmt.Errorf("%w: no completed signer preparation for this ceremony: %v", api.ErrCAHierarchyConflict, err)
		}
		if err := h.checkPreparedExistingCSREvent(ctx, preparation); err != nil {
			return api.CAAuthority{}, err
		}
		purpose, err := preparedExistingCAPurpose(chainDER[1:], req.Spec, req.ParentID)
		if err != nil {
			return api.CAAuthority{}, err
		}
		if ceremony.Purpose != purpose || preparation.Purpose != purpose ||
			preparation.ParentID != req.ParentID ||
			preparation.IssuerSHA256 != crypto.SHA256Hex(flattenDERChain(chainDER[1:])) {
			return api.CAAuthority{}, fmt.Errorf("%w: signed CA chain differs from the approved issuer, parent or profile", api.ErrCAHierarchyConflict)
		}
	}
	client := h.signer.Client()
	if client == nil {
		return api.CAAuthority{}, api.ErrCAHierarchyUnavailable
	}
	signer, err := client.SignerForDualControlHandle(ctx, req.SignerHandle, signing.PurposeCASign, h.signAuthz)
	if err != nil {
		return api.CAAuthority{}, err
	}
	// eMudhra, Part 4: the bound signer proves it holds the key the imported
	// certificate names before the chain is accepted.
	possession, err := signerPossession(signer)
	if err != nil {
		return api.CAAuthority{}, err
	}
	issued, kind, err := crypto.VerifyImportedCAChain(chainDER, signer.Public(), cryptoProfile(req.Spec))
	if err != nil {
		return api.CAAuthority{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	purpose := ceremony.Purpose
	if !preparedImport && !importedKey {
		purpose, err = existingCAPurpose(chainDER, req.SignerHandle, req.Spec, req.ParentID)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	if req.ParentID != "" {
		parent, err := h.store.GetCAAuthority(ctx, tenantID, req.ParentID)
		if err != nil {
			return api.CAAuthority{}, err
		}
		if err := validateImportedCAParent(parent, chainDER); err != nil {
			return api.CAAuthority{}, err
		}
	}
	if err := h.claimCeremonyCASigner(ctx, tenantID, req.CeremonyID, purpose, req.SignerHandle); err != nil {
		return api.CAAuthority{}, err
	}
	authorityID := uuid.NewString()
	if preparedImport {
		authorityID = crypto.UUIDv5OID([]byte("ca-existing-import:" + tenantID + ":" + req.CeremonyID))
	}
	var created store.CAAuthority
	var appended events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var parentID *string
		if req.ParentID != "" {
			parent, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, req.ParentID)
			if err != nil {
				return err
			}
			if err := validateImportedCAParent(parent, chainDER); err != nil {
				return err
			}
			parentID = &parent.ID
		}
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		notAfter := issued.NotAfter
		created = store.CAAuthority{
			ID: authorityID, TenantID: tenantID, ParentID: parentID, CommonName: issued.CommonName, Kind: kind, Status: "active",
			CertificatePEM: chainPEM, SignerHandle: req.SignerHandle, Serial: issued.Serial,
			NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendAuthorityCreatedEventTx(ctx, tx, tenantID, projections.EventCAAuthorityImported, created, req.CeremonyID, false, crypto.SHA256Hex([]byte(chainPEM)), possession)
		appended = ev
		if err != nil {
			return err
		}
		created.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if appended.ID == "" {
			return api.CAAuthority{}, caHierarchyConflict(err)
		}
		created, err = h.reconcileAppendedAuthority(ctx, tenantID, req.CeremonyID, created, appended, err)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	h.rememberSigner(created.ID, signer)
	return withPossession(authorityResponse(created), possession), nil
}

func (h *caHierarchyService) CreateIntermediate(ctx context.Context, tenantID string, req api.CACreateIntermediateRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" || req.ParentID == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id and parent_id are required", api.ErrCAHierarchyInvalid)
	}
	parent, err := h.store.GetCAAuthority(ctx, tenantID, req.ParentID)
	if err != nil {
		return api.CAAuthority{}, err
	}
	if err := validateOnlineCeremonyIssuer(parent); err != nil {
		return api.CAAuthority{}, err
	}
	parentDER, err := firstCertDER(parent.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	parentSigner, err := h.signerForAuthority(ctx, parent)
	if err != nil {
		return api.CAAuthority{}, err
	}
	if err := validateSignerBackedCASpec(req.Spec); err != nil {
		return api.CAAuthority{}, err
	}
	purpose, err := hierarchyPurpose("create_intermediate", req.ParentID, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	if err := h.claimCeremonyCASigner(ctx, tenantID, req.CeremonyID, purpose, handle); err != nil {
		return api.CAAuthority{}, err
	}
	authorityID := uuid.NewString()
	var created store.CAAuthority
	var childSigner *signing.RemoteSigner
	var signerCreated bool
	var appended events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		lockedParent, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, req.ParentID)
		if err != nil {
			return err
		}
		if err := validateOnlineCeremonyIssuer(lockedParent); err != nil {
			return err
		}
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		keyAlgorithm, err := crypto.SignerBackedCAKeyAlgorithm(req.Spec.SignatureAlgorithm)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		childSigner, signerCreated, err = h.createOrBindSigner(ctx, handle, keyAlgorithm)
		if err != nil {
			return err
		}
		// eMudhra, Part 4: the new key signs a fresh challenge that verifies
		// against the exact public key going into the certificate first.
		issued, err := crypto.SignIntermediateHierarchyCAForSigner(parentDER, parentSigner, childSigner, cryptoProfile(req.Spec))
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		chain := append([]byte{}, issued.CertificatePEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		pid := req.ParentID
		notAfter := issued.NotAfter
		created = store.CAAuthority{
			ID: authorityID, TenantID: tenantID, ParentID: &pid, CommonName: req.Spec.CommonName, Kind: "intermediate", Status: "active",
			CertificatePEM: string(chain), SignerHandle: handle, Serial: issued.Serial,
			NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendAuthorityCreatedEventTx(ctx, tx, tenantID, projections.EventCAIntermediateCreated, created, req.CeremonyID, false, "", api.CAPossessionSignerChallenge)
		appended = ev
		if err != nil {
			return err
		}
		created.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if signerCreated && appended.ID == "" && childSigner != nil {
			_ = childSigner.Destroy(ctx)
		}
		if appended.ID == "" {
			return api.CAAuthority{}, caHierarchyConflict(err)
		}
		created, err = h.reconcileAppendedAuthority(ctx, tenantID, req.CeremonyID, created, appended, err)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	h.rememberSigner(created.ID, childSigner)
	return withPossession(authorityResponse(created), api.CAPossessionSignerChallenge), nil
}

func (h *caHierarchyService) CreateOfflineIntermediateCSR(ctx context.Context, tenantID, caID string, req api.CACreateOfflineIntermediateCSRRequest) (api.CAIntermediateCSR, error) {
	if req.CeremonyID == "" {
		return api.CAIntermediateCSR{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	parent, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAIntermediateCSR{}, err
	}
	if parent.Kind != "root" || parent.SignerHandle != "" {
		return api.CAIntermediateCSR{}, fmt.Errorf("%w: parent must be an imported offline root", api.ErrCAHierarchyInvalid)
	}
	purpose, err := offlineIntermediatePurpose(caID, req.Spec)
	if err != nil {
		return api.CAIntermediateCSR{}, err
	}
	if err := h.requirePendingCeremonyQuorum(ctx, tenantID, req.CeremonyID, purpose); err != nil {
		return api.CAIntermediateCSR{}, caHierarchyConflict(err)
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	if err := h.store.ClaimCASignerHandle(ctx, tenantID, req.CeremonyID, handle); err != nil {
		return api.CAIntermediateCSR{}, caHierarchyConflict(err)
	}
	if _, pure := crypto.PureX509Algorithm(mustSignerBackedKeyAlgorithm(req.Spec)); pure {
		return api.CAIntermediateCSR{}, fmt.Errorf("%w: an offline-root-signed intermediate CSR uses a classical key; a post-quantum hierarchy starts from a signer-backed ML-DSA root", api.ErrCAHierarchyInvalid)
	}
	signer, signerCreated, err := h.createOrBindSigner(ctx, handle, crypto.ECDSAP256)
	if err != nil {
		return api.CAIntermediateCSR{}, err
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: req.Spec.CommonName}, signer)
	if err != nil {
		if signerCreated {
			_ = signer.Destroy(ctx)
		}
		return api.CAIntermediateCSR{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err := h.emit(ctx, tenantID, projections.EventCAIntermediateCSRIssued, map[string]any{
		"ca_id": caID, "ceremony_id": req.CeremonyID, "signer_handle": handle, "csr_sha256": crypto.SHA256Hex(csrDER), "offline_root": true,
	}); err != nil {
		if signerCreated {
			_ = signer.Destroy(ctx)
		}
		return api.CAIntermediateCSR{}, err
	}
	return api.CAIntermediateCSR{CeremonyID: req.CeremonyID, ParentID: caID, CSRPem: csrPEM, SignerHandle: handle}, nil
}

func (h *caHierarchyService) ImportOfflineIntermediate(ctx context.Context, tenantID, caID string, req api.CAImportOfflineIntermediateRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	parent, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAAuthority{}, err
	}
	if parent.Kind != "root" || parent.SignerHandle != "" {
		return api.CAAuthority{}, fmt.Errorf("%w: parent must be an imported offline root", api.ErrCAHierarchyInvalid)
	}
	parentDER, err := firstCertDER(parent.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	childDER, childPEM, err := singleCertificatePEM(req.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	purpose, err := offlineIntermediatePurpose(caID, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	client := h.signer.Client()
	if client == nil {
		return api.CAAuthority{}, api.ErrCAHierarchyUnavailable
	}
	childSigner, err := client.SignerForDualControlHandle(ctx, handle, signing.PurposeCASign, h.signAuthz)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return api.CAAuthority{}, fmt.Errorf("%w: offline intermediate CSR has not been generated", api.ErrCAHierarchyConflict)
		}
		return api.CAAuthority{}, err
	}
	// eMudhra, Part 4: the served signer proves it holds the key the
	// offline-signed certificate names.
	possession, err := signerPossession(childSigner)
	if err != nil {
		return api.CAAuthority{}, err
	}
	issued, err := crypto.VerifyOfflineSignedIntermediate(parentDER, childDER, childSigner.Public(), cryptoProfile(req.Spec))
	if err != nil {
		return api.CAAuthority{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	authorityID := uuid.NewString()
	var created store.CAAuthority
	var appended events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		chain := append([]byte{}, childPEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		pid := caID
		notAfter := issued.NotAfter
		created = store.CAAuthority{
			ID: authorityID, TenantID: tenantID, ParentID: &pid, CommonName: issued.CommonName, Kind: "intermediate", Status: "active",
			CertificatePEM: string(chain), SignerHandle: handle, Serial: issued.Serial,
			NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendAuthorityCreatedEventTx(ctx, tx, tenantID, projections.EventCAIntermediateCreated, created, req.CeremonyID, true, "", possession)
		appended = ev
		if err != nil {
			return err
		}
		created.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if appended.ID == "" {
			return api.CAAuthority{}, caHierarchyConflict(err)
		}
		created, err = h.reconcileAppendedAuthority(ctx, tenantID, req.CeremonyID, created, appended, err)
		if err != nil {
			return api.CAAuthority{}, err
		}
	}
	h.rememberSigner(created.ID, childSigner)
	return withPossession(authorityResponse(created), possession), nil
}

func (h *caHierarchyService) IssueIntermediateCSR(ctx context.Context, tenantID, caID string, req api.CAIssueIntermediateRequest) (api.CAIssuedIntermediate, error) {
	if req.CeremonyID == "" {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	if len(req.CSRDER) == 0 {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: CSR is required", api.ErrCAHierarchyInvalid)
	}
	if req.Spec.TTLSeconds <= 0 {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: spec.ttl_seconds must be positive", api.ErrCAHierarchyInvalid)
	}
	if err := validateCASpec(req.Spec); err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	ca, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	signer, err := h.signerForAuthority(ctx, ca)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	caDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	profile := cryptoProfile(req.Spec)
	if len(profile.PermittedDNSDomains) == 0 {
		profile.PermittedDNSDomains = append([]string(nil), ca.PermittedDNSNames...)
	}
	purpose, err := externalIntermediateCSRPurpose(caID, req.CSRDER, req.Spec)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	var issued crypto.IssuedHierarchyCA
	var info certinfo.Info
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		if err := h.emit(ctx, tenantID, projections.EventCAIntermediateCSRSignRequested, map[string]any{
			"ca_id": caID, "ceremony_id": req.CeremonyID, "csr_sha256": crypto.SHA256Hex(req.CSRDER),
		}); err != nil {
			return err
		}
		var err error
		issued, err = crypto.SignIntermediateHierarchyCAFromCSR(caDER, signer, req.CSRDER, profile)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		info, err = certinfo.Inspect(issued.CertificateDER)
		if err != nil {
			return err
		}
		return h.emit(ctx, tenantID, projections.EventCAIntermediateCSRIssued, map[string]any{
			"ca_id": caID, "serial": info.SerialNumber, "subject": info.Subject, "ceremony_id": req.CeremonyID,
			"csr_sha256": crypto.SHA256Hex(req.CSRDER),
		})
	})
	if err != nil {
		return api.CAIssuedIntermediate{}, caHierarchyConflict(err)
	}
	out := append([]byte{}, issued.CertificatePEM...)
	out = append(out, []byte(ca.CertificatePEM)...)
	return api.CAIssuedIntermediate{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
}

func (h *caHierarchyService) IssueLeaf(ctx context.Context, tenantID, caID string, req api.CAIssueLeafRequest) (api.CAIssuedLeaf, error) {
	if len(req.CSRDER) == 0 {
		return api.CAIssuedLeaf{}, fmt.Errorf("%w: CSR is required", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds <= 0 {
		return api.CAIssuedLeaf{}, fmt.Errorf("%w: ttl_seconds must be positive", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds > math.MaxInt64/int64(time.Second) {
		return api.CAIssuedLeaf{}, fmt.Errorf("%w: ttl_seconds exceeds the supported duration range", api.ErrCAHierarchyInvalid)
	}
	requestedCA, ca, err := h.issuingAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	signer, err := h.signerForAuthority(ctx, ca)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	caDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	profile, err := h.leafProfileForAuthority(tenantID, ca, h.leafProfile)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	// The TTL clamp happens inside the signer, which already parses the issuer
	// certificate — one parse per issuance (E2/V34). An expired issuer surfaces
	// as a profile violation and keeps the invalid-hierarchy error surface.
	profile.ClampTTLToIssuer = true
	// A pure ML-DSA subject (RFC 9881) takes the prepared post-quantum signer;
	// a classical subject keeps the direct path. Either way the CA signer is
	// the authority's own, so an ML-DSA authority issues either kind.
	issuedLeaf, err := signSubjectLifecycleLeaf(ctx, caDER, signer, req.CSRDER, time.Duration(req.TTLSeconds)*time.Second, profile,
		h.parseSubjectCSR, h.inspectHybridSubjectCSR, h.preparedSubjectLeafSigner)
	if err != nil {
		if crypto.IsLeafProfileViolation(err) {
			return api.CAIssuedLeaf{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return api.CAIssuedLeaf{}, err
	}
	leafDER := issuedLeaf.DER
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, []byte(ca.CertificatePEM)...)
	event := managedCALeafEvent(ca.ID, leafDER, info)
	if requestedCA.ID != ca.ID {
		event.RequestedCAID = requestedCA.ID
		event.RotationRouted = true
	}
	ev, err := h.appendVersionedEvent(ctx, tenantID, projections.EventCAEndEntityIssued, projections.CAEndEntityInventorySchemaVersion, event)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		return api.CAIssuedLeaf{}, err
	}
	return api.CAIssuedLeaf{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
}

func managedCALeafEvent(caID string, der []byte, info certinfo.Info) projections.CAEndEntityInventoried {
	return projections.CAEndEntityInventoried{
		ID: uuid.NewString(), CAID: caID, Subject: info.Subject, SANs: sansOf(info),
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		CertificateDER: der, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyOrigin: string(custody.OriginRequester),
	}
}

func (h *caHierarchyService) RotateAuthority(ctx context.Context, tenantID, caID string, req api.CAAuthorityRotationRequest) (api.CAAuthorityRotation, error) {
	successorID := strings.TrimSpace(req.SuccessorID)
	if caID == "" || successorID == "" {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: predecessor and successor_id are required", api.ErrCAHierarchyInvalid)
	}
	if caID == successorID {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: successor_id must be a different CA authority", api.ErrCAHierarchyInvalid)
	}
	var predecessor, successor store.CAAuthority
	err := h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		predecessor, err = h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		successor, err = h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, successorID)
		if err != nil {
			return err
		}
		if err := validateAuthorityRotation(predecessor, successor); err != nil {
			return err
		}
		ev, err := h.appendEvent(ctx, tenantID, projections.EventCAAuthorityRotated, projections.CAAuthorityRotated{
			PredecessorCAID: predecessor.ID,
			SuccessorCAID:   successor.ID,
			Reason:          strings.TrimSpace(req.Reason),
			IssuePath:       caAuthorityIssuePath(predecessor.ID),
			ActiveIssuePath: caAuthorityIssuePath(successor.ID),
		})
		if err != nil {
			return err
		}
		if err := projections.New(h.store).ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		predecessor.Status = "superseded"
		replacesID := predecessor.ID
		successor.ReplacesID = &replacesID
		return nil
	})
	if err != nil {
		return api.CAAuthorityRotation{}, caHierarchyConflict(err)
	}
	return authorityRotationResponse(predecessor, successor), nil
}

func (h *caHierarchyService) PreviewRotation(ctx context.Context, tenantID, caID string, req api.CAAuthorityRotationRequest) (api.CAAuthorityRotationPlanPreview, error) {
	successorID := strings.TrimSpace(req.SuccessorID)
	if caID == "" || successorID == "" {
		return api.CAAuthorityRotationPlanPreview{}, fmt.Errorf("%w: predecessor and successor_id are required", api.ErrCAHierarchyInvalid)
	}
	if caID == successorID {
		return api.CAAuthorityRotationPlanPreview{}, fmt.Errorf("%w: successor_id must be a different CA authority", api.ErrCAHierarchyInvalid)
	}
	predecessor, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAAuthorityRotationPlanPreview{}, err
	}
	successor, err := h.store.GetCAAuthority(ctx, tenantID, successorID)
	if err != nil {
		return api.CAAuthorityRotationPlanPreview{}, err
	}
	if err := validateAuthorityRotation(predecessor, successor); err != nil {
		return api.CAAuthorityRotationPlanPreview{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	fingerprintPayload, err := json.Marshal(struct {
		PredecessorID string `json:"predecessor_id"`
		SuccessorID   string `json:"successor_id"`
		Reason        string `json:"reason"`
	}{PredecessorID: predecessor.ID, SuccessorID: successor.ID, Reason: reason})
	if err != nil {
		return api.CAAuthorityRotationPlanPreview{}, err
	}
	return api.CAAuthorityRotationPlanPreview{
		Capability:         "F48",
		Operation:          "rotate_ca",
		Ready:              true,
		RequestFingerprint: crypto.SHA256Hex(fingerprintPayload),
		RequiredPermission: "issuers:write",
		Reason:             reason,
		Predecessor:        *caCeremonyPlanAuthority(predecessor),
		Successor:          *caCeremonyPlanAuthority(successor),
		Changes: []string{
			"Route the predecessor's stable issue URL to the reviewed successor CA.",
			"Mark the predecessor superseded while retaining both authorities for the overlap period.",
		},
		Risks: []string{
			"New issuance will use the successor immediately after confirmation.",
			"Clients that do not trust the successor chain can fail until their trust stores are updated.",
		},
		VerificationSteps: []string{
			"Issue a test certificate through the predecessor's stable URL and verify the successor signed it.",
			"Confirm both predecessor and successor chains remain trusted during the overlap window.",
			"Review the immutable ca.authority.rotated event and active issue path.",
		},
		PreviewWrites:          []string{},
		PreviewExternalEffects: []string{},
	}, nil
}

func (h *caHierarchyService) CrossSignAuthority(ctx context.Context, tenantID, caID string, req api.CACrossSignRequest) (api.CACrossSign, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if caID == "" || ceremonyID == "" {
		return api.CACrossSign{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	targetDER, _, err := singleCertificatePEM(req.CertificatePEM)
	if err != nil {
		return api.CACrossSign{}, err
	}
	authority, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CACrossSign{}, err
	}
	if authority.Status != "active" || authority.SignerHandle == "" {
		return api.CACrossSign{}, fmt.Errorf("%w: cross-sign issuer must be an active signer-backed authority", api.ErrCAHierarchyInvalid)
	}
	issuerDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return api.CACrossSign{}, err
	}
	signer, err := h.signerForAuthority(ctx, authority)
	if err != nil {
		return api.CACrossSign{}, err
	}
	purpose := libhierarchy.PurposeCrossSign(caID, targetDER)
	var crossDER []byte
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		lockedAuthority, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		if err := validateOnlineCeremonyIssuer(lockedAuthority); err != nil {
			return err
		}
		if _, _, err := h.store.ValidateKeyCeremonyWithApprovalEvidenceTx(ctx, tx, tenantID, ceremonyID, purpose); err != nil {
			return err
		}
		issued, err := crypto.CrossSignHierarchyCA(issuerDER, signer, targetDER)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		crossDER = issued.CertificateDER
		payload := caCrossSignedEvent{
			CAID: caID, CeremonyID: ceremonyID, TargetCertificateDER: targetDER,
			CrossCertificateDER: crossDER, TargetSHA256: crypto.SHA256Hex(targetDER),
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		event, err := h.log.Append(ctx, events.Event{ID: "ca-cross-sign-" + ceremonyID, Type: projections.EventCACrossSigned, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		var canonical caCrossSignedEvent
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.CAID != caID || canonical.CeremonyID != ceremonyID || canonical.OfflineRoot ||
			canonical.TargetSHA256 != crypto.SHA256Hex(targetDER) || !bytes.Equal(canonical.TargetCertificateDER, targetDER) {
			return fmt.Errorf("%w: canonical CA cross-sign event does not match request", api.ErrCAHierarchyConflict)
		}
		if err := crypto.VerifyCrossSignedCA(issuerDER, targetDER, canonical.CrossCertificateDER); err != nil {
			return fmt.Errorf("%w: canonical CA cross-sign event: %v", api.ErrCAHierarchyInvalid, err)
		}
		crossDER = append([]byte(nil), canonical.CrossCertificateDER...)
		return projections.New(h.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		return api.CACrossSign{}, caHierarchyConflict(err)
	}
	return api.CACrossSign{
		IssuerAuthorityID: caID, TargetSHA256: crypto.SHA256Hex(targetDER),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER})),
		CeremonyID:     ceremonyID,
	}, nil
}

func (h *caHierarchyService) ImportOfflineRootCrossSign(ctx context.Context, tenantID, caID string, req api.CAOfflineCrossSignImportRequest) (api.CACrossSign, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if caID == "" || ceremonyID == "" {
		return api.CACrossSign{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	targetDER, _, err := singleCertificatePEM(req.TargetCertificatePEM)
	if err != nil {
		return api.CACrossSign{}, err
	}
	crossDER, crossPEM, err := singleCertificatePEM(req.CrossCertificatePEM)
	if err != nil {
		return api.CACrossSign{}, err
	}
	authority, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CACrossSign{}, err
	}
	issuerDER, err := verifyOfflineCrossSignPackage(authority, targetDER, crossDER)
	if err != nil {
		return api.CACrossSign{}, err
	}
	purpose := offlineCrossSignPurpose(caID, targetDER, crossDER)
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, _, err := h.store.ValidateKeyCeremonyWithApprovalEvidenceTx(ctx, tx, tenantID, ceremonyID, purpose); err != nil {
			return err
		}
		raw, err := json.Marshal(caCrossSignedEvent{
			CAID: caID, CeremonyID: ceremonyID, OfflineRoot: true,
			TargetCertificateDER: targetDER, CrossCertificateDER: crossDER,
			TargetSHA256: crypto.SHA256Hex(targetDER),
		})
		if err != nil {
			return err
		}
		event, err := h.log.Append(ctx, events.Event{ID: "ca-offline-cross-sign-" + ceremonyID, Type: projections.EventCACrossSigned, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		var canonical caCrossSignedEvent
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.CAID != caID || canonical.CeremonyID != ceremonyID || !canonical.OfflineRoot ||
			canonical.TargetSHA256 != crypto.SHA256Hex(targetDER) || !bytes.Equal(canonical.TargetCertificateDER, targetDER) ||
			!bytes.Equal(canonical.CrossCertificateDER, crossDER) {
			return fmt.Errorf("%w: canonical offline-root cross-sign event does not match request", api.ErrCAHierarchyConflict)
		}
		if err := crypto.VerifyCrossSignedCA(issuerDER, targetDER, canonical.CrossCertificateDER); err != nil {
			return fmt.Errorf("%w: canonical offline-root cross-sign event: %v", api.ErrCAHierarchyInvalid, err)
		}
		crossDER = append([]byte(nil), canonical.CrossCertificateDER...)
		crossPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER}))
		return projections.New(h.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		return api.CACrossSign{}, caHierarchyConflict(err)
	}
	return api.CACrossSign{IssuerAuthorityID: caID, TargetSHA256: crypto.SHA256Hex(targetDER), CertificatePEM: crossPEM, CeremonyID: ceremonyID, Imported: true}, nil
}

func (h *caHierarchyService) RekeyOfflineRoot(ctx context.Context, tenantID, caID string, req api.CAOfflineRootRekeyRequest) (api.CAOfflineRootRekey, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if caID == "" || ceremonyID == "" {
		return api.CAOfflineRootRekey{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	successorDER, successorPEM, err := singleCertificatePEM(req.SuccessorCertificatePEM)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	newByPreviousDER, newByPreviousPEM, err := singleCertificatePEM(req.NewSignedByPreviousPEM)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	previousByNewDER, previousByNewPEM, err := singleCertificatePEM(req.PreviousSignedByNewPEM)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	verifiedSuccessor, err := crypto.VerifyImportedOfflineRoot(successorDER, cryptoProfile(req.Spec))
	if err != nil {
		return api.CAOfflineRootRekey{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	purpose, err := offlineRootRekeyPurpose(caID, successorDER, newByPreviousDER, previousByNewDER, strings.TrimSpace(req.Reason), req.Spec)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	successorID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+":"+ceremonyID+":offline-root-rekey")).String()
	var predecessor, successor store.CAAuthority
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		predecessor, err = h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		if err := verifyOfflineRootRekeyPackage(predecessor, successorDER, newByPreviousDER, previousByNewDER); err != nil {
			return err
		}
		if _, _, err := h.store.ValidateKeyCeremonyWithApprovalEvidenceTx(ctx, tx, tenantID, ceremonyID, purpose); err != nil {
			return err
		}
		notAfter := verifiedSuccessor.NotAfter
		payload := projections.CAAuthorityRekeyed{
			ID: successorID, PredecessorCAID: predecessor.ID, CommonName: verifiedSuccessor.CommonName,
			Kind: "root", CertificatePEM: successorPEM, Serial: verifiedSuccessor.Serial, NotAfter: notAfter,
			MaxPathLen: verifiedSuccessor.MaxPathLen, PermittedDNSNames: verifiedSuccessor.PermittedDNSDomains, EKUs: verifiedSuccessor.EKUs,
			CeremonyID: ceremonyID, Reason: strings.TrimSpace(req.Reason), OfflineRoot: true,
			NewSignedByPreviousDER: newByPreviousDER, PreviousSignedByNewDER: previousByNewDER,
			IssuePath: caAuthorityIssuePath(predecessor.ID), ActiveIssuePath: caAuthorityIssuePath(successorID),
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		event, err := h.log.Append(ctx, events.Event{ID: "ca-offline-root-rekey-" + ceremonyID, Type: projections.EventCAAuthorityRekeyed, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		var canonical projections.CAAuthorityRekeyed
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.ID != successorID || canonical.PredecessorCAID != predecessor.ID || canonical.CeremonyID != ceremonyID ||
			!canonical.OfflineRoot || canonical.SignerHandle != "" || canonical.CertificatePEM != successorPEM ||
			!bytes.Equal(canonical.NewSignedByPreviousDER, newByPreviousDER) || !bytes.Equal(canonical.PreviousSignedByNewDER, previousByNewDER) {
			return fmt.Errorf("%w: canonical offline-root re-key event does not match request", api.ErrCAHierarchyConflict)
		}
		if err := projections.New(h.store).ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		predecessor.Status = "superseded"
		replacesID := predecessor.ID
		successor = store.CAAuthority{
			ID: canonical.ID, TenantID: tenantID, CommonName: canonical.CommonName, Kind: "root", Status: "active",
			CertificatePEM: canonical.CertificatePEM, Serial: canonical.Serial, NotAfter: &canonical.NotAfter,
			MaxPathLen: canonical.MaxPathLen, PermittedDNSNames: canonical.PermittedDNSNames, EKUs: canonical.EKUs,
			ReplacesID: &replacesID, CreatedAt: event.Time,
		}
		return nil
	})
	if err != nil {
		return api.CAOfflineRootRekey{}, caHierarchyConflict(err)
	}
	return api.CAOfflineRootRekey{
		Rotation:               authorityRotationResponse(predecessor, successor),
		NewSignedByPreviousPEM: newByPreviousPEM, PreviousSignedByNewPEM: previousByNewPEM,
		CeremonyID: ceremonyID,
	}, nil
}

func (h *caHierarchyService) issuingAuthority(ctx context.Context, tenantID, caID string) (store.CAAuthority, store.CAAuthority, error) {
	ca, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return store.CAAuthority{}, store.CAAuthority{}, err
	}
	switch ca.Status {
	case "active":
		return ca, ca, nil
	case "superseded":
		successor, err := h.store.FindActiveCAAuthoritySuccessor(ctx, tenantID, ca.ID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return store.CAAuthority{}, store.CAAuthority{}, fmt.Errorf("%w: superseded CA %s has no active successor", api.ErrCAHierarchyConflict, ca.ID)
			}
			return store.CAAuthority{}, store.CAAuthority{}, err
		}
		return ca, successor, nil
	case "revoked":
		return store.CAAuthority{}, store.CAAuthority{}, fmt.Errorf("%w: revoked CA %s cannot issue", api.ErrCAHierarchyConflict, ca.ID)
	default:
		return store.CAAuthority{}, store.CAAuthority{}, fmt.Errorf("%w: CA %s status %q cannot issue", api.ErrCAHierarchyConflict, ca.ID, ca.Status)
	}
}

func validateAuthorityRotation(predecessor, successor store.CAAuthority) error {
	if predecessor.Status != "active" {
		return fmt.Errorf("%w: predecessor CA must be active", api.ErrCAHierarchyConflict)
	}
	if successor.Status != "active" {
		return fmt.Errorf("%w: successor CA must be active", api.ErrCAHierarchyConflict)
	}
	if predecessor.SignerHandle == "" || successor.SignerHandle == "" {
		return fmt.Errorf("%w: predecessor and successor must both be signer-backed issuing authorities", api.ErrCAHierarchyInvalid)
	}
	if predecessor.Kind != successor.Kind {
		return fmt.Errorf("%w: successor kind must match predecessor kind", api.ErrCAHierarchyInvalid)
	}
	if !sameStringPtr(predecessor.ParentID, successor.ParentID) {
		return fmt.Errorf("%w: successor must share the predecessor parent authority", api.ErrCAHierarchyInvalid)
	}
	if successor.ReplacesID != nil && *successor.ReplacesID != predecessor.ID {
		return fmt.Errorf("%w: successor already replaces a different CA", api.ErrCAHierarchyConflict)
	}
	if predecessor.MaxPathLen != successor.MaxPathLen {
		return fmt.Errorf("%w: successor max_path_len must match predecessor", api.ErrCAHierarchyInvalid)
	}
	if !sameStringSet(predecessor.PermittedDNSNames, successor.PermittedDNSNames) {
		return fmt.Errorf("%w: successor DNS constraints must match predecessor", api.ErrCAHierarchyInvalid)
	}
	if !sameStringSet(predecessor.EKUs, successor.EKUs) {
		return fmt.Errorf("%w: successor EKUs must match predecessor", api.ErrCAHierarchyInvalid)
	}
	return nil
}

func validateAuthorityRekey(ca store.CAAuthority) error {
	if ca.Status != "active" {
		return fmt.Errorf("%w: CA authority must be active to re-key", api.ErrCAHierarchyConflict)
	}
	if ca.SignerHandle == "" {
		return fmt.Errorf("%w: CA authority must be signer-backed to re-key", api.ErrCAHierarchyInvalid)
	}
	switch ca.Kind {
	case "root", "intermediate":
		return nil
	default:
		return fmt.Errorf("%w: unsupported CA kind %q", api.ErrCAHierarchyInvalid, ca.Kind)
	}
}

func sameStringPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, value := range a {
		seen[strings.ToLower(strings.TrimSpace(value))]++
	}
	for _, value := range b {
		key := strings.ToLower(strings.TrimSpace(value))
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func hierarchyPurpose(operation, parentID string, spec api.CASpec) (string, error) {
	if err := validateCASpec(spec); err != nil {
		return "", err
	}
	hs := libhierarchy.CASpec{
		CommonName: spec.CommonName, PermittedDNSDomains: spec.PermittedDNSDomains,
		MaxPathLen: spec.MaxPathLen, EKUs: spec.ExtendedKeyUsages,
		TTL: time.Duration(spec.TTLSeconds) * time.Second,
	}
	switch operation {
	case "create_root", "create_intermediate":
		hs.KeyAlgorithm = signerBackedKeyAlgorithmLabel(spec)
	}
	switch operation {
	case "create_root":
		return libhierarchy.PurposeRoot(hs), nil
	case "create_intermediate":
		if parentID == "" {
			return "", fmt.Errorf("%w: parent_id is required for create_intermediate", api.ErrCAHierarchyInvalid)
		}
		return libhierarchy.PurposeIntermediate(parentID, hs), nil
	default:
		return "", fmt.Errorf("%w: unsupported ceremony operation %q", api.ErrCAHierarchyInvalid, operation)
	}
}

func hierarchyPurposeFromStartRequest(req api.CACeremonyStartRequest) (string, error) {
	if req.Operation == "create_root" || req.Operation == "create_intermediate" {
		if err := validateSignerBackedCASpec(req.Spec); err != nil {
			return "", err
		}
	}
	switch req.Operation {
	case "import_offline_root":
		certDER, _, err := singleCertificatePEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		if _, err := crypto.VerifyImportedOfflineRoot(certDER, cryptoProfile(req.Spec)); err != nil {
			return "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return offlineRootPurpose(certDER, req.Spec)
	case "import_existing_ca":
		chainDER, _, err := certificateChainPEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		return existingCAPurpose(chainDER, req.SignerHandle, req.Spec, req.ParentID)
	case "import_ca_key":
		if strings.TrimSpace(req.SignerHandle) != "" {
			return "", fmt.Errorf("%w: import_ca_key holds the key under its ceremony's own signer handle; do not supply one", api.ErrCAHierarchyInvalid)
		}
		chainDER, _, err := certificateChainPEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		return importCAKeyPurpose(chainDER, req.Spec, req.ParentID)
	case "prepare_existing_ca":
		if strings.TrimSpace(req.SignerHandle) != "" {
			return "", fmt.Errorf("%w: prepare_existing_ca generates its signer handle; do not supply one", api.ErrCAHierarchyInvalid)
		}
		issuerChainDER, _, err := certificateChainPEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		return preparedExistingCAPurpose(issuerChainDER, req.Spec, req.ParentID)
	case "create_offline_intermediate":
		return offlineIntermediatePurpose(req.ParentID, req.Spec)
	case "issue_intermediate_csr":
		csrDER, err := csrDERFromPEM(req.CSRPem)
		if err != nil {
			return "", err
		}
		return externalIntermediateCSRPurpose(req.ParentID, csrDER, req.Spec)
	case "rekey_ca":
		return "", fmt.Errorf("%w: rekey_ca requires authority-backed plan validation", api.ErrCAHierarchyInvalid)
	case "revoke_ca":
		return "", fmt.Errorf("%w: revoke_ca requires authority-backed plan validation", api.ErrCAHierarchyInvalid)
	case "cross_sign_ca":
		targetDER, _, err := singleCertificatePEM(req.TargetCertificatePEM)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(req.AuthorityID) == "" {
			return "", fmt.Errorf("%w: authority_id is required for cross_sign_ca", api.ErrCAHierarchyInvalid)
		}
		return libhierarchy.PurposeCrossSign(strings.TrimSpace(req.AuthorityID), targetDER), nil
	case "import_offline_cross_sign":
		if strings.TrimSpace(req.AuthorityID) == "" {
			return "", fmt.Errorf("%w: authority_id is required for import_offline_cross_sign", api.ErrCAHierarchyInvalid)
		}
		targetDER, _, err := singleCertificatePEM(req.TargetCertificatePEM)
		if err != nil {
			return "", err
		}
		crossDER, _, err := singleCertificatePEM(req.CrossCertificatePEM)
		if err != nil {
			return "", err
		}
		return offlineCrossSignPurpose(strings.TrimSpace(req.AuthorityID), targetDER, crossDER), nil
	case "rekey_offline_root":
		successorDER, _, err := singleCertificatePEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		newByPreviousDER, _, err := singleCertificatePEM(req.CrossCertificatePEM)
		if err != nil {
			return "", err
		}
		previousByNewDER, _, err := singleCertificatePEM(req.ReverseCrossCertificatePEM)
		if err != nil {
			return "", err
		}
		return offlineRootRekeyPurpose(strings.TrimSpace(req.AuthorityID), successorDER, newByPreviousDER, previousByNewDER, strings.TrimSpace(req.Reason), req.Spec)
	default:
		return hierarchyPurpose(req.Operation, req.ParentID, req.Spec)
	}
}

func offlineRootPurpose(certDER []byte, spec api.CASpec) (string, error) {
	if spec.TTLSeconds <= 0 {
		return "", fmt.Errorf("%w: positive ttl_seconds is required for an imported offline root", api.ErrCAHierarchyInvalid)
	}
	rootPurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	return "offline-root:" + crypto.SHA256Hex(certDER) + ":" + rootPurpose, nil
}

func offlineIntermediatePurpose(parentID string, spec api.CASpec) (string, error) {
	if parentID == "" {
		return "", fmt.Errorf("%w: parent_id is required for create_offline_intermediate", api.ErrCAHierarchyInvalid)
	}
	intermediatePurpose, err := hierarchyPurpose("create_intermediate", parentID, spec)
	if err != nil {
		return "", err
	}
	return "offline-" + intermediatePurpose, nil
}

func externalIntermediateCSRPurpose(parentID string, csrDER []byte, spec api.CASpec) (string, error) {
	if parentID == "" {
		return "", fmt.Errorf("%w: parent_id is required for issue_intermediate_csr", api.ErrCAHierarchyInvalid)
	}
	if len(csrDER) == 0 {
		return "", fmt.Errorf("%w: csr_pem is required for issue_intermediate_csr", api.ErrCAHierarchyInvalid)
	}
	specPurpose, err := hierarchyPurpose("create_intermediate", parentID, spec)
	if err != nil {
		return "", err
	}
	return "intermediate-csr:" + parentID + ":" + crypto.SHA256Hex(csrDER) + ":" + specPurpose, nil
}

func offlineCrossSignPurpose(authorityID string, targetDER, crossDER []byte) string {
	payload, err := json.Marshal(struct {
		AuthorityID  string `json:"authority_id"`
		TargetSHA256 string `json:"target_sha256"`
		CrossSHA256  string `json:"cross_sha256"`
	}{authorityID, crypto.SHA256Hex(targetDER), crypto.SHA256Hex(crossDER)})
	if err != nil {
		panic(fmt.Sprintf("server: canonical offline cross-sign purpose: %v", err))
	}
	return "offline-cross-sign:" + crypto.SHA256Hex(payload)
}

func offlineRootRekeyPurpose(authorityID string, successorDER, newByPreviousDER, previousByNewDER []byte, reason string, spec api.CASpec) (string, error) {
	if authorityID == "" {
		return "", fmt.Errorf("%w: authority_id is required for rekey_offline_root", api.ErrCAHierarchyInvalid)
	}
	profilePurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		AuthorityID         string `json:"authority_id"`
		SuccessorSHA256     string `json:"successor_sha256"`
		NewByPreviousSHA256 string `json:"new_by_previous_sha256"`
		PreviousByNewSHA256 string `json:"previous_by_new_sha256"`
		Reason              string `json:"reason"`
		ProfilePurpose      string `json:"profile_purpose"`
	}{authorityID, crypto.SHA256Hex(successorDER), crypto.SHA256Hex(newByPreviousDER), crypto.SHA256Hex(previousByNewDER), reason, profilePurpose})
	if err != nil {
		return "", err
	}
	return "offline-root-rekey:" + crypto.SHA256Hex(payload), nil
}

func flattenDERChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, der...)
	}
	return out
}

func validateCASpec(spec api.CASpec) error {
	if spec.CommonName == "" {
		return fmt.Errorf("%w: common_name is required", api.ErrCAHierarchyInvalid)
	}
	if spec.TTLSeconds < 0 {
		return fmt.Errorf("%w: ttl_seconds cannot be negative", api.ErrCAHierarchyInvalid)
	}
	if spec.TTLSeconds > math.MaxInt64/int64(time.Second) {
		return fmt.Errorf("%w: ttl_seconds exceeds the supported duration range", api.ErrCAHierarchyInvalid)
	}
	// A25: a reviewed label must be one the import path can verify. The served
	// signer path narrows this further (validateSignerBackedCASpec).
	if spec.SignatureAlgorithm != "" && !crypto.ImportedCASignatureAlgorithmSupported(spec.SignatureAlgorithm) {
		return fmt.Errorf("%w: signature_algorithm %q is not a supported CA key algorithm (ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, rsa-2048, rsa-3072, rsa-4096)", api.ErrCAHierarchyInvalid, spec.SignatureAlgorithm)
	}
	return nil
}

// validateSignerBackedCASpec binds a CA the served signer mints to the key
// algorithm that path produces. Imported (offline-held) CAs are not bound by it.
func validateSignerBackedCASpec(spec api.CASpec) error {
	if err := validateCASpec(spec); err != nil {
		return err
	}
	if _, err := crypto.SignerBackedCAKeyAlgorithm(spec.SignatureAlgorithm); err != nil {
		return fmt.Errorf("%w: only ecdsa-p256 or an ML-DSA parameter set (ml-dsa-44, ml-dsa-65, ml-dsa-87) CA keys are minted by the served signer path", api.ErrCAHierarchyInvalid)
	}
	return nil
}

// signerBackedKeyAlgorithmLabel is the reviewed label as the ceremony purpose
// binds it: empty for the classical default, so existing ceremony digests are
// unchanged; the lower-cased ML-DSA parameter set otherwise.
func signerBackedKeyAlgorithmLabel(spec api.CASpec) string {
	label := strings.ToLower(strings.TrimSpace(spec.SignatureAlgorithm))
	if label == "ecdsa-p256" {
		return ""
	}
	return label
}

func (h *caHierarchyService) requirePendingCeremonyQuorum(ctx context.Context, tenantID, ceremonyID, purpose string) error {
	c, err := h.store.GetKeyCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return err
	}
	if c.Status != "pending" {
		return store.ErrKeyCeremonyNotPending
	}
	if c.Purpose != purpose {
		return store.ErrKeyCeremonyPurposeMismatch
	}
	if c.Approvals < c.Threshold {
		return store.ErrKeyCeremonyQuorumNotMet
	}
	return nil
}

func cryptoProfile(spec api.CASpec) crypto.HierarchyCAProfile {
	algorithm := spec.SignatureAlgorithm
	if algorithm == "" {
		algorithm = "ecdsa-p256"
	}
	return crypto.HierarchyCAProfile{
		CommonName: spec.CommonName, PermittedDNSDomains: spec.PermittedDNSDomains,
		MaxPathLen: spec.MaxPathLen, EKUs: spec.ExtendedKeyUsages,
		TTL: time.Duration(spec.TTLSeconds) * time.Second, SignatureAlgorithm: algorithm,
	}
}

func hierarchySignerHandle(ceremonyID string) string {
	return hierarchySignerHandlePrefix + ceremonyID
}

func (h *caHierarchyService) createOrBindSigner(ctx context.Context, handle string, algorithm crypto.Algorithm) (*signing.RemoteSigner, bool, error) {
	client := h.signer.Client()
	if client == nil {
		return nil, false, api.ErrCAHierarchyUnavailable
	}
	if algorithm == "" {
		algorithm = crypto.ECDSAP256
	}
	signer, err := client.GenerateDualControlKeyHandle(ctx, algorithm, handle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.signAuthz)
	if err == nil {
		return signer, true, nil
	}
	if status.Code(err) == codes.AlreadyExists {
		signer, err := client.SignerForDualControlHandle(ctx, handle, signing.PurposeCASign, h.signAuthz)
		return signer, false, err
	}
	if status.Code(err) == codes.FailedPrecondition && status.Convert(err).Message() == signing.ErrDestroyedKeyHandle.Error() {
		return nil, false, fmt.Errorf("%w: this ceremony's signer handle was destroyed after an earlier failed key operation; cancel it and start a new ceremony with fresh custodian approvals", api.ErrCAHierarchyConflict)
	}
	return nil, false, err
}

func (h *caHierarchyService) signerForAuthority(ctx context.Context, ca store.CAAuthority) (*signing.RemoteSigner, error) {
	if ca.SignerHandle == "" {
		if ca.Kind == "root" {
			return nil, fmt.Errorf("%w: offline root %s has no signer handle; create and import a signer-held intermediate under it before issuing certificates", api.ErrCAHierarchyConflict, ca.ID)
		}
		return nil, fmt.Errorf("%w: authority %s has no signer handle; select or import a signer-backed authority", api.ErrCAHierarchyConflict, ca.ID)
	}
	h.mu.Lock()
	if signer := h.signers[ca.ID]; signer != nil {
		h.mu.Unlock()
		return signer, nil
	}
	h.mu.Unlock()
	client := h.signer.Client()
	if client == nil {
		return nil, api.ErrCAHierarchyUnavailable
	}
	signer, err := client.SignerForDualControlHandle(ctx, ca.SignerHandle, signing.PurposeCASign, h.signAuthz)
	if err != nil {
		return nil, err
	}
	h.rememberSigner(ca.ID, signer)
	return signer, nil
}

func (h *caHierarchyService) rememberSigner(caID string, signer *signing.RemoteSigner) {
	if caID == "" || signer == nil {
		return
	}
	h.mu.Lock()
	h.signers[caID] = signer
	h.mu.Unlock()
}

func firstCertDER(chainPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: CA certificate PEM is malformed", api.ErrCAHierarchyInvalid)
	}
	return block.Bytes, nil
}

func applyAuthorityLane(profile crypto.LeafProfile, ca store.CAAuthority) crypto.LeafProfile {
	if len(ca.PermittedDNSNames) > 0 {
		if len(profile.PermittedDNSSuffixes) == 0 {
			profile.PermittedDNSSuffixes = append([]string(nil), ca.PermittedDNSNames...)
		} else {
			profile.PermittedDNSSuffixes = intersectDNSSuffixes(profile.PermittedDNSSuffixes, ca.PermittedDNSNames)
		}
	}
	if len(profile.AllowedExtKeyUsage) == 0 && len(ca.EKUs) > 0 {
		profile.AllowedExtKeyUsage = append([]string(nil), ca.EKUs...)
	}
	return profile
}

// leafProfileForAuthority keeps revocation pointers bound to the CA that signs
// this exact leaf. The global ca.* pointers describe the built-in issuer and
// would send managed-CA relying parties to a different authority's responder.
func (h *caHierarchyService) leafProfileForAuthority(tenantID string, ca store.CAAuthority, profile crypto.LeafProfile) (crypto.LeafProfile, error) {
	profile = applyAuthorityLane(profile, ca)
	profile.CRLDistributionPoints = nil
	profile.OCSPServers = nil
	profile.IssuingCertificateURL = nil
	if h.revocationBaseURL == "" {
		if h.requireRevocationPointers {
			return crypto.LeafProfile{}, fmt.Errorf("%w: regulated managed CA issuance requires ca.hierarchy_revocation_base_url", api.ErrCAHierarchyInvalid)
		}
		return profile, nil
	}
	base := strings.TrimRight(h.revocationBaseURL, "/")
	profile.CRLDistributionPoints = []string{base + "/crl/" + tenantID + "/authorities/" + ca.ID}
	profile.OCSPServers = []string{base + "/ocsp/" + tenantID + "/authorities/" + ca.ID}
	return profile, nil
}

func intersectDNSSuffixes(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if dnsSuffixWithin(x, y) || dnsSuffixWithin(y, x) {
				if len(x) >= len(y) {
					out = append(out, x)
				} else {
					out = append(out, y)
				}
			}
		}
	}
	return out
}

func dnsSuffixWithin(name, suffix string) bool {
	name = strings.TrimPrefix(strings.ToLower(name), ".")
	suffix = strings.TrimPrefix(strings.ToLower(suffix), ".")
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

func authorityResponse(c store.CAAuthority) api.CAAuthority {
	out := api.CAAuthority{
		ID: c.ID, TenantID: c.TenantID, ParentID: c.ParentID, CommonName: c.CommonName,
		Kind: c.Kind, Status: c.Status, CertificatePEM: c.CertificatePEM, SignerHandle: c.SignerHandle,
		Serial: c.Serial, NotAfter: c.NotAfter, MaxPathLen: c.MaxPathLen,
		PermittedDNSNames: c.PermittedDNSNames, ExtendedKeyUsages: c.EKUs, ReplacesID: c.ReplacesID, CreatedAt: c.CreatedAt,
		RevokedAt: c.RevokedAt, RevocationReason: c.RevocationReason,
	}
	if der, err := firstCertDER(c.CertificatePEM); err == nil {
		out.KeyAlgorithm = crypto.CertificateKeyAlgorithmLabel(der)
	}
	return out
}

// mustSignerBackedKeyAlgorithm resolves a spec label already accepted by
// validateCASpec; an unmintable label falls back to the classical default.
func mustSignerBackedKeyAlgorithm(spec api.CASpec) crypto.Algorithm {
	alg, err := crypto.SignerBackedCAKeyAlgorithm(spec.SignatureAlgorithm)
	if err != nil {
		return crypto.ECDSAP256
	}
	return alg
}

func authorityRotationResponse(predecessor, successor store.CAAuthority) api.CAAuthorityRotation {
	return api.CAAuthorityRotation{
		Predecessor:     authorityResponse(predecessor),
		Successor:       authorityResponse(successor),
		IssuePath:       caAuthorityIssuePath(predecessor.ID),
		ActiveIssuePath: caAuthorityIssuePath(successor.ID),
		OverlapIssuers: []api.CAAuthorityRotationIssuer{
			{AuthorityID: predecessor.ID, Role: "predecessor", Status: predecessor.Status, IssuePath: caAuthorityIssuePath(predecessor.ID)},
			{AuthorityID: successor.ID, Role: "successor", Status: successor.Status, IssuePath: caAuthorityIssuePath(successor.ID)},
		},
	}
}

func caAuthorityIssuePath(id string) string {
	return "/api/v1/ca/authorities/" + url.PathEscape(id) + "/issue"
}

func ceremonyResponse(c store.KeyCeremony) api.CAKeyCeremony {
	return api.CAKeyCeremony{
		ID: c.ID, TenantID: c.TenantID, Purpose: c.Purpose, Threshold: c.Threshold,
		Status: c.Status, Approvals: c.Approvals, Opener: c.Opener, CreatedAt: c.CreatedAt,
		ClosedAt: c.ClosedAt, ClosedBy: c.ClosedBy, CloseReason: c.CloseReason,
	}
}

func caHierarchyConflict(err error) error {
	switch {
	case errors.Is(err, store.ErrKeyCeremonyQuorumNotMet),
		errors.Is(err, store.ErrIdempotencyConflict),
		errors.Is(err, store.ErrKeyCeremonyNotPending),
		errors.Is(err, store.ErrKeyCeremonyPurposeMismatch),
		errors.Is(err, store.ErrSelfApproval),
		errors.Is(err, store.ErrAnonymousApproval),
		errors.Is(err, store.ErrCASignerHandleClaimed):
		return fmt.Errorf("%w: %v", api.ErrCAHierarchyConflict, err)
	default:
		return err
	}
}

func (h *caHierarchyService) emit(ctx context.Context, tenantID, eventType string, data map[string]any) error {
	_, err := h.appendEvent(ctx, tenantID, eventType, data)
	return err
}

func (h *caHierarchyService) appendEvent(ctx context.Context, tenantID, eventType string, data any) (events.Event, error) {
	return h.appendVersionedEvent(ctx, tenantID, eventType, 0, data)
}

func (h *caHierarchyService) appendVersionedEvent(ctx context.Context, tenantID, eventType string, schemaVersion int, data any) (events.Event, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return events.Event{}, err
	}
	return h.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, SchemaVersion: schemaVersion, Data: payload})
}

// The leaf-TTL clamp (a caller-supplied TTL must not outlive the issuing CA)
// lives inside crypto.SignLeafFromCSRWithProfile as
// LeafProfile.ClampTTLToIssuer, which already parses the issuer certificate.
// The pre-flight helper that used to sit here ran a full certinfo.Inspect
// purely to read NotAfter, parsing the same DER twice per issuance (AUD-201
// follow-up E2/V34).
