package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

const hierarchySignerHandlePrefix = "ca-hierarchy-"

type caHierarchyService struct {
	store       *store.Store
	log         *events.Log
	signer      SignerProvider
	signAuthz   signing.SignTokenProvider
	leafProfile crypto.LeafProfile

	mu      sync.Mutex
	signers map[string]*signing.RemoteSigner
}

func (s *Server) buildCAHierarchyService(d Deps) api.CAHierarchyService {
	if d.Signer == nil || d.Signer.Client() == nil || s.signAuthz == nil {
		return nil
	}
	return &caHierarchyService{
		store: d.Store, log: d.Log, signer: d.Signer, signAuthz: s.signAuthz,
		leafProfile: d.LeafProfile, signers: map[string]*signing.RemoteSigner{},
	}
}

func (h *caHierarchyService) StartCeremony(ctx context.Context, tenantID string, req api.CACeremonyStartRequest) (api.CAKeyCeremony, error) {
	if req.Threshold < 1 {
		return api.CAKeyCeremony{}, fmt.Errorf("%w: threshold must be at least 1", api.ErrCAHierarchyInvalid)
	}
	purpose, err := hierarchyPurposeFromStartRequest(req)
	if err != nil {
		return api.CAKeyCeremony{}, err
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
	return ceremonyResponse(c), nil
}

func (h *caHierarchyService) ApproveCeremony(ctx context.Context, tenantID, id string) (api.CAKeyCeremony, error) {
	custodian := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		custodian = a.Subject
	}
	if custodian == "" {
		return api.CAKeyCeremony{}, store.ErrAnonymousApproval
	}
	current, err := h.store.GetKeyCeremony(ctx, tenantID, id)
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if current.Status != "pending" {
		return api.CAKeyCeremony{}, store.ErrKeyCeremonyNotPending
	}
	if current.Opener != "" && current.Opener == custodian {
		return api.CAKeyCeremony{}, store.ErrSelfApproval
	}
	evidenced, err := h.store.KeyCeremonyApprovalEvidenced(ctx, tenantID, id, custodian)
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if evidenced {
		return ceremonyResponse(current), nil
	}
	ev, err := h.appendEvent(ctx, tenantID, projections.EventCACeremonyApproved, projections.CACeremonyApproved{
		CeremonyID: id,
		Custodian:  custodian,
		Approvals:  current.Approvals + 1,
	})
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		return api.CAKeyCeremony{}, err
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
	purpose, err := hierarchyPurpose("create_root", "", req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	var created store.CAAuthority
	var signer *signing.RemoteSigner
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		var err error
		signer, err = h.createOrBindSigner(ctx, handle)
		if err != nil {
			return err
		}
		issued, err := crypto.SelfSignedHierarchyCA(signer, cryptoProfile(req.Spec))
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		inserted, err := h.store.InsertCAAuthorityTx(ctx, tx, store.CAAuthority{
			TenantID: tenantID, CommonName: req.Spec.CommonName, Kind: "root", Status: "active",
			CertificatePEM: string(issued.CertificatePEM), SignerHandle: handle, Serial: issued.Serial,
			NotAfter: &issued.NotAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		})
		if err != nil {
			return err
		}
		created = inserted
		return nil
	})
	if err != nil {
		return api.CAAuthority{}, caHierarchyConflict(err)
	}
	h.rememberSigner(created.ID, signer)
	if err := h.emit(ctx, tenantID, "ca.root.created", map[string]any{
		"ca_id": created.ID, "common_name": created.CommonName, "ceremony_id": req.CeremonyID, "signer_handle": handle,
	}); err != nil {
		return api.CAAuthority{}, err
	}
	return authorityResponse(created), nil
}

func (h *caHierarchyService) CreateIntermediate(ctx context.Context, tenantID string, req api.CACreateIntermediateRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" || req.ParentID == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id and parent_id are required", api.ErrCAHierarchyInvalid)
	}
	parent, err := h.store.GetCAAuthority(ctx, tenantID, req.ParentID)
	if err != nil {
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
	purpose, err := hierarchyPurpose("create_intermediate", req.ParentID, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	var created store.CAAuthority
	var childSigner *signing.RemoteSigner
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		var err error
		childSigner, err = h.createOrBindSigner(ctx, handle)
		if err != nil {
			return err
		}
		issued, err := crypto.SignIntermediateHierarchyCA(parentDER, parentSigner, childSigner.Public(), cryptoProfile(req.Spec))
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		chain := append([]byte{}, issued.CertificatePEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		pid := req.ParentID
		inserted, err := h.store.InsertCAAuthorityTx(ctx, tx, store.CAAuthority{
			TenantID: tenantID, ParentID: &pid, CommonName: req.Spec.CommonName, Kind: "intermediate", Status: "active",
			CertificatePEM: string(chain), SignerHandle: handle, Serial: issued.Serial,
			NotAfter: &issued.NotAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		})
		if err != nil {
			return err
		}
		created = inserted
		return nil
	})
	if err != nil {
		return api.CAAuthority{}, caHierarchyConflict(err)
	}
	h.rememberSigner(created.ID, childSigner)
	if err := h.emit(ctx, tenantID, "ca.intermediate.created", map[string]any{
		"ca_id": created.ID, "parent_id": req.ParentID, "ceremony_id": req.CeremonyID, "signer_handle": handle,
	}); err != nil {
		return api.CAAuthority{}, err
	}
	return authorityResponse(created), nil
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
		var err error
		issued, err = crypto.SignIntermediateHierarchyCAFromCSR(caDER, signer, req.CSRDER, profile)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		info, err = certinfo.Inspect(issued.CertificateDER)
		return err
	})
	if err != nil {
		return api.CAIssuedIntermediate{}, caHierarchyConflict(err)
	}
	out := append([]byte{}, issued.CertificatePEM...)
	out = append(out, []byte(ca.CertificatePEM)...)
	if err := h.emit(ctx, tenantID, "ca.intermediate_csr.issued", map[string]any{
		"ca_id": caID, "serial": info.SerialNumber, "subject": info.Subject, "ceremony_id": req.CeremonyID,
	}); err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	return api.CAIssuedIntermediate{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
}

func (h *caHierarchyService) IssueLeaf(ctx context.Context, tenantID, caID string, req api.CAIssueLeafRequest) (api.CAIssuedLeaf, error) {
	if len(req.CSRDER) == 0 {
		return api.CAIssuedLeaf{}, fmt.Errorf("%w: CSR is required", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds <= 0 {
		return api.CAIssuedLeaf{}, fmt.Errorf("%w: ttl_seconds must be positive", api.ErrCAHierarchyInvalid)
	}
	ca, err := h.store.GetCAAuthority(ctx, tenantID, caID)
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
	profile := h.leafProfile
	profile = applyAuthorityLane(profile, ca)
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, signer, req.CSRDER, time.Duration(req.TTLSeconds)*time.Second, profile)
	if err != nil {
		if crypto.IsLeafProfileViolation(err) {
			return api.CAIssuedLeaf{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return api.CAIssuedLeaf{}, err
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, []byte(ca.CertificatePEM)...)
	if err := h.emit(ctx, tenantID, "ca.endentity.issued", map[string]any{
		"ca_id": caID, "serial": info.SerialNumber, "subject": info.Subject,
	}); err != nil {
		return api.CAIssuedLeaf{}, err
	}
	return api.CAIssuedLeaf{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
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
	switch req.Operation {
	case "issue_intermediate_csr":
		csrDER, err := csrDERFromPEM(req.CSRPem)
		if err != nil {
			return "", err
		}
		return externalIntermediateCSRPurpose(req.ParentID, csrDER, req.Spec)
	default:
		return hierarchyPurpose(req.Operation, req.ParentID, req.Spec)
	}
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

func csrDERFromPEM(csrPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: csr_pem must contain one CERTIFICATE REQUEST PEM block", api.ErrCAHierarchyInvalid)
	}
	return block.Bytes, nil
}

func validateCASpec(spec api.CASpec) error {
	if spec.CommonName == "" {
		return fmt.Errorf("%w: common_name is required", api.ErrCAHierarchyInvalid)
	}
	if spec.TTLSeconds < 0 {
		return fmt.Errorf("%w: ttl_seconds cannot be negative", api.ErrCAHierarchyInvalid)
	}
	switch strings.ToLower(spec.SignatureAlgorithm) {
	case "", "ecdsa-p256":
		return nil
	default:
		return fmt.Errorf("%w: only ecdsa-p256 CA keys are supported by the served signer path", api.ErrCAHierarchyInvalid)
	}
}

func cryptoProfile(spec api.CASpec) crypto.HierarchyCAProfile {
	return crypto.HierarchyCAProfile{
		CommonName: spec.CommonName, PermittedDNSDomains: spec.PermittedDNSDomains,
		MaxPathLen: spec.MaxPathLen, EKUs: spec.ExtendedKeyUsages,
		TTL: time.Duration(spec.TTLSeconds) * time.Second,
	}
}

func hierarchySignerHandle(ceremonyID string) string {
	return hierarchySignerHandlePrefix + ceremonyID
}

func (h *caHierarchyService) createOrBindSigner(ctx context.Context, handle string) (*signing.RemoteSigner, error) {
	client := h.signer.Client()
	if client == nil {
		return nil, api.ErrCAHierarchyUnavailable
	}
	signer, err := client.GenerateDualControlKeyHandle(ctx, crypto.ECDSAP256, handle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.signAuthz)
	if err == nil {
		return signer, nil
	}
	if status.Code(err) == codes.AlreadyExists {
		return client.SignerForDualControlHandle(ctx, handle, signing.PurposeCASign, h.signAuthz)
	}
	return nil, err
}

func (h *caHierarchyService) signerForAuthority(ctx context.Context, ca store.CAAuthority) (*signing.RemoteSigner, error) {
	if ca.SignerHandle == "" {
		return nil, fmt.Errorf("%w: CA %s has no signer handle", api.ErrCAHierarchyUnavailable, ca.ID)
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
	return api.CAAuthority{
		ID: c.ID, TenantID: c.TenantID, ParentID: c.ParentID, CommonName: c.CommonName,
		Kind: c.Kind, Status: c.Status, CertificatePEM: c.CertificatePEM, SignerHandle: c.SignerHandle,
		Serial: c.Serial, NotAfter: c.NotAfter, MaxPathLen: c.MaxPathLen,
		PermittedDNSNames: c.PermittedDNSNames, ExtendedKeyUsages: c.EKUs, CreatedAt: c.CreatedAt,
	}
}

func ceremonyResponse(c store.KeyCeremony) api.CAKeyCeremony {
	return api.CAKeyCeremony{
		ID: c.ID, TenantID: c.TenantID, Purpose: c.Purpose, Threshold: c.Threshold,
		Status: c.Status, Approvals: c.Approvals, Opener: c.Opener, CreatedAt: c.CreatedAt,
	}
}

func caHierarchyConflict(err error) error {
	switch {
	case errors.Is(err, store.ErrKeyCeremonyQuorumNotMet),
		errors.Is(err, store.ErrKeyCeremonyNotPending),
		errors.Is(err, store.ErrKeyCeremonyPurposeMismatch),
		errors.Is(err, store.ErrSelfApproval),
		errors.Is(err, store.ErrAnonymousApproval):
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
	payload, err := json.Marshal(data)
	if err != nil {
		return events.Event{}, err
	}
	return h.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
}
