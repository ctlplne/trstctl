package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
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
	purpose, err := offlineRootPurpose(rootDER, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	var created store.CAAuthority
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		inserted, err := h.store.InsertCAAuthorityTx(ctx, tx, store.CAAuthority{
			TenantID: tenantID, CommonName: issued.CommonName, Kind: "root", Status: "active",
			CertificatePEM: rootPEM, Serial: issued.Serial, NotAfter: &issued.NotAfter,
			MaxPathLen: issued.MaxPathLen, PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
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
	if err := h.emit(ctx, tenantID, "ca.root.created", map[string]any{
		"ca_id": created.ID, "common_name": created.CommonName, "ceremony_id": req.CeremonyID, "offline_root": true,
	}); err != nil {
		return api.CAAuthority{}, err
	}
	return authorityResponse(created), nil
}

func (h *caHierarchyService) ImportExisting(ctx context.Context, tenantID string, req api.CAImportExistingRequest) (api.CAAuthority, error) {
	if req.CeremonyID == "" || req.SignerHandle == "" {
		return api.CAAuthority{}, fmt.Errorf("%w: ceremony_id and signer_handle are required", api.ErrCAHierarchyInvalid)
	}
	chainDER, chainPEM, err := certificateChainPEM(req.CertificatePEM)
	if err != nil {
		return api.CAAuthority{}, err
	}
	client := h.signer.Client()
	if client == nil {
		return api.CAAuthority{}, api.ErrCAHierarchyUnavailable
	}
	signer, err := client.SignerForDualControlHandle(ctx, req.SignerHandle, signing.PurposeCASign, h.signAuthz)
	if err != nil {
		return api.CAAuthority{}, err
	}
	issued, kind, err := crypto.VerifyImportedCAChain(chainDER, signer.Public(), cryptoProfile(req.Spec))
	if err != nil {
		return api.CAAuthority{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	purpose, err := existingCAPurpose(chainDER, req.SignerHandle, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	var created store.CAAuthority
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		inserted, err := h.store.InsertCAAuthorityTx(ctx, tx, store.CAAuthority{
			TenantID: tenantID, CommonName: issued.CommonName, Kind: kind, Status: "active",
			CertificatePEM: chainPEM, SignerHandle: req.SignerHandle, Serial: issued.Serial,
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
	if err := h.emit(ctx, tenantID, "ca.authority.imported", map[string]any{
		"ca_id": created.ID, "common_name": created.CommonName, "ceremony_id": req.CeremonyID,
		"signer_handle": req.SignerHandle, "kind": kind, "chain_sha256": crypto.SHA256Hex([]byte(chainPEM)),
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
	signer, err := h.createOrBindSigner(ctx, handle)
	if err != nil {
		return api.CAIntermediateCSR{}, err
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: req.Spec.CommonName}, signer)
	if err != nil {
		return api.CAIntermediateCSR{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err := h.emit(ctx, tenantID, "ca.intermediate_csr.issued", map[string]any{
		"ca_id": caID, "ceremony_id": req.CeremonyID, "signer_handle": handle, "csr_sha256": crypto.SHA256Hex(csrDER), "offline_root": true,
	}); err != nil {
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
	issued, err := crypto.VerifyOfflineSignedIntermediate(parentDER, childDER, childSigner.Public(), cryptoProfile(req.Spec))
	if err != nil {
		return api.CAAuthority{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	var created store.CAAuthority
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		chain := append([]byte{}, childPEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		pid := caID
		inserted, err := h.store.InsertCAAuthorityTx(ctx, tx, store.CAAuthority{
			TenantID: tenantID, ParentID: &pid, CommonName: issued.CommonName, Kind: "intermediate", Status: "active",
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
		"ca_id": created.ID, "parent_id": caID, "ceremony_id": req.CeremonyID, "signer_handle": handle, "offline_root": true,
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
	event := map[string]any{
		"ca_id": caID, "serial": info.SerialNumber, "subject": info.Subject,
	}
	if requestedCA.ID != ca.ID {
		event["ca_id"] = ca.ID
		event["requested_ca_id"] = requestedCA.ID
		event["rotation_routed"] = true
	}
	ev, err := h.appendEvent(ctx, tenantID, projections.EventCAEndEntityIssued, event)
	if err != nil {
		return api.CAIssuedLeaf{}, err
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		return api.CAIssuedLeaf{}, err
	}
	return api.CAIssuedLeaf{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
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

func (h *caHierarchyService) RekeyAuthority(ctx context.Context, tenantID, caID string, req api.CAAuthorityRekeyRequest) (api.CAAuthorityRotation, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if caID == "" || ceremonyID == "" {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds < 0 {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: ttl_seconds cannot be negative", api.ErrCAHierarchyInvalid)
	}
	purpose, err := rekeyCAPurpose(caID)
	if err != nil {
		return api.CAAuthorityRotation{}, err
	}
	handle := hierarchySignerHandle(ceremonyID)
	newID := uuid.NewString()
	var predecessor, successor store.CAAuthority
	var rekeySigner *signing.RemoteSigner
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		predecessor, err = h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		if err := validateAuthorityRekey(predecessor); err != nil {
			return err
		}
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, ceremonyID, purpose); err != nil {
			return err
		}
		rekeySigner, err = h.createOrBindSigner(ctx, handle)
		if err != nil {
			return err
		}
		spec := rekeyAuthoritySpec(predecessor, req.TTLSeconds)
		issued, chainPEM, err := h.issueRekeyedCA(ctx, tx, tenantID, predecessor, rekeySigner, spec)
		if err != nil {
			return err
		}
		notAfter := issued.NotAfter
		successor = store.CAAuthority{
			ID: newID, TenantID: tenantID, ParentID: predecessor.ParentID, CommonName: spec.CommonName,
			Kind: predecessor.Kind, Status: "active", CertificatePEM: chainPEM, SignerHandle: handle,
			Serial: issued.Serial, NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendEvent(ctx, tenantID, projections.EventCAAuthorityRekeyed, projections.CAAuthorityRekeyed{
			ID: newID, PredecessorCAID: predecessor.ID, ParentID: predecessor.ParentID,
			CommonName: successor.CommonName, Kind: successor.Kind, CertificatePEM: successor.CertificatePEM,
			SignerHandle: successor.SignerHandle, Serial: successor.Serial, NotAfter: notAfter,
			MaxPathLen: successor.MaxPathLen, PermittedDNSNames: successor.PermittedDNSNames, EKUs: successor.EKUs,
			CeremonyID: ceremonyID, Reason: strings.TrimSpace(req.Reason),
			IssuePath: caAuthorityIssuePath(predecessor.ID), ActiveIssuePath: caAuthorityIssuePath(successor.ID),
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
		successor.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		return api.CAAuthorityRotation{}, caHierarchyConflict(err)
	}
	h.rememberSigner(successor.ID, rekeySigner)
	return authorityRotationResponse(predecessor, successor), nil
}

func (h *caHierarchyService) issueRekeyedCA(ctx context.Context, tx pgx.Tx, tenantID string, predecessor store.CAAuthority, signer *signing.RemoteSigner, spec api.CASpec) (crypto.IssuedHierarchyCA, string, error) {
	switch predecessor.Kind {
	case "root":
		issued, err := crypto.SelfSignedHierarchyCA(signer, cryptoProfile(spec))
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return issued, string(issued.CertificatePEM), nil
	case "intermediate":
		if predecessor.ParentID == nil || *predecessor.ParentID == "" {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: intermediate CA has no parent authority", api.ErrCAHierarchyInvalid)
		}
		parent, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, *predecessor.ParentID)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		if parent.Status != "active" || parent.SignerHandle == "" {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: parent CA must be active and signer-backed for served re-key", api.ErrCAHierarchyInvalid)
		}
		parentDER, err := firstCertDER(parent.CertificatePEM)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		parentSigner, err := h.signerForAuthority(ctx, parent)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		issued, err := crypto.SignIntermediateHierarchyCA(parentDER, parentSigner, signer.Public(), cryptoProfile(spec))
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		chain := append([]byte{}, issued.CertificatePEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		return issued, string(chain), nil
	default:
		return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: unsupported CA kind %q", api.ErrCAHierarchyInvalid, predecessor.Kind)
	}
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

func rekeyAuthoritySpec(ca store.CAAuthority, ttlSeconds int64) api.CASpec {
	return api.CASpec{
		CommonName: ca.CommonName, PermittedDNSDomains: append([]string(nil), ca.PermittedDNSNames...),
		MaxPathLen: ca.MaxPathLen, ExtendedKeyUsages: append([]string(nil), ca.EKUs...),
		TTLSeconds: ttlSeconds, SignatureAlgorithm: "ecdsa-p256",
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
	case "import_offline_root":
		certDER, _, err := singleCertificatePEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		return offlineRootPurpose(certDER, req.Spec)
	case "import_existing_ca":
		chainDER, _, err := certificateChainPEM(req.CertificatePEM)
		if err != nil {
			return "", err
		}
		return existingCAPurpose(chainDER, req.SignerHandle, req.Spec)
	case "create_offline_intermediate":
		return offlineIntermediatePurpose(req.ParentID, req.Spec)
	case "issue_intermediate_csr":
		csrDER, err := csrDERFromPEM(req.CSRPem)
		if err != nil {
			return "", err
		}
		return externalIntermediateCSRPurpose(req.ParentID, csrDER, req.Spec)
	case "rekey_ca":
		return rekeyCAPurpose(req.AuthorityID)
	default:
		return hierarchyPurpose(req.Operation, req.ParentID, req.Spec)
	}
}

func offlineRootPurpose(certDER []byte, spec api.CASpec) (string, error) {
	rootPurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	return "offline-root:" + crypto.SHA256Hex(certDER) + ":" + rootPurpose, nil
}

func existingCAPurpose(chainDER [][]byte, signerHandle string, spec api.CASpec) (string, error) {
	if signerHandle == "" {
		return "", fmt.Errorf("%w: signer_handle is required for import_existing_ca", api.ErrCAHierarchyInvalid)
	}
	rootPurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	return "import-existing-ca:" + signerHandle + ":" + crypto.SHA256Hex(flattenDERChain(chainDER)) + ":" + rootPurpose, nil
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

func rekeyCAPurpose(authorityID string) (string, error) {
	authorityID = strings.TrimSpace(authorityID)
	if authorityID == "" {
		return "", fmt.Errorf("%w: authority_id is required for rekey_ca", api.ErrCAHierarchyInvalid)
	}
	return libhierarchy.PurposeRotate(authorityID), nil
}

func flattenDERChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, der...)
	}
	return out
}

func csrDERFromPEM(csrPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: csr_pem must contain one CERTIFICATE REQUEST PEM block", api.ErrCAHierarchyInvalid)
	}
	return block.Bytes, nil
}

func certificateChainPEM(raw string) ([][]byte, string, error) {
	rest := []byte(raw)
	var chain [][]byte
	var normalized []byte
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, "", fmt.Errorf("%w: certificate_pem contains trailing non-PEM data", api.ErrCAHierarchyInvalid)
			}
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, "", fmt.Errorf("%w: certificate_pem must not contain private key material", api.ErrCAHierarchyInvalid)
		}
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("%w: certificate_pem contains unsupported PEM block %q", api.ErrCAHierarchyInvalid, block.Type)
		}
		der := append([]byte(nil), block.Bytes...)
		chain = append(chain, der)
		normalized = append(normalized, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		rest = next
	}
	if len(chain) == 0 {
		return nil, "", fmt.Errorf("%w: certificate_pem must contain at least one CERTIFICATE PEM block", api.ErrCAHierarchyInvalid)
	}
	return chain, string(normalized), nil
}

func singleCertificatePEM(raw string) ([]byte, string, error) {
	rest := []byte(raw)
	var der []byte
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, "", fmt.Errorf("%w: certificate_pem contains trailing non-PEM data", api.ErrCAHierarchyInvalid)
			}
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, "", fmt.Errorf("%w: certificate_pem must not contain private key material", api.ErrCAHierarchyInvalid)
		}
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("%w: certificate_pem contains unsupported PEM block %q", api.ErrCAHierarchyInvalid, block.Type)
		}
		if der != nil {
			return nil, "", fmt.Errorf("%w: certificate_pem must contain exactly one CERTIFICATE block", api.ErrCAHierarchyInvalid)
		}
		der = append([]byte(nil), block.Bytes...)
		rest = next
	}
	if der == nil {
		return nil, "", fmt.Errorf("%w: certificate_pem must contain one CERTIFICATE PEM block", api.ErrCAHierarchyInvalid)
	}
	normalized := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return der, normalized, nil
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
		PermittedDNSNames: c.PermittedDNSNames, ExtendedKeyUsages: c.EKUs, ReplacesID: c.ReplacesID, CreatedAt: c.CreatedAt,
	}
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
