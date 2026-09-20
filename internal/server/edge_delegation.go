// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// Constrained edge sub-CA service (epic B6).
//
// B6 is the one deliberate exception to "signing lives only in the isolated
// signer": a host with no path to the brain issues leaves locally under a
// delegated CA. This service is the brain's half of the bargain, and every
// method here is a bound on the exception:
//
//   - the delegated CA is minted BY the central isolated signer (the parent
//     CA's key never leaves it), name-constrained to exactly the identifiers
//     the segment's policy declared, path-length zero, short-lived;
//   - minting is per-segment OPT-IN (no policy row means OFF) and
//     attestation-gated and custody-policy-bound: TPM2 requires same-key proof;
//     PKCS#11/software exceptions require an explicit segment allowlist and
//     carry weaker, honest assurance labels;
//   - the delegation is revocable from the brain, and because its certificate
//     joins the parent CA's issued ledger, OCSP and the CRL answer for it;
//   - local issuances reconcile back on reconnect, re-verified here, and a
//     leaf outside the delegation's constraints is recorded AS A VIOLATION —
//     visible, never silently dropped and never silently accepted.

// tpmAttestationAlgorithms are the COSE algorithms accepted from edge TPMs:
// ES256 (-7) and RS256 (-257), matching the WebAuthn TPM attestation formats
// deviceattest verifies.
var tpmAttestationAlgorithms = []int64{-7, -257}

type edgeDelegationService struct {
	store     *store.Store
	orch      *orchestrator.Orchestrator
	signer    SignerProvider
	signAuthz signing.SignTokenProvider

	mu      sync.Mutex
	signers map[string]*signing.RemoteSigner
}

func (s *Server) buildEdgeDelegationService(d Deps, orch *orchestrator.Orchestrator) api.EdgeDelegationService {
	if d.Store == nil || orch == nil || d.Signer == nil || d.Signer.Client() == nil || s.signAuthz == nil {
		return nil
	}
	return &edgeDelegationService{
		store: d.Store, orch: orch, signer: d.Signer, signAuthz: s.signAuthz,
		signers: map[string]*signing.RemoteSigner{},
	}
}

func (s *edgeDelegationService) SetSegmentPolicy(ctx context.Context, tenantID string, req api.EdgeSegmentPolicyRequest) (api.EdgeSegmentPolicy, error) {
	segmentID := strings.TrimSpace(req.SegmentID)
	if segmentID == "" {
		return api.EdgeSegmentPolicy{}, fmt.Errorf("%w: segment_id is required", api.ErrEdgeDelegationInvalid)
	}
	if _, err := s.segmentName(ctx, tenantID, segmentID); err != nil {
		return api.EdgeSegmentPolicy{}, err
	}
	allowedProviders, err := normalizeEdgeAllowedKeyProviders(req.AllowedKeyProviders)
	if err != nil {
		return api.EdgeSegmentPolicy{}, fmt.Errorf("%w: %v", api.ErrEdgeDelegationInvalid, err)
	}
	if req.Enabled {
		// Enabling IS the declaration. A segment enabled without attestation
		// roots would admit any key that asks; one without identifiers would
		// mint an unconstrained CA, which the crypto layer refuses anyway —
		// refuse both here, where the operator can fix the declaration.
		if len(req.AttestationRootsPEM) == 0 {
			return api.EdgeSegmentPolicy{}, fmt.Errorf(
				"%w: enabling edge delegation requires at least one TPM attestation root; "+
					"without one, any key that asks would be vouched for", api.ErrEdgeDelegationInvalid)
		}
		for i, root := range req.AttestationRootsPEM {
			block, _ := pem.Decode([]byte(root))
			if block == nil || block.Type != "CERTIFICATE" {
				return api.EdgeSegmentPolicy{}, fmt.Errorf(
					"%w: attestation root %d is not a PEM certificate", api.ErrEdgeDelegationInvalid, i)
			}
			if _, err := certinfo.Inspect(block.Bytes); err != nil {
				return api.EdgeSegmentPolicy{}, fmt.Errorf(
					"%w: attestation root %d: %v", api.ErrEdgeDelegationInvalid, i, err)
			}
		}
		if len(req.PermittedDNSDomains) == 0 {
			return api.EdgeSegmentPolicy{}, fmt.Errorf(
				"%w: enabling edge delegation requires the segment's permitted DNS domains; "+
					"they become the name constraints of every delegation minted for it", api.ErrEdgeDelegationInvalid)
		}
	}
	if err := s.orch.SetEdgeSegmentPolicy(ctx, tenantID, projections.EdgeSegmentPolicySet{
		SegmentID:           segmentID,
		Enabled:             req.Enabled,
		AttestationRootsPEM: req.AttestationRootsPEM,
		PermittedDNSDomains: req.PermittedDNSDomains,
		ExcludedDNSDomains:  req.ExcludedDNSDomains,
		AllowedKeyProviders: allowedProviders,
	}); err != nil {
		return api.EdgeSegmentPolicy{}, err
	}
	policy, _, err := s.store.GetEdgeSegmentPolicy(ctx, tenantID, segmentID)
	if err != nil {
		return api.EdgeSegmentPolicy{}, err
	}
	return s.policyView(ctx, tenantID, policy), nil
}

func (s *edgeDelegationService) ListSegmentPolicies(ctx context.Context, tenantID string) ([]api.EdgeSegmentPolicy, error) {
	policies, err := s.store.ListEdgeSegmentPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.EdgeSegmentPolicy, 0, len(policies))
	for _, p := range policies {
		out = append(out, s.policyView(ctx, tenantID, p))
	}
	return out, nil
}

func (s *edgeDelegationService) MintDelegation(ctx context.Context, tenantID string, req api.EdgeDelegationMintRequest) (api.EdgeDelegation, error) {
	segmentID := strings.TrimSpace(req.SegmentID)
	caID := strings.TrimSpace(req.CAID)
	host := strings.TrimSpace(req.Host)
	if segmentID == "" || caID == "" || host == "" {
		return api.EdgeDelegation{}, fmt.Errorf("%w: segment_id, ca_id and host are required", api.ErrEdgeDelegationInvalid)
	}
	if len(req.CSRDER) == 0 {
		return api.EdgeDelegation{}, fmt.Errorf("%w: csr_der is required", api.ErrEdgeDelegationInvalid)
	}
	policy, found, err := s.store.GetEdgeSegmentPolicy(ctx, tenantID, segmentID)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	if !found || !policy.Enabled {
		// Default OFF, stated as the refusal reason: the exception to the
		// signing boundary exists only where an operator turned it on.
		return api.EdgeDelegation{}, fmt.Errorf(
			"%w: segment %s has not opted in to edge delegation", api.ErrEdgeDelegationRefused, segmentID)
	}
	provider, custody, err := edgeCustodyForProvider(req.KeyProvider)
	if err != nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: %v", api.ErrEdgeDelegationInvalid, err)
	}
	if !containsEdgeProvider(policy.AllowedKeyProviders, provider) {
		return api.EdgeDelegation{}, fmt.Errorf(
			"%w: key provider %s is not allowed by segment policy; software and PKCS#11 lanes must be named explicitly",
			api.ErrEdgeDelegationRefused, provider)
	}

	// The attestation gate. The TPM credential must verify against the roots
	// the segment pinned, over a challenge binding tenant, segment and THIS
	// CSR. In the TPM2 custody lane the attested key must also BE the CSR key.
	// For an explicitly allowed PKCS#11/software lane it authenticates the host
	// and request only; the stored assurance label preserves that distinction.
	if len(req.AttestationCredentialJSON) == 0 {
		return api.EdgeDelegation{}, fmt.Errorf(
			"%w: an un-attested host cannot receive a delegated CA", api.ErrEdgeDelegationRefused)
	}
	roots := make([][]byte, 0, len(policy.AttestationRootsPEM))
	for _, root := range policy.AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	challenge := crypto.EdgeAttestationChallenge(tenantID, segmentID, req.CSRDER)
	attested, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		req.AttestationCredentialJSON, challenge, roots, tpmAttestationAlgorithms, time.Now().UTC())
	if err != nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: attestation: %v", api.ErrEdgeDelegationRefused, err)
	}
	csrKeyDigest, err := deviceattest.CSRPublicKeySHA256(req.CSRDER)
	if err != nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: csr: %v", api.ErrEdgeDelegationInvalid, err)
	}
	if provider == "tpm2" && !bytesEqualConst(attested.PublicKeySHA256, csrKeyDigest) {
		return api.EdgeDelegation{}, fmt.Errorf(
			"%w: the attested key is not the CSR's key; a TPM vouching for a different key "+
				"vouches for nothing here", api.ErrEdgeDelegationRefused)
	}

	ca, err := s.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	if ca.Status != "active" {
		return api.EdgeDelegation{}, fmt.Errorf("%w: CA %s is %s", api.ErrEdgeDelegationRefused, caID, ca.Status)
	}
	parentSigner, err := s.signerForAuthority(ctx, ca)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	parentDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	issued, err := crypto.MintDelegatedEdgeCAFromCSR(parentDER, parentSigner, req.CSRDER, crypto.EdgeCARequest{
		CommonName: strings.TrimSpace(req.CommonName),
		// Constraints come from the segment's POLICY, never from the request:
		// an edge host does not get to choose its own scope.
		PermittedDNSDomains: policy.PermittedDNSDomains,
		ExcludedDNSDomains:  policy.ExcludedDNSDomains,
		TTL:                 time.Duration(req.TTLSeconds) * time.Second,
	})
	if err != nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: %v", api.ErrEdgeDelegationInvalid, err)
	}
	info, err := certinfo.Inspect(issued.CertificateDER)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	id := uuid.NewString()
	if err := s.orch.RecordEdgeDelegationIssued(ctx, tenantID, projections.EdgeDelegationIssued{
		ID: id, SegmentID: segmentID, CAID: caID, Host: host,
		CommonName: issued.CommonName, Serial: issued.Serial,
		CertificatePEM:        string(issued.CertificatePEM),
		PermittedDNSDomains:   policy.PermittedDNSDomains,
		ExcludedDNSDomains:    policy.ExcludedDNSDomains,
		AttestedKeySHA256:     crypto.SHA256Hex(attested.PublicKeySHA256),
		AttestationCertSHA256: crypto.SHA256Hex(attested.AttestationCertificateSHA256),
		CSRKeySHA256:          crypto.SHA256Hex(csrKeyDigest),
		KeyProvider:           provider,
		KeyStorage:            custody.storage,
		KeyExportable:         custody.exportable,
		CustodyAssurance:      custody.assurance,
		NotBefore:             info.NotBefore, NotAfter: info.NotAfter,
	}); err != nil {
		return api.EdgeDelegation{}, err
	}
	delegation, _, err := s.store.GetEdgeDelegation(ctx, tenantID, id)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	view := edgeDelegationView(delegation, time.Now().UTC())
	// The chain travels with the delegation so the edge host can serve it.
	view.CertificatePEM = string(issued.CertificatePEM) + ca.CertificatePEM
	return view, nil
}

func (s *edgeDelegationService) ListDelegations(ctx context.Context, tenantID string) ([]api.EdgeDelegation, error) {
	rows, err := s.store.ListEdgeDelegations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]api.EdgeDelegation, 0, len(rows))
	for _, d := range rows {
		out = append(out, edgeDelegationView(d, now))
	}
	return out, nil
}

func (s *edgeDelegationService) GetDelegation(ctx context.Context, tenantID, id string) (api.EdgeDelegationDetail, error) {
	d, found, err := s.store.GetEdgeDelegation(ctx, tenantID, id)
	if err != nil {
		return api.EdgeDelegationDetail{}, err
	}
	if !found {
		return api.EdgeDelegationDetail{}, api.ErrEdgeDelegationNotFound
	}
	issuances, err := s.store.ListEdgeIssuances(ctx, tenantID, id, 200)
	if err != nil {
		return api.EdgeDelegationDetail{}, err
	}
	detail := api.EdgeDelegationDetail{Delegation: edgeDelegationView(d, time.Now().UTC())}
	for _, i := range issuances {
		detail.Issuances = append(detail.Issuances, api.EdgeIssuance{
			Serial: i.Serial, Subject: i.Subject, DNSNames: i.DNSNames,
			NotBefore: i.NotBefore, NotAfter: i.NotAfter,
			IssuedAt: i.IssuedAt, ReconciledAt: i.ReconciledAt,
			WithinConstraints: i.WithinConstraints, Violation: i.Violation,
		})
	}
	return detail, nil
}

func (s *edgeDelegationService) RevokeDelegation(ctx context.Context, tenantID, id, reason string) (api.EdgeDelegation, error) {
	d, found, err := s.store.GetEdgeDelegation(ctx, tenantID, id)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	if !found {
		return api.EdgeDelegation{}, api.ErrEdgeDelegationNotFound
	}
	if d.Status != "revoked" {
		if err := s.orch.RevokeEdgeDelegation(ctx, tenantID, projections.EdgeDelegationRevoked{
			ID: id, CAID: d.CAID, Serial: d.Serial,
			Reason: strings.TrimSpace(reason), RevokedAt: time.Now().UTC(),
		}); err != nil {
			return api.EdgeDelegation{}, err
		}
		d, _, err = s.store.GetEdgeDelegation(ctx, tenantID, id)
		if err != nil {
			return api.EdgeDelegation{}, err
		}
	}
	return edgeDelegationView(d, time.Now().UTC()), nil
}

func (s *edgeDelegationService) Reconcile(ctx context.Context, tenantID, id string, req api.EdgeReconcileRequest) (api.EdgeReconcileResult, error) {
	var out api.EdgeReconcileResult
	d, found, err := s.store.GetEdgeDelegation(ctx, tenantID, id)
	if err != nil {
		return out, err
	}
	if !found {
		return out, api.ErrEdgeDelegationNotFound
	}
	delegationDER, err := firstCertDER(d.CertificatePEM)
	if err != nil {
		return out, err
	}
	constraints := crypto.EdgeConstraints{
		PermittedDNSDomains: d.PermittedDNSDomains,
		ExcludedDNSDomains:  d.ExcludedDNSDomains,
		NotAfter:            d.NotAfter,
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = d.Host
	}
	for _, reportPEM := range req.CertificatesPEM {
		block, _ := pem.Decode([]byte(reportPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			out.Rejected++
			continue
		}
		leaf, err := crypto.InspectEdgeReportedLeaf(delegationDER, block.Bytes)
		if err != nil {
			// Not this delegation's issuance (or not a certificate at all).
			// Recording it here would let anyone stuff another delegation's
			// ledger; the report is refused, counted, and the count is the
			// caller's signal to investigate.
			out.Rejected++
			continue
		}
		exists, err := s.store.EdgeIssuanceExists(ctx, tenantID, id, leaf.SerialHex)
		if err != nil {
			return out, err
		}
		if exists {
			out.Already++
			continue
		}
		violation := ""
		if err := crypto.CheckEdgeIssuance(constraints, leaf.DNSNames, leaf.IPSANs, leaf.NotBefore); err != nil {
			violation = err.Error()
		} else if d.RevokedAt != nil && leaf.NotBefore.After(*d.RevokedAt) {
			violation = "issued after the delegation was revoked"
		} else if leaf.NotAfter.After(d.NotAfter) {
			violation = "leaf outlives the delegated CA"
		}
		if err := s.orch.RecordEdgeIssuanceReconciled(ctx, tenantID, projections.EdgeIssuanceReconciled{
			DelegationID: id, Host: host, Serial: leaf.SerialHex,
			Subject: leaf.Subject, DNSNames: leaf.DNSNames,
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			IssuedAt:          leaf.NotBefore,
			CertificateDER:    leaf.DER,
			CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER})),
			Fingerprint:       crypto.SHA256Hex(leaf.DER),
			WithinConstraints: violation == "",
			Violation:         violation,
		}); err != nil {
			return out, err
		}
		if violation == "" {
			out.Reconciled++
		} else {
			out.Violations++
		}
	}
	return out, nil
}

func (s *edgeDelegationService) policyView(ctx context.Context, tenantID string, p store.EdgeSegmentPolicy) api.EdgeSegmentPolicy {
	name, _ := s.segmentName(ctx, tenantID, p.SegmentID)
	return api.EdgeSegmentPolicy{
		SegmentID:           p.SegmentID,
		SegmentName:         name,
		Enabled:             p.Enabled,
		AttestationRoots:    len(p.AttestationRootsPEM),
		PermittedDNSDomains: p.PermittedDNSDomains,
		ExcludedDNSDomains:  p.ExcludedDNSDomains,
		AllowedKeyProviders: edgeProvidersOrDefault(p.AllowedKeyProviders),
		UpdatedAt:           p.UpdatedAt,
	}
}

func (s *edgeDelegationService) segmentName(ctx context.Context, tenantID, segmentID string) (string, error) {
	segments, err := s.store.ListDiscoverySegments(ctx, tenantID)
	if err != nil {
		return "", err
	}
	for _, seg := range segments {
		if seg.ID == segmentID {
			return seg.Name, nil
		}
	}
	return "", fmt.Errorf("%w: segment %s is not declared; edge delegation scopes to a "+
		"declared segment, not an implied one", api.ErrEdgeDelegationInvalid, segmentID)
}

func (s *edgeDelegationService) signerForAuthority(ctx context.Context, ca store.CAAuthority) (*signing.RemoteSigner, error) {
	if ca.SignerHandle == "" {
		return nil, fmt.Errorf("%w: CA %s has no signer handle", api.ErrEdgeDelegationRefused, ca.ID)
	}
	s.mu.Lock()
	if signer := s.signers[ca.ID]; signer != nil {
		s.mu.Unlock()
		return signer, nil
	}
	s.mu.Unlock()
	client := s.signer.Client()
	if client == nil {
		return nil, api.ErrEdgeDelegationRefused
	}
	signer, err := client.SignerForDualControlHandle(ctx, ca.SignerHandle, signing.PurposeCASign, s.signAuthz)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.signers[ca.ID] = signer
	s.mu.Unlock()
	return signer, nil
}

func edgeDelegationView(d store.EdgeDelegation, now time.Time) api.EdgeDelegation {
	status := d.Status
	if status == "active" && d.Expired(now) {
		// Auto-expiry is the certificate's own clock, reported as such rather
		// than waiting for a process to flip a column.
		status = "expired"
	}
	return api.EdgeDelegation{
		ID: d.ID, SegmentID: d.SegmentID, CAID: d.CAID, Host: d.Host,
		CommonName: d.CommonName, Serial: d.Serial,
		CertificatePEM:      d.CertificatePEM,
		PermittedDNSDomains: d.PermittedDNSDomains,
		ExcludedDNSDomains:  d.ExcludedDNSDomains,
		AttestedKeySHA256:   d.AttestedKeySHA256,
		CSRKeySHA256:        d.CSRKeySHA256,
		KeyProvider:         d.KeyProvider,
		KeyStorage:          d.KeyStorage,
		KeyExportable:       d.KeyExportable,
		CustodyAssurance:    d.CustodyAssurance,
		Status:              status,
		NotBefore:           d.NotBefore, NotAfter: d.NotAfter,
		RevokedAt: d.RevokedAt, RevokeReason: d.RevokeReason,
	}
}

type edgeCustodyEvidence struct {
	storage    string
	exportable bool
	assurance  string
}

func edgeCustodyForProvider(raw string) (string, edgeCustodyEvidence, error) {
	provider := strings.ToLower(strings.TrimSpace(raw))
	if provider == "" {
		provider = "tpm2"
	}
	switch provider {
	case "tpm2":
		return provider, edgeCustodyEvidence{storage: "device_bound", assurance: "hardware_key_attested"}, nil
	case "pkcs11":
		// The shipping agent creates a CKA_SENSITIVE, CKA_EXTRACTABLE=false
		// object. The WebAuthn TPM proof authenticates the host and CSR request,
		// but cannot cryptographically attest a separate PKCS#11 token object;
		// the assurance name says exactly that instead of laundering the host
		// TPM proof into a token-key attestation.
		return provider, edgeCustodyEvidence{storage: "pkcs11", assurance: "host_attested_operator_claim"}, nil
	case "software":
		return provider, edgeCustodyEvidence{storage: "file", exportable: true, assurance: "host_attested_software_exception"}, nil
	default:
		return "", edgeCustodyEvidence{}, fmt.Errorf("unknown key_provider %q (want tpm2, pkcs11, or software)", raw)
	}
}

func normalizeEdgeAllowedKeyProviders(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{"tpm2"}, nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		provider, _, err := edgeCustodyForProvider(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[provider]; duplicate {
			return nil, fmt.Errorf("allowed_key_providers contains duplicate %q", provider)
		}
		seen[provider] = struct{}{}
		out = append(out, provider)
	}
	return out, nil
}

func edgeProvidersOrDefault(in []string) []string {
	if len(in) == 0 {
		return []string{"tpm2"}
	}
	return in
}

func containsEdgeProvider(allowed []string, provider string) bool {
	for _, candidate := range edgeProvidersOrDefault(allowed) {
		if candidate == provider {
			return true
		}
	}
	return false
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
