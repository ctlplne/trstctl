package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/signing"
)

func TestServedCAHierarchyCeremonyAndLeafIssuance(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	openerToken := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "trstctl customer root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"svc.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, openerToken, "create_root", "", rootSpec, 2, "root-ceremony")

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", openerToken, "root-before-quorum", map[string]any{
		"ceremony_id": rootCeremony.ID,
		"spec":        rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("root before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+rootCeremony.ID+"/approvals", openerToken, "root-self-approval", nil)
	if code != http.StatusConflict {
		t.Fatalf("root self-approval = %d body=%s; want 409 separation-of-duties refusal", code, body)
	}
	approveCACeremony(t, h, approverOne, rootCeremony.ID, 1, "root-approval-one")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", openerToken, "root-one-approval", map[string]any{
		"ceremony_id": rootCeremony.ID,
		"spec":        rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("root after one approval = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverTwo, rootCeremony.ID, 2, "root-approval-two")
	root := createRootCA(t, h, openerToken, rootCeremony.ID, rootSpec, "root-create")
	if root.Kind != "root" || root.CommonName != rootSpec["common_name"] || root.CertificatePEM == "" || root.SignerHandle == "" {
		t.Fatalf("root response = %+v; want root with certificate and signer handle", root)
	}

	interSpec := map[string]any{
		"common_name":           "trstctl customer issuing intermediate",
		"ttl_seconds":           int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"svc.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, openerToken, "create_intermediate", root.ID, interSpec, 2, "intermediate-ceremony")
	approveCACeremony(t, h, approverOne, interCeremony.ID, 1, "intermediate-approval-one")
	approveCACeremony(t, h, approverTwo, interCeremony.ID, 2, "intermediate-approval-two")
	inter := createIntermediateCA(t, h, openerToken, interCeremony.ID, root.ID, interSpec, "intermediate-create")
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID || inter.SignerHandle == "" {
		t.Fatalf("intermediate response = %+v; want child of root with signer handle", inter)
	}

	client := h.signer.Client()
	leafSigner, err := client.GenerateKey(context.Background(), crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate leaf key in signer: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "leaf.svc.example.test",
		DNSNames:   []string{"leaf.svc.example.test"},
	}, leafSigner)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/issue", openerToken, "hierarchy-leaf-issue", map[string]any{
		"csr_pem":     csrPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue hierarchy leaf = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode issued leaf: %v body=%s", err, body)
	}
	leafDER := caCertDER(t, []byte(issued.CertificatePEM))
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, []byte(inter.CertificatePEM))); err != nil {
		t.Fatalf("leaf was not signed by served hierarchy intermediate: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect leaf: %v", err)
	}
	if info.Subject != "CN=leaf.svc.example.test" || len(info.DNSNames) != 1 || info.DNSNames[0] != "leaf.svc.example.test" {
		t.Fatalf("leaf identity = subject %q DNS %v; want hierarchy-issued leaf.svc.example.test", info.Subject, info.DNSNames)
	}
	if rec, found, err := h.store.LookupIssuedCert(context.Background(), h.tenant, inter.ID, issued.Serial); err != nil {
		t.Fatalf("lookup hierarchy issued serial: %v", err)
	} else if !found || rec.Revoked() {
		t.Fatalf("hierarchy issued serial row = found %v %+v, want active ca_issued_certs row", found, rec)
	}

	storedInter, err := h.store.GetCAAuthority(context.Background(), h.tenant, inter.ID)
	if err != nil {
		t.Fatalf("load hierarchy intermediate: %v", err)
	}
	hierarchySvc := h.srv.buildCAHierarchyService(Deps{
		Store: h.store, Log: h.log, Signer: h.signer, LeafProfile: h.srv.leafProfile,
	}).(*caHierarchyService)
	caSigner, err := hierarchySvc.signerForAuthority(context.Background(), storedInter)
	if err != nil {
		t.Fatalf("hierarchy CA signer: %v", err)
	}
	ocspSigner, err := h.srv.provisionOCSPResponderSigner(context.Background(), h.signer.Client(), inter.ID)
	if err != nil {
		t.Fatalf("hierarchy OCSP signer: %v", err)
	}
	interDER := caCertDER(t, []byte(inter.CertificatePEM))
	revoc := newRevocationService(h.store, h.log, inter.ID, caSigner, interDER, ocspSigner)
	reqDER, err := crypto.BuildOCSPRequestForSerial(interDER, issued.Serial)
	if err != nil {
		t.Fatalf("build hierarchy OCSP request: %v", err)
	}
	goodDER, err := revoc.respondOCSP(context.Background(), h.tenant, reqDER)
	if err != nil {
		t.Fatalf("hierarchy OCSP before revoke: %v", err)
	}
	good, err := crypto.ParseOCSPResponse(goodDER, interDER)
	if err != nil {
		t.Fatalf("parse hierarchy OCSP before revoke: %v", err)
	}
	if good.Status != crypto.OCSPGood {
		t.Fatalf("hierarchy OCSP status before revoke = %q, want good", good.Status)
	}
	reasonCode := crypto.CRLReasonCode(crypto.RevocationReasonKeyCompromise)
	if err := h.srv.orch.RevokeCertificateForCA(context.Background(), h.tenant, "", issued.Serial, inter.ID, string(crypto.RevocationReasonKeyCompromise), reasonCode, time.Now().UTC()); err != nil {
		t.Fatalf("revoke hierarchy issued serial: %v", err)
	}
	if rec, found, err := h.store.LookupIssuedCert(context.Background(), h.tenant, inter.ID, issued.Serial); err != nil {
		t.Fatalf("lookup revoked hierarchy serial: %v", err)
	} else if !found || !rec.Revoked() {
		t.Fatalf("revoked hierarchy serial row = found %v %+v, want revoked ca_issued_certs row", found, rec)
	}
	revokedDER, err := revoc.respondOCSP(context.Background(), h.tenant, reqDER)
	if err != nil {
		t.Fatalf("hierarchy OCSP after revoke: %v", err)
	}
	revoked, err := crypto.ParseOCSPResponse(revokedDER, interDER)
	if err != nil {
		t.Fatalf("parse hierarchy OCSP after revoke: %v", err)
	}
	if revoked.Status != crypto.OCSPRevoked {
		t.Fatalf("hierarchy OCSP status after revoke = %q, want revoked", revoked.Status)
	}
	crlDER, err := revoc.generateCRL(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("generate hierarchy CRL: %v", err)
	}
	crlInfo, err := crypto.ParseCRL(crlDER, interDER)
	if err != nil {
		t.Fatalf("parse hierarchy CRL: %v", err)
	}
	if !protoContains(crlInfo.RevokedSerials, issued.Serial) {
		t.Fatalf("hierarchy CRL revoked serials = %v, want %s", crlInfo.RevokedSerials, issued.Serial)
	}
	if !h.hasEvent(t, "ca.root.created") || !h.hasEvent(t, "ca.intermediate.created") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("hierarchy create/issue events were not recorded")
	}
}

func TestServedCARotationWithoutDowntimeCAPCA03(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-rotation-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-rotation-approver", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "rotation root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"rotation.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "rotation-root-ceremony")
	approveCACeremony(t, h, approver, rootCeremony.ID, 1, "rotation-root-approval")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "rotation-root-create")

	intermediateSpec := map[string]any{
		"common_name":           "rotation issuing intermediate",
		"ttl_seconds":           int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"rotation.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	oldCeremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, intermediateSpec, 1, "rotation-old-ceremony")
	approveCACeremony(t, h, approver, oldCeremony.ID, 1, "rotation-old-approval")
	oldCA := createIntermediateCA(t, h, operator, oldCeremony.ID, root.ID, intermediateSpec, "rotation-old-create")

	successorSpec := map[string]any{
		"common_name":           "rotation issuing intermediate v2",
		"ttl_seconds":           int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"rotation.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	successorCeremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, successorSpec, 1, "rotation-successor-ceremony")
	approveCACeremony(t, h, approver, successorCeremony.ID, 1, "rotation-successor-approval")
	successorCA := createIntermediateCA(t, h, operator, successorCeremony.ID, root.ID, successorSpec, "rotation-successor-create")

	before := issueHierarchyLeaf(t, h, operator, oldCA.ID, "before.rotation.example.test", "rotation-old-before")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(before.CertificatePEM)), caCertDER(t, []byte(oldCA.CertificatePEM))); err != nil {
		t.Fatalf("pre-rotation leaf did not chain to predecessor: %v", err)
	}

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+oldCA.ID+"/rotate", operator, "rotation-activate-cap-ca-03", map[string]any{
		"successor_id": successorCA.ID,
		"reason":       "CAP-CA-03 zero-downtime overlap",
	})
	if code != http.StatusOK {
		t.Fatalf("activate CA rotation = %d body=%s; want 200", code, body)
	}
	var rotation struct {
		Predecessor     servedCAAuthority `json:"predecessor"`
		Successor       servedCAAuthority `json:"successor"`
		IssuePath       string            `json:"issue_path"`
		ActiveIssuePath string            `json:"active_issue_path"`
		OverlapIssuers  []struct {
			AuthorityID string `json:"authority_id"`
			Role        string `json:"role"`
			Status      string `json:"status"`
			IssuePath   string `json:"issue_path"`
		} `json:"overlap_issuers"`
	}
	if err := json.Unmarshal(body, &rotation); err != nil {
		t.Fatalf("decode CA rotation: %v body=%s", err, body)
	}
	if rotation.Predecessor.Status != "superseded" || rotation.Successor.Status != "active" {
		t.Fatalf("rotation statuses = predecessor %q successor %q; want superseded/active", rotation.Predecessor.Status, rotation.Successor.Status)
	}
	if rotation.Successor.ReplacesID == nil || *rotation.Successor.ReplacesID != oldCA.ID {
		t.Fatalf("successor replaces_id = %v; want predecessor %s", rotation.Successor.ReplacesID, oldCA.ID)
	}
	storedPredecessor, err := h.store.GetCAAuthority(context.Background(), h.tenant, oldCA.ID)
	if err != nil {
		t.Fatalf("load projected predecessor: %v", err)
	}
	storedSuccessor, err := h.store.GetCAAuthority(context.Background(), h.tenant, successorCA.ID)
	if err != nil {
		t.Fatalf("load projected successor: %v", err)
	}
	if storedPredecessor.Status != "superseded" {
		t.Fatalf("projected predecessor status = %q; want superseded", storedPredecessor.Status)
	}
	if storedSuccessor.ReplacesID == nil || *storedSuccessor.ReplacesID != oldCA.ID {
		t.Fatalf("projected successor replaces_id = %v; want predecessor %s", storedSuccessor.ReplacesID, oldCA.ID)
	}
	if rotation.IssuePath != "/api/v1/ca/authorities/"+oldCA.ID+"/issue" || rotation.ActiveIssuePath != "/api/v1/ca/authorities/"+successorCA.ID+"/issue" {
		t.Fatalf("rotation paths = %q / %q; want predecessor and successor issue paths", rotation.IssuePath, rotation.ActiveIssuePath)
	}
	if len(rotation.OverlapIssuers) != 2 {
		t.Fatalf("overlap issuers = %+v; want predecessor and successor", rotation.OverlapIssuers)
	}

	throughStableOldURL := issueHierarchyLeaf(t, h, operator, oldCA.ID, "after.rotation.example.test", "rotation-old-after")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(throughStableOldURL.CertificatePEM)), caCertDER(t, []byte(successorCA.CertificatePEM))); err != nil {
		t.Fatalf("post-rotation leaf from predecessor URL did not chain to successor: %v", err)
	}
	throughSuccessorURL := issueHierarchyLeaf(t, h, operator, successorCA.ID, "direct.rotation.example.test", "rotation-successor-direct")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(throughSuccessorURL.CertificatePEM)), caCertDER(t, []byte(successorCA.CertificatePEM))); err != nil {
		t.Fatalf("post-rotation leaf from successor URL did not chain to successor: %v", err)
	}
	if !h.hasEvent(t, "ca.authority.rotated") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("CA rotation did not record rotation and issuance audit events")
	}
}

func TestServedCARekeyCAPCA06(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-rekey-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-rekey-approver", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "rekey root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"rekey.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "rekey-root-ceremony")
	approveCACeremony(t, h, approver, rootCeremony.ID, 1, "rekey-root-approval")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "rekey-root-create")

	intermediateSpec := map[string]any{
		"common_name":           "rekey issuing intermediate",
		"ttl_seconds":           int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"rekey.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, intermediateSpec, 1, "rekey-intermediate-ceremony")
	approveCACeremony(t, h, approver, interCeremony.ID, 1, "rekey-intermediate-approval")
	oldCA := createIntermediateCA(t, h, operator, interCeremony.ID, root.ID, intermediateSpec, "rekey-intermediate-create")

	before := issueHierarchyLeaf(t, h, operator, oldCA.ID, "before.rekey.example.test", "rekey-before")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(before.CertificatePEM)), caCertDER(t, []byte(oldCA.CertificatePEM))); err != nil {
		t.Fatalf("pre-rekey leaf did not chain to original CA: %v", err)
	}

	rekeyCeremony := createCARekeyCeremony(t, h, operator, oldCA.ID, 1, "rekey-ceremony")
	approveCACeremony(t, h, approver, rekeyCeremony.ID, 1, "rekey-approval")
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+oldCA.ID+"/rekey", operator, "rekey-activate-cap-ca-06", map[string]any{
		"ceremony_id": rekeyCeremony.ID,
		"ttl_seconds": int64((90 * 24 * time.Hour).Seconds()),
		"reason":      "CAP-CA-06 planned CA certificate renewal and re-key",
	})
	if code != http.StatusCreated {
		t.Fatalf("re-key CA authority = %d body=%s; want 201", code, body)
	}
	var rotation struct {
		Predecessor     servedCAAuthority `json:"predecessor"`
		Successor       servedCAAuthority `json:"successor"`
		IssuePath       string            `json:"issue_path"`
		ActiveIssuePath string            `json:"active_issue_path"`
	}
	if err := json.Unmarshal(body, &rotation); err != nil {
		t.Fatalf("decode CA re-key: %v body=%s", err, body)
	}
	if rotation.Predecessor.Status != "superseded" || rotation.Successor.Status != "active" {
		t.Fatalf("re-key statuses = predecessor %q successor %q; want superseded/active", rotation.Predecessor.Status, rotation.Successor.Status)
	}
	if rotation.Successor.ID == oldCA.ID || rotation.Successor.SignerHandle == oldCA.SignerHandle || rotation.Successor.CertificatePEM == oldCA.CertificatePEM {
		t.Fatalf("re-key successor did not get fresh authority material: old=%+v successor=%+v", oldCA, rotation.Successor)
	}
	if rotation.Successor.ReplacesID == nil || *rotation.Successor.ReplacesID != oldCA.ID {
		t.Fatalf("successor replaces_id = %v; want predecessor %s", rotation.Successor.ReplacesID, oldCA.ID)
	}
	if rotation.IssuePath != "/api/v1/ca/authorities/"+oldCA.ID+"/issue" || rotation.ActiveIssuePath != "/api/v1/ca/authorities/"+rotation.Successor.ID+"/issue" {
		t.Fatalf("re-key paths = %q / %q; want stable predecessor and active successor paths", rotation.IssuePath, rotation.ActiveIssuePath)
	}
	storedPredecessor, err := h.store.GetCAAuthority(context.Background(), h.tenant, oldCA.ID)
	if err != nil {
		t.Fatalf("load projected re-key predecessor: %v", err)
	}
	storedSuccessor, err := h.store.GetCAAuthority(context.Background(), h.tenant, rotation.Successor.ID)
	if err != nil {
		t.Fatalf("load projected re-key successor: %v", err)
	}
	if storedPredecessor.Status != "superseded" || storedSuccessor.ReplacesID == nil || *storedSuccessor.ReplacesID != oldCA.ID {
		t.Fatalf("projected re-key state = predecessor %+v successor %+v", storedPredecessor, storedSuccessor)
	}

	throughStableOldURL := issueHierarchyLeaf(t, h, operator, oldCA.ID, "after.rekey.example.test", "rekey-old-after")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(throughStableOldURL.CertificatePEM)), caCertDER(t, []byte(rotation.Successor.CertificatePEM))); err != nil {
		t.Fatalf("post-rekey leaf from predecessor URL did not chain to fresh CA: %v", err)
	}
	throughSuccessorURL := issueHierarchyLeaf(t, h, operator, rotation.Successor.ID, "direct.rekey.example.test", "rekey-successor-direct")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(throughSuccessorURL.CertificatePEM)), caCertDER(t, []byte(rotation.Successor.CertificatePEM))); err != nil {
		t.Fatalf("post-rekey leaf from successor URL did not chain to fresh CA: %v", err)
	}
	if !h.hasEvent(t, "ca.authority.rekeyed") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("CA re-key did not record re-key and issuance audit events")
	}
}

func TestServedCAHierarchySignsExternalIntermediateCSRRequiresCeremony(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-approver", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-approver-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	certsIssueOnly := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "leaf-issuer", []string{
		"certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "trstctl SPIRE upstream root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.org"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, token, "create_root", "", rootSpec, 1, "spire-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "spire-root-approval")
	root := createRootCA(t, h, token, ceremony.ID, rootSpec, "spire-root-create")

	spireCAKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spireCAKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "SPIRE Server CA",
	}, spireCAKey)
	if err != nil {
		t.Fatalf("create SPIRE intermediate CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	intermediateSpec := map[string]any{
		"common_name":           "SPIRE Server CA",
		"max_path_len":          0,
		"ttl_seconds":           int64((24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.org"},
		"extended_key_usages":   []string{"serverAuth"},
	}
	issueBody := map[string]any{
		"csr_pem": csrPEM,
		"spec":    intermediateSpec,
	}

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", certsIssueOnly, "spire-intermediate-csr-certs-only", issueBody)
	if code != http.StatusForbidden {
		t.Fatalf("certs:issue-only external intermediate CSR = %d body=%s; want 403 issuers:write", code, body)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-no-ceremony", issueBody)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "ceremony_id") {
		t.Fatalf("external intermediate CSR without ceremony = %d body=%s; want 422 ceremony_id", code, body)
	}

	intermediateCeremony := createCACeremonyWithCSR(t, h, token, root.ID, csrPEM, intermediateSpec, 2, "spire-intermediate-csr-ceremony")
	issueBody["ceremony_id"] = intermediateCeremony.ID

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-before-quorum", issueBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("external intermediate CSR before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+intermediateCeremony.ID+"/approvals", token, "spire-intermediate-csr-self-approval", nil)
	if code != http.StatusConflict {
		t.Fatalf("external intermediate CSR self-approval = %d body=%s; want 409 separation-of-duties refusal", code, body)
	}
	approveCACeremony(t, h, approver, intermediateCeremony.ID, 1, "spire-intermediate-csr-approval-one")

	mismatchedSpec := map[string]any{
		"common_name":           "SPIRE Server CA",
		"max_path_len":          0,
		"ttl_seconds":           int64((24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"wrong.example.org"},
		"extended_key_usages":   []string{"serverAuth"},
	}
	mismatchedCeremony := createCACeremonyWithCSR(t, h, token, root.ID, csrPEM, mismatchedSpec, 1, "spire-intermediate-csr-mismatch-ceremony")
	approveCACeremony(t, h, approver, mismatchedCeremony.ID, 1, "spire-intermediate-csr-mismatch-approval")
	mismatchedBody := map[string]any{
		"ceremony_id": mismatchedCeremony.ID,
		"csr_pem":     csrPEM,
		"spec":        intermediateSpec,
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-purpose-mismatch", mismatchedBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "purpose") {
		t.Fatalf("external intermediate CSR purpose mismatch = %d body=%s; want 409 purpose mismatch", code, body)
	}

	approveCACeremony(t, h, approverTwo, intermediateCeremony.ID, 2, "spire-intermediate-csr-approval-two")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr", issueBody)
	if code != http.StatusCreated {
		t.Fatalf("sign external intermediate CSR = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode issued intermediate: %v body=%s", err, body)
	}
	childDER := caCertDER(t, []byte(issued.CertificatePEM))
	if err := crypto.VerifyLeafSignedByCA(childDER, caCertDER(t, []byte(root.CertificatePEM))); err != nil {
		t.Fatalf("SPIRE intermediate did not verify against trstctl root: %v", err)
	}
	info, err := certinfo.Inspect(childDER)
	if err != nil {
		t.Fatalf("inspect issued SPIRE intermediate: %v", err)
	}
	if !info.IsCA {
		t.Fatal("issued SPIRE authority is not a CA certificate")
	}
	if !h.hasEvent(t, "ca.intermediate_csr.issued") {
		t.Fatal("no ca.intermediate_csr.issued event was recorded for the served SPIRE path")
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-replay-new-idem", issueBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "pending") {
		t.Fatalf("external intermediate CSR ceremony replay = %d body=%s; want 409 consumed ceremony", code, body)
	}
}

func TestServedCAHierarchyOfflineRootWorkflow(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	offlineRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(offlineRootKey.Destroy)
	rootProfile := crypto.HierarchyCAProfile{
		CommonName:          "offline airgapped root",
		MaxPathLen:          1,
		TTL:                 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"offline.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	offlineRoot, err := crypto.SelfSignedHierarchyCA(offlineRootKey, rootProfile)
	if err != nil {
		t.Fatalf("create offline root fixture: %v", err)
	}
	rootPEM := string(offlineRoot.CertificatePEM)
	rootSpec := map[string]any{
		"common_name":           rootProfile.CommonName,
		"max_path_len":          rootProfile.MaxPathLen,
		"ttl_seconds":           int64(rootProfile.TTL.Seconds()),
		"permitted_dns_domains": rootProfile.PermittedDNSDomains,
		"extended_key_usages":   rootProfile.EKUs,
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremonyWithCertificate(t, h, operator, "import_offline_root", rootPEM, rootSpec, 2, "offline-root-ceremony")

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/offline-roots", operator, "offline-root-before-quorum", map[string]any{
		"ceremony_id":     rootCeremony.ID,
		"certificate_pem": rootPEM,
		"spec":            rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("offline root import before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverOne, rootCeremony.ID, 1, "offline-root-approval-one")
	approveCACeremony(t, h, approverTwo, rootCeremony.ID, 2, "offline-root-approval-two")
	root := importOfflineRootCA(t, h, operator, rootCeremony.ID, rootPEM, rootSpec, "offline-root-import")
	if root.Kind != "root" || root.SignerHandle != "" || root.CertificatePEM == "" {
		t.Fatalf("offline root = %+v; want imported public root with no signer handle", root)
	}

	leafCSRDER := hierarchyLeafCSR(t, "root-hotpath.offline.example.test")
	leafCSRPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator, "offline-root-hotpath-issue", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("offline root hot-path leaf issue = %d body=%s; want 503 because root key is absent", code, body)
	}

	interSpec := map[string]any{
		"common_name":           "offline issuing intermediate",
		"max_path_len":          0,
		"ttl_seconds":           int64((30 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"offline.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, operator, "create_offline_intermediate", root.ID, interSpec, 2, "offline-intermediate-ceremony")
	approveCACeremony(t, h, approverOne, interCeremony.ID, 1, "offline-intermediate-approval-one")
	approveCACeremony(t, h, approverTwo, interCeremony.ID, 2, "offline-intermediate-approval-two")
	csr := createOfflineIntermediateCSR(t, h, operator, root.ID, interCeremony.ID, interSpec, "offline-intermediate-csr")
	if csr.SignerHandle == "" || csr.ParentID != root.ID || csr.CSRPem == "" {
		t.Fatalf("offline intermediate CSR = %+v; want signer handle, parent id, and CSR PEM", csr)
	}
	csrDER := csrDERFromPEMForTest(t, csr.CSRPem)
	csrInfo, err := crypto.InspectCSR(csrDER)
	if err != nil {
		t.Fatalf("inspect offline intermediate CSR: %v", err)
	}
	if csrInfo.CommonName != interSpec["common_name"] {
		t.Fatalf("offline intermediate CSR CN = %q, want %q", csrInfo.CommonName, interSpec["common_name"])
	}
	offlineIntermediate, err := crypto.SignIntermediateHierarchyCAFromCSR(offlineRoot.CertificateDER, offlineRootKey, csrDER, crypto.HierarchyCAProfile{
		CommonName:          "offline issuing intermediate",
		MaxPathLen:          0,
		TTL:                 30 * 24 * time.Hour,
		PermittedDNSDomains: []string{"offline.example.test"},
		EKUs:                []string{"serverAuth"},
	})
	if err != nil {
		t.Fatalf("offline-sign intermediate CSR: %v", err)
	}
	inter := importOfflineIntermediateCA(t, h, operator, root.ID, interCeremony.ID, string(offlineIntermediate.CertificatePEM), interSpec, "offline-intermediate-import")
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID || inter.SignerHandle != csr.SignerHandle {
		t.Fatalf("offline intermediate = %+v; want child of offline root bound to CSR signer handle %q", inter, csr.SignerHandle)
	}

	leafCSRDER = hierarchyLeafCSR(t, "leaf.offline.example.test")
	leafCSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/issue", operator, "offline-intermediate-leaf", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue leaf from offline-root intermediate = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode offline-root leaf: %v body=%s", err, body)
	}
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(issued.CertificatePEM)), caCertDER(t, []byte(inter.CertificatePEM))); err != nil {
		t.Fatalf("offline-root intermediate did not sign served leaf: %v", err)
	}
	if !h.hasEvent(t, "ca.root.created") || !h.hasEvent(t, "ca.intermediate_csr.issued") || !h.hasEvent(t, "ca.intermediate.created") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("offline-root workflow did not emit the expected CA hierarchy events")
	}
}

func TestServedCAHierarchyImportsExistingSignerBackedChain(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	externalRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(externalRootKey.Destroy)
	rootProfile := crypto.HierarchyCAProfile{
		CommonName:          "customer existing root",
		MaxPathLen:          1,
		TTL:                 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"imported.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	externalRoot, err := crypto.SelfSignedHierarchyCA(externalRootKey, rootProfile)
	if err != nil {
		t.Fatalf("create external root fixture: %v", err)
	}

	client := h.signer.Client()
	importedHandle := "imported-existing-intermediate"
	importedSigner, err := client.GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, importedHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.authz)
	if err != nil {
		t.Fatalf("pre-provision imported CA signer handle: %v", err)
	}
	wrongHandle := "imported-existing-wrong"
	wrongSigner, err := client.GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, wrongHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.authz)
	if err != nil || wrongSigner == nil {
		t.Fatalf("pre-provision wrong signer handle: %v", err)
	}
	interProfile := crypto.HierarchyCAProfile{
		CommonName:          "customer existing issuing ca",
		MaxPathLen:          0,
		TTL:                 30 * 24 * time.Hour,
		PermittedDNSDomains: []string{"imported.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	existingIntermediate, err := crypto.SignIntermediateHierarchyCA(externalRoot.CertificateDER, externalRootKey, importedSigner.Public(), interProfile)
	if err != nil {
		t.Fatalf("create externally signed intermediate fixture: %v", err)
	}
	chainPEM := string(existingIntermediate.CertificatePEM) + string(externalRoot.CertificatePEM)
	interSpec := map[string]any{
		"common_name":           interProfile.CommonName,
		"max_path_len":          interProfile.MaxPathLen,
		"ttl_seconds":           int64(interProfile.TTL.Seconds()),
		"permitted_dns_domains": interProfile.PermittedDNSDomains,
		"extended_key_usages":   interProfile.EKUs,
		"signature_algorithm":   "ecdsa-p256",
	}

	wrongCeremony := createImportExistingCACeremony(t, h, operator, chainPEM, wrongHandle, interSpec, 1, "byo-ca-wrong-ceremony")
	approveCACeremony(t, h, approverOne, wrongCeremony.ID, 1, "byo-ca-wrong-approval")
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", operator, "byo-ca-wrong-import", map[string]any{
		"ceremony_id":     wrongCeremony.ID,
		"certificate_pem": chainPEM,
		"signer_handle":   wrongHandle,
		"spec":            interSpec,
	})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "public key") {
		t.Fatalf("import existing CA with wrong signer = %d body=%s; want 422 public-key mismatch", code, body)
	}

	ceremony := createImportExistingCACeremony(t, h, operator, chainPEM, importedHandle, interSpec, 2, "byo-ca-ceremony")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", operator, "byo-ca-before-quorum", map[string]any{
		"ceremony_id":     ceremony.ID,
		"certificate_pem": chainPEM,
		"signer_handle":   importedHandle,
		"spec":            interSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("import existing CA before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "byo-ca-approval-one")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "byo-ca-approval-two")
	imported := importExistingCA(t, h, operator, ceremony.ID, chainPEM, importedHandle, interSpec, "byo-ca-import")
	if imported.Kind != "intermediate" || imported.SignerHandle != importedHandle || imported.CommonName != interProfile.CommonName {
		t.Fatalf("imported CA = %+v; want signer-backed existing intermediate", imported)
	}
	if strings.Contains(imported.CertificatePEM, "PRIVATE KEY") || strings.Count(imported.CertificatePEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("imported CA certificate response leaked key material or lost chain: %q", imported.CertificatePEM)
	}

	leafCSRDER := hierarchyLeafCSR(t, "leaf.imported.example.test")
	leafCSRPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+imported.ID+"/issue", operator, "byo-ca-leaf", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue leaf from imported existing CA = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode imported-CA leaf: %v body=%s", err, body)
	}
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(issued.CertificatePEM)), caCertDER(t, []byte(imported.CertificatePEM))); err != nil {
		t.Fatalf("imported existing CA did not sign served leaf: %v", err)
	}
	if !h.hasEvent(t, "ca.authority.imported") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("imported existing CA workflow did not emit the expected events")
	}
}

type servedCACeremony struct {
	ID        string `json:"id"`
	Purpose   string `json:"purpose"`
	Threshold int    `json:"threshold"`
	Status    string `json:"status"`
	Approvals int    `json:"approvals"`
}

type servedCAAuthority struct {
	ID             string  `json:"id"`
	ParentID       *string `json:"parent_id"`
	CommonName     string  `json:"common_name"`
	Kind           string  `json:"kind"`
	Status         string  `json:"status"`
	CertificatePEM string  `json:"certificate_pem"`
	SignerHandle   string  `json:"signer_handle"`
	ReplacesID     *string `json:"replaces_id"`
}

type servedCAIssuedLeaf struct {
	CertificatePEM string `json:"certificate_pem"`
	Serial         string `json:"serial"`
}

type servedCAIntermediateCSR struct {
	CeremonyID   string `json:"ceremony_id"`
	ParentID     string `json:"parent_id"`
	CSRPem       string `json:"csr_pem"`
	SignerHandle string `json:"signer_handle"`
}

func createCACeremony(t *testing.T, h *servedHarness, token, operation, parentID string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	body := map[string]any{"operation": operation, "threshold": threshold, "spec": spec}
	if parentID != "" {
		body["parent_id"] = parentID
	}
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, body)
	if code != http.StatusCreated {
		t.Fatalf("create %s ceremony = %d body=%s; want 201", operation, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode %s ceremony: %v got=%+v body=%s", operation, err, got, raw)
	}
	return got
}

func createCACeremonyWithCertificate(t *testing.T, h *servedHarness, token, operation, certificatePEM string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation":       operation,
		"certificate_pem": certificatePEM,
		"threshold":       threshold,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create %s ceremony = %d body=%s; want 201", operation, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode %s ceremony: %v got=%+v body=%s", operation, err, got, raw)
	}
	return got
}

func createImportExistingCACeremony(t *testing.T, h *servedHarness, token, certificatePEM, signerHandle string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation":       "import_existing_ca",
		"certificate_pem": certificatePEM,
		"signer_handle":   signerHandle,
		"threshold":       threshold,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create import_existing_ca ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode import_existing_ca ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createCACeremonyWithCSR(t *testing.T, h *servedHarness, token, parentID, csrPEM string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation": "issue_intermediate_csr",
		"parent_id": parentID,
		"csr_pem":   csrPEM,
		"threshold": threshold,
		"spec":      spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create issue_intermediate_csr ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode issue_intermediate_csr ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createCARekeyCeremony(t *testing.T, h *servedHarness, token, authorityID string, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation":    "rekey_ca",
		"authority_id": authorityID,
		"threshold":    threshold,
		"spec": map[string]any{
			"common_name": "re-key existing CA",
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create rekey_ca ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode rekey_ca ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importExistingCA(t *testing.T, h *servedHarness, token, ceremonyID, certificatePEM, signerHandle string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"signer_handle":   signerHandle,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import existing CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode imported existing CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func issueHierarchyLeaf(t *testing.T, h *servedHarness, token, authorityID, dnsName, idem string) servedCAIssuedLeaf {
	t.Helper()
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: hierarchyLeafCSR(t, dnsName)}))
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+authorityID+"/issue", token, idem, map[string]any{
		"csr_pem":     csrPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue hierarchy leaf from %s = %d body=%s; want 201", authorityID, code, raw)
	}
	var got servedCAIssuedLeaf
	if err := json.Unmarshal(raw, &got); err != nil || got.CertificatePEM == "" || got.Serial == "" {
		t.Fatalf("decode issued hierarchy leaf: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importOfflineRootCA(t *testing.T, h *servedHarness, token, ceremonyID, certificatePEM string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/offline-roots", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import offline root CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode offline root CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createOfflineIntermediateCSR(t *testing.T, h *servedHarness, token, parentID, ceremonyID string, spec map[string]any, idem string) servedCAIntermediateCSR {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+parentID+"/offline-intermediates/csr", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create offline intermediate CSR = %d body=%s; want 201", code, raw)
	}
	var got servedCAIntermediateCSR
	if err := json.Unmarshal(raw, &got); err != nil || got.CSRPem == "" || got.SignerHandle == "" {
		t.Fatalf("decode offline intermediate CSR: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importOfflineIntermediateCA(t *testing.T, h *servedHarness, token, parentID, ceremonyID, certificatePEM string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+parentID+"/offline-intermediates", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import offline intermediate CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode offline intermediate CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func approveCACeremony(t *testing.T, h *servedHarness, token, ceremonyID string, wantApprovals int, idem string) {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremonyID+"/approvals", token, idem, nil)
	if code != http.StatusOK {
		t.Fatalf("approve ceremony %s = %d body=%s; want 200", ceremonyID, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.Approvals != wantApprovals {
		t.Fatalf("decode approval count: %v got=%+v body=%s", err, got, raw)
	}
}

func hierarchyLeafCSR(t *testing.T, dnsName string) []byte {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: dnsName,
		DNSNames:   []string{dnsName},
	}, leafKey)
	if err != nil {
		t.Fatalf("create hierarchy leaf CSR: %v", err)
	}
	return csrDER
}

func csrDERFromPEMForTest(t *testing.T, csrPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM = %q, want CERTIFICATE REQUEST block", csrPEM)
	}
	return block.Bytes
}

func createRootCA(t *testing.T, h *servedHarness, token, ceremonyID string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create root CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode root CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createIntermediateCA(t *testing.T, h *servedHarness, token, ceremonyID, parentID string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/intermediates", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"parent_id":   parentID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create intermediate CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode intermediate CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}
