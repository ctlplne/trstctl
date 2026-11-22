// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pqc"
)

func requireServedOpenSSLMLDSA(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("stock OpenSSL is required for the post-quantum hierarchy proof: %v", err)
	}
	out, err := exec.Command(path, "list", "-signature-algorithms").CombinedOutput() // #nosec G204 -- LookPath-resolved OpenSSL with fixed arguments
	if err != nil || !bytes.Contains(out, []byte("ML-DSA-65")) {
		t.Skipf("OpenSSL at %s lacks ML-DSA-65: %v", path, err)
	}
	return path
}

func runServedOpenSSL(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput() // #nosec G204 -- LookPath-resolved OpenSSL; arguments are test-owned paths and flags
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func fetchServedBytes(t *testing.T, url, contentType string, body []byte) []byte {
	t.Helper()
	var response *http.Response
	var err error
	if body == nil {
		response, err = http.Get(url) // #nosec G107 -- the served test harness URL
	} else {
		response, err = http.Post(url, contentType, bytes.NewReader(body)) // #nosec G107 -- the served test harness URL
	}
	if err != nil {
		t.Fatalf("fetch %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("fetch %s = HTTP %d read %v", url, response.StatusCode, err)
	}
	return raw
}

// A26/A27 (card P10): an ML-DSA-65 root and intermediate are minted through
// the same two-custodian ceremonies as the classical hierarchy, with the CA
// keys held only in the isolated signer. They issue an ECDSA leaf and a pure
// ML-DSA leaf whose chain, the authority's served CRL and its OCSP responses
// verify with stock OpenSSL, while a classical hierarchy keeps issuing beside
// them; a ceremony reviewed for ecdsa-p256 cannot mint the post-quantum root.
func TestServedPostQuantumHierarchyBesideClassical(t *testing.T) {
	ossl := requireServedOpenSSLMLDSA(t)
	dir := t.TempDir()
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
		d.HierarchyRevocationBaseURL = "https://status.example.test"
		d.LicensedCSRParser = pqc.ParsePureMLDSACSR
		d.LicensedCSRInspector = pqc.InspectHybridCSR
		d.LicensedLeafSigner = pqc.SignLicensedLeafFromCSRWithProfile
		d.PreparedSubjectLeafSigner = pqc.SignPQCLeafFromCSRWithPreparation
	})
	registerServedTenant(t, h, "post-quantum pilot tenant")
	ctx := context.Background()
	opener := seedServedAPIToken(t, ctx, h.store, h.tenant, "pq-operator", []string{"issuers:write", "issuers:read", "certs:issue", "certs:read", "identities:write"})
	custodianOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "pq-custodian-one", []string{"issuers:write", "issuers:read"})
	custodianTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "pq-custodian-two", []string{"issuers:write", "issuers:read"})
	approveBoth := func(ceremonyID, idem string) {
		approveCACeremony(t, h, custodianOne, ceremonyID, 1, idem+"-one")
		approveCACeremony(t, h, custodianTwo, ceremonyID, 2, idem+"-two")
	}
	type authorityReadback struct {
		servedCAAuthority
		KeyAlgorithm string `json:"key_algorithm"`
	}
	readAuthority := func(id string) authorityReadback {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/ca/authorities", opener, "", nil)
		if code != http.StatusOK {
			t.Fatalf("list authorities = %d %s", code, body)
		}
		var listed struct {
			Items []authorityReadback `json:"items"`
		}
		if err := json.Unmarshal(body, &listed); err != nil {
			t.Fatal(err)
		}
		for _, item := range listed.Items {
			if item.ID == id {
				return item
			}
		}
		t.Fatalf("authority %s is not listed: %s", id, body)
		return authorityReadback{}
	}

	pqRootSpec := map[string]any{
		"common_name": "pq pilot root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"pq.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ML-DSA-65",
	}
	// A ceremony reviewed for the classical key cannot mint the ML-DSA root.
	classicalReview := map[string]any{}
	for k, v := range pqRootSpec {
		classicalReview[k] = v
	}
	classicalReview["signature_algorithm"] = "ecdsa-p256"
	reviewedClassical := createCACeremony(t, h, opener, "create_root", "", classicalReview, 2, "pq-root-classical-review")
	approveBoth(reviewedClassical.ID, "pq-root-classical-review")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", opener, "pq-root-under-classical-review",
		map[string]any{"ceremony_id": reviewedClassical.ID, "spec": pqRootSpec}); code != http.StatusConflict {
		t.Fatalf("ML-DSA root under a ceremony reviewed for ecdsa-p256 = %d %s; want 409", code, body)
	}

	pqRootCeremony := createCACeremony(t, h, opener, "create_root", "", pqRootSpec, 2, "pq-root-ceremony")
	approveBoth(pqRootCeremony.ID, "pq-root-approval")
	pqRoot := createRootCA(t, h, opener, pqRootCeremony.ID, pqRootSpec, "pq-root-create")
	if got := readAuthority(pqRoot.ID); got.KeyAlgorithm != "ml-dsa-65" || got.Kind != "root" || got.SignerHandle == "" {
		t.Fatalf("post-quantum root readback = %+v; want a signer-held ml-dsa-65 root", got)
	}
	pqInterSpec := map[string]any{
		"common_name": "pq pilot issuing ca", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"pq.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ml-dsa-65",
	}
	pqInterCeremony := createCACeremony(t, h, opener, "create_intermediate", pqRoot.ID, pqInterSpec, 2, "pq-inter-ceremony")
	approveBoth(pqInterCeremony.ID, "pq-inter-approval")
	pqInter := createIntermediateCA(t, h, opener, pqInterCeremony.ID, pqRoot.ID, pqInterSpec, "pq-inter-create")
	if got := readAuthority(pqInter.ID); got.KeyAlgorithm != "ml-dsa-65" || got.ParentID == nil || *got.ParentID != pqRoot.ID {
		t.Fatalf("post-quantum intermediate readback = %+v", got)
	}
	// B5-4: creating the authority queued its first publication; delivering it
	// provisions the OCSP responder before any leaf exists, so the status
	// endpoints answer honestly from the start: "not published yet" is a 404,
	// never the 502 the lab saw while the responder did not exist.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain after the intermediate's creation: %v", err)
	}
	var undelivered int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='revocation.crl.publish' AND delivered_at IS NULL`, h.tenant).Scan(&undelivered); err != nil || undelivered != 0 {
		t.Fatalf("creation-time CRL publications undelivered = %d (%v); want every one delivered", undelivered, err)
	}
	statusAt := func(when string) int {
		t.Helper()
		response, err := http.Get(h.ts.URL + "/crl/" + h.tenant + "/authorities/" + pqInter.ID) // #nosec G107 -- served test harness URL
		if err != nil {
			t.Fatalf("fetch CRL %s: %v", when, err)
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusBadGateway {
			t.Fatalf("CRL %s = 502: the authority's status surface is not provisioned", when)
		}
		return response.StatusCode
	}
	if code := statusAt("before any leaf"); code != http.StatusNotFound {
		t.Fatalf("CRL before any leaf = %d; want 404 (nothing issued, nothing published)", code)
	}

	// The classical hierarchy runs beside it, through the same ceremonies.
	classicalRootSpec := map[string]any{
		"common_name": "classical root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"classic.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	classicalRootCeremony := createCACeremony(t, h, opener, "create_root", "", classicalRootSpec, 2, "classical-root-ceremony")
	approveBoth(classicalRootCeremony.ID, "classical-root-approval")
	classicalRoot := createRootCA(t, h, opener, classicalRootCeremony.ID, classicalRootSpec, "classical-root-create")
	classicalInterSpec := map[string]any{
		"common_name": "classical issuing ca", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"classic.example.test"}, "extended_key_usages": []string{"serverAuth"},
	}
	classicalInterCeremony := createCACeremony(t, h, opener, "create_intermediate", classicalRoot.ID, classicalInterSpec, 2, "classical-inter-ceremony")
	approveBoth(classicalInterCeremony.ID, "classical-inter-approval")
	classicalInter := createIntermediateCA(t, h, opener, classicalInterCeremony.ID, classicalRoot.ID, classicalInterSpec, "classical-inter-create")
	if got := readAuthority(classicalInter.ID); got.KeyAlgorithm != "ecdsa-p256" {
		t.Fatalf("classical intermediate readback = %+v", got)
	}

	issue := func(authorityID, csrPEM, idem string) (leafDER []byte, serial string) {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+authorityID+"/issue", opener, idem,
			map[string]any{"csr_pem": csrPEM, "ttl_seconds": int64((24 * time.Hour).Seconds())})
		if code != http.StatusCreated {
			t.Fatalf("issue under %s = %d %s", authorityID, code, body)
		}
		var issued servedCAIssuedLeaf
		if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" {
			t.Fatalf("decode issued leaf: %v %s", err, body)
		}
		return caCertDER(t, []byte(issued.CertificatePEM)), issued.Serial
	}
	ecdsaKey, err := h.signer.Client().GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "host.pq.example.test", DNSNames: []string{"host.pq.example.test"}}, ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaLeaf, ecdsaSerial := issue(pqInter.ID, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: ecdsaCSR})), "pq-ecdsa-leaf")
	pqSubject, err := pqc.GenerateKey(pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pqSubject.Destroy)
	pqCSR, err := crypto.CreateOpaqueCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "pure.pq.example.test", DNSNames: []string{"pure.pq.example.test"}}, pqc.MLDSA65OID, pqSubject)
	if err != nil {
		t.Fatal(err)
	}
	pqLeaf, _ := issue(pqInter.ID, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: pqCSR})), "pq-mldsa-leaf")
	// The lab's window: leaves issued, their publication intent not yet
	// delivered. The read must not be a 502.
	statusAt("after issuance, before the publication delivered")
	pqInterDER := caCertDER(t, []byte(pqInter.CertificatePEM))
	for _, leaf := range [][]byte{ecdsaLeaf, pqLeaf} {
		if err := crypto.VerifyLeafSignedByCA(leaf, pqInterDER); err != nil {
			t.Fatalf("leaf is not signed by the ML-DSA intermediate: %v", err)
		}
	}
	if info, err := certinfo.Inspect(pqLeaf); err != nil || !strings.Contains(strings.ToUpper(info.KeyAlgorithm), "ML-DSA") {
		t.Fatalf("pure leaf key algorithm = %+v err=%v; want ML-DSA", info, err)
	}
	classicalKey, err := h.signer.Client().GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	classicalCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "host.classic.example.test", DNSNames: []string{"host.classic.example.test"}}, classicalKey)
	if err != nil {
		t.Fatal(err)
	}
	classicalLeaf, _ := issue(classicalInter.ID, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: classicalCSR})), "classical-leaf")
	if err := crypto.VerifyLeafSignedByCA(classicalLeaf, caCertDER(t, []byte(classicalInter.CertificatePEM))); err != nil {
		t.Fatalf("classical hierarchy stopped issuing beside the post-quantum one: %v", err)
	}

	// Stock OpenSSL verifies the post-quantum chain for both leaves.
	writeFile := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pqRootDER := caCertDER(t, []byte(pqRoot.CertificatePEM))
	rootPEM := writeFile("pq-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pqRootDER}))
	interPEM := writeFile("pq-inter.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pqInterDER}))
	chainPEM := writeFile("pq-chain.pem", append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pqRootDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pqInterDER})...))
	for name, leaf := range map[string][]byte{"ecdsa-leaf.pem": ecdsaLeaf, "pq-leaf.pem": pqLeaf} {
		leafPEM := writeFile(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
		if out := runServedOpenSSL(t, ossl, "verify", "-CAfile", rootPEM, "-untrusted", interPEM, leafPEM); !strings.Contains(out, ": OK") {
			t.Fatalf("openssl verify %s: %s", name, out)
		}
	}

	// The authority's served CRL and OCSP carry the ML-DSA CA's own signature.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("publish the initial CRL: %v", err)
	}
	crlURL := h.ts.URL + "/crl/" + h.tenant + "/authorities/" + pqInter.ID
	ocspURL := h.ts.URL + "/ocsp/" + h.tenant + "/authorities/" + pqInter.ID
	crlDER := fetchServedBytes(t, crlURL, "", nil)
	if info, err := crypto.ParseCRL(crlDER, pqInterDER); err != nil || protoContains(info.RevokedSerials, ecdsaSerial) {
		t.Fatalf("initial served CRL = %+v err=%v", info, err)
	}
	crlPath := writeFile("pq.crl", crlDER)
	if out := runServedOpenSSL(t, ossl, "crl", "-inform", "DER", "-in", crlPath, "-CAfile", interPEM, "-noout"); !strings.Contains(out, "verify OK") {
		t.Fatalf("openssl crl verify: %q", out)
	}
	ocspRequest, err := crypto.BuildOCSPRequestForSerial(pqInterDER, ecdsaSerial)
	if err != nil {
		t.Fatal(err)
	}
	ocspDER := fetchServedBytes(t, ocspURL, "application/ocsp-request", ocspRequest)
	if status, err := crypto.ParseOCSPResponse(ocspDER, pqInterDER); err != nil || status.Status != crypto.OCSPGood {
		t.Fatalf("served OCSP before revocation = %+v err=%v", status, err)
	}
	ocspPath := writeFile("pq-good.ocsp", ocspDER)
	if out := runServedOpenSSL(t, ossl, "ocsp", "-respin", ocspPath, "-issuer", interPEM, "-CAfile", chainPEM, "-no_nonce"); !strings.Contains(out, "Response verify OK") {
		t.Fatalf("openssl ocsp verify: %s", out)
	}

	// Revoke the ECDSA leaf under the post-quantum authority.
	ecdsaInfo, err := certinfo.Inspect(ecdsaLeaf)
	if err != nil {
		t.Fatal(err)
	}
	inventoried, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, ecdsaInfo.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("leaf under the post-quantum authority is not inventoried: %v", err)
	}
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", opener, "pq-leaf-revoke",
		map[string]any{"certificate_ids": []string{inventoried.ID}, "reason": "keyCompromise"}); code != http.StatusOK || !strings.Contains(string(body), `"total_revoked":1`) {
		t.Fatalf("revoke under the post-quantum authority = %d %s", code, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("publish the revocation: %v", err)
	}
	revokedCRL := fetchServedBytes(t, crlURL, "", nil)
	if info, err := crypto.ParseCRL(revokedCRL, pqInterDER); err != nil || !protoContains(info.RevokedSerials, ecdsaSerial) {
		t.Fatalf("served CRL after revocation = %+v err=%v", info, err)
	}
	revokedCRLPath := writeFile("pq-revoked.crl", revokedCRL)
	if out := runServedOpenSSL(t, ossl, "crl", "-inform", "DER", "-in", revokedCRLPath, "-CAfile", interPEM, "-noout"); !strings.Contains(out, "verify OK") {
		t.Fatalf("openssl crl verify after revocation: %q", out)
	}
	revokedOCSP := fetchServedBytes(t, ocspURL, "application/ocsp-request", ocspRequest)
	if status, err := crypto.ParseOCSPResponse(revokedOCSP, pqInterDER); err != nil || status.Status != crypto.OCSPRevoked {
		t.Fatalf("served OCSP after revocation = %+v err=%v", status, err)
	}
	revokedOCSPPath := writeFile("pq-revoked.ocsp", revokedOCSP)
	if out := runServedOpenSSL(t, ossl, "ocsp", "-respin", revokedOCSPPath, "-issuer", interPEM, "-CAfile", chainPEM, "-no_nonce", "-resp_text"); !strings.Contains(out, "Response verify OK") || !strings.Contains(out, "revoked") {
		t.Fatalf("openssl ocsp verify after revocation: %s", out)
	}
}
