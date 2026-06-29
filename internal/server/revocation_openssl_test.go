package server

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

func TestServedRevocationOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_OPENSSL_OCSP") != "" || os.Getenv("TRSTCTL_REQUIRE_OPENSSL_CRL") != "" {
			t.Fatalf("openssl is required by TRSTCTL_REQUIRE_OPENSSL_* but was not found: %v", err)
		}
		t.Skipf("openssl not found: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "OpenSSL Revocation Interop Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "revoked.openssl.test",
		DNSNames:   []string{"revoked.openssl.test"},
	}, leafKey)
	if err != nil {
		t.Fatalf("create leaf CSR: %v", err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://127.0.0.1/crl"},
		OCSPServers:           []string{"http://127.0.0.1/ocsp"},
	})
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect leaf: %v", err)
	}

	responderKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate OCSP responder key: %v", err)
	}
	t.Cleanup(responderKey.Destroy)

	revokedAt := now.Add(-time.Minute)
	st := &opensslRevocationStore{
		issued: store.IssuedCert{
			TenantID:   publicCRLTestTenant,
			CAID:       IssuingCAID(),
			Serial:     leafInfo.SerialNumber,
			IssuedAt:   now.Add(-time.Hour),
			RevokedAt:  &revokedAt,
			ReasonCode: 1,
		},
	}
	svc := &revocationService{
		store:      st,
		caID:       IssuingCAID(),
		caSigner:   caKey,
		caCertDER:  caDER,
		ocspSigner: responderKey,
		ocspCache:  newOCSPResponseCache(),
		now:        func() time.Time { return now },
	}
	if _, err := svc.generateCRL(ctx, publicCRLTestTenant); err != nil {
		t.Fatalf("generate CRL: %v", err)
	}

	mux := http.NewServeMux()
	svc.routes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.pem")
	leafPath := filepath.Join(tmp, "leaf.pem")
	crlDERPath := filepath.Join(tmp, "served.crl.der")
	crlPEMPath := filepath.Join(tmp, "served.crl.pem")
	writePEMBlock(t, caPath, "CERTIFICATE", caDER)
	writePEMBlock(t, leafPath, "CERTIFICATE", leafDER)

	servedCRLDER := fetchServedCRL(t, server, publicCRLTestTenant)
	if err := os.WriteFile(crlDERPath, servedCRLDER, 0o600); err != nil {
		t.Fatalf("write served CRL DER: %v", err)
	}
	writePEMBlock(t, crlPEMPath, "X509 CRL", servedCRLDER)

	crlText := runOpenSSL(t, openssl, "crl", "-inform", "DER", "-in", crlDERPath, "-noout", "-text")
	if !strings.Contains(strings.ToLower(crlText), strings.ToLower(leafInfo.SerialNumber)) {
		t.Fatalf("openssl crl output did not include revoked serial %s:\n%s", leafInfo.SerialNumber, crlText)
	}

	verifyOut, verifyErr := runOpenSSLMaybeError(openssl, "verify", "-CAfile", caPath, "-crl_check", "-CRLfile", crlPEMPath, leafPath)
	if verifyErr == nil {
		t.Fatalf("openssl verify accepted revoked leaf; output:\n%s", verifyOut)
	}
	if !strings.Contains(strings.ToLower(verifyOut), "certificate revoked") {
		t.Fatalf("openssl verify did not report certificate revoked; err=%v output:\n%s", verifyErr, verifyOut)
	}

	ocspOut := runOpenSSL(t, openssl,
		"ocsp",
		"-issuer", caPath,
		"-cert", leafPath,
		"-url", server.URL+"/ocsp/"+publicCRLTestTenant,
		"-CAfile", caPath,
		"-resp_text",
		"-no_nonce",
	)
	if !strings.Contains(strings.ToLower(ocspOut), "cert status: revoked") {
		t.Fatalf("openssl ocsp output did not report revoked status:\n%s", ocspOut)
	}
}

func writePEMBlock(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if pemBytes == nil {
		t.Fatalf("encode %s PEM", blockType)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fetchServedCRL(t *testing.T, server *httptest.Server, tenantID string) []byte {
	t.Helper()
	resp, err := server.Client().Get(server.URL + "/crl/" + tenantID)
	if err != nil {
		t.Fatalf("GET served CRL: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET served CRL status = %d, want 200: %s", resp.StatusCode, body)
	}
	der, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read served CRL body: %v", err)
	}
	return der
}

func runOpenSSL(t *testing.T, openssl string, args ...string) string {
	t.Helper()
	out, err := runOpenSSLMaybeError(openssl, args...)
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func runOpenSSLMaybeError(openssl string, args ...string) (string, error) {
	out, err := exec.Command(openssl, args...).CombinedOutput()
	return string(out), err
}

type opensslRevocationStore struct {
	issued         store.IssuedCert
	responder      store.OCSPResponder
	responderFound bool
	crls           []store.CRL
}

func (f *opensslRevocationStore) LookupIssuedCert(_ context.Context, tenantID, caID, serial string) (store.IssuedCert, bool, error) {
	if f.issued.TenantID == tenantID && f.issued.CAID == caID && f.issued.Serial == serial {
		return f.issued, true, nil
	}
	return store.IssuedCert{}, false, nil
}

func (f *opensslRevocationStore) HasIssuedCerts(_ context.Context, tenantID, caID string) (bool, error) {
	return f.issued.TenantID == tenantID && f.issued.CAID == caID && f.issued.Serial != "", nil
}

func (f *opensslRevocationStore) ListRevokedCerts(_ context.Context, tenantID, caID string) ([]store.IssuedCert, error) {
	if f.issued.TenantID != tenantID || f.issued.CAID != caID || !f.issued.Revoked() {
		return nil, nil
	}
	return []store.IssuedCert{f.issued}, nil
}

func (f *opensslRevocationStore) NextCRLNumber(context.Context, string, string) (int64, error) {
	return int64(len(f.crls) + 1), nil
}

func (f *opensslRevocationStore) InsertCRL(_ context.Context, crl store.CRL) error {
	f.crls = append(f.crls, crl)
	return nil
}

func (f *opensslRevocationStore) TenantsWithIssuedCerts(context.Context, string) ([]string, error) {
	return []string{publicCRLTestTenant}, nil
}

func (f *opensslRevocationStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return false, nil
}

func (f *opensslRevocationStore) LatestCRL(context.Context, string, string) (store.CRL, bool, error) {
	return latestFullCRL(f.crls)
}

func (f *opensslRevocationStore) LatestCRLShard(_ context.Context, _ string, _ string, shardIndex int) (store.CRL, bool, error) {
	return latestShardCRL(f.crls, shardIndex)
}

func (f *opensslRevocationStore) LatestDeltaCRL(_ context.Context, _ string, _ string, baseNumber int64) (store.CRL, bool, error) {
	return latestDeltaCRL(f.crls, baseNumber)
}

func (f *opensslRevocationStore) ListLatestCRLArtifacts(context.Context, string, string) ([]store.CRL, error) {
	return latestCRLArtifacts(f.crls), nil
}

func (f *opensslRevocationStore) ActiveOCSPResponder(_ context.Context, tenantID, caID string) (store.OCSPResponder, bool, error) {
	if f.responderFound && f.responder.TenantID == tenantID && f.responder.CAID == caID {
		return f.responder, true, nil
	}
	return store.OCSPResponder{}, false, nil
}

func (f *opensslRevocationStore) UpsertOCSPResponder(_ context.Context, responder store.OCSPResponder) error {
	f.responder = responder
	f.responderFound = true
	return nil
}
