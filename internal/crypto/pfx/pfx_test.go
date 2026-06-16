package pfx_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pfx"
)

// credential mints a real PEM key + cert chain via the crypto boundary.
func credential(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	ca, err := mtls.NewCA("pfx test CA")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("workload.local")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSR(csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := id.Save(filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")); err != nil {
		t.Fatal(err)
	}
	certPEM, _ = os.ReadFile(filepath.Join(dir, "c.pem"))
	keyPEM, _ = os.ReadFile(filepath.Join(dir, "k.pem"))
	return certPEM, keyPEM
}

// TestEncodeProducesImportablePKCS12 checks that Encode yields a valid PKCS#12
// that decodes back to the same key and leaf — i.e. exactly what
// PFXImportCertStore consumes on Windows.
func TestEncodeProducesImportablePKCS12(t *testing.T) {
	certPEM, keyPEM := credential(t)
	blob, err := pfx.Encode(keyPEM, certPEM, "transient-pw")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	key, leaf, cas, err := pkcs12.DecodeChain(blob, "transient-pw")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if key == nil {
		t.Error("decoded PFX has no private key")
	}
	if leaf == nil || leaf.Subject.CommonName != "workload.local" {
		t.Errorf("decoded leaf = %v, want CN=workload.local", leaf)
	}
	if len(cas) == 0 {
		t.Error("decoded PFX carries no CA certificate (chain not preserved)")
	}
}

// TestEncodeTransientUsesAFreshPassword: the transient password is random and
// actually protects the blob (the returned password decodes it).
func TestEncodeTransientUsesAFreshPassword(t *testing.T) {
	certPEM, keyPEM := credential(t)
	blob1, pw1, err := pfx.EncodeTransient(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, pw2, err := pfx.EncodeTransient(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if pw1 == "" || pw1 == pw2 {
		t.Errorf("transient passwords not fresh: %q vs %q", pw1, pw2)
	}
	if _, _, _, err := pkcs12.DecodeChain(blob1, pw1); err != nil {
		t.Errorf("returned password does not open the blob: %v", err)
	}
}

// TestEncodeRejectsBadInput: malformed key or cert is reported, not panicked.
func TestEncodeRejectsBadInput(t *testing.T) {
	certPEM, keyPEM := credential(t)
	if _, err := pfx.Encode(nil, certPEM, "x"); err == nil {
		t.Error("Encode with no key succeeded, want error")
	}
	if _, err := pfx.Encode(keyPEM, []byte("not a pem"), "x"); err == nil {
		t.Error("Encode with no certificate succeeded, want error")
	}
}
