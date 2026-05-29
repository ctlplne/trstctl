package destination_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"certctl.io/certctl/internal/agent/destination"
	"certctl.io/certctl/internal/agent/destination/softtoken"
	"certctl.io/certctl/internal/crypto/mtls"
)

// makeCredential mints a real key + certificate via the crypto boundary and
// returns them as a destination.Credential (PEM bytes). The key is generated on
// the host and only ever exists as local PEM here — exactly the material the
// agent installs to a destination.
func makeCredential(t *testing.T) destination.Credential {
	t.Helper()
	ca, err := mtls.NewCA("certctl destinations test CA")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("workload.svc.internal")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := ca.SignClientCSR(csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UseCertificate(chainPEM); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "src.key")
	certPath := filepath.Join(dir, "src.crt")
	if err := id.Save(keyPath, certPath); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	return destination.Credential{KeyPEM: keyPEM, CertPEM: certPEM}
}

// Both concrete destinations satisfy the Destination interface.
var (
	_ destination.Destination = (*destination.Filesystem)(nil)
	_ destination.Destination = (*destination.PKCS11)(nil)
)

// TestFilesystemInstallSetsPermissions is half of the acceptance: a certificate
// (and its key) installs to the filesystem, the bytes round-trip, and the
// permissions are correct — the key is owner-only (0600), the certificate is
// world-readable (0644), and the directory that holds the key is private
// (0700). The destination must create the directory itself.
func TestFilesystemInstallSetsPermissions(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "tls") // deliberately not pre-created
	certPath := filepath.Join(sub, "workload.crt")
	keyPath := filepath.Join(sub, "workload.key")

	cred := makeCredential(t)
	fs := destination.NewFilesystem(certPath, keyPath)
	if err := fs.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// The certificate round-trips.
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read installed cert: %v", err)
	}
	if !bytes.Equal(gotCert, cred.CertPEM) {
		t.Error("installed certificate bytes differ from the credential")
	}
	// The key round-trips.
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read installed key: %v", err)
	}
	if !bytes.Equal(gotKey, cred.KeyPEM) {
		t.Error("installed key bytes differ from the credential")
	}

	// Permissions: key 0600, cert 0644, key directory 0700.
	if ki, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions = %o, want 0600", perm)
	}
	if ci, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	} else if perm := ci.Mode().Perm(); perm != 0o644 {
		t.Errorf("cert permissions = %o, want 0644", perm)
	}
	if di, err := os.Stat(sub); err != nil {
		t.Fatal(err)
	} else if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory permissions = %o, want 0700", perm)
	}
}

// TestFilesystemReinstallTightensLoosePermissions: installing over a key file
// that was left world-readable re-tightens it to 0600 (the destination owns the
// final mode regardless of a permissive umask or a pre-existing loose file).
func TestFilesystemReinstallTightensLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "workload.key")
	certPath := filepath.Join(dir, "workload.crt")

	// Pre-existing, world-readable key file.
	if err := os.WriteFile(keyPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	cred := makeCredential(t)
	if err := destination.NewFilesystem(certPath, keyPath).Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions after reinstall = %o, want 0600 (tightened)", perm)
	}
}

// TestFilesystemCertOnly: with no key in the credential, only the certificate is
// written and no key file is created (the key may live in an HSM instead).
func TestFilesystemCertOnly(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "workload.crt")
	keyPath := filepath.Join(dir, "workload.key")

	cred := makeCredential(t)
	cred.KeyPEM = nil
	if err := destination.NewFilesystem(certPath, keyPath).Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("certificate not installed: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("key file should not exist when no key is supplied, stat err = %v", err)
	}
}

// TestPKCS11InstallStoresCertAndSensitiveKey is the other half of the
// acceptance: a certificate installs to a PKCS#11 token (a SoftHSM stand-in),
// the certificate object is retrievable by label, and the private-key object
// carries HSM custody attributes — sensitive, non-extractable, private, and
// token-resident. That attribute set is the PKCS#11 analog of "verified
// permissions": the key cannot be read back out of the token.
func TestPKCS11InstallStoresCertAndSensitiveKey(t *testing.T) {
	token := softtoken.New()
	label := "workload-1"
	id := []byte{0x01, 0x02, 0x03, 0x04}

	cred := makeCredential(t)
	dest := destination.NewPKCS11(token, label, id)
	if err := dest.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}

	gotCert, found, err := token.FindCertificate(label)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("certificate object not found in the token after install")
	}
	if !bytes.Equal(gotCert, cred.CertPEM) {
		t.Error("certificate object bytes differ from the credential")
	}

	attrs, found, err := token.KeyAttributes(label)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("private-key object not found in the token after install")
	}
	if !attrs.Sensitive {
		t.Error("key object is not CKA_SENSITIVE — it could be read out of the token")
	}
	if attrs.Extractable {
		t.Error("key object is CKA_EXTRACTABLE — it can be exported from the token")
	}
	if !attrs.Private {
		t.Error("key object is not CKA_PRIVATE — it is readable without authentication")
	}
	if !attrs.Token {
		t.Error("key object is not CKA_TOKEN — it would not persist on the token")
	}
}

// TestPKCS11CertOnly: with no key supplied, the cert object is stored and no key
// object is created (the matching key was generated in the token out-of-band).
func TestPKCS11CertOnly(t *testing.T) {
	token := softtoken.New()
	cred := makeCredential(t)
	cred.KeyPEM = nil
	if err := destination.NewPKCS11(token, "cert-only", nil).Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, found, _ := token.FindCertificate("cert-only"); !found {
		t.Error("certificate object not stored")
	}
	if _, found, _ := token.KeyAttributes("cert-only"); found {
		t.Error("a key object was created even though no key was supplied")
	}
}

// TestInstallRejectsEmptyCertificate: every destination refuses to install a
// credential with no certificate.
func TestInstallRejectsEmptyCertificate(t *testing.T) {
	dir := t.TempDir()
	dests := map[string]destination.Destination{
		"filesystem": destination.NewFilesystem(filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")),
		"pkcs11":     destination.NewPKCS11(softtoken.New(), "empty", nil),
	}
	for name, d := range dests {
		if err := d.Install(context.Background(), destination.Credential{}); err == nil {
			t.Errorf("%s: Install with empty certificate succeeded, want error", name)
		}
	}
}
