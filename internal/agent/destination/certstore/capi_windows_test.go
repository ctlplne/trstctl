//go:build windows

package certstore

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// winTestCredential mints a real key + certificate chain via the crypto
// boundary and returns the PEM cert chain and PEM key. It uses encoding/pem
// only (no crypto/* in a non-boundary package; AN-3).
func winTestCredential(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	ca, err := mtls.NewCA("trstctl windows store test CA")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("win-workload.local")
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
	keyPath := filepath.Join(dir, "k.pem")
	certPath := filepath.Join(dir, "c.pem")
	if err := id.Save(keyPath, certPath); err != nil {
		t.Fatal(err)
	}
	certPEM, err = os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

func leafDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM certificate block")
	}
	return block.Bytes
}

// userMY is the per-user Personal store: writable without administrative
// rights, so the CI runner can exercise the real CryptoAPI path.
var userMY = destination.StoreRef{Location: destination.CurrentUser, Name: "MY"}

// TestWindowsStoreInstallsCertWithKey exercises the real CryptoAPI/CNG path on
// Windows: a certificate and key install into CurrentUser\MY via
// PFXImportCertStore, the certificate round-trips, and it has an associated
// (non-exportable) private key.
func TestWindowsStoreInstallsCertWithKey(t *testing.T) {
	w := NewWindows()
	name := fmt.Sprintf("trstctl-test-key-%d", time.Now().UnixNano())
	certPEM, keyPEM := winTestCredential(t)

	if err := w.ImportWithKey(userMY, name, certPEM, keyPEM); err != nil {
		t.Fatalf("ImportWithKey: %v", err)
	}
	t.Cleanup(func() { _ = w.Delete(userMY, name) })

	e, found, err := w.Find(userMY, name)
	if err != nil || !found {
		t.Fatalf("Find: found=%v err=%v", found, err)
	}
	if !e.HasPrivateKey {
		t.Error("installed certificate has no associated private key")
	}
	if e.Exportable {
		t.Error("associated key is exportable, want non-exportable")
	}
	if got, want := leafDER(t, e.CertPEM), leafDER(t, certPEM); !bytes.Equal(got, want) {
		t.Error("stored certificate differs from the installed leaf")
	}
}

// TestWindowsStoreCertOnly: a key-less install adds the certificate with no
// associated key, and Delete removes it.
func TestWindowsStoreCertOnly(t *testing.T) {
	w := NewWindows()
	name := fmt.Sprintf("trstctl-test-certonly-%d", time.Now().UnixNano())
	certPEM, _ := winTestCredential(t)

	if err := w.AddCertificate(userMY, name, certPEM); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	t.Cleanup(func() { _ = w.Delete(userMY, name) })

	e, found, err := w.Find(userMY, name)
	if err != nil || !found {
		t.Fatalf("Find: found=%v err=%v", found, err)
	}
	if e.HasPrivateKey {
		t.Error("cert-only install reported an associated private key")
	}

	if err := w.Delete(userMY, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, _ := w.Find(userMY, name); found {
		t.Error("certificate still present after Delete")
	}
}
