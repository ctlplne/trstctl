package destination_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/destination/certstore"
)

// The Windows cert store destination satisfies the Destination interface.
var _ destination.Destination = (*destination.WindowsCertStore)(nil)

// myStore is the LocalMachine\MY (Personal) store an agent installs a workload
// certificate into.
var myStore = destination.StoreRef{Location: destination.LocalMachine, Name: "MY"}

// TestWindowsCertStoreInstallsCertWithKey is the Windows half of the acceptance
// ("installs a cert into the Windows store"): a certificate and its key install
// into LocalMachine\MY, the certificate round-trips, and the associated private
// key is non-exportable — the Windows custody analog of "verified permissions".
func TestWindowsCertStoreInstallsCertWithKey(t *testing.T) {
	store := certstore.NewMemory()
	dest := destination.NewWindowsCertStore(store, myStore, "trstctl-agent")

	cred := makeCredential(t) // helper in destination_test.go (same package)
	if err := dest.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}

	e, found, err := store.Find(myStore, "trstctl-agent")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("certificate not found in the store after install")
	}
	if !bytes.Equal(e.CertPEM, cred.CertPEM) {
		t.Error("stored certificate bytes differ from the credential")
	}
	if e.Ref != myStore {
		t.Errorf("entry store ref = %v, want %v", e.Ref, myStore)
	}
	if !e.HasPrivateKey {
		t.Error("entry has no associated private key, want one")
	}
	if e.Exportable {
		t.Error("associated key is exportable — a machine-store key should be non-exportable")
	}
}

// TestWindowsCertStoreCertOnly: a key-less credential installs only the
// certificate, with no associated private key.
func TestWindowsCertStoreCertOnly(t *testing.T) {
	store := certstore.NewMemory()
	dest := destination.NewWindowsCertStore(store, myStore, "trust-anchor")
	cred := makeCredential(t)
	cred.KeyPEM = nil
	if err := dest.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}
	e, found, err := store.Find(myStore, "trust-anchor")
	if err != nil || !found {
		t.Fatalf("find: found=%v err=%v", found, err)
	}
	if e.HasPrivateKey {
		t.Error("cert-only install reported an associated private key")
	}
}

// TestWindowsCertStoreIsolatesStores: a certificate installed into one store is
// not visible in another (location/name identify the store).
func TestWindowsCertStoreIsolatesStores(t *testing.T) {
	store := certstore.NewMemory()
	cred := makeCredential(t)
	if err := destination.NewWindowsCertStore(store, myStore, "svc").Install(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	rootStore := destination.StoreRef{Location: destination.LocalMachine, Name: "ROOT"}
	if _, found, _ := store.Find(rootStore, "svc"); found {
		t.Error("certificate installed into MY was found in ROOT — stores are not isolated")
	}
	userMy := destination.StoreRef{Location: destination.CurrentUser, Name: "MY"}
	if _, found, _ := store.Find(userMy, "svc"); found {
		t.Error("LocalMachine cert was found under CurrentUser — locations are not isolated")
	}
}

// TestWindowsCertStoreRejectsEmptyCertificate: installing a credential with no
// certificate fails.
func TestWindowsCertStoreRejectsEmptyCertificate(t *testing.T) {
	dest := destination.NewWindowsCertStore(certstore.NewMemory(), myStore, "x")
	if err := dest.Install(context.Background(), destination.Credential{}); err == nil {
		t.Error("Install with empty certificate succeeded, want error")
	}
}
