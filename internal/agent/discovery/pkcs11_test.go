// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// The PKCS#11 source (epic C1). The dlopen ABI lives behind a cgo build tag;
// everything that decides what an operator SEES is tested on any build.

type fakePKCS11Reader struct {
	blobs map[string][]byte
	err   error
	calls int
}

func (f *fakePKCS11Reader) readTokens(context.Context, PKCS11Config) (map[string][]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.blobs, nil
}

func pkcs11TestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, cn, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestPKCS11ReportsTokenCertificates is the capability: the certificates whose
// keys cannot be copied, which is exactly why nobody has a list of them.
func TestPKCS11ReportsTokenCertificates(t *testing.T) {
	reader := &fakePKCS11Reader{blobs: map[string][]byte{
		"pkcs11:hsm-prod/signing-cert": pkcs11TestCertDER(t, "signing"),
		"pkcs11:hsm-prod/tls-cert":     pkcs11TestCertDER(t, "tls"),
	}}
	src := &PKCS11Source{cfg: PKCS11Config{ModulePath: "/usr/lib/softhsm2.so"}, reader: reader}

	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d certificates, want 2", len(found))
	}
	for _, f := range found {
		if f.Source != SourcePKCS11 {
			t.Errorf("finding source = %q, want %q", f.Source, SourcePKCS11)
		}
		if !strings.HasPrefix(f.Location, "pkcs11:") {
			t.Errorf("finding location %q does not name the token", f.Location)
		}
		// The module path is a host filesystem path that differs per host for
		// the same physical token; putting it in the location would make one
		// certificate look like several across a fleet.
		if strings.Contains(f.Location, "softhsm2.so") {
			t.Errorf("finding location %q leaks the host module path", f.Location)
		}
	}
}

// TestPKCS11FailsRatherThanReportingEmpty: an unreadable token and an empty one
// must never read the same.
func TestPKCS11FailsRatherThanReportingEmpty(t *testing.T) {
	reader := &fakePKCS11Reader{err: errors.New("CKR_PIN_INCORRECT")}
	src := &PKCS11Source{cfg: PKCS11Config{ModulePath: "/usr/lib/softhsm2.so"}, reader: reader}

	found, err := src.Discover(context.Background())
	if err == nil {
		t.Fatal("an unreadable token reported success; an operator would read that as a clean estate")
	}
	if len(found) != 0 {
		t.Fatalf("a failed read returned %d findings", len(found))
	}
}

// TestPKCS11SkipsUnparseableObjects: tokens hold objects this does not
// understand, and one of them must not cost the inventory of the rest.
func TestPKCS11SkipsUnparseableObjects(t *testing.T) {
	reader := &fakePKCS11Reader{blobs: map[string][]byte{
		"pkcs11:tok/data-object": []byte("not a certificate"),
		"pkcs11:tok/real":        pkcs11TestCertDER(t, "real"),
	}}
	src := &PKCS11Source{cfg: PKCS11Config{ModulePath: "/usr/lib/softhsm2.so"}, reader: reader}

	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d certificates, want 1", len(found))
	}
}

// TestPKCS11RequiresAModulePath: guessing one would mean loading whatever
// happened to be installed on the host.
func TestPKCS11RequiresAModulePath(t *testing.T) {
	reader := &fakePKCS11Reader{}
	src := &PKCS11Source{cfg: PKCS11Config{}, reader: reader}
	if _, err := src.Discover(context.Background()); err == nil {
		t.Fatal("PKCS#11 discovery ran with no module path")
	}
	if reader.calls != 0 {
		t.Fatal("the source loaded a module before validating its configuration")
	}
}

// TestPKCS11CensusMatchesThisBuild is the honesty property, and the reason the
// census is build-dependent: a cgo-free binary cannot dlopen a PKCS#11 module,
// so it must not advertise that it collects one.
func TestPKCS11CensusMatchesThisBuild(t *testing.T) {
	advertised := IsShippedSourceKind(SourcePKCS11)
	if advertised != pkcs11Shipped() {
		t.Fatalf("census advertises pkcs11=%v but this build's reader reports %v", advertised, pkcs11Shipped())
	}
	src := NewPKCS11CertSource(PKCS11Config{ModulePath: "/nonexistent/module.so"})
	_, err := src.Discover(context.Background())
	if !pkcs11Shipped() {
		if !errors.Is(err, ErrPKCS11Unsupported) {
			t.Fatalf("a cgo-free build's discover error = %v, want ErrPKCS11Unsupported", err)
		}
		// And it must be absent from the advertised set entirely.
		for _, kind := range ShippedSourceKinds() {
			if kind.Kind == SourcePKCS11 {
				t.Fatal("a cgo-free build advertises pkcs11")
			}
		}
		return
	}
	// A cgo build fails on the missing module, which is also correct — what it
	// must not do is succeed with an empty inventory.
	if err == nil {
		t.Fatal("loading a nonexistent module reported success")
	}
}
