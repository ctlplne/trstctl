// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// factoryStationFixture is a station with a software key (by explicit
// exception) under a delegation minted from its CSR, and a batch manifest.
func factoryStationFixture(t *testing.T, quota int) (dir string, opts edgeCAOptions) {
	t.Helper()
	dir = t.TempDir()
	keyPath, csrPath := filepath.Join(dir, "station.key"), filepath.Join(dir, "station.csr")
	if err := runEdgeCSR(edgeCAOptions{csrMode: true, tenantID: "77777777-7777-7777-7777-777777777777",
		segmentID: "88888888-8888-8888-8888-888888888888", commonName: "line 1 station", keyProvider: "software",
		allowSoftwareKey: true, keyOut: keyPath, csrOut: csrPath}); err != nil {
		t.Fatal(err)
	}
	csrDER, err := os.ReadFile(csrPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	parentSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentSigner, crypto.HierarchyCAProfile{CommonName: "factory parent", MaxPathLen: 1,
		TTL: 24 * time.Hour, PermittedDNSDomains: []string{"devices.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, crypto.EdgeCARequest{
		CommonName: "line 1 station", PermittedDNSDomains: []string{"devices.example.test"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "delegation.pem")
	if err := os.WriteFile(certPath, delegation.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(factoryManifest{BatchID: "batch-7", TenantID: "77777777-7777-7777-7777-777777777777",
		DelegationID: "delegation-1", DelegationFingerprint: crypto.SHA256Hex(delegation.CertificateDER), Label: "lot 7",
		Quota: quota, BirthTTLSeconds: 3600, ESTPath: "/.well-known/est/factory"})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, edgeCAOptions{factoryMode: true, keyProvider: "software", allowSoftwareKey: true, caKey: keyPath, caCert: certPath,
		factoryManifest: manifestPath, factoryJournal: filepath.Join(dir, "factory-journal.json")}
}

// factoryDeviceCSR is the request a device makes with its own key.
func factoryDeviceCSR(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// P12: the station issues a batch within its quota and refuses one more; the
// journal is the reconcile body, one PEM per birth certificate.
func TestFactoryStationIssuesWithinItsQuotaAndRefusesOneMoreP12(t *testing.T) {
	dir, opts := factoryStationFixture(t, 2)
	issue := func(i int) error {
		name := "sn-" + strconv.Itoa(i) + ".devices.example.test"
		o := opts
		o.factoryDevice, o.factoryCSR, o.certOut = name, factoryDeviceCSR(t, dir, name), filepath.Join(dir, name+".crt")
		return runFactoryIssue(o, "line-1")
	}
	for i := 1; i <= 2; i++ {
		if err := issue(i); err != nil {
			t.Fatalf("birth certificate %d: %v", i, err)
		}
	}
	if err := issue(3); !errors.Is(err, errFactoryQuota) {
		t.Fatalf("one past the quota = %v; want the quota refusal", err)
	}
	raw, err := os.ReadFile(opts.factoryJournal)
	if err != nil {
		t.Fatal(err)
	}
	var journal factoryJournal
	if err := json.Unmarshal(raw, &journal); err != nil || journal.BatchID != "batch-7" || journal.Host != "line-1" || len(journal.CertificatesPEM) != 2 {
		t.Fatalf("journal = %+v %v", journal, err)
	}
	if info, err := os.Stat(opts.factoryJournal); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v %v", info, err)
	}
	if _, err := os.Stat(opts.factoryJournal + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the issuance lock outlived the issuance")
	}
}

// The station refuses what it cannot vouch for, before it signs anything.
func TestFactoryStationRefusesWhatItCannotVouchForP12(t *testing.T) {
	dir, opts := factoryStationFixture(t, 5)
	device := "sn-1.devices.example.test"
	csr := factoryDeviceCSR(t, dir, device)

	other := opts
	other.factoryDevice, other.factoryCSR = "sn-2.devices.example.test", csr
	if err := runFactoryIssue(other, "line-1"); err == nil {
		t.Fatal("a request naming another device was certified")
	}
	outside := opts
	outside.factoryDevice, outside.factoryCSR = "sn-1.other.example.test", factoryDeviceCSR(t, dir, "sn-1.other.example.test")
	if err := runFactoryIssue(outside, "line-1"); err == nil {
		t.Fatal("a device outside the delegation's names was certified")
	}
	wrong := opts
	wrong.factoryDevice, wrong.factoryCSR = device, csr
	manifest := filepath.Join(dir, "other-manifest.json")
	raw, _ := json.Marshal(factoryManifest{BatchID: "batch-7", DelegationFingerprint: strings.Repeat("0", 64), Quota: 5, BirthTTLSeconds: 60})
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong.factoryManifest = manifest
	if err := runFactoryIssue(wrong, "line-1"); err == nil || !strings.Contains(err.Error(), "not the delegation") {
		t.Fatalf("another batch's delegation = %v", err)
	}
	locked := opts
	locked.factoryDevice, locked.factoryCSR = device, csr
	if err := os.WriteFile(opts.factoryJournal+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runFactoryIssue(locked, "line-1"); err == nil || !strings.Contains(err.Error(), "another factory issuance") {
		t.Fatalf("a concurrent issuance = %v", err)
	}
	if _, err := os.Stat(opts.factoryJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused issuance wrote the journal")
	}
}

// P12 rule 2: the factory station has no network listener and makes no
// network call; the line's tooling runs it locally, one shot at a time.
func TestFactoryStationHasNoListenerP12(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "factory.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "net" || strings.HasPrefix(path, "net/") || strings.Contains(path, "/transport") || strings.Contains(path, "grpc") {
			t.Fatalf("the factory station imports %s; it must hold no listener and make no network call", path)
		}
	}
}
