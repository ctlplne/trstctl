// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestCheckedTPMPersistentHandleBaseRejectsOverflow(t *testing.T) {
	for _, value := range []uint{0, uint(math.MaxUint32)} {
		got, err := checkedTPMPersistentHandleBase(value)
		if err != nil || uint64(got) != uint64(value) {
			t.Fatalf("checkedTPMPersistentHandleBase(%d) = %d, %v", value, got, err)
		}
	}
	if uint64(^uint(0)) > uint64(math.MaxUint32) {
		if got, err := checkedTPMPersistentHandleBase(uint(math.MaxUint32) + 1); err == nil || got != 0 {
			t.Fatalf("overflow = %d, %v; want zero plus error", got, err)
		}
	}
}

// The agent's offline half of B6, end to end with no control plane anywhere:
// edge-csr writes the key that never travels, a delegation is minted over the
// CSR, edge-issue succeeds inside the delegation's constraints and FAILS
// CLOSED outside them, and every issuance lands in the journal in exactly the
// reconcile request's shape.
func TestEdgeCSRAndIssueOffline(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "edge.key")
	csrPath := filepath.Join(dir, "edge.csr")
	if err := runEdgeCSR(edgeCAOptions{
		csrMode:          true,
		tenantID:         "77777777-7777-7777-7777-777777777777",
		segmentID:        "88888888-8888-8888-8888-888888888888",
		commonName:       "offline edge CA",
		keyProvider:      "software",
		allowSoftwareKey: true,
		keyOut:           keyPath,
		csrOut:           csrPath,
	}); err != nil {
		t.Fatalf("edge-csr: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", info.Mode().Perm())
	}
	csrDER, err := os.ReadFile(csrPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}

	// The brain's side, in miniature: a parent in a locked signer minting the
	// delegation over exactly the CSR the host wrote.
	parentSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("parent key: %v", err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentSigner, crypto.HierarchyCAProfile{
		CommonName: "offline parent", MaxPathLen: 1, TTL: 24 * time.Hour,
		PermittedDNSDomains: []string{"edge.example.test"},
	})
	if err != nil {
		t.Fatalf("parent CA: %v", err)
	}
	delegation, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, crypto.EdgeCARequest{
		CommonName:          "offline edge CA",
		PermittedDNSDomains: []string{"edge.example.test"},
		ExcludedDNSDomains:  []string{"blocked.edge.example.test"},
		TTL:                 time.Hour,
	})
	if err != nil {
		t.Fatalf("mint delegation: %v", err)
	}
	delegationPath := filepath.Join(dir, "delegation.pem")
	if err := os.WriteFile(delegationPath, delegation.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(dir, "journal.json")
	issue := func(cn string) error {
		return runEdgeIssue(edgeCAOptions{
			issueMode:        true,
			keyProvider:      "software",
			allowSoftwareKey: true,
			caCert:           delegationPath,
			caKey:            keyPath,
			leafCN:           cn,
			leafTTL:          30 * time.Minute,
			certOut:          filepath.Join(dir, "leaf.crt"),
			leafKeyOut:       filepath.Join(dir, "leaf.key"),
			journal:          journalPath,
		}, "bunker-offline")
	}
	if err := issue("db.edge.example.test"); err != nil {
		t.Fatalf("in-constraint issue: %v", err)
	}
	if err := issue("evil.other.example.test"); err == nil {
		t.Fatal("out-of-constraint issue succeeded on the host; the local check must fail closed, " +
			"not defer to the brain's reconcile verdict")
	} else if !strings.Contains(err.Error(), "permitted names") {
		t.Fatalf("out-of-constraint error = %v, want the permitted names named", err)
	}
	if err := issue("x.blocked.edge.example.test"); err == nil {
		t.Fatal("excluded-subtree issue succeeded; exclusion must beat permission")
	}

	raw, err := os.ReadFile(journalPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var journal struct {
		Host            string   `json:"host"`
		CertificatesPEM []string `json:"certificates_pem"`
	}
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatalf("journal shape: %v", err)
	}
	if journal.Host != "bunker-offline" || len(journal.CertificatesPEM) != 1 {
		t.Fatalf("journal = host=%q certs=%d; want exactly the ONE in-constraint issuance — "+
			"refused requests must never reach the record of what was issued", journal.Host, len(journal.CertificatesPEM))
	}
	if !strings.Contains(journal.CertificatesPEM[0], "BEGIN CERTIFICATE") {
		t.Fatal("journal entry is not a PEM certificate")
	}
}

func TestEdgeSoftwareKeyIsAnExplicitPolicyException(t *testing.T) {
	dir := t.TempDir()
	err := runEdgeCSR(edgeCAOptions{
		csrMode: true, tenantID: "tenant-a", segmentID: "segment-a",
		keyProvider: "software", keyOut: filepath.Join(dir, "edge.key"), csrOut: filepath.Join(dir, "edge.csr"),
	})
	if err == nil || !strings.Contains(err.Error(), "allow-software") {
		t.Fatalf("software fallback error = %v, want explicit opt-in refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "edge.key")); !os.IsNotExist(statErr) {
		t.Fatalf("software key was written before custody opt-in: %v", statErr)
	}
}

type edgeCLITestProvider struct {
	name string
	key  *crypto.LockedSigner
}

func (p *edgeCLITestProvider) Name() string { return p.name }
func (p *edgeCLITestProvider) GenerateManagedKey(ctx context.Context, algorithm crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKeyForOperation(ctx, "test-unscoped", algorithm)
}
func (p *edgeCLITestProvider) GenerateManagedKeyForOperation(ctx context.Context, _ string, algorithm crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	if p.key == nil {
		key, err := crypto.GenerateLockedKey(algorithm)
		if err != nil {
			return nil, crypto.KeyRef{}, err
		}
		p.key = key
	}
	return edgeCLITestMessageSigner{p.key}, crypto.KeyRef{ID: "opaque-device-handle", Algorithm: algorithm}, nil
}
func (p *edgeCLITestProvider) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKey(ctx, ref.Algorithm)
}
func (p *edgeCLITestProvider) RotateKeyForOperation(ctx context.Context, op string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKeyForOperation(ctx, op, ref.Algorithm)
}
func (*edgeCLITestProvider) RevokeKey(context.Context, crypto.KeyRef) error  { return nil }
func (*edgeCLITestProvider) ZeroizeKey(context.Context, crypto.KeyRef) error { return nil }
func (*edgeCLITestProvider) RevokeKeyForOperation(context.Context, string, crypto.KeyRef) error {
	return nil
}
func (*edgeCLITestProvider) ZeroizeKeyForOperation(context.Context, string, crypto.KeyRef) error {
	return nil
}
func (p *edgeCLITestProvider) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.ID != "opaque-device-handle" || p.key == nil {
		return nil, fmt.Errorf("test device: unknown handle")
	}
	return p.key.SignDigest(digest, opts)
}

type edgeCLITestMessageSigner struct{ *crypto.LockedSigner }

func (s edgeCLITestMessageSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	hash := opts.Hash
	if hash == "" {
		hash = crypto.SHA256
	}
	digest, err := crypto.Digest(hash, message)
	if err != nil {
		return nil, err
	}
	return s.SignDigest(digest, opts)
}

func TestEdgeHardwareCLIUsesOnlyOpaqueHandleAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	provider := &edgeCLITestProvider{name: "tpm2"}
	t.Cleanup(func() {
		if provider.key != nil {
			provider.key.Destroy()
		}
	})
	oldOpen := openEdgeCAKeyProvider
	openEdgeCAKeyProvider = func(opts edgeCAOptions) (crypto.EdgeCAKeyProvider, func() error, error) {
		if opts.keyProvider != "tpm2" {
			return nil, nil, fmt.Errorf("unexpected provider %q", opts.keyProvider)
		}
		return provider, func() error { return nil }, nil
	}
	t.Cleanup(func() { openEdgeCAKeyProvider = oldOpen })

	handlePath := filepath.Join(dir, "edge.keyref.json")
	csrPath := filepath.Join(dir, "edge.csr")
	opts := edgeCAOptions{
		csrMode: true, tenantID: "tenant-a", segmentID: "segment-a", commonName: "hardware edge CA",
		keyProvider: "tpm2", keyGeneration: "1", keyHandleOut: handlePath, csrOut: csrPath,
	}
	if err := runEdgeCSR(opts); err != nil {
		t.Fatalf("hardware edge-csr: %v", err)
	}
	handleRaw, err := os.ReadFile(handlePath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(handleRaw), "PRIVATE KEY") || strings.Contains(string(handleRaw), "private_key") {
		t.Fatalf("opaque handle file contains private-key material: %s", handleRaw)
	}
	var handle crypto.EdgeCAKeyHandle
	if err := json.Unmarshal(handleRaw, &handle); err != nil || handle.Provider != "tpm2" || handle.KeyID == "" {
		t.Fatalf("handle = %+v, err=%v", handle, err)
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
	parent, err := crypto.SelfSignedHierarchyCA(parentSigner, crypto.HierarchyCAProfile{
		CommonName: "parent", MaxPathLen: 1, TTL: 24 * time.Hour, PermittedDNSDomains: []string{"edge.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, crypto.EdgeCARequest{
		CommonName: "hardware edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	delegationPath := filepath.Join(dir, "edge-ca.crt")
	if err := os.WriteFile(delegationPath, delegation.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEdgeIssue(edgeCAOptions{
		issueMode: true, keyProvider: "tpm2", caCert: delegationPath, caKeyHandle: handlePath,
		leafCN: "db.edge.example.test", certOut: filepath.Join(dir, "leaf.crt"),
		leafKeyOut: filepath.Join(dir, "leaf.key"), journal: filepath.Join(dir, "journal.json"),
	}, "edge-host"); err != nil {
		t.Fatalf("hardware edge-issue: %v", err)
	}

	openEdgeCAKeyProvider = func(edgeCAOptions) (crypto.EdgeCAKeyProvider, func() error, error) {
		return nil, nil, fmt.Errorf("TPM unavailable")
	}
	if err := runEdgeIssue(edgeCAOptions{
		issueMode: true, keyProvider: "tpm2", caCert: delegationPath, caKeyHandle: handlePath,
		leafCN: "db.edge.example.test",
	}, "edge-host"); err == nil || !strings.Contains(err.Error(), "TPM unavailable") {
		t.Fatalf("unavailable device error = %v; hardware mode must not fall back to software", err)
	}
}
