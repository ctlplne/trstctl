// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

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
		csrMode:    true,
		tenantID:   "77777777-7777-7777-7777-777777777777",
		segmentID:  "88888888-8888-8888-8888-888888888888",
		commonName: "offline edge CA",
		keyOut:     keyPath,
		csrOut:     csrPath,
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
			issueMode:  true,
			caCert:     delegationPath,
			caKey:      keyPath,
			leafCN:     cn,
			leafTTL:    30 * time.Minute,
			certOut:    filepath.Join(dir, "leaf.crt"),
			leafKeyOut: filepath.Join(dir, "leaf.key"),
			journal:    journalPath,
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
