// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Edge sub-CA host operations (epic B6). These are ONE-SHOT, fully offline
// modes: they need no path to the control plane, which is the point — the
// host they run on is the host that has none.
//
//   - edge-csr generates the delegated CA's keypair locally and writes the CSR
//     the operator carries to the brain. The key never travels. The printed
//     challenge is what the host's TPM tooling must attest over.
//   - edge-issue issues one leaf under the delegated CA. The constraints are
//     read FROM THE DELEGATION CERTIFICATE, so a tampered local config cannot
//     widen what the brain delegated, and an out-of-constraint name fails
//     closed here rather than becoming a certificate that gets flagged later.
//     Every issuance is appended to the journal file.
//   - The journal IS the reconciliation artifact: when a path (or a courier)
//     exists, `trstctl edge delegations reconcile -f <journal>` posts it. The
//     agent needs no network client of its own for this.

type edgeCAOptions struct {
	csrMode    bool
	tenantID   string
	segmentID  string
	commonName string
	keyOut     string
	csrOut     string

	issueMode  bool
	caCert     string
	caKey      string
	leafCN     string
	leafDNS    string
	leafTTL    time.Duration
	certOut    string
	leafKeyOut string
	journal    string
}

// edgeJournal is the reconcile request body, maintained on disk in exactly the
// shape POST /api/v1/edge/delegations/{id}/reconcile accepts.
type edgeJournal struct {
	Host            string   `json:"host"`
	CertificatesPEM []string `json:"certificates_pem"`
}

// runEdgeCAOps handles the one-shot edge modes; reports whether one ran.
func runEdgeCAOps(opts edgeCAOptions, host string) (bool, error) {
	switch {
	case opts.csrMode:
		return true, runEdgeCSR(opts)
	case opts.issueMode:
		return true, runEdgeIssue(opts, host)
	}
	return false, nil
}

func runEdgeCSR(opts edgeCAOptions) error {
	if strings.TrimSpace(opts.tenantID) == "" || strings.TrimSpace(opts.segmentID) == "" {
		return fmt.Errorf("edge-csr requires --edge-tenant and --edge-segment: the attestation challenge binds both")
	}
	cn := strings.TrimSpace(opts.commonName)
	if cn == "" {
		cn = "trstctl-edge-ca"
	}
	keyPEM, csrDER, err := crypto.GenerateEdgeCAKeyAndCSR(cn)
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.keyOut, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write edge CA key: %w", err)
	}
	if err := os.WriteFile(opts.csrOut, csrDER, 0o600); err != nil {
		return fmt.Errorf("write edge CA CSR: %w", err)
	}
	challenge := crypto.EdgeAttestationChallenge(
		strings.TrimSpace(opts.tenantID), strings.TrimSpace(opts.segmentID), csrDER)
	fmt.Printf("edge CA key written to %s (0600) — it never leaves this host\n", opts.keyOut)
	fmt.Printf("edge CA CSR written to %s\n", opts.csrOut)
	fmt.Printf("csr_der (base64, for the mint request): %s\n", base64.StdEncoding.EncodeToString(csrDER))
	fmt.Printf("attestation challenge (hex): %s\n", hex.EncodeToString(challenge))
	fmt.Println("have this host's TPM tooling produce a WebAuthn TPM attestation over that challenge;")
	fmt.Println("the brain refuses the mint without it")
	return nil
}

func runEdgeIssue(opts edgeCAOptions, host string) error {
	if opts.caCert == "" || opts.caKey == "" {
		return fmt.Errorf("edge-issue requires --edge-ca-cert and --edge-ca-key")
	}
	if strings.TrimSpace(opts.leafCN) == "" {
		return fmt.Errorf("edge-issue requires --edge-issue-cn")
	}
	certPEM, err := os.ReadFile(opts.caCert) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(opts.caKey) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return err
	}
	var dns []string
	for _, name := range strings.Split(opts.leafDNS, ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			dns = append(dns, trimmed)
		}
	}
	leaf, err := crypto.IssueEdgeLeaf(certPEM, keyPEM, crypto.EdgeLeafRequest{
		CommonName: strings.TrimSpace(opts.leafCN),
		DNSNames:   dns,
		TTL:        opts.leafTTL,
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	certOut := opts.certOut
	if certOut == "" {
		certOut = "edge-leaf.crt"
	}
	keyOut := opts.leafKeyOut
	if keyOut == "" {
		keyOut = "edge-leaf.key"
	}
	if err := os.WriteFile(certOut, leaf.CertificatePEM, 0o600); err != nil {
		return fmt.Errorf("write leaf certificate: %w", err)
	}
	if err := os.WriteFile(keyOut, leaf.LeafKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write leaf key: %w", err)
	}
	if err := appendEdgeJournal(opts.journal, host, string(leaf.CertificatePEM)); err != nil {
		return err
	}
	fmt.Printf("issued serial %s, expires %s\n", leaf.SerialHex, leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("certificate: %s  key: %s  journal: %s\n", certOut, keyOut, opts.journal)
	fmt.Println("reconcile the journal when a path exists: trstctl edge delegations reconcile <id> -f " + opts.journal)
	return nil
}

// appendEdgeJournal records the issuance in the reconcile-shaped journal. The
// journal only ever GROWS on the host; the brain deduplicates by serial, so
// re-reporting the whole file is idempotent.
func appendEdgeJournal(path, host, certPEM string) error {
	if path == "" {
		path = "edge-journal.json"
	}
	journal := edgeJournal{Host: host}
	if raw, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-configured journal path on the agent's own host (CWE-22)
		if err := json.Unmarshal(raw, &journal); err != nil {
			return fmt.Errorf("journal %s exists but does not parse: %w — refusing to overwrite an "+
				"issuance record", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if journal.Host == "" {
		journal.Host = host
	}
	journal.CertificatesPEM = append(journal.CertificatesPEM, certPEM)
	out, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}
