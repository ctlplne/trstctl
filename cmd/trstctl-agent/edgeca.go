// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	csrMode                 bool
	tenantID                string
	segmentID               string
	commonName              string
	keyProvider             string
	keyGeneration           string
	allowSoftwareKey        bool
	keyOut                  string
	keyHandleOut            string
	csrOut                  string
	tpmPath                 string
	tpmOwnerAuthFile        string
	tpmKeyAuthFile          string
	tpmPersistentHandleBase uint32
	pkcs11Module            string
	pkcs11Token             string
	pkcs11PINFile           string
	pkcs11KeyLabelPrefix    string

	issueMode   bool
	caCert      string
	caKey       string
	caKeyHandle string
	leafCN      string
	leafDNS     string
	leafTTL     time.Duration
	certOut     string
	leafKeyOut  string
	journal     string
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
	providerName := normalizedEdgeKeyProvider(opts.keyProvider)
	var csrDER []byte
	switch providerName {
	case "software":
		if !opts.allowSoftwareKey {
			return fmt.Errorf("software edge CA custody is exportable and requires --edge-allow-software-key plus control-plane policy approval")
		}
		keyPEM, generatedCSR, err := crypto.GenerateEdgeCAKeyAndCSR(cn)
		if err != nil {
			return err
		}
		defer secret.Wipe(keyPEM)
		if err := os.WriteFile(opts.keyOut, keyPEM, 0o600); err != nil {
			return fmt.Errorf("write edge CA key: %w", err)
		}
		csrDER = generatedCSR
		fmt.Printf("edge CA SOFTWARE key written to %s (0600); this is an explicit EXPORTABLE custody exception\n", opts.keyOut)
	case "tpm2", "pkcs11":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		provider, closeProvider, err := openEdgeCAKeyProvider(opts)
		if err != nil {
			return fmt.Errorf("open %s edge CA key provider: %w", providerName, err)
		}
		defer func() { _ = closeProvider() }()
		generation := strings.TrimSpace(opts.keyGeneration)
		if generation == "" {
			generation = "1"
		}
		operationID := fmt.Sprintf("edge-ca/%s/%s/%s", strings.TrimSpace(opts.tenantID), strings.TrimSpace(opts.segmentID), generation)
		handle, generatedCSR, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, operationID, cn, edgeKeyAlgorithm(providerName), provider)
		if err != nil {
			return err
		}
		handleJSON, err := json.MarshalIndent(handle, "", "  ")
		if err != nil {
			return fmt.Errorf("encode edge CA public key handle: %w", err)
		}
		if err := os.WriteFile(opts.keyHandleOut, handleJSON, 0o600); err != nil {
			return fmt.Errorf("write edge CA public key handle: %w", err)
		}
		csrDER = generatedCSR
		fmt.Printf("edge CA key generated NON-EXTRACTABLY in %s; opaque public handle written to %s\n", providerName, opts.keyHandleOut)
	default:
		return fmt.Errorf("unknown --edge-key-provider %q (want tpm2, pkcs11, or software)", opts.keyProvider)
	}
	if err := os.WriteFile(opts.csrOut, csrDER, 0o600); err != nil {
		return fmt.Errorf("write edge CA CSR: %w", err)
	}
	challenge := crypto.EdgeAttestationChallenge(
		strings.TrimSpace(opts.tenantID), strings.TrimSpace(opts.segmentID), csrDER)
	fmt.Printf("edge CA CSR written to %s\n", opts.csrOut)
	fmt.Printf("mint custody: provider=%s storage=%s exportable=%t\n", providerName, edgeKeyStorage(providerName), providerName == "software")
	fmt.Printf("csr_der (base64, for the mint request): %s\n", base64.StdEncoding.EncodeToString(csrDER))
	fmt.Printf("attestation challenge (hex): %s\n", hex.EncodeToString(challenge))
	fmt.Println("have this host's TPM tooling produce a WebAuthn TPM attestation over that challenge;")
	fmt.Println("the brain refuses the mint without it")
	return nil
}

func runEdgeIssue(opts edgeCAOptions, host string) error {
	providerName := normalizedEdgeKeyProvider(opts.keyProvider)
	if opts.caCert == "" {
		return fmt.Errorf("edge-issue requires --edge-ca-cert")
	}
	if strings.TrimSpace(opts.leafCN) == "" {
		return fmt.Errorf("edge-issue requires --edge-issue-cn")
	}
	certPEM, err := os.ReadFile(opts.caCert) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return err
	}
	var dns []string
	for _, name := range strings.Split(opts.leafDNS, ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			dns = append(dns, trimmed)
		}
	}
	request := crypto.EdgeLeafRequest{
		CommonName: strings.TrimSpace(opts.leafCN),
		DNSNames:   dns,
		TTL:        opts.leafTTL,
	}
	var leaf crypto.EdgeIssuedLeaf
	switch providerName {
	case "software":
		if !opts.allowSoftwareKey {
			return fmt.Errorf("software edge CA custody is exportable and requires --edge-allow-software-key")
		}
		if opts.caKey == "" {
			return fmt.Errorf("software edge-issue requires --edge-ca-key")
		}
		keyPEM, readErr := os.ReadFile(opts.caKey) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
		if readErr != nil {
			return readErr
		}
		defer secret.Wipe(keyPEM)
		leaf, err = crypto.IssueEdgeLeaf(certPEM, keyPEM, request, time.Now().UTC())
	case "tpm2", "pkcs11":
		if opts.caKeyHandle == "" {
			return fmt.Errorf("%s edge-issue requires --edge-ca-key-handle", providerName)
		}
		raw, readErr := os.ReadFile(opts.caKeyHandle) // #nosec G304 -- operator-configured local handle path from the agent's own flags (CWE-22)
		if readErr != nil {
			return readErr
		}
		var handle crypto.EdgeCAKeyHandle
		if decodeErr := json.Unmarshal(raw, &handle); decodeErr != nil {
			return fmt.Errorf("decode edge CA public key handle: %w", decodeErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		provider, closeProvider, openErr := openEdgeCAKeyProvider(opts)
		if openErr != nil {
			return fmt.Errorf("open %s edge CA key provider: %w", providerName, openErr)
		}
		defer func() { _ = closeProvider() }()
		leaf, err = crypto.IssueEdgeLeafWithKeyHandle(ctx, certPEM, handle, provider, request, time.Now().UTC())
	default:
		return fmt.Errorf("unknown --edge-key-provider %q (want tpm2, pkcs11, or software)", opts.keyProvider)
	}
	if err != nil {
		return err
	}
	defer secret.Wipe(leaf.LeafKeyPEM)
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

func normalizedEdgeKeyProvider(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "tpm2"
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func edgeKeyAlgorithm(provider string) crypto.Algorithm {
	if provider == "pkcs11" {
		// The shipped PKCS#11 module path creates non-extractable RSA-2048 token
		// objects today; TPM 2.0 uses its native ECDSA P-256 signing object.
		return crypto.RSA2048
	}
	return crypto.ECDSAP256
}

func edgeKeyStorage(provider string) string {
	switch provider {
	case "tpm2":
		return "device_bound"
	case "pkcs11":
		return "pkcs11"
	default:
		return "file"
	}
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
