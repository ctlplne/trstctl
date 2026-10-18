// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
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
	attestMode              bool
	csrIn                   string
	caKeyHandle             string
	aikKeyHandle            string
	aikCertChain            string
	aikAuthFile             string
	attestationOut          string
	mintRequestOut          string
	mintParentCAID          string
	mintHost                string
	mintTTL                 time.Duration
	tpmPath                 string
	tpmOwnerAuthFile        string
	tpmKeyAuthFile          string
	tpmPersistentHandleBase uint32
	pkcs11Module            string
	pkcs11Token             string
	pkcs11PINFile           string
	pkcs11KeyLabelPrefix    string

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
	if modes := boolCount(opts.csrMode, opts.attestMode, opts.issueMode); modes > 1 {
		return true, fmt.Errorf("use exactly one of --edge-csr, --edge-attest or --edge-issue")
	}
	switch {
	case opts.csrMode:
		return true, runEdgeCSR(opts)
	case opts.attestMode:
		return true, runEdgeAttest(opts)
	case opts.issueMode:
		return true, runEdgeIssue(opts, host)
	}
	return false, nil
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func runEdgeAttest(opts edgeCAOptions) error {
	if normalizedEdgeKeyProvider(opts.keyProvider) != "tpm2" {
		return fmt.Errorf("edge-attest requires a TPM2 edge CA key")
	}
	if strings.TrimSpace(opts.tenantID) == "" || strings.TrimSpace(opts.segmentID) == "" || opts.csrIn == "" || opts.caKeyHandle == "" || opts.aikKeyHandle == "" || opts.aikCertChain == "" || opts.attestationOut == "" {
		return fmt.Errorf("edge-attest requires tenant, segment, CSR, edge key handle, AIK handle, AIK certificate chain and output path")
	}
	csrDER, err := os.ReadFile(opts.csrIn) // #nosec G304 -- explicit operator file path
	if err != nil {
		return fmt.Errorf("read edge CA CSR: %w", err)
	}
	readHandle := func(path string) (crypto.EdgeCAKeyHandle, error) {
		raw, err := os.ReadFile(path) // #nosec G304 -- explicit operator file path
		if err != nil {
			return crypto.EdgeCAKeyHandle{}, err
		}
		var handle crypto.EdgeCAKeyHandle
		if err := json.Unmarshal(raw, &handle); err != nil {
			return crypto.EdgeCAKeyHandle{}, err
		}
		return handle, nil
	}
	edgeHandle, err := readHandle(opts.caKeyHandle)
	if err != nil {
		return fmt.Errorf("read edge TPM handle: %w", err)
	}
	aikHandle, err := readHandle(opts.aikKeyHandle)
	if err != nil {
		return fmt.Errorf("read AIK TPM handle: %w", err)
	}
	chain, err := os.ReadFile(opts.aikCertChain) // #nosec G304 -- explicit operator file path
	if err != nil {
		return fmt.Errorf("read AIK certificate chain: %w", err)
	}
	aikAuth, err := readEdgeSecretFile(opts.aikAuthFile, false)
	if err != nil {
		return fmt.Errorf("read AIK authorization: %w", err)
	}
	defer secret.Wipe(aikAuth)
	provider, closeProvider, err := openEdgeCAKeyProvider(opts)
	if err != nil {
		return fmt.Errorf("open TPM2 edge CA provider: %w", err)
	}
	defer func() { _ = closeProvider() }()
	certifier, ok := provider.(crypto.EdgeTPMCertifier)
	if !ok {
		return fmt.Errorf("TPM2 provider cannot certify a persistent edge key")
	}
	credential, err := deviceattest.CreateEdgeTPMCredential(opts.tenantID, opts.segmentID, csrDER, edgeHandle, aikHandle, chain, aikAuth, certifier)
	if err != nil {
		return err
	}
	if err := writeEdgePrivateFile(opts.attestationOut, credential); err != nil {
		return fmt.Errorf("write edge TPM attestation: %w", err)
	}
	fmt.Printf("TPM2_Certify evidence for tenant %s segment %s written to %s (0600)\n", opts.tenantID, opts.segmentID, opts.attestationOut)
	if opts.mintRequestOut != "" {
		if strings.TrimSpace(opts.mintParentCAID) == "" || strings.TrimSpace(opts.mintHost) == "" || opts.mintTTL < 0 || opts.mintTTL > 30*24*time.Hour || (opts.mintTTL > 0 && opts.mintTTL < time.Second) {
			return fmt.Errorf("edge mint request needs parent CA id, host and a TTL within the 30-day ceiling")
		}
		request := map[string]any{
			"segment_id": opts.segmentID, "ca_id": opts.mintParentCAID, "host": opts.mintHost,
			"csr_der": csrDER, "attestation_credential_json": credential, "key_provider": "tpm2",
		}
		if opts.mintTTL > 0 {
			request["ttl_seconds"] = int(opts.mintTTL.Seconds())
		}
		requestJSON, err := json.MarshalIndent(request, "", "  ")
		if err != nil {
			return fmt.Errorf("encode edge mint request: %w", err)
		}
		if err := writeEdgePrivateFile(opts.mintRequestOut, append(requestJSON, '\n')); err != nil {
			return fmt.Errorf("write edge mint request: %w", err)
		}
		fmt.Printf("reviewed CLI mint body written to %s (0600); send with trstctl-cli edge delegations mint -f\n", opts.mintRequestOut)
	}
	return nil
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
		if err := writeEdgePrivateFile(opts.keyOut, keyPEM); err != nil {
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
		if err := writeEdgePrivateFile(opts.keyHandleOut, handleJSON); err != nil {
			return fmt.Errorf("write edge CA public key handle: %w", err)
		}
		csrDER = generatedCSR
		fmt.Printf("edge CA key generated NON-EXTRACTABLY in %s; opaque public handle written to %s\n", providerName, opts.keyHandleOut)
	default:
		return fmt.Errorf("unknown --edge-key-provider %q (want tpm2, pkcs11, or software)", opts.keyProvider)
	}
	if err := writeEdgePrivateFile(opts.csrOut, csrDER); err != nil {
		return fmt.Errorf("write edge CA CSR: %w", err)
	}
	challenge := crypto.EdgeAttestationChallenge(
		strings.TrimSpace(opts.tenantID), strings.TrimSpace(opts.segmentID), csrDER)
	fmt.Printf("edge CA CSR written to %s\n", opts.csrOut)
	fmt.Printf("mint custody: provider=%s storage=%s exportable=%t\n", providerName, edgeKeyStorage(providerName), providerName == "software")
	fmt.Printf("csr_der (base64, for the mint request): %s\n", base64.StdEncoding.EncodeToString(csrDER))
	fmt.Printf("attestation challenge (hex): %s\n", hex.EncodeToString(challenge))
	fmt.Println("run trstctl-agent --edge-attest with this CSR, its TPM handle, and a certified TPM AIK;")
	fmt.Println("the brain refuses the mint without that TPM2_Certify evidence")
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
	if err := writeEdgePrivateFile(certOut, leaf.CertificatePEM); err != nil {
		return fmt.Errorf("write leaf certificate: %w", err)
	}
	if err := writeEdgePrivateFile(keyOut, leaf.LeafKeyPEM); err != nil {
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
	return writeEdgePrivateFile(path, out)
}

// writeEdgePrivateFile replaces a local edge artifact atomically with mode
// 0600. os.WriteFile would preserve an existing loose mode and follow an
// existing symlink; neither is acceptable for a private key or mint evidence.
func writeEdgePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir) // #nosec G304 -- directory of the operator-selected output, synced after an atomic rename
	if err == nil {
		defer func() { _ = directory.Close() }()
		if err := directory.Sync(); err != nil {
			return err
		}
	}
	return nil
}
