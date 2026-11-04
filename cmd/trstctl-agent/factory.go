// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Factory station (P12). `trstctl-agent --factory-issue` certifies one device
// on the production line: the line's tooling runs it once per device, with
// the batch manifest from the control plane, the station's delegated edge CA
// and its key (TPM 2.0, PKCS#11, or a software key by explicit exception), and
// the device's own CSR — its key is made on the device and never reaches the
// station. The station holds no network listener and makes no network call:
// the batch journal it appends to is reconciled with
// `trstctl edge factory-batches reconcile <batch> -f <journal>` when it
// reconnects. The quota is enforced here against the journal, and again at
// reconcile, where a birth certificate past it is recorded as over-production
// and cannot enroll.

// factoryManifest is GET /api/v1/edge/factory-batches/{id}/manifest.
type factoryManifest struct {
	BatchID               string `json:"batch_id"`
	TenantID              string `json:"tenant_id"`
	DelegationID          string `json:"delegation_id"`
	DelegationFingerprint string `json:"delegation_fingerprint"`
	Label                 string `json:"label"`
	Quota                 int    `json:"quota"`
	BirthTTLSeconds       int    `json:"birth_ttl_seconds"`
	ESTPath               string `json:"est_path"`
}

// factoryJournal is the batch journal, in the shape
// POST /api/v1/edge/factory-batches/{id}/reconcile accepts.
type factoryJournal struct {
	Host            string   `json:"host"`
	BatchID         string   `json:"batch_id"`
	CertificatesPEM []string `json:"certificates_pem"`
}

// errFactoryQuota is the refusal past the batch's quota.
var errFactoryQuota = errors.New("factory batch quota reached")

func readFactoryManifest(path string) (factoryManifest, error) {
	var m factoryManifest
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return m, fmt.Errorf("read factory manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("decode factory manifest: %w", err)
	}
	if m.BatchID == "" || m.DelegationFingerprint == "" || m.Quota <= 0 || m.BirthTTLSeconds <= 0 {
		return m, fmt.Errorf("the factory manifest names no batch, delegation, quota or birth lifetime")
	}
	return m, nil
}

func readFactoryJournal(path, batchID string) (factoryJournal, error) {
	journal := factoryJournal{BatchID: batchID}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}
	if err != nil {
		return journal, fmt.Errorf("read factory journal: %w", err)
	}
	if err := json.Unmarshal(raw, &journal); err != nil {
		return journal, fmt.Errorf("decode factory journal: %w", err)
	}
	if journal.BatchID != batchID {
		return journal, fmt.Errorf("the factory journal %s belongs to batch %s, not %s", path, journal.BatchID, batchID)
	}
	return journal, nil
}

func readFactoryCSR(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read device CSR: %w", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("the device CSR PEM block is %q", block.Type)
		}
		return block.Bytes, nil
	}
	return raw, nil
}

// lockFactoryJournal makes one issuance at a time against a journal: two
// line tools running at once would otherwise both see room under the quota.
func lockFactoryJournal(journalPath string) (func(), error) {
	lock := journalPath + ".lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- derived from the operator-configured journal path (CWE-22)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("another factory issuance holds %s; wait for it, or remove the lock if no issuance is running", lock)
		}
		return nil, err
	}
	_ = f.Close()
	return func() { _ = os.Remove(lock) }, nil
}

func writeFactoryJournal(path string, journal factoryJournal) error {
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".factory-journal-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func runFactoryIssue(opts edgeCAOptions, host string) error {
	if opts.factoryManifest == "" || opts.factoryCSR == "" || strings.TrimSpace(opts.factoryDevice) == "" || opts.caCert == "" {
		return fmt.Errorf("factory-issue requires --factory-manifest, --factory-csr, --factory-device and --edge-ca-cert")
	}
	manifest, err := readFactoryManifest(opts.factoryManifest)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(opts.caCert) // #nosec G304 -- operator-configured local path from the agent's own flags (CWE-22)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || !strings.EqualFold(crypto.SHA256Hex(block.Bytes), manifest.DelegationFingerprint) {
		return fmt.Errorf("--edge-ca-cert is not the delegation batch %s issues under", manifest.BatchID)
	}
	journalPath := opts.factoryJournal
	if journalPath == "" {
		journalPath = "factory-journal.json"
	}
	unlock, err := lockFactoryJournal(journalPath)
	if err != nil {
		return err
	}
	defer unlock()
	journal, err := readFactoryJournal(journalPath, manifest.BatchID)
	if err != nil {
		return err
	}
	if len(journal.CertificatesPEM) >= manifest.Quota {
		return fmt.Errorf("%w: batch %s has issued %d of %d birth certificates; one more would be over-production",
			errFactoryQuota, manifest.BatchID, len(journal.CertificatesPEM), manifest.Quota)
	}
	csrDER, err := readFactoryCSR(opts.factoryCSR)
	if err != nil {
		return err
	}
	leaf, err := issueEdgeLeafFromOptions(opts, certPEM, crypto.EdgeLeafRequest{
		CommonName: strings.TrimSpace(opts.factoryDevice), TTL: time.Duration(manifest.BirthTTLSeconds) * time.Second,
		CSRDER: csrDER, ClientAuthOnly: true,
	})
	if err != nil {
		return err
	}
	certOut := opts.certOut
	if certOut == "" || certOut == "edge-leaf.crt" {
		certOut = "factory-birth.crt"
	}
	if err := writeEdgePrivateFile(certOut, leaf.CertificatePEM); err != nil {
		return fmt.Errorf("write birth certificate: %w", err)
	}
	if journal.Host == "" {
		journal.Host = host
	}
	journal.CertificatesPEM = append(journal.CertificatesPEM, string(leaf.CertificatePEM))
	if err := writeFactoryJournal(journalPath, journal); err != nil {
		return fmt.Errorf("record the birth certificate in the journal: %w", err)
	}
	fmt.Printf("birth certificate %d of %d for %s: serial %s, expires %s\n", len(journal.CertificatesPEM), manifest.Quota,
		strings.TrimSpace(opts.factoryDevice), leaf.SerialHex, leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("certificate: %s  journal: %s\n", certOut, journalPath)
	fmt.Println("reconcile the journal when the station reconnects: trstctl edge factory-batches reconcile " + manifest.BatchID + " -f " + journalPath)
	return nil
}
