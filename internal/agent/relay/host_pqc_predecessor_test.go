// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestPQCHostCSRAndIssuedLeafResumeFromEncryptedStateAfterRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rollback")
	state, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	predecessor := strings.Repeat("a", 64)
	if err := state.PinPQCPredecessor("apache", "target-a", "run-a", predecessor,
		[]byte("original cert"), []byte("original private key")); err != nil {
		t.Fatal(err)
	}
	csr := []byte("same csr across reclaimed claims")
	key := []byte("pending ml-dsa private key")
	if err := state.RecordPQCKey("apache", "target-a", "run-a", "asset-a", csr, key); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordPQCCertificate("apache", "target-a", "run-a", "asset-a",
		[]byte("issued leaf"), []byte("chain"), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(root, entry.Name())) // #nosec G304 -- test-owned directory (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, clear := range [][]byte{csr, key, []byte("original private key"), []byte("issued leaf")} {
			if bytes.Contains(raw, clear) {
				t.Fatalf("%s contains plaintext key or certificate state", entry.Name())
			}
		}
	}
	restarted, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.LoadPQCPending("apache", "target-a", "run-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil || !bytes.Equal(pending.CSRDER, csr) || !bytes.Equal(pending.KeyPEM, key) ||
		!bytes.Equal(pending.CertPEM, []byte("issued leaf")) || pending.Fingerprint != strings.Repeat("b", 64) {
		t.Fatal("reclaimed job did not recover exact sealed CSR, key and signed leaf")
	}
	wipePQCPending(pending)
	if _, err := restarted.LoadPQCPending("apache", "target-a", "run-a", "other-asset"); err == nil {
		t.Fatal("different asset reached pending host key")
	}
	if err := restarted.ClearPQCPending("apache", "target-a", "run-a", "asset-a"); err != nil {
		t.Fatal(err)
	}
	pending, err = restarted.LoadPQCPending("apache", "target-a", "run-a", "asset-a")
	if err != nil || pending != nil {
		t.Fatalf("accepted signed report left pending key: %v %+v", err, pending)
	}
}

func TestPQCPredecessorRefusesChangedCBOMAndUnmatchedInstalledKeyBeforeIssuance(t *testing.T) {
	root := t.TempDir()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "test issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateHostSubjectKey("example.test", []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, subject.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM, err := subject.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(keyPEM)
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(HostTargetConfig{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewHostRollbackStore(filepath.Join(root, "rollback"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	intent := DeployIntent{Connector: "apache", TargetID: "target-a", TargetConfig: config,
		VerifyAddress: "127.0.0.1:1", VerifyServerName: "example.test", PQCRunID: "run-a", PQCAssetID: "asset-a",
		PQCPredecessorFingerprint: strings.Repeat("0", 64)}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}}
	if err := adoptPQCPredecessor(t.Context(), profile, state, intent); err == nil || !strings.Contains(err.Error(), "CBOM") {
		t.Fatalf("changed discovered fingerprint was accepted: %v", err)
	}
	info, err := certinfo.Inspect(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	intent.PQCPredecessorFingerprint = info.SHA256Fingerprint
	other, err := crypto.GenerateHostSubjectKey("example.test", []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	wrongKey, err := other.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(wrongKey)
	if err := os.WriteFile(keyPath, wrongKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adoptPQCPredecessor(context.Background(), profile, state, intent); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("unmatched installed key was accepted: %v", err)
	}
}
