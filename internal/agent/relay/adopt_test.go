// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// A45: before this agent's first deploy to a host target, the pair the host
// already serves is read; after the deploy it becomes the retained predecessor
// a rollback can restore. A second deploy, a ledger that already has state, or
// an installed leaf equal to the one being deployed adopts nothing.
func TestFirstHostDeployAdoptsTheInstalledPredecessor(t *testing.T) {
	root := t.TempDir()
	installed, err := tlsprobe.NewServingTestServer("adopt.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(installed.Close)
	successor, err := tlsprobe.NewServingTestServer("successor.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(successor.Close)
	ledger, err := NewHostRollbackStore(filepath.Join(root, "ledger"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(root, "tls", "server.crt")
	key := filepath.Join(root, "tls", "server.key")
	if err := os.MkdirAll(filepath.Dir(cert), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, installed.LeafPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("installed-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{filepath.Join(root, "tls")}}
	config, _ := json.Marshal(map[string]string{"cert_path": cert, "key_path": key})
	installedFP := fingerprintOf(t, installed.LeafPEM)
	successorFP := fingerprintOf(t, successor.LeafPEM)
	intent := DeployIntent{Connector: "nginx", Target: "web", TargetID: "target-1", Fingerprint: successorFP, TargetConfig: config}

	// Same leaf as the one being deployed: nothing to adopt.
	same := readAdoptablePredecessor(profile, ledger, true, DeployIntent{Connector: "nginx", TargetID: "target-1", Fingerprint: installedFP, TargetConfig: config})
	if same.ok {
		t.Fatal("the leaf being deployed must not be adopted as its own predecessor")
	}
	// Not a host job, or no ledger: nothing is read.
	if readAdoptablePredecessor(profile, ledger, false, intent).ok || readAdoptablePredecessor(profile, nil, true, intent).ok {
		t.Fatal("adoption must only run for host jobs with a ledger")
	}

	adopted := readAdoptablePredecessor(profile, ledger, true, intent)
	if !adopted.ok || adopted.fingerprint != installedFP || string(adopted.keyPEM) != "installed-key" {
		t.Fatalf("adopted = %+v", adopted)
	}
	// The deploy records its own pair first, then the adoption lands as the
	// retained predecessor.
	if err := ledger.RecordDeploy("nginx", "target-1", successorFP, successor.LeafPEM, []byte("successor-key")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AdoptPredecessor("nginx", "target-1", adopted.fingerprint, adopted.certPEM, adopted.keyPEM); err != nil {
		t.Fatal(err)
	}
	adopted.wipe()
	restored := ""
	if err := ledger.Restore("nginx", "target-1", installedFP, func(certPEM, keyPEM []byte) (bool, error) {
		restored = string(keyPEM)
		return true, nil
	}); err != nil || restored != "installed-key" {
		t.Fatalf("restore of the adopted predecessor = %v restored=%q", err, restored)
	}

	// With state present, a later deploy reads nothing, and adoption never
	// displaces a predecessor the agent already retains.
	if readAdoptablePredecessor(profile, ledger, true, intent).ok {
		t.Fatal("a target with ledger state must not re-adopt from disk")
	}
	if err := ledger.AdoptPredecessor("nginx", "target-1", "ab", []byte("x"), []byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Restore("nginx", "target-1", "ab", func([]byte, []byte) (bool, error) { return false, nil }); err == nil {
		t.Fatal("adoption displaced a retained predecessor")
	}
}
