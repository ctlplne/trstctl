// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

func TestPurgeIsClaimedAndAdvertisedWithItsHostProfile(t *testing.T) {
	if !slices.Contains(ClaimableKinds(), KindEndpointPurge) {
		t.Fatal("the host agent never asks for endpoint.purge")
	}
	for _, shipped := range ShippedJobKinds() {
		if shipped.Kind != KindEndpointPurge {
			continue
		}
		if len(shipped.Connectors) != 0 || !slices.Contains(shipped.Flags, "--host-exec-profile") ||
			!slices.Contains(shipped.Flags, "--host-rollback-dir") || !slices.Contains(shipped.Roles, "host") {
			t.Fatalf("purge must advertise the host profile, ledger and host role without connector work: %+v", shipped)
		}
		return
	}
	t.Fatal("the agent claims and executes endpoint.purge but its shipped capabilities omit it")
}

type purgeFixture struct {
	root        string
	profile     connector.LocalOpsConfig
	ledger      *HostRollbackStore
	compromised *tlsprobe.ServingTestServer
	safe        *tlsprobe.ServingTestServer
	intent      PurgeIntent
}

func newPurgeFixture(t *testing.T, connectorName string, config map[string]string) purgeFixture {
	t.Helper()
	root := t.TempDir()
	compromised, err := tlsprobe.NewServingTestServer("purge.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(compromised.Close)
	safe, err := tlsprobe.NewServingTestServer("safe.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(safe.Close)
	ledger, err := NewHostRollbackStore(filepath.Join(root, "ledger"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return purgeFixture{
		root:    root,
		profile: connector.LocalOpsConfig{AllowedRoots: []string{filepath.Join(root, "tls")}},
		ledger:  ledger, compromised: compromised, safe: safe,
		intent: PurgeIntent{TargetID: "target-1", TargetRevision: "rev-1", IdentityID: "identity-1",
			RequiredAgentID: "agent-1", Connector: connectorName, TargetConfig: raw,
			ExpectedFingerprint: fingerprintOf(t, compromised.LeafPEM)},
	}
}

func fingerprintOf(t *testing.T, leafPEM []byte) string {
	t.Helper()
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(info.SHA256Fingerprint)
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The whole point: the compromised leaf is proven on disk, both files are
// scrubbed and removed, every ledger snapshot with that fingerprint is gone so
// a rollback cannot bring it back, the safe predecessor is the only snapshot
// left, and the bound stop action ran.
func TestPurgeRemovesMatchingMaterialAndWipesTheLedger(t *testing.T) {
	f := newPurgeFixture(t, "nginx", nil)
	cert := filepath.Join(f.root, "tls", "server.crt")
	key := filepath.Join(f.root, "tls", "server.key")
	cfg, _ := json.Marshal(map[string]string{"cert_path": cert, "key_path": key})
	f.intent.TargetConfig = cfg
	writeFixtureFile(t, cert, f.compromised.LeafPEM)
	writeFixtureFile(t, key, []byte("-----BEGIN PRIVATE KEY-----\ncompromised\n-----END PRIVATE KEY-----\n"))
	safeFP := fingerprintOf(t, f.safe.LeafPEM)
	if err := f.ledger.RecordDeploy("nginx", "target-1", safeFP, f.safe.LeafPEM, []byte("safe-key")); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.RecordDeploy("nginx", "target-1", f.intent.ExpectedFingerprint, f.compromised.LeafPEM, []byte("compromised-key")); err != nil {
		t.Fatal(err)
	}
	stops := 0
	got := executePurge(f.profile, f.intent, f.ledger, func() error { stops++; return nil })
	if got.State != PurgeRemoved || !got.LedgerWiped || got.Listener != PurgeListenerStopped || stops != 1 {
		t.Fatalf("report=%+v stops=%d", got, stops)
	}
	if !slices.Equal(got.RemovedFiles, []string{key, cert}) {
		t.Fatalf("removed files = %v, want key then cert", got.RemovedFiles)
	}
	for _, path := range []string{cert, key} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists after purge: %v", path, err)
		}
	}
	if err := ValidatePurgeReport(f.intent, got, got.Digest()); err != nil {
		t.Fatalf("receiver rejected the report: %v", err)
	}
	// The compromised snapshot is unrestorable; the safe one is still there.
	err := f.ledger.Restore("nginx", "target-1", f.intent.ExpectedFingerprint, func(certPEM, keyPEM []byte) (bool, error) {
		t.Fatal("purged material must never be handed back")
		return false, nil
	})
	if !errors.Is(err, ErrHostRollbackPredecessorMissing) {
		t.Fatalf("restore of purged fingerprint = %v, want predecessor missing", err)
	}
	restored := false
	if err := f.ledger.Restore("nginx", "target-1", safeFP, func(certPEM, keyPEM []byte) (bool, error) {
		restored = string(keyPEM) == "safe-key"
		return true, nil
	}); err != nil || !restored {
		t.Fatalf("safe predecessor restore = %v restored=%v", err, restored)
	}
	// Idempotent: a second purge finds the files absent and nothing to wipe.
	again := executePurge(f.profile, f.intent, f.ledger, nil)
	if again.State != PurgeAbsent || again.LedgerWiped || len(again.RemovedFiles) != 0 || again.Listener != PurgeListenerNotBound {
		t.Fatalf("second purge = %+v, want absent with nothing wiped", again)
	}
}

func TestPurgeLeavesADifferentLeafAlone(t *testing.T) {
	f := newPurgeFixture(t, "apache", nil)
	cert := filepath.Join(f.root, "tls", "server.crt")
	key := filepath.Join(f.root, "tls", "server.key")
	cfg, _ := json.Marshal(map[string]string{"cert_path": cert, "key_path": key})
	f.intent.TargetConfig = cfg
	writeFixtureFile(t, cert, f.safe.LeafPEM)
	writeFixtureFile(t, key, []byte("safe-key"))
	if err := f.ledger.RecordDeploy("apache", "target-1", f.intent.ExpectedFingerprint, f.compromised.LeafPEM, []byte("compromised-key")); err != nil {
		t.Fatal(err)
	}
	got := executePurge(f.profile, f.intent, f.ledger, func() error { t.Fatal("no stop for a different leaf"); return nil })
	if got.State != PurgeDifferentLeaf || got.LedgerWiped || len(got.RemovedFiles) != 0 ||
		got.ObservedFingerprint != fingerprintOf(t, f.safe.LeafPEM) {
		t.Fatalf("report=%+v", got)
	}
	for _, path := range []string{cert, key} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s must remain: %v", path, err)
		}
	}
	// The ledger keeps the compromised snapshot: the operator's leaf is not
	// what this target serves, so this target's purge is not the place to
	// decide about it.
	if err := f.ledger.Restore("apache", "target-1", f.intent.ExpectedFingerprint, func([]byte, []byte) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("ledger changed on a different-leaf purge: %v", err)
	}
	if err := ValidatePurgeReport(f.intent, got, got.Digest()); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeHandlesBundlesAndRefusesPathsOutsideTheProfile(t *testing.T) {
	f := newPurgeFixture(t, "haproxy", nil)
	bundle := filepath.Join(f.root, "tls", "site.pem")
	cfg, _ := json.Marshal(map[string]string{"crt_path": bundle})
	f.intent.TargetConfig = cfg
	writeFixtureFile(t, bundle, append(append([]byte(nil), f.compromised.LeafPEM...),
		[]byte("-----BEGIN PRIVATE KEY-----\nY29tcHJvbWlzZWQ=\n-----END PRIVATE KEY-----\n")...))
	got := executePurge(f.profile, f.intent, f.ledger, nil)
	if got.State != PurgeRemoved || !slices.Equal(got.RemovedFiles, []string{bundle}) || got.LedgerWiped {
		t.Fatalf("bundle purge = %+v", got)
	}
	if _, err := os.Lstat(bundle); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle remains: %v", err)
	}

	outside := filepath.Join(f.root, "elsewhere", "site.pem")
	writeFixtureFile(t, outside, f.compromised.LeafPEM)
	cfg, _ = json.Marshal(map[string]string{"crt_path": outside})
	f.intent.TargetConfig = cfg
	got = executePurge(f.profile, f.intent, f.ledger, nil)
	if got.State != PurgeFailed || got.Failure == "" || len(got.RemovedFiles) != 0 {
		t.Fatalf("outside-root purge = %+v, want failed without touching the file", got)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("file outside the profile was touched: %v", err)
	}
	if err := ValidatePurgeReport(f.intent, got, got.Digest()); err != nil {
		t.Fatal(err)
	}

	// A family without an exact file layout is refused before any read.
	f.intent.Connector = "java-keystore"
	got = executePurge(f.profile, f.intent, f.ledger, nil)
	if got.State != PurgeFailed || !strings.Contains(got.Failure, "no exact file layout") {
		t.Fatalf("keystore purge = %+v", got)
	}
}

func TestPurgeReportValidationIsStrict(t *testing.T) {
	intent := PurgeIntent{TargetID: "t", TargetRevision: "r", IdentityID: "i", RequiredAgentID: "a",
		Connector: "nginx", ExpectedFingerprint: strings.Repeat("a", 64), TargetConfig: json.RawMessage(`{}`)}
	good := PurgeReport{TargetID: "t", TargetRevision: "r", IdentityID: "i", Connector: "nginx",
		ExpectedFingerprint: strings.Repeat("a", 64), State: PurgeRemoved, RemovedFiles: []string{"/etc/x.key"},
		LedgerWiped: true, Listener: PurgeListenerStopped}
	if err := ValidatePurgeReport(intent, good, good.Digest()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PurgeReport){
		"wrong target":           func(r *PurgeReport) { r.TargetID = "other" },
		"unknown state":          func(r *PurgeReport) { r.State = "purged" },
		"unknown listener":       func(r *PurgeReport) { r.Listener = "maybe" },
		"removed without files":  func(r *PurgeReport) { r.RemovedFiles = nil },
		"absent naming files":    func(r *PurgeReport) { r.State = PurgeAbsent },
		"failure on a removal":   func(r *PurgeReport) { r.Failure = "x" },
		"digest of other report": func(r *PurgeReport) { r.LedgerWiped = false },
	} {
		r := good
		r.RemovedFiles = append([]string(nil), good.RemovedFiles...)
		digest := good.Digest()
		mutate(&r)
		if name != "digest of other report" {
			digest = r.Digest()
		}
		if err := ValidatePurgeReport(intent, r, digest); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if validPurgeIntent(PurgeIntent{TargetID: "t", TargetRevision: "r", IdentityID: "i", RequiredAgentID: "a",
		Connector: "nginx", ExpectedFingerprint: "short"}) {
		t.Fatal("a short fingerprint or missing config must be refused")
	}
}
