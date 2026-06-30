package projections_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/crypto/sshtestserver"
	"trstctl.com/trstctl/internal/discovery/sshscan"
	"trstctl.com/trstctl/internal/sshinv"
	"trstctl.com/trstctl/internal/store"
)

const (
	sshEdPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt alice@laptop"
	sshEcPub = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCTRiePj3JSBO27Q7RQcNOhLFvuJVqXzGAJAradHGDPH3fXi2KBp0c2FK8o5YYdngfTuUexh06+qAZXDqkxVmbY="
	sshEcFP  = "SHA256:Qqg49fPYXEb9soSN6Ebjr/udvM1M5Cm5cmUEC1T81qg"
)

func sshKeyByFingerprint(t *testing.T, ctx context.Context, s *store.Store, fp string) (store.SSHKey, bool) {
	t.Helper()
	keys, err := s.ListSSHKeysPage(ctx, tenantA, store.ZeroUUID, 1000)
	if err != nil {
		t.Fatalf("list ssh keys: %v", err)
	}
	for _, k := range keys {
		if k.Fingerprint == fp {
			return k, true
		}
	}
	return store.SSHKey{}, false
}

// TestSSHHostKeyProbeReconcilesIntoInventory is the S6.3 probe acceptance: an SSH
// host key discovered by the network probe lands in the inventory, idempotently.
func TestSSHHostKeyProbeReconcilesIntoInventory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	srv, err := sshtestserver.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	sink := sshinv.NewStoreSink(s, tenantA)
	sc := sshscan.New(sink, sshscan.WithAllowLoopbackTargets(true))
	defer sc.Close()

	if rep := sc.Scan(ctx, []string{srv.Addr()}); rep.Discovered != 1 {
		t.Fatalf("scan report = %+v, want 1 discovered", rep)
	}

	key, ok := sshKeyByFingerprint(t, ctx, s, srv.FingerprintSHA256())
	if !ok {
		t.Fatalf("probed host key %s not in inventory", srv.FingerprintSHA256())
	}
	if key.Source != sshinv.SourceHostProbe || key.KeyType != "ssh-ed25519" {
		t.Errorf("inventory row = %+v", key)
	}
	if key.Location != srv.Addr() {
		t.Errorf("location = %q, want %q", key.Location, srv.Addr())
	}

	// Re-probing the same host refreshes the row rather than duplicating it.
	_ = sc.Scan(ctx, []string{srv.Addr()})
	n := 0
	keys, _ := s.ListSSHKeysPage(ctx, tenantA, store.ZeroUUID, 1000)
	for _, k := range keys {
		if k.Fingerprint == srv.FingerprintSHA256() {
			n++
		}
	}
	if n != 1 {
		t.Errorf("re-probe produced %d rows for the host key, want 1", n)
	}
}

// TestAgentSSHMaterialReconcilesIntoInventory is the S6.3 agent acceptance: the
// agent inventories on-host SSH material, and an orphaned standing-access grant
// appears flagged in the inventory.
func TestAgentSSHMaterialReconcilesIntoInventory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	home := filepath.Join(t.TempDir(), ".ssh")
	// authorized_keys: an owned grant and an unattributable (no-comment) one.
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "authorized_keys"), []byte(sshEdPub+"\n"+sshEcPub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := sshdiscovery.New(sshdiscovery.Config{
		AuthorizedKeysPaths: []string{filepath.Join(home, "authorized_keys")},
	})
	found, err := src.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sink := sshinv.NewStoreSink(s, tenantA)
	for _, f := range found {
		if err := sink.Record(ctx, f); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	// The orphaned, no-comment grant is flagged in the inventory.
	orphan, ok := sshKeyByFingerprint(t, ctx, s, sshEcFP)
	if !ok {
		t.Fatal("orphaned grant not in inventory")
	}
	if !orphan.Orphaned || !orphan.StandingAccess {
		t.Errorf("orphaned grant in inventory = %+v, want orphaned + standing access", orphan)
	}
	if orphan.Source != sshinv.SourceAuthorizedKeys {
		t.Errorf("source = %q, want ssh-authorized-keys", orphan.Source)
	}
}
