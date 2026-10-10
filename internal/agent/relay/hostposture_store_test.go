// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
)

func TestHostPosturePredecessorSurvivesRestartAndRestoresExactOrder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rollback")
	store, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_AES_256_GCM_SHA384"}, KeyExchangeGroups: []string{"X25519", "P-256"}}
	desired := connector.TLSPosture{MinimumVersion: "TLSv1.3", CipherSuites: []string{"TLS_AES_256_GCM_SHA384"}, KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"}}
	if err := store.PreparePosture("run-1", "target-1", "revision-1", previous, desired); err != nil {
		t.Fatal(err)
	}
	if err := store.PreparePosture("run-1", "target-1", "revision-1", previous, desired); err != nil {
		t.Fatalf("exact prepared retry: %v", err)
	}
	if err := store.PreparePosture("run-2", "target-1", "revision-1", previous, desired); err == nil {
		t.Fatal("another run replaced an unfinished predecessor")
	}
	for _, entry := range mustReadDir(t, root) {
		raw, err := os.ReadFile(filepath.Join(root, entry.Name())) // #nosec G304 -- test-owned directory
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("TLS_RSA_WITH_3DES_EDE_CBC_SHA")) {
			t.Fatalf("predecessor leaked in %s", entry.Name())
		}
	}
	restarted, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.PreparedPosture("run-1", "target-1", "revision-1", desired)
	if err != nil || !connector.EqualTLSPosture(got, previous) {
		t.Fatalf("cold predecessor = %+v, %v", got, err)
	}
	if err := restarted.CommitPosture("run-1", "target-1", "revision-1", desired); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := restarted.RestorePosture("run-1", "target-1", "revision-1", func(prior, applied connector.TLSPosture) error {
		called = true
		if !connector.EqualTLSPosture(prior, previous) || !connector.EqualTLSPosture(applied, desired) {
			t.Fatalf("restore received wrong state: prior=%+v applied=%+v", prior, applied)
		}
		return errors.New("receiver unavailable")
	}); err == nil || !called {
		t.Fatalf("first restore err=%v called=%v", err, called)
	}
	if err := restarted.RestorePosture("run-1", "target-1", "revision-1", func(prior, applied connector.TLSPosture) error {
		if !connector.EqualTLSPosture(prior, previous) || !connector.EqualTLSPosture(applied, desired) {
			t.Fatal("failed restore lost exact predecessor")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.PreparedPosture("run-1", "target-1", "revision-1", desired); !errors.Is(err, relay.ErrHostPostureConflict) {
		t.Fatalf("completed run could reapply after rollback: %v", err)
	}
	if err := restarted.PreparePosture("run-1", "target-1", "revision-1", previous, desired); !errors.Is(err, relay.ErrHostPostureConflict) {
		t.Fatalf("completed run could replace its predecessor after rollback: %v", err)
	}
	if _, err := restarted.PreparedPosture("run-2", "target-1", "revision-1", desired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new run could not prepare after rollback: %v", err)
	}
	if err := restarted.PreparePosture("run-2", "target-1", "revision-1", previous, desired); err != nil {
		t.Fatalf("new run could not preserve its own predecessor: %v", err)
	}
	other, err := relay.NewHostRollbackStore(root, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.PreparedPosture("run-1", "target-1", "revision-1", desired); err == nil {
		t.Fatal("other tenant recovered predecessor")
	}
}

func mustReadDir(t *testing.T, root string) []os.DirEntry {
	t.Helper()
	items, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return items
}
