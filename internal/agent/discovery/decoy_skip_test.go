// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/decoy"
	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Q6-O1: the agent's private-key scan finds a real SSH key beside a decoy the
// agent planted, and never opens the decoy: an open would be a decoy alert.
func TestPrivateKeyScanSkipsTheAgentsDecoysQ6O1(t *testing.T) {
	dir := t.TempDir()
	private, _, err := cryptoboundary.GenerateSSHClientKey("deploy@host")
	if err != nil {
		t.Fatal(err)
	}
	realKey := filepath.Join(dir, "id_ed25519")
	err = os.WriteFile(realKey, private, 0o600)
	secret.Wipe(private)
	if err != nil {
		t.Fatal(err)
	}
	decoyPath := filepath.Join(dir, "id_ed25519_backup")
	if _, err := decoy.Plant([]string{decoyPath}, filepath.Join(t.TempDir(), "decoys.json")); err != nil {
		t.Fatal(err)
	}
	found, err := NewPrivateKeySource(dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var locations []string
	for _, f := range found {
		locations = append(locations, f.Location)
	}
	if len(found) != 1 || found[0].Location != realKey {
		t.Fatalf("private-key scan found %v; want only the real key %s, never the decoy", locations, realKey)
	}
	if got, err := NewKeystoreSource(nil, decoyPath).Discover(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("keystore scan of the decoy = %v, %v; want nothing", got, err)
	}
}
