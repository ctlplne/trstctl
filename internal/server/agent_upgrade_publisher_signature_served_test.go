// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// A68: a control plane that pins an upgrade publisher key refuses to open a
// campaign whose artifacts the publisher did not sign, by name, and accepts
// the signed one. Without a pinned key the sha256 pin alone still opens a
// campaign, which is the documented default.
func TestServedUpgradeCampaignRequiresThePublisherSignatureWhenAKeyIsPinned(t *testing.T) {
	privPEM, pubPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "upgrade-publisher.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Production pins the key the same way: the file path on Deps, loaded while
	// the agent enrollment surface is configured.
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentUpgradePublisherKeyFile = keyFile
	})
	if len(h.srv.agentUpgradePublisherKeyDER) != len(pub.DER) {
		t.Fatal("the pinned publisher key was not loaded from the configured file")
	}
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	artifact := map[string]any{"os": "linux", "arch": "amd64", "url": "https://mirror.example.test/trstctl-agent", "sha256": strings.Repeat("ab", 32)}
	open := func(key string, artifacts []map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok, key, map[string]any{
			"target_version": "9.9.9", "artifacts": artifacts,
		})
	}
	if status, body := open("a68-unsigned", []map[string]any{artifact}); status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "publisher") {
		t.Fatalf("unsigned artifact with a pinned publisher key: status %d body %s; want 422 naming the publisher signature", status, body)
	}
	signature, err := fleet.SignArtifact(fleet.Artifact{OS: "linux", Arch: "amd64", URL: "https://mirror.example.test/trstctl-agent", SHA256: strings.Repeat("ab", 32)}, privPEM)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"os": "linux", "arch": "amd64", "url": "https://mirror.example.test/trstctl-agent", "sha256": strings.Repeat("ab", 32), "signature": signature}
	if status, body := open("a68-signed", []map[string]any{signed}); status != http.StatusCreated {
		t.Fatalf("signed artifact with a pinned publisher key: status %d body %s; want 201", status, body)
	}
}
