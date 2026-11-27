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

func signedUpgradeFixture(t *testing.T) (func(*Deps), func(string, string) map[string]any) {
	t.Helper()
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "upgrade-publisher.pub")
	if err := os.WriteFile(keyFile, public, 0o600); err != nil {
		t.Fatal(err)
	}
	option := func(d *Deps) { d.AgentUpgradePublisherKeyFile = keyFile }
	artifact := func(url, digest string) map[string]any {
		t.Helper()
		a := fleet.Artifact{OS: "linux", Arch: "amd64", URL: url, SHA256: digest}
		signature, err := fleet.SignArtifact(a, private)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"os": a.OS, "arch": a.Arch, "url": a.URL, "sha256": a.SHA256, "signature": signature}
	}
	return option, artifact
}

// A68: a control plane that pins an upgrade publisher key refuses to open a
// campaign whose artifacts the publisher did not sign, by name, and accepts
// the signed one.
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

func TestServedUpgradeCampaignRefusesExecutableWithoutPublisherTrustAnchor(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	artifact := map[string]any{"os": "linux", "arch": "amd64", "url": "http://mirror.example.test/trstctl-agent", "sha256": strings.Repeat("ab", 32)}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"unsigned-without-publisher-key", map[string]any{"target_version": "9.9.9", "artifacts": []map[string]any{artifact}})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "publisher key") {
		t.Fatalf("campaign without publisher trust anchor: status %d body %s, want 422", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"observe-only-without-publisher-key", map[string]any{"target_version": "9.9.9"})
	if status != http.StatusCreated || !strings.Contains(string(body), `"observe_only":true`) {
		t.Fatalf("observe-only campaign without artifacts: status %d body %s, want 201", status, body)
	}
}
