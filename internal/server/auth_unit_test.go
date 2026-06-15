package server

import (
	"bytes"
	"path/filepath"
	"testing"

	"trustctl.io/trustctl/internal/config"
)

// TestBuildOIDCAuthDisabledIsNoOp: with OIDC disabled, no auth option is produced
// (the binary keeps token-only auth, exactly as before EXC-WIRE-01).
func TestBuildOIDCAuthDisabledIsNoOp(t *testing.T) {
	opt, err := buildOIDCAuth(config.OIDC{Enabled: false}, false, nil)
	if err != nil {
		t.Fatalf("disabled OIDC: %v", err)
	}
	if opt != nil {
		t.Fatal("disabled OIDC must produce no auth option")
	}
}

// TestBuildOIDCAuthEnabledFailsClosed: an enabled-but-misconfigured OIDC block makes
// Build fail closed rather than serving a half-wired login.
func TestBuildOIDCAuthEnabledFailsClosed(t *testing.T) {
	// Enabled but missing essentials (no issuer/endpoints/jwks/secret/tenant mapping).
	_, err := buildOIDCAuth(config.OIDC{Enabled: true}, false, nil)
	if err == nil {
		t.Fatal("enabled-but-misconfigured OIDC must fail closed in Build")
	}
}

// TestSessionSecretPersistsAcrossRestart: the session secret is created once and
// reloaded byte-for-byte, so a restart does not log users out (and HA replicas share
// one secret). It is >= 32 bytes (the HMAC strength floor).
func TestSessionSecretPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.secret")
	first, err := loadOrCreateSessionSecret(path)
	if err != nil {
		t.Fatalf("create session secret: %v", err)
	}
	if len(first) < 32 {
		t.Fatalf("session secret is %d bytes, want >= 32", len(first))
	}
	second, err := loadOrCreateSessionSecret(path)
	if err != nil {
		t.Fatalf("reload session secret: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("session secret changed across reload; a restart would invalidate live sessions")
	}
}
