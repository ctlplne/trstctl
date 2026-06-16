package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCALine = "ecdsa-sha2-nistp256 AAAAtestcakey ca@trstctl\n"

// writeCAKey drops the SSH CA public key into a temp file and returns its path.
func writeCAKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pub")
	if err := os.WriteFile(p, []byte(testCALine), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseOpts wires the SSH-trust op against a fresh temp sshd_config + keys file,
// using the real production osFS and runShell so the test exercises the actual
// wiring, not a stand-in. validateCmd/reloadCmd default to shell no-ops the test
// can flip to induce failure.
func baseOpts(t *testing.T) sshTrustOptions {
	t.Helper()
	dir := t.TempDir()
	return sshTrustOptions{
		addCA:       true,
		confirm:     true,
		caKeyPath:   writeCAKey(t),
		tenantID:    "t-ssh",
		sshdConfig:  filepath.Join(dir, "sshd_config"),
		trustedKeys: filepath.Join(dir, "trusted_user_ca_keys"),
		reloadCmd:   "true", // a successful reload
		validateCmd: "true", // a successful `sshd -t` stand-in
	}
}

// TestAgentSSHTrustRequiresConfirmation is the SIGNER-004 / CLAUDE.md §8 assertion:
// the trust rewrite refuses to proceed without --ssh-trust-confirm, and writes
// NOTHING when refused. Forgetting the confirmation fails closed.
func TestAgentSSHTrustRequiresConfirmation(t *testing.T) {
	o := baseOpts(t)
	o.confirm = false

	handled, err := runSSHTrustAddCA(context.Background(), o)
	if !handled {
		t.Fatal("the op should be handled (the flag is on) even when confirmation is missing")
	}
	if err == nil {
		t.Fatal("the SSH-trust rewrite ran WITHOUT confirmation; it must fail closed (CLAUDE.md §8)")
	}
	if _, statErr := os.Stat(o.trustedKeys); statErr == nil {
		t.Error("the trust file was written despite missing confirmation")
	}
}

// TestAgentSSHTrustDisabledIsNoOp confirms the default-off posture: with the flag
// off the op is not handled and nothing is written.
func TestAgentSSHTrustDisabledIsNoOp(t *testing.T) {
	o := baseOpts(t)
	o.addCA = false

	handled, err := runSSHTrustAddCA(context.Background(), o)
	if handled || err != nil {
		t.Fatalf("disabled SSH-trust must be a no-op: handled=%v err=%v", handled, err)
	}
}

// TestAgentSSHTrustAddsCAAdditively is the SIGNER-004 happy path against the real
// osFS: it adds the CA to TrustedUserCAKeys (preserving any existing trust),
// references it from sshd_config, and "validates" + "reloads" before committing.
func TestAgentSSHTrustAddsCAAdditively(t *testing.T) {
	o := baseOpts(t)
	// Pre-existing trust + config that must be preserved (additive).
	if err := os.WriteFile(o.trustedKeys, []byte("ssh-ed25519 AAAAexisting other-ca@corp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.sshdConfig, []byte("Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	handled, err := runSSHTrustAddCA(context.Background(), o)
	if !handled || err != nil {
		t.Fatalf("AddCATrust: handled=%v err=%v", handled, err)
	}
	trust, _ := os.ReadFile(o.trustedKeys)
	if !strings.Contains(string(trust), "ca@trstctl") || !strings.Contains(string(trust), "other-ca@corp") {
		t.Errorf("trust file not additive: %q", trust)
	}
	cfg, _ := os.ReadFile(o.sshdConfig)
	if !strings.Contains(string(cfg), "TrustedUserCAKeys "+o.trustedKeys) || !strings.Contains(string(cfg), "Port 2222") {
		t.Errorf("sshd_config not updated correctly: %q", cfg)
	}
}

// TestAgentSSHTrustRollsBackOnValidateFailure is the SIGNER-004 lockout-protection
// assertion: when `sshd -t` (here, a failing validate command) rejects the new
// config, the change is rolled back — the trust file returns to its prior content
// and the op reports an error. This proves the rollback wiring on an induced
// failure (the design's whole point: a bad rewrite must not lock operators out).
func TestAgentSSHTrustRollsBackOnValidateFailure(t *testing.T) {
	o := baseOpts(t)
	o.validateCmd = "false" // induce a validation failure (sshd -t rejects)
	const orig = "ssh-ed25519 AAAAexisting other-ca@corp\n"
	if err := os.WriteFile(o.trustedKeys, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.sshdConfig, []byte("Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	handled, err := runSSHTrustAddCA(context.Background(), o)
	if !handled {
		t.Fatal("op should be handled")
	}
	if err == nil {
		t.Fatal("expected an error when validation fails (rollback path)")
	}
	trust, _ := os.ReadFile(o.trustedKeys)
	if string(trust) != orig {
		t.Errorf("trust file not rolled back to last-known-good after validate failure: %q", trust)
	}
}

// TestAgentSSHTrustReloadRequired is the fail-closed assertion for the reload
// command: with no reload command configured, the op refuses rather than guessing
// how to reload sshd — and rolls back any staged change.
func TestAgentSSHTrustReloadRequired(t *testing.T) {
	o := baseOpts(t)
	o.reloadCmd = "" // no reload command → fail closed at the reload stage
	const orig = "existing\n"
	if err := os.WriteFile(o.trustedKeys, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.sshdConfig, []byte("Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runSSHTrustAddCA(context.Background(), o)
	if err == nil {
		t.Fatal("expected an error when no reload command is configured")
	}
	trust, _ := os.ReadFile(o.trustedKeys)
	if string(trust) != orig {
		t.Errorf("trust file not rolled back after the reload failed closed: %q", trust)
	}
}
