package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"trstctl.com/trstctl/internal/agent/sshtrust"
)

// sshTrustOptions are the operator opt-in for the privileged SSH-trust rewrite
// (SIGNER-004). The whole feature is DEFAULT-OFF (addCA=false): the agent reads
// SSH trust during discovery but never rewrites a host's trust unless an operator
// deliberately turns this on. Configuring a host to trust the SSH CA is a
// high-blast-radius mutation (a bad rewrite can lock operators out), so it is
// gated behind both an explicit enable flag AND an explicit confirmation flag,
// and the underlying Applier is additive (it never removes existing trust) with
// an automatic validate→reload→health-check→rollback (see internal/agent/sshtrust).
type sshTrustOptions struct {
	addCA       bool   // --ssh-trust-add-ca: opt in to the trust rewrite
	confirm     bool   // --ssh-trust-confirm: explicit operator confirmation (required)
	caKeyPath   string // path to the SSH CA public key to trust (OpenSSH authorized-key line)
	tenantID    string // tenant the trust change is audited under (AN-1)
	sshdConfig  string // sshd_config path
	trustedKeys string // TrustedUserCAKeys path
	reloadCmd   string // command to reload sshd after a validated config (e.g. "systemctl reload sshd")
	validateCmd string // command that runs `sshd -t` (defaults to "sshd -t")
	healthCmd   string // command that proves sshd is healthy after reload; required for mutation
}

// runSSHTrustAddCA performs the opt-in SSH-trust rewrite when enabled, then
// returns (handled=true) so the caller knows the agent ran this one-shot op
// instead of the steady-state loop. It is fail-closed and refuses to proceed
// without explicit confirmation — forgetting --ssh-trust-confirm does NOT silently
// rewrite trust (CLAUDE.md §8: never weaken sshd/authorized_keys trust without
// explicit confirmation and rollback). On success the agent prints what changed.
func runSSHTrustAddCA(ctx context.Context, o sshTrustOptions) (handled bool, err error) {
	if !o.addCA {
		return false, nil
	}
	if !o.confirm {
		return true, fmt.Errorf("--ssh-trust-add-ca rewrites this host's SSH CA trust; re-run with --ssh-trust-confirm to proceed (the change is additive and auto-rolls-back, but is intentionally gated)")
	}
	if o.caKeyPath == "" {
		return true, fmt.Errorf("--ssh-trust-ca-key (the SSH CA public key to trust) is required with --ssh-trust-add-ca")
	}
	if o.tenantID == "" {
		return true, fmt.Errorf("--ssh-trust-tenant is required so the trust change is audited under a tenant (AN-1)")
	}
	caKey, rerr := os.ReadFile(o.caKeyPath)
	if rerr != nil {
		return true, fmt.Errorf("read SSH CA public key %q: %w", o.caKeyPath, rerr)
	}

	cfg := sshtrust.Config{
		FS:                    osFS{},
		Reloader:              &sshdReloader{validateCmd: o.validateCmd, reloadCmd: o.reloadCmd, healthCmd: o.healthCmd},
		SSHDConfigPath:        o.sshdConfig,
		TrustedUserCAKeysPath: o.trustedKeys,
		// AllowUnconfirmedRemoval stays false (the safe default): this opt-in only
		// ADDS trust; removals would still require their own explicit confirmation.
	}
	applier, aerr := sshtrust.New(o.tenantID, cfg, nil)
	if aerr != nil {
		return true, aerr
	}
	changed, aerr := applier.AddCATrust(ctx, caKey)
	if aerr != nil {
		return true, fmt.Errorf("ssh-trust add-ca: %w", aerr)
	}
	if changed {
		fmt.Printf("trstctl-agent: SSH CA trust added to %s (sshd validated, reloaded, health-checked; auto-rollback armed)\n", o.trustedKeys)
	} else {
		fmt.Printf("trstctl-agent: SSH CA already trusted in %s (no change)\n", o.trustedKeys)
	}
	return true, nil
}

// osFS is the production sshtrust.FileSystem: real reads, atomic writes
// (write-temp-then-rename so a crash mid-write can never leave a half-written
// sshd_config), and removes.
type osFS struct{}

func (osFS) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

func (osFS) WriteFileAtomic(p string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".trstctl-sshtrust-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func (osFS) Remove(p string) error { return os.Remove(p) }
func (osFS) Exists(p string) bool  { _, err := os.Stat(p); return err == nil }

// sshdReloader is the production sshtrust.Reloader: it validates the config with
// `sshd -t`, reloads via the operator-supplied reload command, then runs an
// operator-supplied health command that must prove sshd is usable after reload.
// A non-zero exit at any stage drives the Applier's automatic rollback. Reload
// and health commands are operator-supplied because platform init systems and
// acceptable SSH probes vary; there is no safe universal default, so unset
// commands fail closed rather than guessing.
type sshdReloader struct {
	validateCmd string
	reloadCmd   string
	healthCmd   string
}

func (r *sshdReloader) Validate(ctx context.Context) error {
	cmd := r.validateCmd
	if cmd == "" {
		cmd = "sshd -t"
	}
	return runShell(ctx, cmd)
}

func (r *sshdReloader) Reload(ctx context.Context) error {
	if r.reloadCmd == "" {
		return fmt.Errorf("no sshd reload command configured (--ssh-trust-reload-cmd); refusing to guess how to reload sshd")
	}
	return runShell(ctx, r.reloadCmd)
}

func (r *sshdReloader) HealthCheck(ctx context.Context) error {
	if r.healthCmd == "" {
		return fmt.Errorf("no sshd health command configured (--ssh-trust-health-cmd); refusing to treat reload success as daemon health")
	}
	return runShell(ctx, r.healthCmd)
}

// runShell runs a command line via the system shell, returning its combined
// output in the error on failure so the operator sees why sshd rejected the
// change (which triggers rollback).
func runShell(ctx context.Context, line string) error {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", line)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%q failed: %v: %s", line, err, string(out))
	}
	return nil
}
