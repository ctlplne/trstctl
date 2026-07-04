// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

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

func (osFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

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
	return runCommandLine(ctx, cmd)
}

func (r *sshdReloader) Reload(ctx context.Context) error {
	if r.reloadCmd == "" {
		return fmt.Errorf("no sshd reload command configured (--ssh-trust-reload-cmd); refusing to guess how to reload sshd")
	}
	return runCommandLine(ctx, r.reloadCmd)
}

func (r *sshdReloader) HealthCheck(ctx context.Context) error {
	if r.healthCmd == "" {
		return fmt.Errorf("no sshd health command configured (--ssh-trust-health-cmd); refusing to treat reload success as daemon health")
	}
	return runCommandLine(ctx, r.healthCmd)
}

// runCommandLine runs a whitespace-delimited argv directly, without a shell.
// Operator-provided reload/health commands are intentionally simple command
// lines; shell pipelines and expansions are rejected so trust rewrites cannot
// become a command-injection surface.
func runCommandLine(ctx context.Context, line string) error {
	argv, err := parseCommandLine(line)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%q failed: %v: %s", line, err, string(out))
	}
	return nil
}

func parseCommandLine(line string) ([]string, error) {
	if strings.ContainsAny(line, "\x00\r\n") {
		return nil, fmt.Errorf("command contains a newline or NUL")
	}
	argv := strings.Fields(line)
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	if shellName(argv[0]) {
		return nil, fmt.Errorf("command %q is a shell interpreter; configure the target binary directly", argv[0])
	}
	for i, token := range argv {
		if err := validateCommandToken(fmt.Sprintf("arg[%d]", i), token); err != nil {
			return nil, err
		}
	}
	return argv, nil
}

func validateCommandToken(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if strings.ContainsAny(value, "\x00\r\n;&|`$<>{}[]*?") {
		return fmt.Errorf("%s %q contains shell metacharacters", label, value)
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%s %q contains whitespace; configure argv tokens explicitly", label, value)
		}
	}
	return nil
}

func shellName(command string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}
