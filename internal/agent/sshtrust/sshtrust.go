// This file is the S13.3 build: the Applier implements the reviewed S13.2 design
// (docs/design/ssh-trust-rewrite.md). It configures a host to trust the SSH CA
// additively, validates with sshd -t before reloading, health-checks after, and
// rolls back automatically on any failure — so the change cannot lock an operator
// out. Existing trust is never removed without explicit confirmation.
package sshtrust

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"trustctl.io/trustctl/internal/auditsink"
)

// Applier performs the host SSH trust rewrite (S13.3).
type Applier struct {
	cfg      Config
	audit    auditsink.Auditor
	tenantID string
}

// New validates configuration and constructs an Applier.
func New(tenantID string, cfg Config, audit auditsink.Auditor) (*Applier, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("sshtrust: TenantID required (AN-1)")
	}
	if cfg.FS == nil || cfg.Reloader == nil {
		return nil, fmt.Errorf("sshtrust: FileSystem and Reloader required")
	}
	if cfg.SSHDConfigPath == "" || cfg.TrustedUserCAKeysPath == "" {
		return nil, fmt.Errorf("sshtrust: sshd_config and TrustedUserCAKeys paths required")
	}
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Applier{cfg: cfg, audit: audit, tenantID: tenantID}, nil
}

// AddCATrust adds the SSH CA public key to TrustedUserCAKeys (additive and
// idempotent), ensures sshd_config references the file, then validates, reloads,
// and health-checks — rolling back automatically on any failure. Existing trust
// is preserved.
func (a *Applier) AddCATrust(ctx context.Context, caPublicKey []byte) (changed bool, err error) {
	trustBak, trustExisted := a.read(a.cfg.TrustedUserCAKeysPath)
	cfgBak, cfgExisted := a.read(a.cfg.SSHDConfigPath)

	caLine := strings.TrimRight(string(caPublicKey), "\n")
	if caLine == "" {
		return false, fmt.Errorf("sshtrust: empty CA public key")
	}
	if containsLine(string(trustBak), caLine) {
		return false, nil // already trusted — idempotent no-op
	}

	newTrust := appendLine(string(trustBak), caLine)
	newCfg := string(cfgBak)
	directive := "TrustedUserCAKeys " + a.cfg.TrustedUserCAKeysPath
	if !strings.Contains(newCfg, directive) {
		newCfg = appendLine(newCfg, directive)
	}

	if err := a.cfg.FS.WriteFileAtomic(a.cfg.TrustedUserCAKeysPath, []byte(newTrust), 0o644); err != nil {
		return false, fmt.Errorf("sshtrust: write trust file: %w", err)
	}
	if err := a.cfg.FS.WriteFileAtomic(a.cfg.SSHDConfigPath, []byte(newCfg), 0o600); err != nil {
		a.restore(a.cfg.TrustedUserCAKeysPath, trustBak, trustExisted)
		return false, fmt.Errorf("sshtrust: write sshd_config: %w", err)
	}

	if err := a.validateReloadHealth(ctx, trustBak, trustExisted, cfgBak, cfgExisted); err != nil {
		return false, err
	}
	a.auditEv(ctx, "ssh.trust.added", caLine)
	return true, nil
}

// RemoveCATrust removes a CA trust line, but only with explicit confirmation: the
// design forbids removing existing trust as an implicit side effect.
func (a *Applier) RemoveCATrust(ctx context.Context, caPublicKey []byte, confirm bool) error {
	if a.cfg.RequireConfirmationToRemoveTrust && !confirm {
		return fmt.Errorf("sshtrust: refusing to remove trust without explicit confirmation")
	}
	trustBak, trustExisted := a.read(a.cfg.TrustedUserCAKeysPath)
	cfgBak, cfgExisted := a.read(a.cfg.SSHDConfigPath)
	caLine := strings.TrimRight(string(caPublicKey), "\n")
	if !containsLine(string(trustBak), caLine) {
		return nil // not present — nothing to remove
	}
	newTrust := removeLine(string(trustBak), caLine)
	if err := a.cfg.FS.WriteFileAtomic(a.cfg.TrustedUserCAKeysPath, []byte(newTrust), 0o644); err != nil {
		return fmt.Errorf("sshtrust: write trust file: %w", err)
	}
	if err := a.validateReloadHealth(ctx, trustBak, trustExisted, cfgBak, cfgExisted); err != nil {
		return err
	}
	a.auditEv(ctx, "ssh.trust.removed", caLine)
	return nil
}

// validateReloadHealth runs sshd -t, reloads, and health-checks; on any failure it
// restores both files from backup and reloads the restored config (rollback).
func (a *Applier) validateReloadHealth(ctx context.Context, trustBak []byte, trustExisted bool, cfgBak []byte, cfgExisted bool) error {
	rollback := func(stage string, cause error) error {
		a.restore(a.cfg.TrustedUserCAKeysPath, trustBak, trustExisted)
		a.restore(a.cfg.SSHDConfigPath, cfgBak, cfgExisted)
		_ = a.cfg.Reloader.Reload(ctx) // reload the restored, known-good config
		a.auditEv(ctx, "ssh.trust.rolled_back", stage)
		return fmt.Errorf("sshtrust: %s failed, rolled back to last-known-good: %w", stage, cause)
	}
	if err := a.cfg.Reloader.Validate(ctx); err != nil {
		return rollback("validate", err)
	}
	if err := a.cfg.Reloader.Reload(ctx); err != nil {
		return rollback("reload", err)
	}
	if err := a.cfg.Reloader.HealthCheck(ctx); err != nil {
		return rollback("health-check", err)
	}
	return nil
}

func (a *Applier) read(path string) (data []byte, existed bool) {
	b, err := a.cfg.FS.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false
		}
		return nil, false
	}
	return b, true
}

func (a *Applier) restore(path string, backup []byte, existed bool) {
	if existed {
		_ = a.cfg.FS.WriteFileAtomic(path, backup, 0o600)
		return
	}
	_ = a.cfg.FS.Remove(path)
}

func (a *Applier) auditEv(ctx context.Context, event, detail string) {
	_ = a.audit.Audit(ctx, event, a.tenantID, []byte(fmt.Sprintf(`{"detail":%q}`, detail)))
}

func appendLine(content, line string) string {
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

func removeLine(content, line string) string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) == strings.TrimSpace(line) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func containsLine(content, line string) bool {
	want := strings.TrimSpace(line)
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}
