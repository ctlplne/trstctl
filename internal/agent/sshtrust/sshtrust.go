// SPDX-License-Identifier: MPL-2.0

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
	"path"
	"sort"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/auditsink"
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
	trustHasCA := containsLine(string(trustBak), caLine)
	newTrust := string(trustBak)
	if !trustHasCA {
		newTrust = appendLine(newTrust, caLine)
	}
	newCfg := string(cfgBak)
	directive := "TrustedUserCAKeys " + a.cfg.TrustedUserCAKeysPath
	cfgReferencesTrustFile := a.sshdConfigReferencesTrustedKeys(a.cfg.SSHDConfigPath, newCfg, a.cfg.TrustedUserCAKeysPath, map[string]bool{})
	if trustHasCA && cfgReferencesTrustFile {
		return false, nil // already trusted and enabled — idempotent no-op
	}
	if !cfgReferencesTrustFile {
		newCfg = appendLine(newCfg, directive)
	}

	if err := a.cfg.FS.WriteFileAtomic(a.cfg.TrustedUserCAKeysPath, []byte(newTrust), 0o644); err != nil {
		return false, fmt.Errorf("sshtrust: write trust file: %w", err)
	}
	if err := a.cfg.FS.WriteFileAtomic(a.cfg.SSHDConfigPath, []byte(newCfg), 0o600); err != nil {
		if rollbackErr := a.rollbackFiles(ctx, "write sshd_config", err, false, fileBackup{path: a.cfg.TrustedUserCAKeysPath, data: trustBak, existed: trustExisted}); rollbackErr != nil {
			return false, rollbackErr
		}
		return false, fmt.Errorf("sshtrust: write sshd_config: %w", err)
	}

	if err := a.validateReloadHealth(ctx, trustBak, trustExisted, cfgBak, cfgExisted); err != nil {
		return false, err
	}
	a.auditEv(ctx, "ssh.trust.added", caLine)
	return true, nil
}

// RemoveCATrust removes a CA trust line, but only with explicit confirmation: the
// design forbids removing existing trust as an implicit side effect. Confirmation
// is required by DEFAULT — a zero-value Config (AllowUnconfirmedRemoval=false)
// rejects RemoveCATrust(..., false), so forgetting the flag fails closed rather
// than silently removing trust and risking lockout (SIGNER-007). Only a Config that
// deliberately sets AllowUnconfirmedRemoval=true may bypass the confirmation.
func (a *Applier) RemoveCATrust(ctx context.Context, caPublicKey []byte, confirm bool) error {
	if !a.cfg.AllowUnconfirmedRemoval && !confirm {
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
		return a.rollbackFiles(ctx, stage, cause, true,
			fileBackup{path: a.cfg.TrustedUserCAKeysPath, data: trustBak, existed: trustExisted},
			fileBackup{path: a.cfg.SSHDConfigPath, data: cfgBak, existed: cfgExisted},
		)
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

type fileBackup struct {
	path    string
	data    []byte
	existed bool
}

func (a *Applier) rollbackFiles(ctx context.Context, stage string, cause error, reload bool, backups ...fileBackup) error {
	var rollbackErrs []error
	for _, backup := range backups {
		if err := a.restore(backup.path, backup.data, backup.existed); err != nil {
			rollbackErrs = append(rollbackErrs, err)
		}
	}
	if reload {
		// Reload the restored, known-good config only after best-effort file
		// restoration. A reload failure is a rollback failure, not a successful
		// rollback with a hidden footnote.
		if err := a.cfg.Reloader.Reload(ctx); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("sshtrust: reload restored config: %w", err))
		}
	}
	if rollbackErr := errors.Join(rollbackErrs...); rollbackErr != nil {
		a.auditEv(ctx, "ssh.trust.rollback_failed", stage)
		return fmt.Errorf("sshtrust: %s failed and rollback failed: %w", stage, errors.Join(cause, rollbackErr))
	}
	a.auditEv(ctx, "ssh.trust.rolled_back", stage)
	return fmt.Errorf("sshtrust: %s failed, rolled back to last-known-good: %w", stage, cause)
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

func (a *Applier) restore(path string, backup []byte, existed bool) error {
	if existed {
		if err := a.cfg.FS.WriteFileAtomic(path, backup, 0o600); err != nil {
			return fmt.Errorf("sshtrust: restore %s: %w", path, err)
		}
		return nil
	}
	if err := a.cfg.FS.Remove(path); err != nil {
		return fmt.Errorf("sshtrust: remove new %s during rollback: %w", path, err)
	}
	return nil
}

func (a *Applier) auditEv(ctx context.Context, event, detail string) {
	_ = auditsink.Emit(ctx, a.audit, nil, event, a.tenantID, []byte(fmt.Sprintf(`{"detail":%q}`, detail)))
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

func (a *Applier) sshdConfigReferencesTrustedKeys(path, content, trustedKeysPath string, seen map[string]bool) bool {
	cleanPath := cleanSSHDPath(path)
	if seen[cleanPath] {
		return false
	}
	seen[cleanPath] = true

	for _, line := range strings.Split(content, "\n") {
		fields := sshdConfigFields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "TrustedUserCAKeys") && len(fields) >= 2:
			if sameSSHDPath(path, fields[1], trustedKeysPath) {
				return true
			}
		case strings.EqualFold(fields[0], "Include"):
			for _, include := range fields[1:] {
				for _, includePath := range a.expandInclude(path, include) {
					includeContent, err := a.cfg.FS.ReadFile(includePath)
					if err != nil {
						continue
					}
					if a.sshdConfigReferencesTrustedKeys(includePath, string(includeContent), trustedKeysPath, seen) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (a *Applier) expandInclude(configPath, pattern string) []string {
	resolved := strings.ReplaceAll(pattern, `\`, `/`)
	if !path.IsAbs(resolved) {
		resolved = path.Join(path.Dir(cleanSSHDPath(configPath)), resolved)
	}
	if globber, ok := a.cfg.FS.(interface {
		Glob(pattern string) ([]string, error)
	}); ok {
		matches, err := globber.Glob(resolved)
		if err == nil && len(matches) > 0 {
			sort.Strings(matches)
			return matches
		}
	}
	return []string{resolved}
}

func sameSSHDPath(configPath, got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	configDir := path.Dir(cleanSSHDPath(configPath))
	got = strings.ReplaceAll(got, `\`, `/`)
	want = strings.ReplaceAll(want, `\`, `/`)
	if !path.IsAbs(got) {
		got = path.Join(configDir, got)
	}
	if !path.IsAbs(want) {
		want = path.Join(configDir, want)
	}
	return cleanSSHDPath(got) == cleanSSHDPath(want)
}

func cleanSSHDPath(p string) string {
	return path.Clean(strings.ReplaceAll(p, `\`, `/`))
}

func sshdConfigFields(line string) []string {
	var fields []string
	var b strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if b.Len() == 0 {
			return
		}
		fields = append(fields, b.String())
		b.Reset()
	}
	for _, r := range line {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if quote != 0 {
			switch r {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			default:
				b.WriteRune(r)
			}
			continue
		}
		switch {
		case r == '#':
			flush()
			return fields
		case r == '"' || r == '\'':
			quote = r
		case unicode.IsSpace(r):
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return fields
}
