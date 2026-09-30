// SPDX-License-Identifier: BUSL-1.1

package sshkrl

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	sshprotocol "trstctl.com/trstctl/internal/protocols/ssh"
)

type fakeChecks struct {
	activePath string
	validate   int
	reload     int
	health     int
	healthErr  error
}

func (f *fakeChecks) ActiveKRLPath(context.Context, string) (string, error) { return f.activePath, nil }
func (f *fakeChecks) ValidateKRL(_ context.Context, path string) error {
	f.validate++
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture path created under t.TempDir
	if err != nil {
		return err
	}
	_, err = Version(data)
	return err
}
func (f *fakeChecks) ValidateSSHD(context.Context, string) error { return nil }
func (f *fakeChecks) Reload(context.Context) error {
	f.reload++
	return nil
}
func (f *fakeChecks) Health(context.Context) error {
	f.health++
	if f.health == 1 {
		return f.healthErr
	}
	return nil
}

func krlFixture(version uint64, serials ...uint64) []byte {
	k := sshprotocol.NewKRL()
	for _, serial := range serials {
		k.RevokeSerial(serial)
	}
	return k.DistributeKRL(version)
}

func setupInstaller(t *testing.T) (Config, *fakeChecks, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "revoked_keys")
	old := krlFixture(1, 101)
	if err := os.WriteFile(target, old, 0o644); err != nil { // #nosec G306 -- public KRL fixture checks that mode is preserved
		t.Fatal(err)
	}
	checks := &fakeChecks{activePath: target}
	cfg := Config{TargetPath: target, SSHDConfigPath: filepath.Join(dir, "sshd_config"), RollbackDir: filepath.Join(dir, "rollbacks"), Checks: checks}
	return cfg, checks, old, krlFixture(2, 101, 202)
}

func TestApplyUpdatesVersionAndKeepsDurablePredecessor(t *testing.T) {
	cfg, checks, old, next := setupInstaller(t)
	result, err := Apply(context.Background(), cfg, next, crypto.SHA256Hex(next))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.PreviousVersion != 1 || result.Version != 2 || result.RollbackPath == "" {
		t.Fatalf("result = %+v", result)
	}
	installed, err := os.ReadFile(cfg.TargetPath)
	if err != nil || !bytes.Equal(installed, next) {
		t.Fatalf("installed KRL mismatch: %v", err)
	}
	backup, err := os.ReadFile(result.RollbackPath)
	if err != nil || !bytes.Equal(backup, old) {
		t.Fatalf("rollback predecessor mismatch: %v", err)
	}
	if checks.validate != 2 || checks.reload != 1 || checks.health != 1 {
		t.Fatalf("checks = %+v", checks)
	}
}

func TestApplyRejectsUnboundOrRegressingKRLWithoutChangingTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config, *fakeChecks, []byte) ([]byte, string)
	}{
		{"wrong target", func(c *Config, f *fakeChecks, b []byte) ([]byte, string) {
			f.activePath = c.TargetPath + "-other"
			return b, crypto.SHA256Hex(b)
		}},
		{"older version", func(_ *Config, _ *fakeChecks, _ []byte) ([]byte, string) {
			b := krlFixture(0)
			return b, crypto.SHA256Hex(b)
		}},
		{"same version different bytes", func(_ *Config, _ *fakeChecks, _ []byte) ([]byte, string) {
			b := krlFixture(1, 999)
			return b, crypto.SHA256Hex(b)
		}},
		{"wrong digest", func(_ *Config, _ *fakeChecks, b []byte) ([]byte, string) { return b, strings.Repeat("0", 64) }},
		{"truncated", func(_ *Config, _ *fakeChecks, b []byte) ([]byte, string) { b = b[:9]; return b, crypto.SHA256Hex(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, checks, old, next := setupInstaller(t)
			next, digest := tc.change(&cfg, checks, next)
			if _, err := Apply(context.Background(), cfg, next, digest); err == nil {
				t.Fatal("unsafe KRL accepted")
			}
			current, err := os.ReadFile(cfg.TargetPath)
			if err != nil || !bytes.Equal(current, old) {
				t.Fatalf("target changed after refusal: %v", err)
			}
		})
	}
}

func TestApplyHealthFailureRestoresPredecessorAndReloads(t *testing.T) {
	cfg, checks, old, next := setupInstaller(t)
	checks.healthErr = errors.New("listener refused connection")
	result, err := Apply(context.Background(), cfg, next, crypto.SHA256Hex(next))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	current, err := os.ReadFile(cfg.TargetPath)
	if err != nil || !bytes.Equal(current, old) {
		t.Fatalf("target not restored: %v", err)
	}
	if checks.reload != 2 || checks.health != 2 {
		t.Fatalf("rollback checks = %+v", checks)
	}
}

func TestApplyRefusesSymlinkTargetAndPublicRollbackDirectory(t *testing.T) {
	for _, kind := range []string{"symlink target", "public rollback"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _, old, next := setupInstaller(t)
			switch kind {
			case "symlink target":
				real := cfg.TargetPath + "-real"
				if err := os.Rename(cfg.TargetPath, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, cfg.TargetPath); err != nil {
					t.Fatal(err)
				}
			case "public rollback":
				if err := os.Mkdir(cfg.RollbackDir, 0o755); err != nil { // #nosec G301 -- intentionally unsafe rollback-directory fixture must be rejected
					t.Fatal(err)
				}
			}
			if _, err := Apply(context.Background(), cfg, next, crypto.SHA256Hex(next)); err == nil {
				t.Fatal("unsafe target or rollback directory accepted")
			}
			path := cfg.TargetPath
			if kind == "symlink target" {
				path += "-real"
			}
			current, err := os.ReadFile(path) // #nosec G304 -- test fixture path under t.TempDir
			if err != nil || !bytes.Equal(current, old) {
				t.Fatalf("predecessor changed: %v", err)
			}
		})
	}
}

func FuzzVersion(f *testing.F) {
	f.Add([]byte{})
	f.Add(krlFixture(2, 101))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Version(data) })
}
