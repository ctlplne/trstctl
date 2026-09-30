// SPDX-License-Identifier: BUSL-1.1

// Package sshkrl updates a host's already-configured OpenSSH revocation list.
// It never edits sshd_config: an operator must first bind RevokedKeys to the
// exact target path. The old list is retained durably for recovery.
package sshkrl

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	maxKRLBytes = 128 << 20
	krlMagic    = "SSHKRL\n\x00"
)

// Checks binds the KRL to this sshd instance and verifies the running daemon.
// Production uses stock sshd and ssh-keygen commands, never a shell.
type Checks interface {
	ActiveKRLPath(ctx context.Context, sshdConfig string) (string, error)
	ValidateKRL(ctx context.Context, path string) error
	ValidateSSHD(ctx context.Context, sshdConfig string) error
	Reload(ctx context.Context) error
	Health(ctx context.Context) error
}

type Config struct {
	TargetPath     string
	SSHDConfigPath string
	RollbackDir    string
	Checks         Checks
	// SkipReloadOnUnchanged is for a continuous watcher: still validate the
	// effective path, existing KRL, sshd config, and known-good login, but do
	// not restart sshd every time the upstream KRL has the same bytes.
	SkipReloadOnUnchanged bool
}

type Result struct {
	Changed         bool
	PreviousVersion uint64
	Version         uint64
	SHA256          string
	RollbackPath    string
}

// Version reads the bounded OpenSSH KRL header. Full syntax is checked by
// ssh-keygen before installation; a header alone is never accepted as a KRL.
func Version(data []byte) (uint64, error) {
	if len(data) < 20 || len(data) > maxKRLBytes || !bytes.Equal(data[:8], []byte(krlMagic)) {
		return 0, errors.New("sshkrl: invalid KRL header or size")
	}
	if binary.BigEndian.Uint32(data[8:12]) != 1 {
		return 0, errors.New("sshkrl: unsupported KRL format version")
	}
	return binary.BigEndian.Uint64(data[12:20]), nil
}

// Apply installs a newer, pinned KRL only at sshd's effective RevokedKeys path.
// A failed runtime check restores the last known-good bytes and checks the
// restored daemon. The predecessor also remains on disk across a process crash.
func Apply(ctx context.Context, cfg Config, next []byte, expectedSHA256 string) (Result, error) {
	if cfg.Checks == nil || !filepath.IsAbs(cfg.TargetPath) || !filepath.IsAbs(cfg.SSHDConfigPath) || !filepath.IsAbs(cfg.RollbackDir) {
		return Result{}, errors.New("sshkrl: checks and absolute target, config, and rollback paths are required")
	}
	if filepath.Clean(cfg.TargetPath) == filepath.Clean(cfg.SSHDConfigPath) || filepath.Clean(cfg.RollbackDir) == filepath.Clean(filepath.Dir(cfg.TargetPath)) {
		return Result{}, errors.New("sshkrl: target, sshd config, and rollback directory must be separate")
	}
	if len(expectedSHA256) != 64 {
		return Result{}, errors.New("sshkrl: exact SHA-256 digest is required")
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return Result{}, fmt.Errorf("sshkrl: invalid SHA-256 digest: %w", err)
	}
	if crypto.SHA256Hex(next) != strings.ToLower(expectedSHA256) {
		return Result{}, errors.New("sshkrl: candidate SHA-256 digest mismatch")
	}
	nextVersion, err := Version(next)
	if err != nil {
		return Result{}, err
	}
	active, err := cfg.Checks.ActiveKRLPath(ctx, cfg.SSHDConfigPath)
	if err != nil {
		return Result{}, fmt.Errorf("sshkrl: read effective RevokedKeys: %w", err)
	}
	if filepath.Clean(active) != filepath.Clean(cfg.TargetPath) {
		return Result{}, fmt.Errorf("sshkrl: sshd uses RevokedKeys %q, not target %q", active, cfg.TargetPath)
	}
	unlock, err := lockTarget(filepath.Dir(cfg.TargetPath))
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	info, err := os.Lstat(cfg.TargetPath)
	if err != nil {
		return Result{}, fmt.Errorf("sshkrl: target must already exist: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxKRLBytes {
		return Result{}, errors.New("sshkrl: target must be a regular bounded KRL, not a symlink or special file")
	}
	previous, err := os.ReadFile(cfg.TargetPath)
	if err != nil {
		return Result{}, fmt.Errorf("sshkrl: read predecessor: %w", err)
	}
	previousVersion, err := Version(previous)
	if err != nil {
		return Result{}, fmt.Errorf("sshkrl: predecessor is not a KRL: %w", err)
	}
	if err := cfg.Checks.ValidateKRL(ctx, cfg.TargetPath); err != nil {
		return Result{}, fmt.Errorf("sshkrl: predecessor failed OpenSSH validation: %w", err)
	}
	if nextVersion < previousVersion || (nextVersion == previousVersion && !bytes.Equal(previous, next)) {
		return Result{}, fmt.Errorf("sshkrl: refusing KRL version %d over installed version %d", nextVersion, previousVersion)
	}
	result := Result{PreviousVersion: previousVersion, Version: nextVersion, SHA256: crypto.SHA256Hex(next)}
	if bytes.Equal(previous, next) {
		if err := verifyUnchangedRuntime(ctx, cfg); err != nil {
			return Result{}, fmt.Errorf("sshkrl: unchanged KRL failed runtime verification; files unchanged: %w", err)
		}
		return result, nil
	}
	// Validate the complete candidate before its first visible write.
	candidate, err := stagedFile(cfg.TargetPath, next, info)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = os.Remove(candidate) }()
	if err := cfg.Checks.ValidateKRL(ctx, candidate); err != nil {
		return Result{}, fmt.Errorf("sshkrl: candidate failed OpenSSH validation: %w", err)
	}
	backupPath, err := durableBackup(cfg.RollbackDir, cfg.TargetPath, previous, previousVersion)
	if err != nil {
		return Result{}, err
	}
	result.RollbackPath = backupPath
	if err := os.Rename(candidate, cfg.TargetPath); err != nil {
		return Result{}, fmt.Errorf("sshkrl: atomic install: %w", err)
	}
	if err := syncDir(filepath.Dir(cfg.TargetPath)); err != nil {
		return Result{}, rollback(cfg, previous, info, backupPath, "sync installed KRL", err)
	}
	installed, err := os.ReadFile(cfg.TargetPath)
	if err != nil {
		return Result{}, rollback(cfg, previous, info, backupPath, "read back installed KRL", err)
	}
	if !bytes.Equal(installed, next) {
		return Result{}, rollback(cfg, previous, info, backupPath, "read back installed KRL", errors.New("installed bytes differ from pinned candidate"))
	}
	if err := verifyRuntime(ctx, cfg); err != nil {
		return Result{}, rollback(cfg, previous, info, backupPath, "verify running sshd", err)
	}
	result.Changed = true
	return result, nil
}

func verifyUnchangedRuntime(ctx context.Context, cfg Config) error {
	if !cfg.SkipReloadOnUnchanged {
		return verifyRuntime(ctx, cfg)
	}
	if err := cfg.Checks.ValidateSSHD(ctx, cfg.SSHDConfigPath); err != nil {
		return fmt.Errorf("validate sshd: %w", err)
	}
	if err := cfg.Checks.Health(ctx); err != nil {
		return fmt.Errorf("health-check sshd: %w", err)
	}
	return nil
}

func verifyRuntime(ctx context.Context, cfg Config) error {
	if err := cfg.Checks.ValidateSSHD(ctx, cfg.SSHDConfigPath); err != nil {
		return fmt.Errorf("validate sshd: %w", err)
	}
	if err := cfg.Checks.Reload(ctx); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}
	if err := cfg.Checks.Health(ctx); err != nil {
		return fmt.Errorf("health-check sshd: %w", err)
	}
	return nil
}

func rollback(cfg Config, previous []byte, info os.FileInfo, backupPath, stage string, cause error) error {
	// A canceled caller must not prevent the safety action it triggered.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failures []error
	if err := replaceFile(cfg.TargetPath, previous, info); err != nil {
		failures = append(failures, err)
	} else if err := verifyRuntime(ctx, cfg); err != nil {
		failures = append(failures, err)
	}
	if len(failures) != 0 {
		return fmt.Errorf("sshkrl: %s failed and rollback failed; predecessor at %s: %w", stage, backupPath, errors.Join(append([]error{cause}, failures...)...))
	}
	return fmt.Errorf("sshkrl: %s failed, rolled back to version in %s: %w", stage, backupPath, cause)
}

func stagedFile(target string, data []byte, info os.FileInfo) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), ".trstctl-krl-*")
	if err != nil {
		return "", fmt.Errorf("sshkrl: stage KRL: %w", err)
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return "", err
	}
	if err := preserveOwner(name, info); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func replaceFile(target string, data []byte, info os.FileInfo) error {
	staged, err := stagedFile(target, data, info)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged) }()          // #nosec G703 -- staged path is created in the bound target directory by CreateTemp
	if err := os.Rename(staged, target); err != nil { // #nosec G703 -- target is an absolute operator path bound to sshd's effective RevokedKeys path
		return err
	}
	return syncDir(filepath.Dir(target))
}

func durableBackup(dir, target string, data []byte, version uint64) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("sshkrl: create rollback directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("sshkrl: inspect rollback directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("sshkrl: rollback directory must be a private real directory")
	}
	name := fmt.Sprintf("%s-v%d-%s.krl", filepath.Base(target), version, crypto.SHA256Hex(data)[:16])
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() { // #nosec G703 -- path is a derived predecessor name inside the checked private rollback directory
		return "", errors.New("sshkrl: rollback predecessor path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("sshkrl: inspect rollback predecessor: %w", err)
	}
	if old, err := os.ReadFile(path); err == nil { // #nosec G304 G703 -- read only the derived predecessor in the checked private rollback directory
		if bytes.Equal(old, data) {
			return path, nil
		}
		return "", errors.New("sshkrl: rollback predecessor path contains different bytes")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("sshkrl: inspect rollback predecessor: %w", err)
	}
	f, err := os.CreateTemp(dir, ".trstctl-krl-predecessor-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), path); err != nil { // #nosec G703 -- target is a derived predecessor name inside the checked private rollback directory
		return "", err
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return path, nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir) // #nosec G304 -- syncs only the validated target or private rollback directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
