// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
)

// sshKRLOptions describe one explicit update of an existing RevokedKeys file.
// The steady-state agent does not touch sshd unless this one-shot is selected.
type sshKRLOptions struct {
	apply       bool
	confirm     bool
	file        string
	sha256      string
	target      string
	sshdConfig  string
	rollbackDir string
	reloadCmd   string
	healthCmd   string
}

func runSSHKRLApply(ctx context.Context, o sshKRLOptions, checks sshkrl.Checks) (bool, error) {
	if !o.apply {
		return false, nil
	}
	if !o.confirm {
		return true, fmt.Errorf("--ssh-krl-apply changes this host's effective RevokedKeys list; review the version, target and rollback path, then re-run with --ssh-krl-confirm")
	}
	if o.file == "" || o.sha256 == "" || o.target == "" || o.sshdConfig == "" || o.rollbackDir == "" {
		return true, fmt.Errorf("--ssh-krl-file, --ssh-krl-sha256, --ssh-krl-target, --ssh-krl-sshd-config, and --ssh-krl-rollback-dir are required")
	}
	if o.reloadCmd == "" || o.healthCmd == "" {
		return true, fmt.Errorf("--ssh-krl-reload-cmd and --ssh-krl-health-cmd are required; reload alone is not proof of usable SSH")
	}
	if _, err := parseCommandLine(o.reloadCmd); err != nil {
		return true, fmt.Errorf("invalid --ssh-krl-reload-cmd: %w", err)
	}
	if _, err := parseCommandLine(o.healthCmd); err != nil {
		return true, fmt.Errorf("invalid --ssh-krl-health-cmd: %w", err)
	}
	f, err := os.Open(o.file) // #nosec G304 -- operator-selected public KRL input
	if err != nil {
		return true, fmt.Errorf("read pinned KRL: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Bound the file before parsing or invoking stock OpenSSH on it.
	data, err := io.ReadAll(io.LimitReader(f, (128<<20)+1))
	if err != nil {
		return true, fmt.Errorf("read pinned KRL: %w", err)
	}
	result, err := sshkrl.Apply(ctx, sshkrl.Config{
		TargetPath: o.target, SSHDConfigPath: o.sshdConfig, RollbackDir: o.rollbackDir, Checks: checks,
	}, data, o.sha256)
	if err != nil {
		return true, err
	}
	if result.Changed {
		fmt.Printf("trstctl-agent: SSH KRL updated from version %d to %d (sha256 %s); sshd validated, reloaded, health-checked; predecessor retained at %s\n", result.PreviousVersion, result.Version, result.SHA256, result.RollbackPath)
	} else {
		fmt.Printf("trstctl-agent: SSH KRL version %d already installed; sshd reloaded and health-checked\n", result.Version)
	}
	return true, nil
}

// sshdKRLChecks uses the host's own OpenSSH binaries for complete KRL parsing
// and effective sshd configuration, then the same validated command runner as
// the existing SSH CA trust rollout for reload and health.
type sshdKRLChecks struct {
	reloadCmd string
	healthCmd string
}

func (c sshdKRLChecks) ActiveKRLPath(ctx context.Context, config string) (string, error) {
	var out bytes.Buffer
	if err := runCommandLine(ctx, "sshd -T -f "+config, &out); err != nil {
		return "", fmt.Errorf("sshd -T: %w", err)
	}
	var path string
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "revokedkeys") {
			if path != "" {
				return "", fmt.Errorf("sshd -T returned multiple RevokedKeys paths")
			}
			path = fields[1]
		}
	}
	if path == "" || path == "none" {
		return "", fmt.Errorf("sshd has no effective RevokedKeys path")
	}
	return path, nil
}

func (c sshdKRLChecks) ValidateKRL(ctx context.Context, path string) error {
	if err := runCommandLine(ctx, "ssh-keygen -Q -l -f "+path); err != nil {
		return fmt.Errorf("ssh-keygen could not parse KRL: %w", err)
	}
	return nil
}

func (c sshdKRLChecks) ValidateSSHD(ctx context.Context, config string) error {
	if err := runCommandLine(ctx, "sshd -t -f "+config); err != nil {
		return fmt.Errorf("sshd -t: %w", err)
	}
	return nil
}

func (c sshdKRLChecks) Reload(ctx context.Context) error { return runCommandLine(ctx, c.reloadCmd) }
func (c sshdKRLChecks) Health(ctx context.Context) error {
	return retryKRLHealth(ctx, func(ctx context.Context) error { return runCommandLine(ctx, c.healthCmd) })
}

// OpenSSH briefly closes its listener while re-execing on SIGHUP. A single
// refused connection during that handover is not a failed health check. Keep
// probing the operator's real login command for a bounded ten seconds.
func retryKRLHealth(ctx context.Context, probe func(context.Context) error) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		err := probe(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("SSH health probe canceled after failure: %w", errors.Join(err, ctx.Err()))
		case <-deadline.C:
			return fmt.Errorf("SSH health probe stayed unhealthy for ten seconds: %w", err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}
