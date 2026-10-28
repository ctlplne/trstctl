// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agent/sshtrust"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

const maxFleetExecutableBytes = 128 << 20

type pinnedSSHCommand struct {
	Argv             []string `json:"argv"`
	ExecutableSHA256 string   `json:"executable_sha256"`
}
type sshFleetPolicy struct {
	Readiness sshtrustrollout.Readiness
	Config    sshtrust.Config
}
type sshFleetDigest struct {
	size     int64
	modified time.Time
	digest   string
}

// sshFleetPolicyLoader caches public executable hashes for display only. Every
// execution requests a full fresh hash, so a metadata-preserving replacement
// cannot inherit the digest reviewers approved.
type sshFleetPolicyLoader struct {
	options sshTrustOptions
	mu      sync.Mutex
	digests map[string]sshFleetDigest
}

func newSSHFleetPolicyLoader(options sshTrustOptions) *sshFleetPolicyLoader {
	return &sshFleetPolicyLoader{options: options, digests: map[string]sshFleetDigest{}}
}

func (l *sshFleetPolicyLoader) load(fresh bool) (sshFleetPolicy, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.options
	policy := sshFleetPolicy{Readiness: sshtrustrollout.Readiness{Enabled: o.fleet, Confirmed: o.fleet && o.confirm}}
	if !o.fleet || !o.confirm {
		return policy, nil
	}
	fail := func(err error) (sshFleetPolicy, error) {
		policy.Readiness.IssueCode = "local_configuration_invalid"
		return policy, err
	}
	if o.addCA {
		return fail(errors.New("choose the one-shot SSH addition or fleet mode"))
	}
	if o.caKeyPath == "" {
		return fail(errors.New("fleet mode needs a locally staged public CA key"))
	}
	file, err := os.Open(o.caKeyPath) // #nosec G304 -- operator-pinned host-local public CA path (CWE-22).
	if err != nil {
		return fail(err)
	}
	ca, readErr := io.ReadAll(io.LimitReader(file, 32<<10+1))
	closeErr := file.Close()
	if readErr != nil {
		return fail(readErr)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	ca = bytes.TrimSpace(ca)
	if len(ca) == 0 || len(ca) > 32<<10 || bytes.ContainsAny(ca, "\r\n") {
		return fail(errors.New("stage exactly one bounded public CA line"))
	}
	keys := sshkeys.ParseAuthorizedKeys(ca)
	if len(keys) != 1 || len(keys[0].Options) != 0 || strings.Contains(keys[0].Type, "-cert-") {
		return fail(errors.New("stage a public CA key without authorized_keys options"))
	}
	configPath, err := filepath.Abs(o.sshdConfig)
	if err != nil {
		return fail(err)
	}
	trustPath, err := filepath.Abs(o.trustedKeys)
	if err != nil {
		return fail(err)
	}
	if configPath == trustPath || strings.ContainsAny(configPath+trustPath, "\x00\r\n\t ") {
		return fail(errors.New("pin distinct absolute SSH configuration and public trust paths without whitespace"))
	}
	configInfo, err := os.Stat(configPath)
	if err != nil {
		return fail(err)
	}
	if !configInfo.Mode().IsRegular() {
		return fail(errors.New("SSH configuration must be an existing regular file"))
	}
	if info, err := os.Stat(trustPath); err == nil && !info.Mode().IsRegular() {
		return fail(errors.New("SSH public trust path must be a regular file"))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	parent, err := os.Stat(filepath.Dir(trustPath))
	if err != nil {
		return fail(err)
	}
	if !parent.IsDir() {
		return fail(errors.New("SSH public trust directory must exist"))
	}
	validate := o.validateCmd
	if validate == "" {
		validate = "sshd -t"
	}
	commands := make([]pinnedSSHCommand, 0, 3)
	for _, line := range []string{validate, o.reloadCmd, o.healthCmd} {
		command, err := l.command(line, fresh)
		if err != nil {
			return fail(err)
		}
		commands = append(commands, command)
	}
	raw, err := json.Marshal(struct {
		CAFingerprint, ConfigPath, TrustPath string
		Commands                             []pinnedSSHCommand
	}{keys[0].FingerprintSHA256, configPath, trustPath, commands})
	if err != nil {
		return fail(err)
	}
	policy.Readiness.CAFingerprint = keys[0].FingerprintSHA256
	policy.Readiness.PolicyDigest = "sha256:" + crypto.SHA256Hex(raw)
	policy.Config = sshtrust.Config{FS: osFS{}, Reloader: pinnedSSHReloader{validate: commands[0], reload: commands[1], health: commands[2]}, SSHDConfigPath: configPath, TrustedUserCAKeysPath: trustPath}
	return policy, nil
}

func (l *sshFleetPolicyLoader) command(line string, fresh bool) (pinnedSSHCommand, error) {
	argv, err := parseCommandLine(line)
	if err != nil {
		return pinnedSSHCommand{}, err
	}
	resolved, err := exec.LookPath(argv[0])
	if err != nil {
		return pinnedSSHCommand{}, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return pinnedSSHCommand{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return pinnedSSHCommand{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFleetExecutableBytes {
		return pinnedSSHCommand{}, errors.New("SSH action must be a bounded local executable")
	}
	cached, ok := l.digests[resolved]
	if fresh || !ok || cached.size != info.Size() || !cached.modified.Equal(info.ModTime()) {
		file, err := os.Open(resolved) // #nosec G304 -- resolved operator-pinned executable, read only to bind its public digest (CWE-22).
		if err != nil {
			return pinnedSSHCommand{}, err
		}
		digest, n, readErr := crypto.SHA256ReaderHex(io.LimitReader(file, maxFleetExecutableBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return pinnedSSHCommand{}, readErr
		}
		if closeErr != nil {
			return pinnedSSHCommand{}, closeErr
		}
		if n > maxFleetExecutableBytes {
			return pinnedSSHCommand{}, errors.New("SSH action exceeds its digest read bound")
		}
		cached = sshFleetDigest{size: info.Size(), modified: info.ModTime(), digest: digest}
		l.digests[resolved] = cached
	}
	if err := validateCommandToken("resolved executable", resolved); err != nil {
		return pinnedSSHCommand{}, err
	}
	argv[0] = resolved
	return pinnedSSHCommand{Argv: argv, ExecutableSHA256: cached.digest}, nil
}

type pinnedSSHReloader struct{ validate, reload, health pinnedSSHCommand }

func (r pinnedSSHReloader) Validate(ctx context.Context) error {
	return runPinnedSSHCommand(ctx, r.validate)
}
func (r pinnedSSHReloader) Reload(ctx context.Context) error {
	return runPinnedSSHCommand(ctx, r.reload)
}
func (r pinnedSSHReloader) HealthCheck(ctx context.Context) error {
	return runPinnedSSHCommand(ctx, r.health)
}
func runPinnedSSHCommand(ctx context.Context, pinned pinnedSSHCommand) error {
	if len(pinned.Argv) == 0 {
		return errors.New("SSH action has no pinned argv")
	}
	return runCommandLine(ctx, strings.Join(pinned.Argv, " "), io.Discard)
}
