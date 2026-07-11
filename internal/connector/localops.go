// SPDX-License-Identifier: MPL-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const localCommandOutputLimit = 64 << 10

var localShellExecutables = map[string]struct{}{
	"bash": {}, "cmd": {}, "dash": {}, "fish": {}, "ksh": {},
	"powershell": {}, "pwsh": {}, "sh": {}, "zsh": {},
}

// LocalAction binds the logical command requested by a connector to one exact,
// operator-owned executable and argv. Tenant target JSON can select a named
// action profile, but cannot add a shell, executable, argument, or environment
// variable.
type LocalAction struct {
	LogicalName string
	// LogicalArgs, when non-nil, must exactly match the connector request.
	// A nil slice allows the connector's own fixed implementation to supply
	// arguments; tenant JSON never reaches this field.
	LogicalArgs []string
	Command     string
	Args        []string
	PassArgs    bool
	Timeout     time.Duration
}

// LocalOpsConfig is the trusted boundary for co-resident/shared-volume targets.
// AllowedRoots and Action come from operator startup config, never from a tenant
// deployment target.
type LocalOpsConfig struct {
	AllowedRoots []string
	Actions      []LocalAction
}

type localOps struct {
	roots   []string
	actions map[string]LocalAction
}

var (
	_ Ops             = (*localOps)(nil)
	_ FileReader      = (*localOps)(nil)
	_ ContextExecutor = (*localOps)(nil)
)

// ContextExecutor is the optional cancellation-aware execution extension. Run
// prefers it over the legacy Ops.Exec method so a wedged reload cannot occupy an
// outbox worker beyond its deadline.
type ContextExecutor interface {
	ExecContext(context.Context, string, []string) error
}

// NewLocalOps returns real filesystem/process operations constrained by an
// operator profile. Writes are 0600, fsync'd, and atomically renamed. Symlinked
// parents and paths outside the allowlist fail closed.
func NewLocalOps(cfg LocalOpsConfig) (Ops, error) {
	if len(cfg.AllowedRoots) == 0 {
		return nil, errors.New("connector: local ops requires at least one allowed root")
	}
	roots := make([]string, 0, len(cfg.AllowedRoots))
	for _, raw := range cfg.AllowedRoots {
		root, err := canonicalExistingDir(raw)
		if err != nil {
			return nil, fmt.Errorf("connector: local allowed root %q: %w", raw, err)
		}
		if !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
	}
	actions := make(map[string]LocalAction, len(cfg.Actions))
	for _, configured := range cfg.Actions {
		copyAction := configured
		copyAction.LogicalName = strings.TrimSpace(copyAction.LogicalName)
		copyAction.Command = filepath.Clean(strings.TrimSpace(copyAction.Command))
		copyAction.LogicalArgs = append([]string(nil), copyAction.LogicalArgs...)
		copyAction.Args = append([]string(nil), copyAction.Args...)
		if copyAction.LogicalName == "" || copyAction.Command == "" || !filepath.IsAbs(copyAction.Command) {
			return nil, errors.New("connector: local action requires a logical name and absolute command")
		}
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(copyAction.Command)), ".exe")
		if _, isShell := localShellExecutables[base]; isShell {
			// IIS exposes PowerShell as its native administrative API. It is safe
			// only when the operator pins both the connector's complete logical
			// argv and a separate complete execution argv. No tenant-derived byte
			// is then forwarded to -Command. General-purpose Unix shells remain
			// forbidden even with fixed argv because they are not needed by a
			// native connector.
			pinnedPowerShell := (base == "powershell" || base == "pwsh") &&
				copyAction.LogicalArgs != nil && len(copyAction.Args) > 0 && !copyAction.PassArgs
			if !pinnedPowerShell {
				return nil, fmt.Errorf("connector: local action command %q is an unpinned shell interpreter", copyAction.Command)
			}
		}
		info, err := os.Lstat(copyAction.Command)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
			return nil, fmt.Errorf("connector: local action command %q is not an executable regular non-symlink file", copyAction.Command)
		}
		if copyAction.Timeout <= 0 {
			copyAction.Timeout = 15 * time.Second
		}
		if _, exists := actions[copyAction.LogicalName]; exists {
			return nil, fmt.Errorf("connector: duplicate local action %q", copyAction.LogicalName)
		}
		actions[copyAction.LogicalName] = copyAction
	}
	return &localOps{roots: roots, actions: actions}, nil
}

func (o *localOps) Send(string, []byte) error {
	return errors.New("connector: local target does not support raw network Send")
}

func (o *localOps) Request(*http.Request) (*http.Response, error) {
	return nil, errors.New("connector: local target does not support HTTP requests")
}

func (o *localOps) ReadFile(path string) ([]byte, error) {
	clean, err := o.allowedPath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("connector: local read %q is not a regular non-symlink file", clean)
	}
	return os.ReadFile(clean)
}

func (o *localOps) WriteFile(path string, data []byte) error {
	clean, err := o.allowedPath(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(clean)
	tmp, err := os.CreateTemp(parent, ".trstctl-credential-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Rename(tmpName, clean); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (o *localOps) Exec(name string, args []string) error {
	return o.ExecContext(context.Background(), name, args)
}

func (o *localOps) ExecContext(parent context.Context, name string, args []string) error {
	action, ok := o.actions[name]
	if !ok {
		return fmt.Errorf("connector: local action %q is not operator-approved", name)
	}
	if action.LogicalArgs != nil && !slices.Equal(args, action.LogicalArgs) {
		return fmt.Errorf("connector: activation %q %q does not match operator profile", name, args)
	}
	ctx, cancel := context.WithTimeout(parent, action.Timeout)
	defer cancel()
	commandArgs := append([]string(nil), action.Args...)
	if action.PassArgs {
		commandArgs = append(commandArgs, args...)
	}
	cmd := exec.CommandContext(ctx, action.Command, commandArgs...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output limitedBuffer
	defer output.Destroy()
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("connector: activation deadline exceeded: %w", ctx.Err())
		}
		return fmt.Errorf("connector: activation failed: %w (bounded output redacted)", err)
	}
	return nil
}

func (o *localOps) allowedPath(raw string) (string, error) {
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("connector: local path %q is not absolute", raw)
	}
	clean := filepath.Clean(raw)
	parent, err := canonicalExistingDir(filepath.Dir(clean))
	if err != nil {
		return "", err
	}
	clean = filepath.Join(parent, filepath.Base(clean))
	for _, root := range o.roots {
		relative, err := filepath.Rel(root, clean)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			if info, statErr := os.Lstat(clean); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("connector: local path %q is a symlink", clean)
			}
			return clean, nil
		}
	}
	return "", fmt.Errorf("connector: local path %q is outside operator-approved roots", clean)
}

func canonicalExistingDir(raw string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(raw))
	if clean == "" || !filepath.IsAbs(clean) {
		return "", errors.New("path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

type limitedBuffer struct {
	bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := localCommandOutputLimit - b.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	written, err := b.Buffer.Write(p[:min(len(p), remaining)])
	if err != nil {
		return written, err
	}
	return len(p), nil
}

func (b *limitedBuffer) Destroy() {
	secret.Wipe(b.Bytes())
	b.Reset()
}

var _ io.Writer = (*limitedBuffer)(nil)
