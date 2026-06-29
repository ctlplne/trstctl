package secretscan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const RepositorySourceKind = "secret_repo"

var (
	ErrRepositoryTargetRequired = errors.New("secretscan: repository scan requires checkout_path or clone_url")
	ErrRepositoryUnsafeCloneURL = errors.New("secretscan: repository clone_url must not embed credentials")
)

// RepositoryScanConfig is the metadata-only discovery source config for realtime
// repository secret scanning. Credentials are references to the secret store, never
// inline token values.
type RepositoryScanConfig struct {
	Provider      string `json:"provider"`
	Repository    string `json:"repository"`
	CloneURL      string `json:"clone_url,omitempty"`
	CheckoutPath  string `json:"checkout_path,omitempty"`
	Ref           string `json:"ref,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	Event         string `json:"event,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

// RepositoryTarget is the local path a worker can pass to Gitleaks.
type RepositoryTarget struct {
	Path    string
	Cleanup func()
	Mode    string
}

// PrepareRepositoryTarget resolves a repository scan config into a local checkout.
// A pre-existing checkout_path is scanned in place. A clone_url is cloned into a
// temporary directory by the outbox worker, with terminal prompts disabled so
// private repository auth cannot hang the worker or leak into process state.
func PrepareRepositoryTarget(ctx context.Context, cfg RepositoryScanConfig) (RepositoryTarget, error) {
	if path := strings.TrimSpace(cfg.CheckoutPath); path != "" {
		return RepositoryTarget{Path: path, Cleanup: func() {}, Mode: "checkout_path"}, nil
	}
	cloneURL := strings.TrimSpace(cfg.CloneURL)
	if cloneURL == "" {
		return RepositoryTarget{}, ErrRepositoryTargetRequired
	}
	if cloneURLHasInlineCredentials(cloneURL) {
		return RepositoryTarget{}, ErrRepositoryUnsafeCloneURL
	}
	tmp, err := os.MkdirTemp("", "trstctl-repo-secret-scan-*")
	if err != nil {
		return RepositoryTarget{}, fmt.Errorf("secretscan: create repo scan checkout: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	args := []string{"clone", "--no-tags", "--depth", "1"}
	ref := strings.TrimSpace(cfg.Ref)
	commit := strings.TrimSpace(cfg.CommitSHA)
	if ref != "" && commit == "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, cloneURL, tmp)
	if err := runGit(ctx, "", args...); err != nil {
		cleanup()
		return RepositoryTarget{}, err
	}
	if commit != "" {
		if err := runGit(ctx, tmp, "checkout", "--detach", commit); err != nil {
			cleanup()
			return RepositoryTarget{}, err
		}
	}
	return RepositoryTarget{Path: tmp, Cleanup: cleanup, Mode: "clone_url"}, nil
}

func cloneURLHasInlineCredentials(raw string) bool {
	if !strings.Contains(raw, "://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.User != nil
}

func runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = filepath.Clean(dir)
	}
	cmd.Env = sanitizedGitEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("secretscan: git %s failed: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("secretscan: git %s failed: %w: %s", strings.Join(args, " "), err, msg)
	}
	return nil
}

func sanitizedGitEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_ASKPASS=") || strings.HasPrefix(kv, "SSH_ASKPASS=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=Never")
	return out
}
