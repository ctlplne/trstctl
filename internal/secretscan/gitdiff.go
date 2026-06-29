package secretscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

var (
	ErrGitRepositoryRequired = errors.New("secretscan: git repository is required")
	ErrGitDiffRefsRequired   = errors.New("secretscan: CI diff scan requires both base and head refs")
	ErrGitDiffUnsafePath     = errors.New("secretscan: git diff produced an unsafe path")
)

// GitDiffConfig selects the staged index or a CI base/head diff to scan.
type GitDiffConfig struct {
	Repo string
	Base string
	Head string
}

// GitDiffTarget is a temporary directory containing only changed file blobs.
// Cleanup must be called after scanning.
type GitDiffTarget struct {
	Path    string
	Files   []string
	Mode    string
	Cleanup func()
}

// PrepareGitDiffTarget materializes changed Git blobs into a temporary scan
// directory. With Base and Head set it scans the Head-side content for CI diff
// checks; without refs it scans the staged index for pre-commit hooks.
func PrepareGitDiffTarget(ctx context.Context, cfg GitDiffConfig) (GitDiffTarget, error) {
	root, err := GitTopLevel(ctx, cfg.Repo)
	if err != nil {
		return GitDiffTarget{}, err
	}
	base := strings.TrimSpace(cfg.Base)
	head := strings.TrimSpace(cfg.Head)
	mode := "staged"
	var names []string
	switch {
	case base == "" && head == "":
		names, err = gitDiffNames(ctx, root, "--cached")
	case base != "" && head != "":
		mode = "ci_diff"
		names, err = gitDiffNames(ctx, root, base, head)
	default:
		err = ErrGitDiffRefsRequired
	}
	if err != nil {
		return GitDiffTarget{}, err
	}

	tmp, err := os.MkdirTemp("", "trstctl-gitdiff-secret-scan-*")
	if err != nil {
		return GitDiffTarget{}, fmt.Errorf("secretscan: create git diff scan target: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	target := GitDiffTarget{Path: tmp, Mode: mode, Cleanup: cleanup}
	for _, name := range names {
		name = cleanGitPath(name)
		if name == "" {
			continue
		}
		if !safeGitPath(name) {
			cleanup()
			return GitDiffTarget{}, fmt.Errorf("%w: %s", ErrGitDiffUnsafePath, name)
		}
		spec := ":" + name
		if mode == "ci_diff" {
			spec = head + ":" + name
		}
		data, err := gitOutput(ctx, root, "show", spec)
		if err != nil {
			cleanup()
			return GitDiffTarget{}, fmt.Errorf("secretscan: read git blob %s: %w", name, err)
		}
		dst := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			zeroBytes(data)
			cleanup()
			return GitDiffTarget{}, err
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			zeroBytes(data)
			cleanup()
			return GitDiffTarget{}, err
		}
		zeroBytes(data)
		target.Files = append(target.Files, name)
	}
	return target, nil
}

// GitTopLevel returns the repository root for repo, defaulting repo to ".".
func GitTopLevel(ctx context.Context, repo string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		repo = "."
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGitRepositoryRequired, err)
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrGitRepositoryRequired, err)
		}
		return "", fmt.Errorf("%w: %s is not a directory", ErrGitRepositoryRequired, abs)
	}
	out, err := gitOutput(ctx, abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGitRepositoryRequired, err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", ErrGitRepositoryRequired
	}
	return filepath.Clean(root), nil
}

// GitPath resolves a git metadata path, such as hooks/pre-commit, for repo.
func GitPath(ctx context.Context, repo, name string) (string, error) {
	root, err := GitTopLevel(ctx, repo)
	if err != nil {
		return "", err
	}
	out, err := gitOutput(ctx, root, "rev-parse", "--git-path", name)
	if err != nil {
		return "", fmt.Errorf("secretscan: resolve git path %s: %w", name, err)
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", fmt.Errorf("secretscan: git path %s was empty", name)
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	return filepath.Clean(filepath.Join(root, p)), nil
}

func gitDiffNames(ctx context.Context, repo string, revArgs ...string) ([]string, error) {
	args := []string{"diff", "--name-only", "--diff-filter=ACMRT"}
	args = append(args, revArgs...)
	out, err := gitOutput(ctx, repo, args...)
	if err != nil {
		return nil, fmt.Errorf("secretscan: list git diff files: %w", err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		name := cleanGitPath(line)
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = filepath.Clean(dir)
	cmd.Env = sanitizedGitEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return nil, fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
		}
		return nil, fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out, nil
}

func cleanGitPath(raw string) string {
	return strings.TrimSpace(filepath.ToSlash(raw))
}

func safeGitPath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") {
		return false
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return false
	}
	return clean != ".git" && !strings.HasPrefix(clean, ".git/")
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
