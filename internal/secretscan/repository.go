// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const RepositorySourceKind = "secret_repo"

const repositoryFetchTimeout = 2 * time.Minute

var (
	ErrRepositoryTargetRequired = errors.New("secretscan: repository scan requires checkout_path or clone_url")
	ErrRepositoryUnsafeCloneURL = errors.New("secretscan: repository clone_url must not embed credentials")
	// ErrRepositoryCredentialNeedsHTTPS refuses to send a repository credential
	// anywhere but an https clone URL (OD-1).
	ErrRepositoryCredentialNeedsHTTPS = errors.New("secretscan: a repository credential_ref needs an https clone_url")
	// ErrRepositoryUnsafeRef is a ref that is not a plain branch or tag name,
	// or a commit that is not a hex commit ID: both reach git's command line,
	// so neither may read as an option (OD-3).
	ErrRepositoryUnsafeRef = errors.New("secretscan: the ref must be a branch or tag name and the commit a hex commit ID")
)

// RepositoryCredential is a private repository's clone credential for one
// clone (OD-1): a token or password and the user name it goes with. The caller
// owns Secret and wipes it after the clone.
type RepositoryCredential struct {
	Username string
	Secret   []byte
}

// DefaultRepositoryUsername is the user name a provider's token clones with
// when the source names none.
func DefaultRepositoryUsername(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "github":
		return "x-access-token"
	case "gitlab":
		return "oauth2"
	case "bitbucket":
		return "x-token-auth"
	}
	return "git"
}

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
	// CredentialAdmissionVersion proves a normalized API request passed the
	// secret-read check. Older stored sources lack it and fail closed at use.
	CredentialAdmissionVersion int `json:"credential_admission_version,omitempty"`
	// ConfiguredHookID names an operator-configured hook credential. The source
	// stores only the hook ID; the worker resolves its fixed ref and origin from
	// server configuration, never from tenant-authored source JSON.
	ConfiguredHookID string `json:"configured_hook_id,omitempty"`
	// CredentialUsername is the user name credential_ref's token clones
	// with; empty uses the provider's (DefaultRepositoryUsername).
	CredentialUsername string `json:"credential_username,omitempty"`
	// Private clone egress is durable source authority only after the API
	// checks egress:private and the worker rechecks the operator ceiling.
	AllowPrivateClone             bool     `json:"allow_private_clone,omitempty"`
	PrivateEgressCIDRs            []string `json:"private_egress_cidrs,omitempty"`
	PrivateEgressAdmissionVersion int      `json:"private_egress_admission_version,omitempty"`
	// Annotation writes each finding back through GitHub code scanning
	// (A174-L5): the connection only; the repository, commit and ref are the
	// scan's own.
	Annotation *AnnotationConfig `json:"annotation,omitempty"`
}

// AnnotationProvider names the provider API a repository scan's findings
// are annotated at: github (code scanning), or "" without an annotation.
func (c RepositoryScanConfig) AnnotationProvider() string {
	if c.Annotation == nil || strings.ToLower(strings.TrimSpace(c.Provider)) != "github" {
		return ""
	}
	return "github"
}

// RepositoryTarget is the local path a worker can pass to Gitleaks.
type RepositoryTarget struct {
	Path    string
	Cleanup func()
	Mode    string
	Egress  RepositoryCloneEgress
}

// PrepareRepositoryTarget resolves a repository scan config into a local checkout.
// A pre-existing checkout_path is scanned in place. A clone_url is cloned into a
// temporary directory by the outbox worker, with terminal prompts disabled so
// private repository auth cannot hang the worker or leak into process state.
func PrepareRepositoryTarget(ctx context.Context, cfg RepositoryScanConfig) (RepositoryTarget, error) {
	return PrepareRepositoryTargetWithCredential(ctx, cfg, nil)
}

// PrepareRepositoryTargetWithCredential is PrepareRepositoryTarget for a
// private repository (OD-1): the clone authenticates with cred over https.
// The credential reaches git as an Authorization header scoped to the clone
// URL's origin, through git's environment, never through its arguments, the
// URL or the checkout's configuration, and is sent nowhere else: a redirect to
// another origin gets no header, and the host's credential helpers are off.
func PrepareRepositoryTargetWithCredential(ctx context.Context, cfg RepositoryScanConfig, cred *RepositoryCredential) (RepositoryTarget, error) {
	return PrepareRepositoryTargetWithCredentialEgress(ctx, cfg, cred, RepositoryCloneEgress{})
}

// PrepareRepositoryTargetWithCredentialEgress applies operator-owned private
// CIDRs when the API has separately admitted this exact source for private
// egress. The zero policy is the safe public-HTTPS default.
func PrepareRepositoryTargetWithCredentialEgress(ctx context.Context, cfg RepositoryScanConfig, cred *RepositoryCredential,
	egress RepositoryCloneEgress,
) (RepositoryTarget, error) {
	return prepareRepositoryTargetWithGitEgress(ctx, cfg, cred, egress, net.DefaultResolver, runGit)
}

func prepareRepositoryTargetWithGit(ctx context.Context, cfg RepositoryScanConfig, cred *RepositoryCredential,
	run func(context.Context, string, []string, ...string) error,
) (RepositoryTarget, error) {
	return prepareRepositoryTargetWithGitEgress(ctx, cfg, cred, RepositoryCloneEgress{}, net.DefaultResolver, run)
}

func prepareRepositoryTargetWithGitEgress(ctx context.Context, cfg RepositoryScanConfig, cred *RepositoryCredential,
	egress RepositoryCloneEgress, resolver repositoryHostResolver,
	run func(context.Context, string, []string, ...string) error,
) (RepositoryTarget, error) {
	if path := strings.TrimSpace(cfg.CheckoutPath); path != "" {
		return RepositoryTarget{Path: path, Cleanup: func() {}, Mode: "checkout_path"}, nil
	}
	cloneURL := strings.TrimSpace(cfg.CloneURL)
	if cloneURL == "" {
		return RepositoryTarget{}, ErrRepositoryTargetRequired
	}
	if cloneURLHasInlineCredentials(cloneURL) || strings.HasPrefix(cloneURL, "-") {
		return RepositoryTarget{}, ErrRepositoryUnsafeCloneURL
	}
	if err := ValidateRepositoryRef(cfg.Ref, cfg.CommitSHA); err != nil {
		return RepositoryTarget{}, err
	}
	var auth []string
	if cred != nil {
		var err error
		if auth, err = credentialGitConfig(cloneURL, cred); err != nil {
			return RepositoryTarget{}, err
		}
	}
	guard, err := egress.gitConfig(ctx, cloneURL, resolver)
	if err != nil {
		return RepositoryTarget{}, err
	}
	gitConfig := append(guard, auth...)
	tmp, err := os.MkdirTemp("", "trstctl-repo-secret-scan-*")
	if err != nil {
		return RepositoryTarget{}, fmt.Errorf("secretscan: create repo scan checkout: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	args := []string{"clone", "--no-tags", "--depth", "1"}
	commit := strings.TrimSpace(cfg.CommitSHA)
	if branch := cloneBranch(cfg.Ref); branch != "" {
		// The pushed branch or tag itself, so a push to any branch, not only
		// the default one, has its commit in the shallow clone (OD-3).
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", cloneURL, tmp)
	if err := run(ctx, "", gitConfig, args...); err != nil {
		cleanup()
		return RepositoryTarget{}, err
	}
	if commit != "" {
		if err := run(ctx, tmp, nil, "checkout", "--detach", commit); err != nil {
			// The branch moved on after the push: fetch the pushed commit
			// itself (hosts serve a reachable commit by its ID).
			fetchCtx, cancel := context.WithTimeout(ctx, repositoryFetchTimeout)
			fetchGuard, guardErr := egress.gitConfig(fetchCtx, cloneURL, resolver)
			if guardErr != nil {
				cancel()
				cleanup()
				return RepositoryTarget{}, guardErr
			}
			fetchErr := run(fetchCtx, tmp, append(fetchGuard, auth...), "fetch", "--no-tags", "--depth", "1", "--", cloneURL, commit)
			cancel()
			if fetchErr != nil {
				cleanup()
				return RepositoryTarget{}, fetchErr
			}
			if err := run(ctx, tmp, nil, "checkout", "--detach", commit); err != nil {
				cleanup()
				return RepositoryTarget{}, err
			}
		}
	}
	return RepositoryTarget{Path: tmp, Cleanup: cleanup, Mode: "clone_url", Egress: egress}, nil
}

// ValidateRepositoryRef refuses a ref that is not a plain branch or tag name
// (refs/heads/<name>, refs/tags/<name> or a bare name, per git's ref-name
// rules: no leading dash, no "..", no spaces, controls or ~^:?*[\) and a
// commit that is not a 7 to 64 character hex commit ID.
func ValidateRepositoryRef(ref, commit string) error {
	ref, commit = strings.TrimSpace(ref), strings.TrimSpace(commit)
	if commit != "" {
		if len(commit) < 7 || len(commit) > 64 {
			return ErrRepositoryUnsafeRef
		}
		for _, c := range commit {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return ErrRepositoryUnsafeRef
			}
		}
	}
	if ref == "" {
		return nil
	}
	if len(ref) > 255 || strings.HasPrefix(ref, "-") || strings.Contains(ref, "..") || strings.HasSuffix(ref, "/") ||
		strings.ContainsAny(ref, " ~^:?*[\\") {
		return ErrRepositoryUnsafeRef
	}
	for _, c := range ref {
		if c < 0x20 || c == 0x7f {
			return ErrRepositoryUnsafeRef
		}
	}
	return nil
}

// cloneBranch names the branch or tag a ref clones as: refs/heads/<name> and
// refs/tags/<name> by name, a bare name as given, and nothing for any other
// ref (a pull request's, for one), which clones the default branch.
func cloneBranch(ref string) string {
	ref = strings.TrimSpace(ref)
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		if name, ok := strings.CutPrefix(ref, prefix); ok {
			return name
		}
	}
	if strings.HasPrefix(ref, "refs/") || strings.HasPrefix(ref, "-") {
		return ""
	}
	return ref
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

// HTTPSCloneOrigin is the exact HTTPS authority that receives a private clone
// credential. Callers compare it to an operator-pinned hook origin before the
// worker opens the credential. Userinfo, query and fragment are never part of
// a credential-bearing clone target.
func HTTPSCloneOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", ErrRepositoryCredentialNeedsHTTPS
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// credentialGitConfig is the git configuration that sends cred's
// Authorization header to the clone URL's origin only, with the host's
// credential helpers off.
func credentialGitConfig(cloneURL string, cred *RepositoryCredential) ([]string, error) {
	u, err := url.Parse(cloneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, ErrRepositoryCredentialNeedsHTTPS
	}
	if len(cred.Secret) == 0 {
		return nil, errors.New("secretscan: the repository credential is empty")
	}
	user := strings.TrimSpace(cred.Username)
	if user == "" || strings.ContainsAny(user, ":\r\n") {
		return nil, errors.New("secretscan: the repository credential user name is empty or not a user name")
	}
	pair := make([]byte, 0, len(user)+1+len(cred.Secret))
	pair = append(append(append(pair, user...), ':'), cred.Secret...)
	header := "Authorization: Basic " + base64.StdEncoding.EncodeToString(pair)
	for i := range pair {
		pair[i] = 0
	}
	origin := u.Scheme + "://" + u.Host + "/"
	return []string{"credential.helper", "", "http." + origin + ".extraHeader", header}, nil
}

// runGit runs git with config given as key, value pairs through
// GIT_CONFIG_COUNT/KEY/VALUE, which keeps values out of its arguments (OD-1:
// the clone credential's header travels that way, never in argv).
func runGit(ctx context.Context, dir string, config []string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- fixed git/gitleaks binaries over the operator's own repository (CWE-78)
	// A terminated Git process may have left stdout or stderr open in a child.
	cmd.WaitDelay = 2 * time.Second
	if dir != "" {
		cmd.Dir = filepath.Clean(dir)
	}
	cmd.Env = sanitizedGitEnv(os.Environ())
	if len(config) > 0 {
		cmd.Env = append(cmd.Env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(config)/2))
		for i := 0; i+1 < len(config); i += 2 {
			n := strconv.Itoa(i / 2)
			cmd.Env = append(cmd.Env, "GIT_CONFIG_KEY_"+n+"="+config[i], "GIT_CONFIG_VALUE_"+n+"="+config[i+1])
		}
	}
	_, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("secretscan: git %s interrupted: %w", args[0], ctx.Err())
		}
		// A remote can echo the URL or response bytes in Git's stderr. Do
		// not return either to the tenant through a discovery-run error.
		return fmt.Errorf("secretscan: git %s failed: %w", args[0], err)
	}
	return nil
}

func sanitizedGitEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		// Only the operator's custom CA file may reach Git. The inherited
		// environment cannot inject config, URL rewrites, proxies, templates,
		// transport helpers, or a TLS-verification bypass.
		if strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "GIT_SSL_CAINFO=") {
			continue
		}
		if strings.HasPrefix(kv, "SSH_ASKPASS=") || strings.HasPrefix(kv, "HTTP_PROXY=") ||
			strings.HasPrefix(kv, "HTTPS_PROXY=") || strings.HasPrefix(kv, "ALL_PROXY=") ||
			strings.HasPrefix(kv, "http_proxy=") || strings.HasPrefix(kv, "https_proxy=") ||
			strings.HasPrefix(kv, "all_proxy=") || strings.HasPrefix(kv, "NO_PROXY=") ||
			strings.HasPrefix(kv, "no_proxy=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=Never",
		"GIT_ALLOW_PROTOCOL=https", "GIT_PROTOCOL_FROM_USER=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	return out
}
