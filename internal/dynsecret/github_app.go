// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	githubAppRefPrefix = "github-app:"
	// githubAppTokenLifetime is the fixed lifetime GitHub gives an installation
	// access token.
	githubAppTokenLifetime = time.Hour
)

var (
	githubPermission   = regexp.MustCompile(`^[a-z][a-z_]{1,63}$`)
	githubRepository   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubInstallation = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	githubLevels       = map[string]int{"read": 1, "write": 2, "admin": 3}
)

// GitHubAppGrant is a role's token scope: the permissions (name to read, write
// or admin) and the repositories of the installation the token may use.
type GitHubAppGrant struct {
	Permissions  map[string]string
	Repositories []string
}

// ParseGitHubAppGrant reads a role binding: "<permission>:<level>[,...] on
// <repository>[,...]", for example "contents:read,metadata:read on api,web".
// Repositories are named explicitly; a token never covers every repository the
// installation can reach.
func ParseGitHubAppGrant(binding string) (GitHubAppGrant, error) {
	perms, repos, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	if !ok {
		return GitHubAppGrant{}, errors.New(`expected "<permission>:<level> on <repositories>", for example "contents:read on api"`)
	}
	grant := GitHubAppGrant{Permissions: map[string]string{}}
	for _, item := range strings.Split(perms, ",") {
		name, level, _ := strings.Cut(strings.TrimSpace(item), ":")
		if !githubPermission.MatchString(name) || githubLevels[level] == 0 {
			return GitHubAppGrant{}, fmt.Errorf("permission %q is not <name>:read, :write or :admin", strings.TrimSpace(item))
		}
		grant.Permissions[name] = level
	}
	for _, repo := range strings.Split(repos, ",") {
		repo = strings.TrimSpace(repo)
		if !githubRepository.MatchString(repo) {
			return GitHubAppGrant{}, fmt.Errorf("repository %q is not a repository name", repo)
		}
		grant.Repositories = append(grant.Repositories, repo)
	}
	return grant, nil
}

// GitHubAppConfig configures the GitHub App provider (A239): each lease is an
// installation access token narrowed to its role's permissions and
// repositories; GitHub ends it after an hour, and revocation ends it at once by
// presenting it (DELETE /installation/token).
type GitHubAppConfig struct {
	// Endpoint is https://api.github.com by default; GitHub Enterprise Server
	// is https://<host>/api/v3.
	Endpoint string
	// ClientID is the app's client ID (or app ID), the JWT issuer; PrivateKey
	// is the app's private key (PEM).
	ClientID       string
	PrivateKey     []byte
	InstallationID string
	RoleBindings   map[string]string
	// MaxLifetime is the provider's maximum lease; at most GitHub's one hour.
	MaxLifetime           time.Duration
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// GitHubAppBackend issues installation access tokens.
type GitHubAppBackend struct {
	endpoint       string
	clientID       string
	installationID string
	privateKey     *secret.Buffer
	grants         map[string]GitHubAppGrant
	maxLifetime    time.Duration
	client         *http.Client
	now            func() time.Time
}

// NewGitHubAppBackend validates cfg.
func NewGitHubAppBackend(cfg GitHubAppConfig) (*GitHubAppBackend, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.github.com"
	}
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret github-app: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.ClientID) == "" || len(cfg.PrivateKey) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret github-app: the app's client ID, private key and an HTTP client are required")
	}
	if !githubInstallation.MatchString(cfg.InstallationID) {
		return nil, errors.New("dynsecret github-app: the installation ID must be GitHub's numeric ID")
	}
	if cfg.MaxLifetime < time.Minute || cfg.MaxLifetime > githubAppTokenLifetime {
		return nil, errors.New("dynsecret github-app: the maximum lifetime must be between 1 minute and GitHub's 1 hour")
	}
	b := &GitHubAppBackend{endpoint: strings.TrimRight(endpoint, "/"), clientID: cfg.ClientID, installationID: cfg.InstallationID,
		grants: map[string]GitHubAppGrant{}, maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient, now: cfg.Now}
	if b.now == nil {
		b.now = time.Now
	}
	for role, binding := range cfg.RoleBindings {
		grant, err := ParseGitHubAppGrant(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret github-app: role %q: %w", role, err)
		}
		b.grants[role] = grant
	}
	if len(b.grants) == 0 {
		return nil, errors.New("dynsecret github-app: every allowed role needs permissions in role_bindings")
	}
	var err error
	if b.privateKey, err = secret.NewFrom(cfg.PrivateKey); err != nil {
		return nil, err
	}
	return b, nil
}

// RevocationConfirmed reports that a lease's token is ended upstream at
// revocation, before its native expiry.
func (b *GitHubAppBackend) RevocationConfirmed() bool { return true }

// Create implements Backend.
func (b *GitHubAppBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: one token request, narrowed to
// the role's permissions and repositories. GitHub has no idempotency key for
// it, so the issuance is at-most-once (an uncertain request is not retried).
// A token whose permissions, repositories or lifetime differ from the request
// is revoked and refused.
func (b *GitHubAppBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret github-app: static credentials are not served")
	}
	grant, ok := b.grants[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret github-app: role %q has no permissions", req.Role)
	}
	jwt, err := b.appJWT()
	if err != nil {
		return "", nil, err
	}
	body, err := json.Marshal(map[string]any{"repositories": grant.Repositories, "permissions": grant.Permissions})
	if err != nil {
		return "", nil, err
	}
	issuedAt := b.now().UTC()
	status, response, err := b.call(ctx, http.MethodPost, "/app/installations/"+b.installationID+"/access_tokens", jwt, body)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(response)
	if status != http.StatusCreated {
		return "", nil, fmt.Errorf("dynsecret github-app: the token request answered HTTP %d", status)
	}
	var token struct {
		Token        secret.JSONBytes  `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(response, &token); err != nil || len(token.Token) == 0 {
		return "", nil, errors.New("dynsecret github-app: the token response carries no token")
	}
	defer secret.Wipe(token.Token)
	refuse := func(reason string) (string, []byte, error) {
		if err := b.revokeToken(ctx, token.Token); err != nil {
			return "", nil, fmt.Errorf("dynsecret github-app: %s, and revoking the token failed: %w", reason, err)
		}
		return "", nil, fmt.Errorf("dynsecret github-app: %s; the token was revoked", reason)
	}
	for name, level := range token.Permissions {
		if githubLevels[level] > githubLevels[grant.Permissions[name]] {
			return refuse(fmt.Sprintf("GitHub granted %s:%s beyond the role", name, level))
		}
	}
	var repositories []string
	for _, repo := range token.Repositories {
		if !slices.Contains(grant.Repositories, repo.Name) {
			return refuse(fmt.Sprintf("GitHub granted repository %q beyond the role", repo.Name))
		}
		repositories = append(repositories, repo.Name)
	}
	if len(repositories) == 0 {
		return refuse("the token names no repositories, so it may reach every repository of the installation")
	}
	lifetime := token.ExpiresAt.Sub(issuedAt)
	switch {
	case token.ExpiresAt.IsZero() || lifetime <= 0:
		return refuse("the token has no future expiry")
	case lifetime > githubAppTokenLifetime+2*time.Minute:
		return refuse(fmt.Sprintf("the token is valid for %s, beyond GitHub's hour", lifetime.Round(time.Second)))
	case req.TTL > lifetime:
		return refuse(fmt.Sprintf("the token is valid for %s, shorter than the %s lease", lifetime.Round(time.Second), req.TTL))
	}
	expiresAt := token.ExpiresAt.UTC().Truncate(time.Second)
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Token        secret.JSONBytes  `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}{Token: token.Token, ExpiresAt: expiresAt, Permissions: token.Permissions, Repositories: repositories})
	if err != nil {
		return "", nil, err
	}
	return githubAppRefPrefix + githubTokenDigest(token.Token) + ":" + strconv.FormatInt(expiresAt.Unix(), 10), credential, nil
}

// appJWT signs the short app JWT GitHub authenticates the token request with:
// issued a minute back for clock skew, valid nine minutes (GitHub's limit is
// ten).
func (b *GitHubAppBackend) appJWT() (string, error) {
	now := b.now().UTC()
	claims := map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": b.clientID}
	var jwt string
	err := b.privateKey.Use(func(key []byte) error {
		var err error
		jwt, err = crypto.SignJWTWithPEMKey(key, "", claims)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("dynsecret github-app: sign the app JWT: %w", err)
	}
	return jwt, nil
}

// githubTokenDigest names a token in its lease's provider reference: the first
// 128 bits of its SHA-256, in hex.
func githubTokenDigest(token []byte) string { return crypto.SHA256Hex(token)[:32] }

// GitHubAppExpiration reads the native expiry from an installation token
// lease's provider reference.
func GitHubAppExpiration(ref string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(ref, githubAppRefPrefix)
	if !ok {
		return time.Time{}, false
	}
	digest, unix, ok := strings.Cut(rest, ":")
	if !ok || len(digest) != 32 {
		return time.Time{}, false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(unix, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

// Revoke implements Backend for a lease whose token is not at hand: the token
// lapses at its native expiry, which is what revocation waits for.
func (b *GitHubAppBackend) Revoke(_ context.Context, ref string) error {
	return CheckNativeExpiration(ref, b.now())
}

// RevokeCredential ends the lease's token by presenting it. credential is the
// lease's credential JSON; its token must be the one ref names. GitHub
// answering 401 means the token is already invalid.
func (b *GitHubAppBackend) RevokeCredential(ctx context.Context, ref string, credential []byte) error {
	var lease struct {
		Token secret.JSONBytes `json:"token"`
	}
	if err := json.Unmarshal(credential, &lease); err != nil || len(lease.Token) == 0 {
		return errors.New("dynsecret github-app: the revocation carries no token")
	}
	defer secret.Wipe(lease.Token)
	if !strings.HasPrefix(ref, githubAppRefPrefix+githubTokenDigest(lease.Token)+":") {
		return errors.New("dynsecret github-app: the revocation's token is not the lease's")
	}
	return b.revokeToken(ctx, lease.Token)
}

func (b *GitHubAppBackend) revokeToken(ctx context.Context, token []byte) error {
	status, body, err := b.call(ctx, http.MethodDelete, "/installation/token", string(token), nil)
	secret.Wipe(body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusUnauthorized {
		return fmt.Errorf("dynsecret github-app: token revocation answered HTTP %d", status)
	}
	return nil
}

func (b *GitHubAppBackend) call(ctx context.Context, method, path, bearer string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret github-app: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		secret.Wipe(response)
		return 0, nil, fmt.Errorf("dynsecret github-app: read the response: %w", err)
	}
	return resp.StatusCode, response, nil
}

// Close wipes the app's private key.
func (b *GitHubAppBackend) Close() { b.privateKey.Destroy() }
