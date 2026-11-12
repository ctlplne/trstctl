// SPDX-License-Identifier: BUSL-1.1

// Package scancollect fetches the content a leaked-secret scan reads from the
// provider itself (N6), instead of from an export an operator downloaded: an
// OCI image's config and layers from its registry, a Slack channel's history,
// Jira issues, GitHub Actions run logs or GitLab job logs, and (OD-4)
// Microsoft Teams channel messages and Confluence content. It writes them
// into a directory in the layout of the provider's own export (Slack: a folder
// per channel holding a JSON array per day plus channels.json; Jira:
// issues.json; CI logs: a folder per run or job named by its repository and
// commit; Teams: a folder per channel holding messages.json, Microsoft
// Graph's chatMessage objects, plus channels.json and users.json;
// Confluence: content.json, the search results), so the scanner and the
// A174 locator read a collection exactly as they read an export. The directory is
// the caller's, private, and removed after the scan; what it holds is the
// provider's content, secrets included, never an event or a log line.
package scancollect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Providers, as the third-party scan names them.
const (
	ProviderContainerRegistry = "container_registry"
	ProviderSlack             = "slack"
	ProviderJira              = "jira"
	ProviderCICDLog           = "cicd_log"
	ProviderTeams             = "teams"
	ProviderConfluence        = "confluence"
)

const (
	// DefaultMaxItems bounds what one collection reads: messages, issues, or
	// an image's manifests and layers.
	DefaultMaxItems = 2000
	// DefaultMaxBytes bounds what one collection writes.
	DefaultMaxBytes  int64 = 512 << 20
	maxResponseBytes       = 32 << 20
	maxErrorBytes          = 8 << 10
)

// ErrRefused is a provider answer that no retry changes: bad credentials, a
// missing channel, project or image.
var ErrRefused = errors.New("scancollect: the provider refused the collection")

// Doer sends one HTTP request. *http.Client satisfies it.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Request is one collection.
type Request struct {
	Provider string
	// BaseURL is the provider API: the registry (https://registry.example),
	// Slack's API (https://slack.com), or the Jira site.
	BaseURL string
	// Token is a bearer token (Slack, a Jira personal access token, a
	// registry token), or with Username the password or API token for basic
	// authentication (a registry's token service, Jira Cloud).
	Token    []byte
	Username string
	// Registry: the repository and a tag or digest.
	Repository string
	Reference  string
	// Slack: channel IDs. Teams: the team's channel IDs.
	Channels []string
	// Teams: the team whose channels are read.
	Team string
	// Jira: the issues to read.
	JQL string
	// Confluence: the content to read, by CQL.
	CQL string
	// CI logs: the system (github or gitlab) and the repository (owner/name,
	// or a GitLab project's ID or path).
	System string
	Repo   string
	// Since bounds Slack history (oldest), Jira issues (updated), CI runs
	// and jobs (created), Teams messages (last modified) and Confluence
	// content (lastmodified).
	Since    time.Time
	MaxItems int
	MaxBytes int64
	Doer     Doer
}

// Result is what one collection read.
type Result struct {
	Items int
	Bytes int64
	// Truncated reports that a limit stopped the collection early.
	Truncated bool
	// Object is the provider object every finding of the collection sits in,
	// when there is one: an image's repository and manifest digest.
	Object map[string]string
}

// Collect fetches req into dir, which must exist and be empty.
func Collect(ctx context.Context, dir string, req Request) (Result, error) {
	if req.Doer == nil || strings.TrimSpace(req.BaseURL) == "" {
		return Result{}, errors.New("scancollect: a base URL and an HTTP client are required")
	}
	if req.MaxItems <= 0 {
		req.MaxItems = DefaultMaxItems
	}
	if req.MaxBytes <= 0 {
		req.MaxBytes = DefaultMaxBytes
	}
	req.BaseURL = strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	w := &writer{dir: dir, budget: req.MaxBytes}
	var (
		res Result
		err error
	)
	switch req.Provider {
	case ProviderContainerRegistry:
		res, err = collectRegistry(ctx, w, req)
	case ProviderSlack:
		res, err = collectSlack(ctx, w, req)
	case ProviderJira:
		res, err = collectJira(ctx, w, req)
	case ProviderCICDLog:
		res, err = collectCILogs(ctx, w, req)
	case ProviderTeams:
		res, err = collectTeams(ctx, w, req)
	case ProviderConfluence:
		res, err = collectConfluence(ctx, w, req)
	default:
		return Result{}, fmt.Errorf("scancollect: provider %q is not collected natively", req.Provider)
	}
	res.Bytes = w.written
	res.Truncated = res.Truncated || w.full
	return res, err
}

// writer writes collected files under one directory within a byte budget.
type writer struct {
	dir     string
	budget  int64
	written int64
	full    bool
}

// path joins a provider-derived relative name under the directory, refusing
// any name that would leave it.
func (w *writer) path(rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("scancollect: %q leaves the collection", rel)
	}
	return filepath.Join(w.dir, clean), nil
}

// write stores data as rel; past the budget it writes nothing and reports
// false.
func (w *writer) write(rel string, data []byte) (bool, error) {
	if w.written+int64(len(data)) > w.budget {
		w.full = true
		return false, nil
	}
	full, err := w.path(rel)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(full, data, 0o600); err != nil {
		return false, err
	}
	w.written += int64(len(data))
	return true, nil
}

// copyFrom stores up to the remaining budget of r as rel; a file that does not
// fit is not written and reports false.
func (w *writer) copyFrom(rel string, r io.Reader, size int64) (bool, error) {
	if size < 0 || w.written+size > w.budget {
		w.full = true
		_, _ = io.Copy(io.Discard, r)
		return false, nil
	}
	full, err := w.path(rel)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return false, err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- a path inside the collection directory, checked by w.path (CWE-22)
	if err != nil {
		return false, err
	}
	n, copyErr := io.Copy(f, io.LimitReader(r, size+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n != size {
		_ = os.Remove(full)
		return false, errors.Join(copyErr, closeErr, fmt.Errorf("scancollect: %s read %d of %d bytes", rel, n, size))
	}
	w.written += n
	return true, nil
}

// get sends a GET with the request's authorization and returns the bounded
// body of a 2xx answer.
func get(ctx context.Context, req Request, url string, header http.Header) ([]byte, http.Header, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range header {
		r.Header[k] = v
	}
	resp, err := req.Doer.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
		return nil, resp.Header, statusError(resp.StatusCode, url)
	}
	body, err := secret.ReadBounded(resp.Body, maxResponseBytes)
	return body, resp.Header, err
}

func statusError(code int, url string) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusNotFound {
		return fmt.Errorf("%w: HTTP %d from %s", ErrRefused, code, redactQuery(url))
	}
	return fmt.Errorf("scancollect: HTTP %d from %s", code, redactQuery(url))
}

func redactQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

// authorization is the request's credential as an Authorization header:
// bearer for a token alone, basic for a username and token.
func authorization(req Request) http.Header {
	switch {
	case len(req.Token) == 0:
		return http.Header{}
	case req.Username == "":
		return http.Header{"Authorization": {secrettext.Prefixed("Bearer ", req.Token)}}
	default:
		return http.Header{"Authorization": {basic(req.Username, req.Token)}}
	}
}

func basic(username string, token []byte) string {
	plain := make([]byte, 0, len(username)+1+len(token))
	plain = append(plain, username...)
	plain = append(plain, ':')
	plain = append(plain, token...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(encoded, plain)
	value := secrettext.Prefixed("Basic ", encoded)
	secret.Wipe(plain)
	secret.Wipe(encoded)
	return value
}

// writeJSON writes v pretty-printed, one element per block, so a finding's
// line maps to one message or issue as it does in an export.
func (w *writer) writeJSON(rel string, v any) (bool, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false, err
	}
	return w.write(rel, append(data, '\n'))
}
