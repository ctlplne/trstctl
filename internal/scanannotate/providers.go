// SPDX-License-Identifier: BUSL-1.1

package scanannotate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const maxResponseBytes = 1 << 20

// RefusalError is a provider's answer that the request itself is wrong (a
// missing channel, a revoked token): delivering it again changes nothing.
type RefusalError struct {
	Op     string
	Reason string
}

func (e *RefusalError) Error() string { return e.Op + ": " + e.Reason }

type httpClient struct {
	base     string
	token    []byte
	username string
	doer     Doer
}

type request struct {
	op, method, path string
	body             []byte
	contentType      string
	auth             func(*http.Request)
	out              any
}

func (h *httpClient) bearer(req *http.Request) {
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", h.token))
}

func (h *httpClient) do(ctx context.Context, r request) (*http.Response, []byte, error) {
	target := r.path
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = h.base + r.path
	}
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, target, body)
	if err != nil {
		return nil, nil, invalid("%s: %v", r.op, err)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	req.Header.Set("Accept", "application/json")
	if r.auth != nil {
		r.auth(req)
	}
	resp, err := h.doer.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", r.op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: read response: %w", r.op, err)
	}
	if resp.StatusCode/100 != 2 {
		return resp, data, &StatusError{Op: r.op, Code: resp.StatusCode, Body: string(data)}
	}
	if r.out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, r.out); err != nil {
			return resp, data, fmt.Errorf("%s: decode response: %w", r.op, err)
		}
	}
	return resp, data, nil
}

func jsonBody(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

func first(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// shortMessage fits the commit-status description limit (140 characters).
func shortMessage(a Annotation) string {
	msg := fmt.Sprintf("Credential exposed in the CI log (rule %s, finding %s). Rotate it.", a.Rule, shortID(a.FindingID))
	if len(msg) > 140 {
		msg = msg[:140]
	}
	return msg
}

type slack struct{ h *httpClient }

func (s slack) Annotate(ctx context.Context, a Annotation) (Result, error) {
	channel, thread := first(a.Object.ChannelID, a.Object.Channel), first(a.Object.ThreadTS, a.Object.MessageTS)
	if channel == "" || thread == "" {
		return Result{}, invalid("the finding names no Slack channel and message")
	}
	if a.Retry {
		if ts, found := s.findReply(ctx, channel, thread, a.FindingID); found {
			return Result{Status: AlreadyPresent, ProviderRef: ts, Detail: "Slack already has the reply in the thread (ts " + ts + ")"}, nil
		}
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	_, _, err := s.h.do(ctx, request{op: "slack chat.postMessage", method: http.MethodPost, path: "/api/chat.postMessage",
		body:        jsonBody(map[string]any{"channel": channel, "thread_ts": thread, "text": Message(a, "message"), "unfurl_links": false}),
		contentType: "application/json; charset=utf-8", auth: s.h.bearer, out: &resp})
	if err != nil {
		return Result{}, err
	}
	if !resp.OK {
		if resp.Error == "ratelimited" {
			return Result{}, fmt.Errorf("slack chat.postMessage: %w", ErrRetryable)
		}
		return Result{}, &RefusalError{Op: "slack chat.postMessage", Reason: first(resp.Error, "not ok")}
	}
	return Result{Status: Confirmed, ProviderRef: resp.TS, Detail: "Slack posted a reply in the thread (ts " + resp.TS + ")"}, nil
}

func (s slack) findReply(ctx context.Context, channel, thread, findingID string) (string, bool) {
	var resp struct {
		OK       bool `json:"ok"`
		Messages []struct {
			TS   string `json:"ts"`
			Text string `json:"text"`
		} `json:"messages"`
	}
	q := url.Values{"channel": {channel}, "ts": {thread}, "limit": {"200"}}
	if _, _, err := s.h.do(ctx, request{op: "slack conversations.replies", method: http.MethodGet, path: "/api/conversations.replies?" + q.Encode(),
		auth: s.h.bearer, out: &resp}); err != nil || !resp.OK {
		return "", false
	}
	for _, m := range resp.Messages {
		if strings.Contains(m.Text, Marker(findingID)) {
			return m.TS, true
		}
	}
	return "", false
}

type jira struct{ h *httpClient }

func (j jira) auth(req *http.Request) {
	if j.h.username == "" {
		j.h.bearer(req)
		return
	}
	plain := make([]byte, 0, len(j.h.username)+1+len(j.h.token))
	plain = append(plain, j.h.username...)
	plain = append(plain, ':')
	plain = append(plain, j.h.token...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(encoded, plain)
	req.Header.Set("Authorization", secrettext.Prefixed("Basic ", encoded))
	secret.Wipe(plain)
	secret.Wipe(encoded)
}

func (j jira) Annotate(ctx context.Context, a Annotation) (Result, error) {
	key := strings.TrimSpace(a.Object.IssueKey)
	if key == "" {
		return Result{}, invalid("the finding names no Jira issue")
	}
	path := "/rest/api/3/issue/" + url.PathEscape(key) + "/comment"
	if a.Retry {
		_, data, err := j.h.do(ctx, request{op: "jira list comments", method: http.MethodGet, path: path + "?maxResults=100&orderBy=-created", auth: j.auth})
		if err == nil && bytes.Contains(data, []byte(Marker(a.FindingID))) {
			return Result{Status: AlreadyPresent, ProviderRef: key, Detail: "Jira issue " + key + " already has the comment"}, nil
		}
	}
	doc := map[string]any{"body": map[string]any{"type": "doc", "version": 1, "content": []any{map[string]any{
		"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": Message(a, "issue")}},
	}}}}
	var resp struct {
		ID string `json:"id"`
	}
	if _, _, err := j.h.do(ctx, request{op: "jira add comment", method: http.MethodPost, path: path, body: jsonBody(doc),
		contentType: "application/json", auth: j.auth, out: &resp}); err != nil {
		return Result{}, err
	}
	return Result{Status: Confirmed, ProviderRef: key + "#comment-" + resp.ID, Detail: "Jira added comment " + resp.ID + " to " + key}, nil
}

type github struct{ h *httpClient }

func (g github) Annotate(ctx context.Context, a Annotation) (Result, error) {
	repo, sha := strings.Trim(strings.TrimSpace(a.Object.Repo), "/"), strings.TrimSpace(a.Object.CommitSHA)
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || sha == "" {
		return Result{}, invalid("the annotation target needs repo (owner/name) and commit_sha")
	}
	statusContext := "trstctl/secret-scan/" + shortID(a.FindingID)
	var resp struct {
		ID int64 `json:"id"`
	}
	if _, _, err := g.h.do(ctx, request{op: "github create status", method: http.MethodPost,
		path:        "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + url.PathEscape(sha),
		body:        jsonBody(map[string]string{"state": "failure", "context": statusContext, "description": shortMessage(a)}),
		contentType: "application/json", auth: func(req *http.Request) {
			g.h.bearer(req)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		}, out: &resp}); err != nil {
		return Result{}, err
	}
	return Result{Status: Confirmed, ProviderRef: statusContext + "@" + sha,
		Detail: "GitHub set commit status " + statusContext + " to failure on " + sha + " (status " + strconv.FormatInt(resp.ID, 10) + ")"}, nil
}

type gitlab struct{ h *httpClient }

func (g gitlab) Annotate(ctx context.Context, a Annotation) (Result, error) {
	project, sha := strings.TrimSpace(a.Object.Repo), strings.TrimSpace(a.Object.CommitSHA)
	if project == "" || sha == "" {
		return Result{}, invalid("the annotation target needs repo (the GitLab project) and commit_sha")
	}
	name := "trstctl/secret-scan/" + shortID(a.FindingID)
	var resp struct {
		ID int64 `json:"id"`
	}
	_, data, err := g.h.do(ctx, request{op: "gitlab create commit status", method: http.MethodPost,
		path:        "/api/v4/projects/" + url.PathEscape(project) + "/statuses/" + url.PathEscape(sha),
		body:        jsonBody(map[string]string{"state": "failed", "name": name, "description": shortMessage(a)}),
		contentType: "application/json", auth: func(req *http.Request) { req.Header.Set("PRIVATE-TOKEN", secrettext.String(g.h.token)) }, out: &resp})
	var status *StatusError
	if err != nil && errors.As(err, &status) && status.Code == http.StatusBadRequest && bytes.Contains(data, []byte("Cannot transition status")) {
		return Result{Status: AlreadyPresent, ProviderRef: name + "@" + sha, Detail: "GitLab already shows " + name + " failed on " + sha}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Status: Confirmed, ProviderRef: name + "@" + sha,
		Detail: "GitLab set commit status " + name + " to failed on " + sha + " (status " + strconv.FormatInt(resp.ID, 10) + ")"}, nil
}

// The OCI 1.1 empty descriptor: the two bytes "{}".
const (
	emptyMediaType   = "application/vnd.oci.empty.v1+json"
	emptyDigest      = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	manifestMedia    = "application/vnd.oci.image.manifest.v1+json"
	findingArtifact  = "application/vnd.trstctl.secret-finding.v1+json"
	annotationPrefix = "dev.trstctl.finding."
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type registry struct{ h *httpClient }

func (r registry) Annotate(ctx context.Context, a Annotation) (Result, error) {
	repo, subjectDigest := strings.Trim(strings.TrimSpace(a.Object.Repository), "/"), strings.TrimSpace(a.Object.Digest)
	if repo == "" || !strings.HasPrefix(subjectDigest, "sha256:") || len(subjectDigest) != len("sha256:")+64 {
		return Result{}, invalid("the annotation target needs repository and a sha256 digest")
	}
	base := "/v2/" + repo
	resp, _, err := r.h.do(ctx, request{op: "registry head subject", method: http.MethodHead, path: base + "/manifests/" + subjectDigest, auth: func(req *http.Request) {
		r.h.bearer(req)
		req.Header.Set("Accept", manifestMedia+", application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	}})
	if err != nil {
		return Result{}, err
	}
	size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	subject := descriptor{MediaType: first(strings.Split(resp.Header.Get("Content-Type"), ";")[0], manifestMedia), Digest: subjectDigest, Size: size}
	if err := r.ensureEmptyBlob(ctx, base); err != nil {
		return Result{}, err
	}
	empty := descriptor{MediaType: emptyMediaType, Digest: emptyDigest, Size: 2}
	manifest := jsonBody(struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		ArtifactType  string            `json:"artifactType"`
		Config        descriptor        `json:"config"`
		Layers        []descriptor      `json:"layers"`
		Subject       descriptor        `json:"subject"`
		Annotations   map[string]string `json:"annotations"`
	}{2, manifestMedia, findingArtifact, empty, []descriptor{empty}, subject, map[string]string{
		annotationPrefix + "id": a.FindingID, annotationPrefix + "rule": a.Rule, annotationPrefix + "message": Message(a, "image"),
		"org.opencontainers.image.created": first(a.DetectedAt, "1970-01-01T00:00:00Z"),
	}})
	digest := "sha256:" + crypto.SHA256Hex(manifest)
	if _, _, err := r.h.do(ctx, request{op: "registry put referrer", method: http.MethodPut, path: base + "/manifests/" + digest, body: manifest,
		contentType: manifestMedia, auth: r.h.bearer}); err != nil {
		return Result{}, err
	}
	return Result{Status: Confirmed, ProviderRef: digest, Detail: "The registry stored referrer " + digest + " on " + repo + "@" + subjectDigest}, nil
}

func (r registry) ensureEmptyBlob(ctx context.Context, base string) error {
	if _, _, err := r.h.do(ctx, request{op: "registry head empty blob", method: http.MethodHead, path: base + "/blobs/" + emptyDigest, auth: r.h.bearer}); err == nil {
		return nil
	}
	resp, _, err := r.h.do(ctx, request{op: "registry start upload", method: http.MethodPost, path: base + "/blobs/uploads/", auth: r.h.bearer})
	if err != nil {
		return err
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.Header.Get("Location") == "" {
		return &RefusalError{Op: "registry start upload", Reason: "no upload location"}
	}
	baseURL, _ := url.Parse(r.h.base)
	target := baseURL.ResolveReference(location)
	q := target.Query()
	q.Set("digest", emptyDigest)
	target.RawQuery = q.Encode()
	_, _, err = r.h.do(ctx, request{op: "registry upload empty blob", method: http.MethodPut, path: target.String(), body: []byte("{}"),
		contentType: "application/octet-stream", auth: r.h.bearer})
	return err
}
