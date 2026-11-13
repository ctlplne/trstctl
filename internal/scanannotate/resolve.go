// SPDX-License-Identifier: BUSL-1.1

package scanannotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/secrettext"
)

// Withdrawing an annotation once its finding is resolved (A174-L1).
//
// An annotation tells the people at the provider that a credential was
// exposed there and must be rotated. Once the finding is resolved (the
// credential rotated, or the finding dismissed) the annotation would keep
// saying so, a stale alarm that teaches people to ignore the next one. So
// resolution settles it the way each provider can: the Slack reply is
// deleted, the Jira comment is rewritten to say the finding was resolved, the
// CI commit status turns to success under the same context, and the image
// referrer is deleted.

// Resolution statuses, as the finding records them.
const (
	Resolved        = "resolved"
	AlreadyResolved = "already_resolved"
)

// Resolver settles one finding's annotation at its provider. ref is the
// provider reference the annotation recorded; an empty ref makes a provider
// that can find its annotation by marker look for it.
type Resolver interface {
	Resolve(ctx context.Context, a Annotation, ref string) (Result, error)
}

// ResolvedMessage is what an annotation says once its finding is resolved.
func ResolvedMessage(a Annotation) string {
	return fmt.Sprintf("Resolved in trstctl: the credential this finding named (rule %s) is no longer an open finding. %s",
		a.Rule, Marker(a.FindingID))
}

func shortResolvedMessage(a Annotation) string {
	msg := fmt.Sprintf("Resolved in trstctl (rule %s, finding %s).", a.Rule, shortID(a.FindingID))
	if len(msg) > 140 {
		msg = msg[:140]
	}
	return msg
}

// Resolve deletes the reply in the thread.
func (s slack) Resolve(ctx context.Context, a Annotation, ref string) (Result, error) {
	channel, thread := first(a.Object.ChannelID, a.Object.Channel), first(a.Object.ThreadTS, a.Object.MessageTS)
	if channel == "" || thread == "" {
		return Result{}, invalid("the finding names no Slack channel and message")
	}
	ts := strings.TrimSpace(ref)
	if ts == "" {
		found, ok, unreadable, err := s.findReply(ctx, channel, thread, a.FindingID)
		if err != nil {
			return Result{}, err
		}
		if !ok {
			// A174-L4: a thread the token cannot read is not a thread without
			// the reply.
			if unreadable != "" {
				return Result{}, &RefusalError{Op: "slack conversations.replies", Reason: "the reply's ts was never recorded and the token cannot read " +
					"the thread to find it (" + unreadable + "); grant channels:history (groups:history for a private channel), or delete the reply by hand"}
			}
			return Result{Status: AlreadyResolved, Detail: "Slack has no reply for this finding in the thread"}, nil
		}
		ts = found
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if _, _, err := s.h.do(ctx, request{op: "slack chat.delete", method: http.MethodPost, path: "/api/chat.delete",
		body:        jsonBody(map[string]any{"channel": channel, "ts": ts}),
		contentType: "application/json; charset=utf-8", auth: s.h.bearer, out: &resp}); err != nil {
		return Result{}, err
	}
	switch {
	case resp.OK:
		return Result{Status: Resolved, ProviderRef: ts, Detail: "Slack deleted the reply in the thread (ts " + ts + ")"}, nil
	case resp.Error == "message_not_found":
		return Result{Status: AlreadyResolved, ProviderRef: ts, Detail: "Slack no longer has the reply (ts " + ts + ")"}, nil
	case resp.Error == "ratelimited":
		return Result{}, fmt.Errorf("slack chat.delete: %w", ErrRetryable)
	}
	return Result{}, &RefusalError{Op: "slack chat.delete", Reason: first(resp.Error, "not ok")}
}

// Resolve rewrites the comment to say the finding was resolved.
func (j jira) Resolve(ctx context.Context, a Annotation, ref string) (Result, error) {
	key := strings.TrimSpace(a.Object.IssueKey)
	if key == "" {
		return Result{}, invalid("the finding names no Jira issue")
	}
	path := "/rest/api/3/issue/" + url.PathEscape(key) + "/comment"
	_, id, _ := strings.Cut(strings.TrimSpace(ref), "#comment-")
	if id == "" {
		_, data, err := j.h.do(ctx, request{op: "jira list comments", method: http.MethodGet, path: path + "?maxResults=100&orderBy=-created", auth: j.auth})
		if err != nil {
			return Result{}, err
		}
		var listed struct {
			Comments []struct {
				ID   string          `json:"id"`
				Body json.RawMessage `json:"body"`
			} `json:"comments"`
		}
		_ = json.Unmarshal(data, &listed)
		for _, c := range listed.Comments {
			if strings.Contains(string(c.Body), Marker(a.FindingID)) {
				id = c.ID
				break
			}
		}
		if id == "" {
			return Result{Status: AlreadyResolved, ProviderRef: key, Detail: "Jira issue " + key + " has no comment for this finding"}, nil
		}
	}
	doc := map[string]any{"body": map[string]any{"type": "doc", "version": 1, "content": []any{map[string]any{
		"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": ResolvedMessage(a)}},
	}}}}
	_, _, err := j.h.do(ctx, request{op: "jira update comment", method: http.MethodPut, path: path + "/" + url.PathEscape(id),
		body: jsonBody(doc), contentType: "application/json", auth: j.auth})
	var status *StatusError
	if errors.As(err, &status) && status.Code == http.StatusNotFound {
		return Result{Status: AlreadyResolved, ProviderRef: key + "#comment-" + id, Detail: "Jira no longer has comment " + id + " on " + key}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Status: Resolved, ProviderRef: key + "#comment-" + id, Detail: "Jira comment " + id + " on " + key + " now says the finding was resolved"}, nil
}

// Resolve turns the commit status to success under the same context.
func (g github) Resolve(ctx context.Context, a Annotation, _ string) (Result, error) {
	if a.Object.Kind == ObjectKindRepositoryFile {
		return g.uploadCodeScanning(ctx, a, true)
	}
	repo, sha := strings.Trim(strings.TrimSpace(a.Object.Repo), "/"), strings.TrimSpace(a.Object.CommitSHA)
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || sha == "" {
		return Result{}, invalid("the annotation target needs repo (owner/name) and commit_sha")
	}
	statusContext := "trstctl/secret-scan/" + shortID(a.FindingID)
	if _, _, err := g.h.do(ctx, request{op: "github resolve status", method: http.MethodPost,
		path:        "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + url.PathEscape(sha),
		body:        jsonBody(map[string]string{"state": "success", "context": statusContext, "description": shortResolvedMessage(a)}),
		contentType: "application/json", auth: func(req *http.Request) {
			g.h.bearer(req)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		}}); err != nil {
		return Result{}, err
	}
	return Result{Status: Resolved, ProviderRef: statusContext + "@" + sha, Detail: "GitHub set commit status " + statusContext + " to success on " + sha}, nil
}

// Resolve turns the commit status to success under the same name.
func (g gitlab) Resolve(ctx context.Context, a Annotation, _ string) (Result, error) {
	project, sha := strings.TrimSpace(a.Object.Repo), strings.TrimSpace(a.Object.CommitSHA)
	if project == "" || sha == "" {
		return Result{}, invalid("the annotation target needs repo (the GitLab project) and commit_sha")
	}
	name := "trstctl/secret-scan/" + shortID(a.FindingID)
	_, data, err := g.h.do(ctx, request{op: "gitlab resolve commit status", method: http.MethodPost,
		path:        "/api/v4/projects/" + url.PathEscape(project) + "/statuses/" + url.PathEscape(sha),
		body:        jsonBody(map[string]string{"state": "success", "name": name, "description": shortResolvedMessage(a)}),
		contentType: "application/json", auth: func(req *http.Request) { req.Header.Set("PRIVATE-TOKEN", secrettext.String(g.h.token)) }})
	var status *StatusError
	if err != nil && errors.As(err, &status) && status.Code == http.StatusBadRequest && strings.Contains(string(data), "Cannot transition status") {
		return Result{Status: AlreadyResolved, ProviderRef: name + "@" + sha, Detail: "GitLab already shows " + name + " succeeded on " + sha}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Status: Resolved, ProviderRef: name + "@" + sha, Detail: "GitLab set commit status " + name + " to success on " + sha}, nil
}

// Resolve deletes the referrer manifest.
func (r registry) Resolve(ctx context.Context, a Annotation, ref string) (Result, error) {
	repo, digest := strings.Trim(strings.TrimSpace(a.Object.Repository), "/"), strings.TrimSpace(ref)
	if repo == "" || !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return Result{}, invalid("resolving an image annotation needs the repository and the referrer's sha256 digest")
	}
	base := "/v2/" + repo
	_, _, err := r.call(ctx, request{op: "registry delete referrer", method: http.MethodDelete, path: base + "/manifests/" + digest}, r.scope(base))
	var status *StatusError
	gone := errors.As(err, &status) && status.Code == http.StatusNotFound
	if err != nil && !gone {
		return Result{}, err
	}
	// A174-L2: on a registry without the referrers API the referrer is also
	// listed in the referrers tag schema's index; take it out.
	if subject := strings.TrimSpace(a.Object.Digest); strings.HasPrefix(subject, "sha256:") {
		if err := r.updateReferrersIndex(ctx, base, subject, func(list []indexDescriptor) ([]indexDescriptor, bool) {
			kept := list[:0:0]
			for _, d := range list {
				if d.Digest != digest {
					kept = append(kept, d)
				}
			}
			return kept, len(kept) != len(list)
		}); err != nil {
			return Result{}, err
		}
	}
	if gone {
		return Result{Status: AlreadyResolved, ProviderRef: digest, Detail: "The registry no longer has referrer " + digest + " on " + repo}, nil
	}
	return Result{Status: Resolved, ProviderRef: digest, Detail: "The registry deleted referrer " + digest + " from " + repo}, nil
}

var (
	_ Resolver = slack{}
	_ Resolver = jira{}
	_ Resolver = github{}
	_ Resolver = gitlab{}
	_ Resolver = registry{}
)
