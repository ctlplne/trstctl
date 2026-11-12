// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secretscan"
)

// OD-3: each native hook proves a delivery its provider's way. GitLab's
// signing token signs webhook-id, webhook-timestamp and the body (Standard
// Webhooks) within five minutes of now; its secret token is compared whole;
// Bitbucket signs the body. Anything else is refused with the reason.
func TestSecretScanHookVerifiesEachProvidersProofOD3(t *testing.T) {
	body := []byte(`{"object_kind":"push"}`)
	now := time.Unix(1_800_000_000, 0)
	rawKey := []byte("od3-signing-key-material-32-byte")
	signingToken := "whsec_" + base64.StdEncoding.EncodeToString(rawKey) // #nosec G101 -- fabricated fixture signing token (CWE-798)
	sign := func(id string, at time.Time, key []byte) string {
		stamp := strconv.FormatInt(at.Unix(), 10)
		return "v1," + base64.StdEncoding.EncodeToString(crypto.HMACSHA256(key, []byte(id+"."+stamp+"."+string(body))))
	}
	signed := func(id string, at time.Time, signature string) http.Header {
		h := http.Header{}
		h.Set("webhook-id", id)
		h.Set("webhook-timestamp", strconv.FormatInt(at.Unix(), 10))
		if signature != "" {
			h.Set("webhook-signature", signature)
		}
		return h
	}
	for name, tc := range map[string]struct {
		provider, key string
		header        http.Header
		want          string
	}{
		"gitlab signed":           {"gitlab", signingToken, signed("msg_1", now, sign("msg_1", now, rawKey)), ""},
		"gitlab signed, rotated":  {"gitlab", signingToken, signed("msg_1", now, "v1,AAAA "+sign("msg_1", now, rawKey)), ""},
		"gitlab signed, wrong":    {"gitlab", signingToken, signed("msg_1", now, sign("msg_1", now, []byte("another key"))), secretScanHookSignatureWrong},
		"gitlab signed, other id": {"gitlab", signingToken, signed("msg_2", now, sign("msg_1", now, rawKey)), secretScanHookSignatureWrong},
		"gitlab signed, stale":    {"gitlab", signingToken, signed("msg_1", now.Add(-6*time.Minute), sign("msg_1", now.Add(-6*time.Minute), rawKey)), secretScanHookSignatureStale},
		"gitlab signed, future":   {"gitlab", signingToken, signed("msg_1", now.Add(6*time.Minute), sign("msg_1", now.Add(6*time.Minute), rawKey)), secretScanHookSignatureStale},
		"gitlab signed, missing":  {"gitlab", signingToken, signed("msg_1", now, ""), secretScanHookSignatureMissing},
		"gitlab token":            {"gitlab", "od3-secret-token", http.Header{"X-Gitlab-Token": {"od3-secret-token"}}, ""},
		"gitlab token, wrong":     {"gitlab", "od3-secret-token", http.Header{"X-Gitlab-Token": {"od3-secret-tokem"}}, secretScanHookSignatureWrong},
		"gitlab token, missing":   {"gitlab", "od3-secret-token", http.Header{}, secretScanHookSignatureMissing},
		"bitbucket":               {"bitbucket", "bb-secret", http.Header{"X-Hub-Signature": {"sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte("bb-secret"), body))}}, ""},
		"bitbucket, wrong":        {"bitbucket", "bb-secret", http.Header{"X-Hub-Signature": {"sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte("bb-other"), body))}}, secretScanHookSignatureWrong},
		"bitbucket, github's":     {"bitbucket", "bb-secret", http.Header{"X-Hub-Signature-256": {"sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte("bb-secret"), body))}}, secretScanHookSignatureMissing},
	} {
		if got := verifySecretScanHook(tc.provider, []byte(tc.key), tc.header, body, now); got != tc.want {
			t.Fatalf("%s: verify = %q, want %q", name, got, tc.want)
		}
	}
}

// OD-3: a verified delivery's event becomes the refs to scan: GitLab push
// and tag push (a deleted branch scans nothing), Bitbucket Cloud's repo:push
// (one per new branch or tag; deletions skipped) and Data Center's
// repo:refs_changed (its http clone link; DELETE skipped); pings answer and
// other events are ignored.
func TestSecretScanHookReadsEachProvidersPushOD3(t *testing.T) {
	head := strings.Repeat("a", 40)
	feature := strings.Repeat("b", 40)
	type want struct {
		status     int
		repository string
		cloneURL   string
		refs       []secretScanHookRef
	}
	for name, tc := range map[string]struct {
		provider, eventHeader, event, body string
		want                               want
	}{
		"gitlab push": {"gitlab", "X-Gitlab-Event", "Push Hook",
			`{"object_kind":"push","ref":"refs/heads/feature","after":"` + feature + `","checkout_sha":"` + feature + `","project":{"path_with_namespace":"acme/api","git_http_url":"https://gitlab.example.test/acme/api.git"}}`,
			want{0, "acme/api", "https://gitlab.example.test/acme/api.git", []secretScanHookRef{{"refs/heads/feature", feature}}}},
		"gitlab tag push": {"gitlab", "X-Gitlab-Event", "Tag Push Hook",
			`{"object_kind":"tag_push","ref":"refs/tags/v1.0","after":"` + head + `","checkout_sha":"` + head + `","project":{"path_with_namespace":"acme/api","git_http_url":"https://gitlab.example.test/acme/api.git"}}`,
			want{0, "acme/api", "https://gitlab.example.test/acme/api.git", []secretScanHookRef{{"refs/tags/v1.0", head}}}},
		"gitlab deleted branch": {"gitlab", "X-Gitlab-Event", "Push Hook",
			`{"object_kind":"push","ref":"refs/heads/old","after":"0000000000000000000000000000000000000000","checkout_sha":null,"project":{"path_with_namespace":"acme/api","git_http_url":"https://gitlab.example.test/acme/api.git"}}`,
			want{status: http.StatusAccepted}},
		"gitlab merge request": {"gitlab", "X-Gitlab-Event", "Merge Request Hook", `{}`, want{status: http.StatusAccepted}},
		"bitbucket cloud push": {"bitbucket", "X-Event-Key", "repo:push",
			`{"push":{"changes":[{"new":{"type":"branch","name":"main","target":{"hash":"` + head + `"}}},` +
				`{"new":null,"old":{"type":"branch","name":"gone"}},` +
				`{"new":{"type":"tag","name":"v2","target":{"hash":"` + feature + `"}}}]},` +
				`"repository":{"full_name":"acme/api","links":{"html":{"href":"https://bitbucket.example.test/acme/api"}}}}`,
			want{0, "acme/api", "https://bitbucket.example.test/acme/api.git", []secretScanHookRef{{"refs/heads/main", head}, {"refs/tags/v2", feature}}}},
		"bitbucket data center push": {"bitbucket", "X-Event-Key", "repo:refs_changed",
			`{"eventKey":"repo:refs_changed","repository":{"slug":"api","project":{"key":"ACME"},"links":{"clone":[{"href":"ssh://git@bitbucket.example.test:7999/acme/api.git","name":"ssh"},{"href":"https://bitbucket.example.test/scm/acme/api.git","name":"http"}]}},` +
				`"changes":[{"ref":{"id":"refs/heads/feature","displayId":"feature","type":"BRANCH"},"fromHash":"` + head + `","toHash":"` + feature + `","type":"UPDATE"},` +
				`{"ref":{"id":"refs/heads/gone","displayId":"gone","type":"BRANCH"},"fromHash":"` + head + `","toHash":"0000000000000000000000000000000000000000","type":"DELETE"}]}`,
			want{0, "ACME/api", "https://bitbucket.example.test/scm/acme/api.git", []secretScanHookRef{{"refs/heads/feature", feature}}}},
		"bitbucket ping":     {"bitbucket", "X-Event-Key", "diagnostics:ping", `{"test":true}`, want{status: http.StatusOK}},
		"bitbucket pr":       {"bitbucket", "X-Event-Key", "pullrequest:created", `{}`, want{status: http.StatusAccepted}},
		"github push":        {"github", "X-GitHub-Event", "push", `{"ref":"refs/heads/main","after":"` + head + `","repository":{"full_name":"acme/api","clone_url":"https://github.example.test/acme/api.git"}}`, want{0, "acme/api", "https://github.example.test/acme/api.git", []secretScanHookRef{{"refs/heads/main", head}}}},
		"github deleted":     {"github", "X-GitHub-Event", "push", `{"ref":"refs/heads/main","after":"` + head + `","deleted":true,"repository":{"full_name":"acme/api"}}`, want{status: http.StatusAccepted}},
		"github ping":        {"github", "X-GitHub-Event", "ping", `{"zen":"x"}`, want{status: http.StatusOK}},
		"github other event": {"github", "X-GitHub-Event", "issues", `{}`, want{status: http.StatusAccepted}},
	} {
		h := http.Header{}
		h.Set(tc.eventHeader, tc.event)
		push, status, reply, err := secretScanHookEvent(tc.provider, h, []byte(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if status != tc.want.status || (status != 0) != (reply != nil) {
			t.Fatalf("%s: status %d reply %v, want %d", name, status, reply, tc.want.status)
		}
		if status != 0 {
			continue
		}
		if push.Repository != tc.want.repository || push.CloneURL != tc.want.cloneURL || len(push.Refs) != len(tc.want.refs) {
			t.Fatalf("%s: push = %+v, want %+v", name, push, tc.want)
		}
		for i, ref := range push.Refs {
			if ref != tc.want.refs[i] {
				t.Fatalf("%s: ref %d = %+v, want %+v", name, i, ref, tc.want.refs[i])
			}
		}
	}
	h := http.Header{}
	h.Set("X-Gitlab-Event", "Push Hook")
	if _, _, _, err := secretScanHookEvent("gitlab", h, []byte(`not json`)); err == nil {
		t.Fatal("a push that is not JSON was read")
	}
}

// OD-3: a ref or commit that reaches git's command line is a plain name or
// a hex commit ID, never something git could read as an option.
func TestRepositoryRefsCannotReadAsGitOptionsOD3(t *testing.T) {
	for _, tc := range []struct{ ref, commit string }{
		{"refs/heads/main", strings.Repeat("a", 40)}, {"feature/x", ""}, {"refs/tags/v1.2.3", "abc1234"}, {"", ""},
		{"refs/pull/12/head", strings.Repeat("F", 64)},
	} {
		if err := secretscan.ValidateRepositoryRef(tc.ref, tc.commit); err != nil {
			t.Fatalf("ValidateRepositoryRef(%q, %q) = %v", tc.ref, tc.commit, err)
		}
	}
	for _, tc := range []struct{ ref, commit string }{
		{"--upload-pack=touch /tmp/x", ""}, {"refs/heads/main", "--upload-pack=touch"}, {"refs/heads/a..b", ""},
		{"refs/heads/a b", ""}, {"main", "abc12"}, {"main", "zzzzzzz"}, {"ma\tin", ""}, {"refs/heads/x\x00", ""},
		{"refs/heads/x~1", ""}, {"refs/heads/", ""},
	} {
		if err := secretscan.ValidateRepositoryRef(tc.ref, tc.commit); err == nil {
			t.Fatalf("ValidateRepositoryRef(%q, %q) accepted", tc.ref, tc.commit)
		}
	}
}
