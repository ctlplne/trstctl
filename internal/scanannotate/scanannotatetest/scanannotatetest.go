// SPDX-License-Identifier: BUSL-1.1

// Package scanannotatetest is an in-repository stand-in for the provider
// APIs the A174 annotations write to: Slack's chat.postMessage and
// conversations.replies, Jira's issue comments, GitHub and GitLab commit
// statuses, and an OCI 1.1 registry's blob upload, manifest and referrers
// endpoints. One server answers all of them, enforces each provider's
// authentication, and records every effect so a test can prove exactly what
// was written and that no secret was.
package scanannotatetest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// Status is one commit status written to GitHub or GitLab.
type Status struct {
	State       string
	Context     string
	Description string
}

// Stand is the stand-in.
type Stand struct {
	srv          *httptest.Server
	token        string
	jiraUser     string
	mu           sync.Mutex
	slackThreads map[string][]string            // channel + "/" + ts → reply texts
	jiraIssues   map[string][]string            // key → comment bodies (raw JSON)
	statuses     map[string][]Status            // "github:" or "gitlab:" + repo + "@" + sha
	commits      map[string]bool                // same keys: commits that exist
	images       map[string]imageManifest       // repo + "@" + digest
	blobs        map[string]bool                // repo + "@" + digest
	referrers    map[string][]map[string]string // repo + "@" + subject digest → annotations
	// referrerRefs is the manifest digest of each referrer, in the same order
	// (A174-L1: a resolved finding's referrer is deleted).
	referrerRefs map[string][]string
	uploads      int
	unauthorized int
	slackLimited int
	// A174-L4: slackReadRefusal makes conversations.replies answer ok:false
	// with it (a token without the history scope answers missing_scope);
	// slackLoseAnswers makes the next n chat.postMessage calls post the
	// reply and then drop the connection without answering.
	slackReadRefusal string
	slackLoseAnswers int
	// A174-L2: noReferrersAPI makes the registry answer manifest puts without
	// OCI-Subject, as a registry without the referrers API does; tokenUser,
	// when set, puts the registry behind a token server that takes tokenUser
	// and the token as basic credentials and issues the bearer the registry
	// accepts.
	noReferrersAPI bool
	tokenUser      string
	issued         map[string]bool
	tokenRequests  int
}

// WithoutReferrersAPI makes the registry one without the OCI referrers API:
// a client keeps the referrers tag schema's index itself (A174-L2).
func (s *Stand) WithoutReferrersAPI() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noReferrersAPI = true
}

// WithTokenServer puts the registry behind a token server (A174-L2): a
// registry request without an issued bearer is answered 401 with a Bearer
// challenge, and GET /token with user and the stand-in's token as basic
// credentials issues one.
func (s *Stand) WithTokenServer(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenUser = user
	s.issued = map[string]bool{}
}

// TokenRequests counts the bearer tokens the token server issued.
func (s *Stand) TokenRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenRequests
}

// ReferrersIndex lists the digests the referrers tag schema's index for a
// subject names (A174-L2).
func (s *Stand) ReferrersIndex(repo, subject string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.images[repo+"@"+strings.Replace(subject, ":", "-", 1)]
	if !ok {
		return nil
	}
	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	_ = json.Unmarshal(m.body, &index)
	out := []string{}
	for _, d := range index.Manifests {
		out = append(out, d.Digest)
	}
	return out
}

type imageManifest struct {
	mediaType string
	body      []byte
}

// New starts a stand-in that accepts token (and, for Jira basic
// authentication, jiraUser with token).
func New(token, jiraUser string) *Stand {
	s := &Stand{token: token, jiraUser: jiraUser, slackThreads: map[string][]string{}, jiraIssues: map[string][]string{},
		statuses: map[string][]Status{}, commits: map[string]bool{}, images: map[string]imageManifest{}, blobs: map[string]bool{},
		referrers: map[string][]map[string]string{}, referrerRefs: map[string][]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the stand-in's base URL.
func (s *Stand) URL() string { return s.srv.URL }

// Client reaches the stand-in.
func (s *Stand) Client() *http.Client { return s.srv.Client() }

// Close stops the stand-in.
func (s *Stand) Close() { s.srv.Close() }

// SeedSlackMessage makes a channel's message exist.
func (s *Stand) SeedSlackMessage(channel, ts string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slackThreads[channel+"/"+ts] = nil
}

// SeedJiraIssue makes an issue exist.
func (s *Stand) SeedJiraIssue(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jiraIssues[key] = nil
}

// SeedCommit makes a commit exist at "github" or "gitlab".
func (s *Stand) SeedCommit(host, repo, sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits[host+":"+repo+"@"+sha] = true
}

// SeedImage stores an image manifest and returns its digest.
func (s *Stand) SeedImage(repo string, manifest []byte) string {
	digest := "sha256:" + crypto.SHA256Hex(manifest)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images[repo+"@"+digest] = imageManifest{mediaType: "application/vnd.oci.image.manifest.v1+json", body: manifest}
	return digest
}

// SlackRefuseReads makes conversations.replies answer ok:false with reason,
// as Slack does for a token without the history scope ("missing_scope");
// "" reads again (A174-L4).
func (s *Stand) SlackRefuseReads(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slackReadRefusal = reason
}

// SlackLoseNextAnswers makes the next n chat.postMessage calls post their
// reply and then drop the connection without answering (A174-L4).
func (s *Stand) SlackLoseNextAnswers(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slackLoseAnswers = n
}

// SlackLimitNext makes the next n chat.postMessage calls answer ratelimited.
func (s *Stand) SlackLimitNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slackLimited = n
}

// SlackReplies returns the replies posted in a thread.
func (s *Stand) SlackReplies(channel, ts string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, text := range s.slackThreads[channel+"/"+ts] {
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}

// JiraComments returns the raw comment bodies on an issue.
func (s *Stand) JiraComments(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.jiraIssues[key]...)
}

// Statuses returns the commit statuses written at "github" or "gitlab".
func (s *Stand) Statuses(host, repo, sha string) []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Status(nil), s.statuses[host+":"+repo+"@"+sha]...)
}

// Referrers returns the annotations of each referrer stored on an image.
func (s *Stand) Referrers(repo, digest string) []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.referrers[repo+"@"+digest]...)
}

// Unauthorized counts refused requests.
func (s *Stand) Unauthorized() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unauthorized
}

func (s *Stand) authorized(r *http.Request) bool {
	if r.Header.Get("Authorization") == "Bearer "+s.token || r.Header.Get("PRIVATE-TOKEN") == s.token {
		return true
	}
	if s.jiraUser != "" {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.jiraUser+":"+s.token))
		return r.Header.Get("Authorization") == basic
	}
	return false
}

func (s *Stand) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenUser != "" && r.URL.Path == "/token" {
		s.issueToken(w, r)
		return
	}
	if s.tokenUser != "" && strings.HasPrefix(r.URL.EscapedPath(), "/v2/") {
		if !s.issued[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			repo := strings.TrimPrefix(r.URL.EscapedPath(), "/v2/")
			for _, marker := range []string{"/manifests/", "/blobs/"} {
				if i := strings.Index(repo, marker); i >= 0 {
					repo = repo[:i]
				}
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+s.srv.URL+`/token",service="stand-in-registry",scope="repository:`+repo+`:pull,push"`)
			s.unauthorized++
			writeJSON(w, http.StatusUnauthorized, map[string]any{"errors": []map[string]string{{"code": "UNAUTHORIZED"}}})
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.registry(w, r, strings.TrimPrefix(r.URL.EscapedPath(), "/v2/"), body)
		return
	}
	if !s.authorized(r) {
		s.unauthorized++
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	path := r.URL.EscapedPath()
	switch {
	case strings.HasPrefix(path, "/api/chat.postMessage") || strings.HasPrefix(path, "/api/conversations.replies") ||
		strings.HasPrefix(path, "/api/chat.delete"):
		s.slack(w, r, path, body)
	case strings.HasPrefix(path, "/rest/api/3/issue/"):
		s.jira(w, r, path, body)
	case strings.HasPrefix(path, "/repos/") && strings.Contains(path, "/statuses/"):
		s.status(w, "github", strings.TrimPrefix(path, "/repos/"), body, "context", "failure")
	case strings.HasPrefix(path, "/api/v4/projects/") && strings.Contains(path, "/statuses/"):
		s.status(w, "gitlab", strings.TrimPrefix(path, "/api/v4/projects/"), body, "name", "failed")
	case strings.HasPrefix(path, "/v2/"):
		s.registry(w, r, strings.TrimPrefix(path, "/v2/"), body)
	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

// issueToken is the token server: basic credentials of tokenUser and the
// stand-in's token earn a bearer for the requested scope.
func (s *Stand) issueToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != s.tokenUser || pass != s.token || r.URL.Query().Get("service") != "stand-in-registry" || r.URL.Query().Get("scope") == "" {
		s.unauthorized++
		writeJSON(w, http.StatusUnauthorized, map[string]any{"details": "bad credentials"})
		return
	}
	s.tokenRequests++
	token := "issued-" + strconv.Itoa(s.tokenRequests)
	s.issued[token] = true
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_in": 300})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Stand) slack(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	if strings.HasPrefix(path, "/api/conversations.replies") {
		if s.slackReadRefusal != "" {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": s.slackReadRefusal})
			return
		}
		key := r.URL.Query().Get("channel") + "/" + r.URL.Query().Get("ts")
		replies, ok := s.slackThreads[key]
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "thread_not_found"})
			return
		}
		messages := []map[string]string{{"ts": r.URL.Query().Get("ts"), "text": "original message"}}
		for i, text := range replies {
			if text == "" {
				continue // deleted
			}
			messages = append(messages, map[string]string{"ts": r.URL.Query().Get("ts") + "-reply-" + strconv.Itoa(i+1), "text": text})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "messages": messages})
		return
	}
	if strings.HasPrefix(path, "/api/chat.delete") {
		// A174-L1: a reply is deleted by its ts ("<thread>-reply-<n>").
		var req struct {
			Channel string `json:"channel"`
			TS      string `json:"ts"`
		}
		_ = json.Unmarshal(body, &req)
		thread, n, found := strings.Cut(req.TS, "-reply-")
		index, err := strconv.Atoi(n)
		replies := s.slackThreads[req.Channel+"/"+thread]
		if !found || err != nil || index < 1 || index > len(replies) || replies[index-1] == "" {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "message_not_found"})
			return
		}
		replies[index-1] = ""
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": req.Channel, "ts": req.TS})
		return
	}
	if s.slackLimited > 0 {
		s.slackLimited--
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "ratelimited"})
		return
	}
	var req struct {
		Channel  string `json:"channel"`
		ThreadTS string `json:"thread_ts"`
		Text     string `json:"text"`
	}
	_ = json.Unmarshal(body, &req)
	key := req.Channel + "/" + req.ThreadTS
	if _, ok := s.slackThreads[key]; !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "thread_not_found"})
		return
	}
	s.slackThreads[key] = append(s.slackThreads[key], req.Text)
	if s.slackLoseAnswers > 0 {
		s.slackLoseAnswers--
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": req.Channel, "ts": req.ThreadTS + "-reply-" + strconv.Itoa(len(s.slackThreads[key]))})
}

func (s *Stand) jira(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	rest := strings.TrimPrefix(path, "/rest/api/3/issue/")
	key, tail, _ := strings.Cut(rest, "/")
	comments, ok := s.jiraIssues[key]
	if id, editing := strings.CutPrefix(tail, "comment/"); ok && editing && r.Method == http.MethodPut {
		// A174-L1: a comment is edited in place by its id.
		index, err := strconv.Atoi(id)
		var req struct {
			Body json.RawMessage `json:"body"`
		}
		if err != nil || index < 10000 || index-10000 >= len(comments) || json.Unmarshal(body, &req) != nil || len(req.Body) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{"errorMessages": []string{"Can not find a comment for the id."}})
			return
		}
		comments[index-10000] = string(req.Body)
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
		return
	}
	if !ok || tail != "comment" {
		writeJSON(w, http.StatusNotFound, map[string]any{"errorMessages": []string{"Issue does not exist or you do not have permission to see it."}})
		return
	}
	if r.Method == http.MethodGet {
		list := make([]json.RawMessage, 0, len(comments))
		for i, c := range comments {
			list = append(list, json.RawMessage(`{"id":"`+strconv.Itoa(10000+i)+`","body":`+c+`}`))
		}
		writeJSON(w, http.StatusOK, map[string]any{"comments": list, "total": len(list)})
		return
	}
	var req struct {
		Body json.RawMessage `json:"body"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errorMessages": []string{"Comment body can not be empty!"}})
		return
	}
	s.jiraIssues[key] = append(comments, string(req.Body))
	writeJSON(w, http.StatusCreated, map[string]any{"id": strconv.Itoa(10000 + len(comments))})
}

func (s *Stand) status(w http.ResponseWriter, host, rest string, body []byte, nameField, failedState string) {
	i := strings.LastIndex(rest, "/statuses/")
	repo, sha := strings.ReplaceAll(rest[:i], "%2F", "/"), rest[i+len("/statuses/"):]
	key := host + ":" + repo + "@" + sha
	if !s.commits[key] {
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "No commit found for SHA: " + sha})
		return
	}
	var req map[string]string
	_ = json.Unmarshal(body, &req)
	next := Status{State: req["state"], Context: req[nameField], Description: req["description"]}
	if next.State != failedState && next.State != "success" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"message": "unexpected state " + next.State})
		return
	}
	if host == "gitlab" {
		for _, existing := range s.statuses[key] {
			if existing.Context == next.Context && existing.State == next.State {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": "Cannot transition status via :drop from :failed"})
				return
			}
		}
	}
	s.statuses[key] = append(s.statuses[key], next)
	writeJSON(w, http.StatusCreated, map[string]any{"id": len(s.statuses[key]), "state": next.State})
}

func (s *Stand) registry(w http.ResponseWriter, r *http.Request, rest string, body []byte) {
	switch {
	case strings.Contains(rest, "/manifests/"):
		i := strings.LastIndex(rest, "/manifests/")
		repo, ref := rest[:i], rest[i+len("/manifests/"):]
		if r.Method == http.MethodHead || r.Method == http.MethodGet {
			m, ok := s.images[repo+"@"+ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", m.mediaType)
			w.Header().Set("Content-Length", strconv.Itoa(len(m.body)))
			w.Header().Set("Docker-Content-Digest", ref)
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(m.body)
			}
			return
		}
		if r.Method == http.MethodDelete {
			// A174-L1: deleting a referrer manifest removes it from its subject.
			if _, ok := s.images[repo+"@"+ref]; !ok {
				writeJSON(w, http.StatusNotFound, map[string]any{"errors": []map[string]string{{"code": "MANIFEST_UNKNOWN"}}})
				return
			}
			delete(s.images, repo+"@"+ref)
			for subject, refs := range s.referrerRefs {
				for i, candidate := range refs {
					if candidate == ref && strings.HasPrefix(subject, repo+"@") {
						s.referrerRefs[subject] = append(refs[:i:i], refs[i+1:]...)
						s.referrers[subject] = append(s.referrers[subject][:i:i], s.referrers[subject][i+1:]...)
						break
					}
				}
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method == http.MethodPut && !strings.HasPrefix(ref, "sha256:") {
			// A tag: the referrers tag schema's index (A174-L2).
			s.images[repo+"@"+ref] = imageManifest{mediaType: r.Header.Get("Content-Type"), body: body}
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method != http.MethodPut || ref != "sha256:"+crypto.SHA256Hex(body) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"code": "DIGEST_INVALID"}}})
			return
		}
		var manifest struct {
			Config  struct{ Digest string } `json:"config"`
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
			Annotations map[string]string `json:"annotations"`
		}
		if json.Unmarshal(body, &manifest) != nil || !s.blobs[repo+"@"+manifest.Config.Digest] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"code": "MANIFEST_BLOB_UNKNOWN"}}})
			return
		}
		if _, exists := s.images[repo+"@"+ref]; !exists && manifest.Subject != nil {
			s.referrers[repo+"@"+manifest.Subject.Digest] = append(s.referrers[repo+"@"+manifest.Subject.Digest], manifest.Annotations)
			s.referrerRefs[repo+"@"+manifest.Subject.Digest] = append(s.referrerRefs[repo+"@"+manifest.Subject.Digest], ref)
		}
		s.images[repo+"@"+ref] = imageManifest{mediaType: "application/vnd.oci.image.manifest.v1+json", body: body}
		w.Header().Set("Docker-Content-Digest", ref)
		if manifest.Subject != nil && !s.noReferrersAPI {
			// A registry with the referrers API names the subject (OCI 1.1).
			w.Header().Set("OCI-Subject", manifest.Subject.Digest)
		}
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(rest, "/blobs/uploads/"):
		repo := rest[:strings.Index(rest, "/blobs/uploads/")]
		if r.Method == http.MethodPost {
			s.uploads++
			w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/session-"+strconv.Itoa(s.uploads))
			w.WriteHeader(http.StatusAccepted)
			return
		}
		digest := r.URL.Query().Get("digest")
		if r.Method != http.MethodPut || digest != "sha256:"+crypto.SHA256Hex(body) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"code": "DIGEST_INVALID"}}})
			return
		}
		s.blobs[repo+"@"+digest] = true
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(rest, "/blobs/"):
		i := strings.LastIndex(rest, "/blobs/")
		if s.blobs[rest[:i]+"@"+rest[i+len("/blobs/"):]] {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
