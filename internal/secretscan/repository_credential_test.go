// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/cgi" // #nosec G504 -- test-only stand-in host: serves the local git-http-backend; the toolchain is far past the CVE-2016-5386 fix (CWE-284)
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// gitStandIn is a private git host: smart HTTP through the local git's own
// http-backend, behind Basic authentication, recording what each request
// carried.
type gitStandIn struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func (g *gitStandIn) record(r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, r.URL.Path+" auth="+r.Header.Get("Authorization")+" leak="+r.Header.Get("X-Leak"))
}

func (g *gitStandIn) requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

func newGitStandIn(t *testing.T, root, user, token string, redirectTo string) *gitStandIn {
	t.Helper()
	exec, err := exec.Command("git", "--exec-path").Output() // #nosec G204 -- the local git (CWE-78)
	if err != nil {
		t.Skipf("git is not available: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(exec)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is not available: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+token))
	g := &gitStandIn{}
	cgiHandler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.record(r)
		if redirectTo != "" && strings.HasPrefix(r.URL.Path, "/moved.git") {
			http.Redirect(w, r, redirectTo+strings.TrimPrefix(r.URL.Path, "/moved.git")+"?"+r.URL.RawQuery, http.StatusFound) // #nosec G710 -- the test's own redirect to its second stand-in host; the clone must not carry the credential there (CWE-601)
			return
		}
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// OD-1: a private repository clones with its credential_ref's token over
// https; without it, or with the wrong one, it does not. The token reaches
// the host as an Authorization header on every request, and nowhere else: not
// the clone URL, the checkout's configuration or an error, not another origin
// a redirect points at, and the inherited environment cannot add headers. A
// credential for a non-https clone URL is refused before any request.
func TestPrivateRepositoryClonesWithItsCredentialOD1(t *testing.T) {
	ctx := context.Background()
	work := t.TempDir()
	repo := filepath.Join(work, "work")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) // #nosec G204 -- the local git over the test's own repository (CWE-78)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+work)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	run(repo, "init", "-q", "-b", "main")
	run(repo, "config", "user.email", "od1@example.test")
	run(repo, "config", "user.name", "od1")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("private payments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(repo, "add", "README.md")
	run(repo, "commit", "-q", "-m", "init")
	hosted := filepath.Join(work, "hosted")
	if err := os.MkdirAll(hosted, 0o700); err != nil {
		t.Fatal(err)
	}
	run(work, "clone", "-q", "--bare", repo, filepath.Join(hosted, "payments.git"))

	const user, token = "x-access-token", "od1-stand-in-repository-token" // #nosec G101 -- fabricated fixture token for the stand-in host (CWE-798)
	other := newGitStandIn(t, hosted, user, token, "")
	host := newGitStandIn(t, hosted, user, token, other.srv.URL+"/payments.git")
	ca := filepath.Join(work, "ca.pem")
	var bundle []byte
	for _, srv := range []*httptest.Server{host.srv, other.srv} {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})...)
	}
	if err := os.WriteFile(ca, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("HOME", work)
	// What the inherited environment tries to add never reaches git.
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.extraHeader")
	t.Setenv("GIT_CONFIG_VALUE_0", "X-Leak: inherited")

	cfg := RepositoryScanConfig{Provider: "github", Repository: "acme/payments", CloneURL: host.srv.URL + "/payments.git"}
	if _, err := PrepareRepositoryTarget(ctx, cfg); err == nil {
		t.Fatal("a private repository cloned without its credential")
	}
	_, err := PrepareRepositoryTargetWithCredential(ctx, cfg, &RepositoryCredential{Username: user, Secret: []byte("not-the-token")})
	if err == nil {
		t.Fatal("a private repository cloned with the wrong token")
	}
	if strings.Contains(err.Error(), "not-the-token") {
		t.Fatalf("the clone error carries the token: %v", err)
	}

	target, err := PrepareRepositoryTargetWithCredential(ctx, cfg, &RepositoryCredential{Username: DefaultRepositoryUsername("github"), Secret: []byte(token)})
	if err != nil {
		t.Fatalf("clone with the credential: %v", err)
	}
	defer target.Cleanup()
	if body, err := os.ReadFile(filepath.Join(target.Path, "README.md")); err != nil || string(body) != "private payments\n" { // #nosec G304 -- the test's own clone (CWE-22)
		t.Fatalf("the clone has no README: %q %v", body, err)
	}
	gitConfig, err := os.ReadFile(filepath.Join(target.Path, ".git", "config")) // #nosec G304 -- the test's own clone (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gitConfig), token) || strings.Contains(strings.ToLower(string(gitConfig)), "extraheader") ||
		strings.Contains(string(gitConfig), base64.StdEncoding.EncodeToString([]byte(user+":"+token))) {
		t.Fatalf("the checkout's configuration keeps the credential:\n%s", gitConfig)
	}
	authorized := 0
	for _, r := range host.requests() {
		if strings.Contains(r, "leak=inherited") {
			t.Fatalf("the inherited environment added a header: %s", r)
		}
		if strings.Contains(r, "auth=Basic ") {
			authorized++
		}
	}
	if authorized == 0 {
		t.Fatalf("no request carried the credential: %v", host.requests())
	}

	// A redirect to another origin gets no credential.
	moved := cfg
	moved.CloneURL = host.srv.URL + "/moved.git"
	if _, err := PrepareRepositoryTargetWithCredential(ctx, moved, &RepositoryCredential{Username: user, Secret: []byte(token)}); err == nil {
		t.Fatal("a clone redirected to another origin succeeded")
	}
	otherRequests := other.requests()
	if len(otherRequests) == 0 {
		t.Fatal("the redirect was not followed, so the test proves nothing")
	}
	for _, r := range otherRequests {
		if strings.Contains(r, "auth=Basic") {
			t.Fatalf("the credential followed a redirect to another origin: %s", r)
		}
	}

	insecure := cfg
	insecure.CloneURL = "http://127.0.0.1:1/payments.git"
	if _, err := PrepareRepositoryTargetWithCredential(ctx, insecure, &RepositoryCredential{Username: user, Secret: []byte(token)}); !errors.Is(err, ErrRepositoryCredentialNeedsHTTPS) {
		t.Fatalf("a credential for an http clone URL: %v, want ErrRepositoryCredentialNeedsHTTPS", err)
	}
}

// OD-1: the user a token clones as, when the source names none, is each
// provider's documented token user.
func TestDefaultRepositoryUsernamesOD1(t *testing.T) {
	for provider, want := range map[string]string{"github": "x-access-token", " GitLab ": "oauth2", "bitbucket": "x-token-auth", "self-hosted": "git"} {
		if got := DefaultRepositoryUsername(provider); got != want {
			t.Fatalf("DefaultRepositoryUsername(%q) = %q, want %q", provider, got, want)
		}
	}
}
