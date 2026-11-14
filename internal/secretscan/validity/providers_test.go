// SPDX-License-Identifier: BUSL-1.1

package validity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// Fabricated tokens in each provider's shape, built from two literals so
// secret scanners do not take the fixtures for credentials.
const (
	liveGitHub = "ghp_" + "P14L1liveGitHubToken0000000000000001"
	deadGitHub = "ghp_" + "P14L1revokedGitHubToken0000000000002"
	liveGitLab = "glpat-" + "P14L1liveGitLab00000"
	deadGitLab = "glpat-" + "P14L1revokedGitLab00"
	liveSlack  = "xoxb-" + "1414-1414-P14L1liveSlackBot"
	deadSlack  = "xoxb-" + "1414-1414-P14L1revokedSlack"
	liveEntra  = "p14" + "1Q~" + "P14L1liveEntraSecret.00000000000"
	wrongEntra = "p14" + "1Q~" + "P14L1wrongEntraSecret.0000000000"
	entraApp   = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9"
	entraOrg   = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
	saEmail    = "p14l1-ci@p14l1-project.iam.gserviceaccount.com"
)

// tokenProviders stands in for GitHub's GET /user, GitLab's GET
// /api/v4/personal_access_tokens/self and Slack's auth.test, each as its
// public API reference documents it, and records how each call carried its
// token.
type tokenProviders struct {
	mu    sync.Mutex
	calls []string
}

func (p *tokenProviders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	private := r.Header.Get("PRIVATE-TOKEN")
	carried := "bearer"
	if private != "" {
		carried = "private-token"
	}
	p.mu.Lock()
	p.calls = append(p.calls, r.Method+" "+r.URL.Path+" "+carried)
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	reply := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user" && r.Header.Get("X-GitHub-Api-Version") != "":
		if bearer == liveGitHub {
			reply(http.StatusOK, map[string]any{"login": "p14l1-ci", "id": 1414})
			return
		}
		reply(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v4/personal_access_tokens/self" && r.Header.Get("Authorization") == "":
		if private == liveGitLab {
			reply(http.StatusOK, map[string]any{"id": 7, "name": "deploy", "user_id": 42, "active": true, "revoked": false, "scopes": []string{"read_api"}})
			return
		}
		reply(http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Token was revoked. You have to re-authorize from the user."})
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth.test":
		if bearer == liveSlack {
			reply(http.StatusOK, map[string]any{"ok": true, "team": "P14L1 Ops", "team_id": "T0P14L1", "user": "deploybot", "user_id": "U0P14L1"})
			return
		}
		reply(http.StatusOK, map[string]any{"ok": false, "error": "token_revoked"})
	default:
		reply(http.StatusNotFound, map[string]string{"message": "Not Found"})
	}
}

func newTokenProviders(t *testing.T) (*tokenProviders, *httptest.Server) {
	t.Helper()
	p := &tokenProviders{}
	srv := httptest.NewTLSServer(p)
	t.Cleanup(srv.Close)
	return p, srv
}

func writeScanned(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// P14-L1: a GitHub, GitLab or Slack token a scan finds is checked against its
// own provider's identity endpoint: a live one is valid and names its user,
// a revoked one invalid, and no verdict carries the token. Two tokens on one
// line are told apart by the finding's column.
func TestTokenChecksMarkLiveTokensValidAndRevokedOnesInvalidP14L1(t *testing.T) {
	providers, srv := newTokenProviders(t)
	c := New(Config{Providers: []string{ProviderGitHub, ProviderGitLab, ProviderSlack},
		Endpoints: map[string]string{ProviderGitHub: srv.URL, ProviderGitLab: srv.URL, ProviderSlack: srv.URL},
		Allowlist: []string{srv.URL}, Client: srv.Client(),
		Rates: map[string]float64{ProviderGitHub: 100, ProviderGitLab: 100, ProviderSlack: 100}})
	root := t.TempDir()
	writeScanned(t, root, "ci.env", "GITHUB_TOKEN="+liveGitHub+"\nOLD_GITHUB_TOKEN="+deadGitHub+"\nGITLAB_TOKEN="+liveGitLab+
		"\nOLD_GITLAB_TOKEN="+deadGitLab+"\nSLACK_BOT_TOKEN="+liveSlack+"\nOLD_SLACK_BOT_TOKEN="+deadSlack+"\n")
	for _, tc := range []struct {
		rule          string
		line          int
		token, state  string
		provider, has string
	}{
		{"github-pat", 1, liveGitHub, StateValid, ProviderGitHub, "user p14l1-ci"},
		{"github-pat", 2, deadGitHub, StateInvalid, ProviderGitHub, "GitHub refused the token: Bad credentials"},
		{"gitlab-pat", 3, liveGitLab, StateValid, ProviderGitLab, `token "deploy" of user 42 (scopes read_api)`},
		{"gitlab-pat", 4, deadGitLab, StateInvalid, ProviderGitLab, "GitLab refused the token: Token was revoked"},
		{"slack-bot-token", 5, liveSlack, StateValid, ProviderSlack, "workspace P14L1 Ops (T0P14L1), user deploybot"},
		{"slack-bot-token", 6, deadSlack, StateInvalid, ProviderSlack, "Slack refused the token: token_revoked"},
	} {
		got, ok := c.CheckFinding(context.Background(), tc.rule, root, "ci.env", tc.line, 0)
		if !ok || got.State != tc.state || got.Provider != tc.provider || !strings.Contains(got.Detail, tc.has) {
			t.Fatalf("%s line %d = %+v %v; want %s %q", tc.rule, tc.line, got, ok, tc.state, tc.has)
		}
		if strings.Contains(got.Detail, tc.token) || strings.Contains(got.Detail, tc.token[len(tc.token)-12:]) {
			t.Fatal("a verdict carries the token")
		}
	}
	writeScanned(t, root, "two.env", "GITHUB_TOKENS="+deadGitHub+","+liveGitHub+"\n")
	if got, _ := c.CheckFinding(context.Background(), "github-pat", root, "two.env", 1, len("GITHUB_TOKENS="+deadGitHub+",")+1); got.State != StateValid {
		t.Fatalf("the second token's finding = %+v", got)
	}
	if got, _ := c.CheckFinding(context.Background(), "github-pat", root, "two.env", 1, len("GITHUB_TOKENS=")+1); got.State != StateInvalid {
		t.Fatalf("the first token's finding = %+v", got)
	}
	providers.mu.Lock()
	defer providers.mu.Unlock()
	want := map[string]int{"GET /user bearer": 4, "GET /api/v4/personal_access_tokens/self private-token": 2, "POST /api/auth.test bearer": 2}
	got := map[string]int{}
	for _, call := range providers.calls {
		got[call]++
	}
	if len(got) != len(want) {
		t.Fatalf("calls = %v; want %v", got, want)
	}
	for call, n := range want {
		if got[call] != n {
			t.Fatalf("calls = %v; want %v", got, want)
		}
	}
}

// P14-L1: a Microsoft Entra ID client secret is checked with the tenant and
// application labeled beside it, in an environment file or az ad sp
// create-for-rbac's output; a wrong secret is invalid, and a secret with no
// application beside it is not sent anywhere.
func TestEntraClientSecretIsCheckedWithItsTenantAndApplicationP14L1(t *testing.T) {
	entra := infratest.StartEntra(entraApp, liveEntra)
	t.Cleanup(entra.Close)
	c := New(Config{Providers: []string{ProviderAzure}, Endpoints: map[string]string{ProviderAzure: entra.URL()},
		Allowlist: []string{entra.URL()}, Client: &http.Client{Timeout: 5 * time.Second}, Rates: map[string]float64{ProviderAzure: 100}})
	root := t.TempDir()
	writeScanned(t, root, "app.env", "AZURE_TENANT_ID="+entraOrg+"\nAZURE_CLIENT_ID="+entraApp+"\nAZURE_CLIENT_SECRET="+liveEntra+"\n")
	writeScanned(t, root, "old.env", "ARM_TENANT_ID="+entraOrg+"\nARM_CLIENT_ID="+entraApp+"\nARM_CLIENT_SECRET="+wrongEntra+"\n")
	writeScanned(t, root, "sp.json", "{\n  \"appId\": \""+entraApp+"\",\n  \"displayName\": \"p14l1-ci\",\n  \"password\": \""+liveEntra+"\",\n  \"tenant\": \""+entraOrg+"\"\n}\n")
	writeScanned(t, root, "alone.txt", "the secret is "+liveEntra+"\n")
	for _, tc := range []struct {
		file       string
		line       int
		state, has string
	}{
		{"app.env", 3, StateValid, "application " + entraApp + " in tenant " + entraOrg},
		{"old.env", 3, StateInvalid, "Microsoft Entra ID refused the secret: AADSTS7000215"},
		{"sp.json", 4, StateValid, "application " + entraApp},
		{"alone.txt", 1, StateUnchecked, "no tenant and application ID beside the client secret"},
	} {
		got, ok := c.CheckFinding(context.Background(), "azure-ad-client-secret", root, tc.file, tc.line, 0)
		if !ok || got.Provider != ProviderAzure || got.State != tc.state || !strings.Contains(got.Detail, tc.has) {
			t.Fatalf("%s = %+v %v; want %s %q", tc.file, got, ok, tc.state, tc.has)
		}
		if strings.Contains(got.Detail, "Q~") {
			t.Fatal("a verdict carries the secret")
		}
	}
}

type serviceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
}

// writeServiceAccountKey writes a key file the way the console downloads one
// (the private key on line 5) whose token_uri names a host the check must
// never follow.
func writeServiceAccountKey(t *testing.T, root, name string, keyPEM []byte) {
	t.Helper()
	raw, err := json.MarshalIndent(serviceAccountKey{Type: "service_account", ProjectID: "p14l1-project", PrivateKeyID: strings.Repeat("ab", 20), // #nosec G101 -- a key file for a key generated at run time for the stand-in, not a credential (CWE-798)
		PrivateKey: string(keyPEM), ClientEmail: saEmail, ClientID: "101414", AuthURI: "https://accounts.example.test/o/oauth2/auth",
		TokenURI: "https://elsewhere.example.test/token"}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeScanned(t, root, name, string(raw)+"\n")
}

// P14-L1: a Google service-account key is checked by asking Google's token
// endpoint for a token with an assertion the key signs: the live key is
// valid, a deleted one ("Invalid JWT Signature.") invalid, and only the signed
// assertion leaves the host — never the key, and never to the file's own
// token_uri. A private key that is not a service-account key is not checked.
func TestGoogleServiceAccountKeyIsCheckedBySignatureAloneP14L1(t *testing.T) {
	google, err := infratest.StartGoogleServiceAccount(saEmail)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(google.Close)
	deleted, err := infratest.StartGoogleServiceAccount(saEmail)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deleted.Close)
	c := New(Config{Providers: []string{ProviderGCP}, Endpoints: map[string]string{ProviderGCP: google.URL()},
		Allowlist: []string{google.URL()}, Client: &http.Client{Timeout: 5 * time.Second}, Rates: map[string]float64{ProviderGCP: 100}})
	root := t.TempDir()
	livePEM, deletedPEM := google.ServiceAccountKeyPEM(), deleted.ServiceAccountKeyPEM()
	writeServiceAccountKey(t, root, "live.json", livePEM)
	writeServiceAccountKey(t, root, "deleted.json", deletedPEM)
	if got, ok := c.CheckFinding(context.Background(), "private-key", root, "live.json", 5, 0); !ok || got.Provider != ProviderGCP ||
		got.State != StateValid || got.Detail != "service account "+saEmail {
		t.Fatalf("the live key = %+v %v", got, ok)
	}
	if got, ok := c.CheckFinding(context.Background(), "private-key", root, "deleted.json", 5, 0); !ok || got.State != StateInvalid ||
		!strings.Contains(got.Detail, "Invalid JWT Signature") {
		t.Fatalf("the deleted key = %+v %v", got, ok)
	}
	writeScanned(t, root, "server.pem", string(livePEM))
	if got, ok := c.CheckFinding(context.Background(), "private-key", root, "server.pem", 1, 0); ok {
		t.Fatalf("a private key outside a service-account key file was checked: %+v", got)
	}
	forms := google.Assertions()
	if len(forms) != 2 {
		t.Fatalf("Google saw %d token requests, want 2", len(forms))
	}
	keyBody := strings.Split(string(livePEM), "\n")[1]
	for _, form := range forms {
		if strings.Contains(form, "PRIVATE") || strings.Contains(form, keyBody) || !strings.Contains(form, "assertion=") {
			t.Fatalf("a token request carried more than an assertion: %.80s", form)
		}
	}
}

// P14-L1: the new providers are opt-in — P14's configuration checks AWS
// alone, and the default allowlist declares only the public endpoints of the
// providers whose checks run — and a named provider whose endpoint is not
// declared is refused before anything is sent.
func TestNewProviderChecksAreOptInAndDeclaredP14L1(t *testing.T) {
	providers, srv := newTokenProviders(t)
	root := t.TempDir()
	writeScanned(t, root, "ci.env", "GITHUB_TOKEN="+liveGitHub+"\n")
	awsOnly := New(Config{Endpoints: map[string]string{ProviderGitHub: srv.URL}, Allowlist: []string{srv.URL}, Client: srv.Client()})
	if got, ok := awsOnly.CheckFinding(context.Background(), "github-pat", root, "ci.env", 1, 0); ok {
		t.Fatalf("a GitHub token was checked with only AWS enabled: %+v", got)
	}
	if p14 := New(Config{}); p14.Declared("https://api.github.com/user") || !p14.Declared(DefaultAWSEndpoint+"/") {
		t.Fatal("P14's default allowlist changed")
	}
	github := New(Config{Providers: []string{ProviderGitHub}})
	if !github.Declared("https://api.github.com/user") || github.Declared(DefaultAWSEndpoint+"/") || github.Declared("https://slack.com/api/auth.test") {
		t.Fatal("the default allowlist declares a provider whose checks do not run")
	}
	undeclared := New(Config{Providers: []string{ProviderGitHub}, Endpoints: map[string]string{ProviderGitHub: srv.URL}, Client: srv.Client()})
	got, ok := undeclared.CheckFinding(context.Background(), "github-pat", root, "ci.env", 1, 0)
	providers.mu.Lock()
	calls := len(providers.calls)
	providers.mu.Unlock()
	if !ok || got.State != StateUnchecked || !strings.Contains(got.Detail, "GitHub endpoint is not in the validity checks' outbound allowlist") || calls != 0 {
		t.Fatalf("an undeclared GitHub endpoint = %+v after %d calls", got, calls)
	}
	for rule, want := range map[string]string{"aws-access-token": ProviderAWS, "github-fine-grained-pat": ProviderGitHub, "github-oauth": ProviderGitHub,
		"github-app-token": ProviderGitHub, "gitlab-pat": ProviderGitLab, "slack-user-token": ProviderSlack, "azure-ad-client-secret": ProviderAzure,
		"private-key": ProviderGCP, "generic-api-key": "", "github-refresh-token": "", "slack-webhook-url": ""} {
		if ProviderForRule(rule) != want {
			t.Fatalf("rule %s is checked by %q, want %q", rule, ProviderForRule(rule), want)
		}
	}
}

// P14-L1: a check never follows a redirect, even to a declared host: the
// token stays with the endpoint it was meant for and the verdict is unknown.
func TestChecksNeverFollowARedirectP14L1(t *testing.T) {
	var mu sync.Mutex
	elsewhereCalls := 0
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elsewhereCalls++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"login": "elsewhere", "id": 1, "name": "elsewhere"})
	}))
	t.Cleanup(elsewhere.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect) // #nosec G710 -- the stand-in redirects on purpose to prove a check never follows (CWE-601)
	}))
	t.Cleanup(redirector.Close)
	c := New(Config{Providers: []string{ProviderGitHub, ProviderGitLab}, Endpoints: map[string]string{ProviderGitHub: redirector.URL, ProviderGitLab: redirector.URL},
		Allowlist: []string{redirector.URL, elsewhere.URL}, Client: redirector.Client(), Rates: map[string]float64{ProviderGitHub: 100, ProviderGitLab: 100}})
	root := t.TempDir()
	writeScanned(t, root, "ci.env", "GITHUB_TOKEN="+liveGitHub+"\nGITLAB_TOKEN="+liveGitLab+"\n")
	for line, rule := range map[int]string{1: "github-pat", 2: "gitlab-pat"} {
		if got, ok := c.CheckFinding(context.Background(), rule, root, "ci.env", line, 0); !ok || got.State != StateUnknown || !strings.Contains(got.Detail, "Temporary Redirect") {
			t.Fatalf("%s through a redirect = %+v %v", rule, got, ok)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if elsewhereCalls != 0 {
		t.Fatalf("a redirect was followed %d times", elsewhereCalls)
	}
}
