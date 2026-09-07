// SPDX-License-Identifier: MPL-2.0

package localoidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testClientID      = "trstctl-local-oidc-test"
	testRedirectURI   = "https://localhost:8443/auth/callback"
	testTenant        = "11111111-1111-4111-8111-111111111111"
	testPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestLocalEvaluationOIDCUsesStableSeparatedKeysAndSingleUsePKCECodes(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the local evaluation OIDC contract")
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	publicDir := filepath.Join(t.TempDir(), "public")
	keyEnv := append(os.Environ(),
		"OIDC_PRIVATE_KEY_DIR="+privateDir,
		"OIDC_JWKS_DIR="+publicDir,
		"OIDC_KEY_ID=trstctl-local-oidc-test-key",
	)
	runNode(t, node, keyEnv, "oidc-keygen.mjs")
	privateBefore := readFile(t, filepath.Join(privateDir, "idp-private.pem"))
	publicBefore := readFile(t, filepath.Join(publicDir, "jwks.json"))
	runNode(t, node, keyEnv, "oidc-keygen.mjs")
	if !bytes.Equal(privateBefore, readFile(t, filepath.Join(privateDir, "idp-private.pem"))) ||
		!bytes.Equal(publicBefore, readFile(t, filepath.Join(publicDir, "jwks.json"))) {
		t.Fatal("local OIDC key generator rotated a valid persisted pair on restart")
	}
	if mode := fileMode(t, filepath.Join(privateDir, "idp-private.pem")); mode != 0o600 {
		t.Fatalf("local OIDC private key mode = %04o, want 0600", mode)
	}
	if _, err := os.Stat(filepath.Join(publicDir, "idp-private.pem")); !os.IsNotExist(err) {
		t.Fatalf("public JWKS directory exposes private key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local OIDC port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
	serverEnv := append(os.Environ(),
		"OIDC_HOST=127.0.0.1",
		fmt.Sprintf("OIDC_PORT=%d", port),
		"OIDC_ISSUER="+issuer,
		"OIDC_CLIENT_ID="+testClientID,
		"OIDC_REDIRECT_URI="+testRedirectURI,
		"OIDC_TENANT="+testTenant,
		"OIDC_SUBJECT=eval-admin",
		"OIDC_EMAIL=eval-admin@trstctl.local",
		"OIDC_NAME=Evaluation Admin",
		"OIDC_KEY_ID=trstctl-local-oidc-test-key",
		"OIDC_PRIVATE_KEY="+filepath.Join(privateDir, "idp-private.pem"),
		"OIDC_JWKS="+filepath.Join(publicDir, "jwks.json"),
	)
	var serverOutput bytes.Buffer
	cmd := exec.Command(node, "oidc-server.mjs") // #nosec G204 -- node path comes from LookPath and the script is a checked-in test target (CWE-78)
	cmd.Env = serverEnv
	cmd.Stdout = &serverOutput
	cmd.Stderr = &serverOutput
	if err := cmd.Start(); err != nil {
		t.Fatalf("start local OIDC server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	waitForHealth(t, client, issuer, &serverOutput)

	bad := authorize(t, client, issuer, "https://attacker.invalid/callback")
	if bad.StatusCode != http.StatusBadRequest || bad.Header.Get("Location") != "" {
		body := readBody(bad)
		t.Fatalf("untrusted redirect response = %d location=%q body=%s", bad.StatusCode, bad.Header.Get("Location"), body)
	}
	_ = bad.Body.Close()

	code := authorizationCode(t, client, issuer)
	if len(code) != 43 || strings.Contains(code, "eval-admin") || strings.Contains(code, testTenant) {
		t.Fatalf("authorization code is not an opaque 256-bit value: %q", code)
	}
	token := exchangeCode(t, client, issuer, code, testPKCEVerifier)
	if token.StatusCode != http.StatusOK {
		body := readBody(token)
		t.Fatalf("valid PKCE exchange = %d body=%s", token.StatusCode, body)
	}
	var tokenBody struct {
		IDToken string `json:"id_token"`
	}
	decodeJSON(t, token.Body, &tokenBody)
	_ = token.Body.Close()
	claims := jwtClaims(t, tokenBody.IDToken)
	for key, want := range map[string]string{
		"iss":    issuer,
		"aud":    testClientID,
		"sub":    "eval-admin",
		"email":  "eval-admin@trstctl.local",
		"tenant": testTenant,
		"nonce":  "nonce-1",
	} {
		if got, _ := claims[key].(string); got != want {
			t.Errorf("ID token claim %s = %q, want %q", key, got, want)
		}
	}

	replay := exchangeCode(t, client, issuer, code, testPKCEVerifier)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed authorization code = %d, want 400", replay.StatusCode)
	}
	_ = replay.Body.Close()

	wrongVerifierCode := authorizationCode(t, client, issuer)
	wrong := exchangeCode(t, client, issuer, wrongVerifierCode, strings.Repeat("x", 43))
	if wrong.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong PKCE verifier = %d, want 400", wrong.StatusCode)
	}
	_ = wrong.Body.Close()
	afterWrong := exchangeCode(t, client, issuer, wrongVerifierCode, testPKCEVerifier)
	if afterWrong.StatusCode != http.StatusBadRequest {
		t.Fatalf("code reused after wrong verifier = %d, want 400", afterWrong.StatusCode)
	}
	_ = afterWrong.Body.Close()
}

func runNode(t *testing.T, node string, env []string, script string) {
	t.Helper()
	cmd := exec.Command(node, script) // #nosec G204 -- arguments are fixed checked-in scripts (CWE-78)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node %s: %v\n%s", script, err, out)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- paths are exact children of t.TempDir (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func waitForHealth(t *testing.T, client *http.Client, issuer string, output *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(issuer + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("local OIDC server did not become healthy: %s", output.String())
}

func authorize(t *testing.T, client *http.Client, issuer, redirectURI string) *http.Response {
	t.Helper()
	query := url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {"state-1"},
		"nonce":                 {"nonce-1"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := client.Get(issuer + "/authorize?" + query.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return resp
}

func authorizationCode(t *testing.T, client *http.Client, issuer string) string {
	t.Helper()
	resp := authorize(t, client, issuer, testRedirectURI)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d body=%s", resp.StatusCode, readBody(resp))
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	if location.Scheme+"://"+location.Host+location.Path != testRedirectURI || location.Query().Get("state") != "state-1" {
		t.Fatalf("authorize redirect = %s, want exact callback and state", location)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorize redirect has no code")
	}
	return code
}

func exchangeCode(t *testing.T, client *http.Client, issuer, code, verifier string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"code":          {code},
		"code_verifier": {verifier},
	}
	resp, err := client.Post(issuer+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	return resp
}

func jwtClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("ID token is not a signed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	return claims
}

func decodeJSON(t *testing.T, r io.Reader, target any) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// The provider-operator sign-in is opt-in and mints a bearer with the role and
// MFA claims a licensed provider plane pins; its form nonce is single-use, and
// a server without a registered provider client does not expose the path.
func TestLocalEvaluationOIDCMintsProviderOperatorTokensOnlyWhenRegistered(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the local evaluation OIDC contract")
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	publicDir := filepath.Join(t.TempDir(), "public")
	keyEnv := append(os.Environ(),
		"OIDC_PRIVATE_KEY_DIR="+privateDir,
		"OIDC_JWKS_DIR="+publicDir,
		"OIDC_KEY_ID=trstctl-local-oidc-test-key",
	)
	runNode(t, node, keyEnv, "oidc-keygen.mjs")

	start := func(t *testing.T, providerClient string) (string, *http.Client) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve local OIDC port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
		serverEnv := append(os.Environ(),
			"OIDC_HOST=127.0.0.1",
			fmt.Sprintf("OIDC_PORT=%d", port),
			"OIDC_ISSUER="+issuer,
			"OIDC_CLIENT_ID="+testClientID,
			"OIDC_REDIRECT_URI="+testRedirectURI,
			"OIDC_KEY_ID=trstctl-local-oidc-test-key",
			"OIDC_PRIVATE_KEY="+filepath.Join(privateDir, "idp-private.pem"),
			"OIDC_JWKS="+filepath.Join(publicDir, "jwks.json"),
			"OIDC_PROVIDER_SUBJECT=op-1",
			"OIDC_PROVIDER_EMAIL=op-1@provider.test",
			"OIDC_PROVIDER_ROLES=provider-admin",
			"OIDC_PROVIDER_MFA=mfa",
		)
		if providerClient != "" {
			serverEnv = append(serverEnv, "OIDC_PROVIDER_CLIENT_ID="+providerClient)
		}
		var serverOutput bytes.Buffer
		cmd := exec.Command(node, "oidc-server.mjs") // #nosec G204 -- node path comes from LookPath and the script is a checked-in test target (CWE-78)
		cmd.Env = serverEnv
		cmd.Stdout = &serverOutput
		cmd.Stderr = &serverOutput
		if err := cmd.Start(); err != nil {
			t.Fatalf("start local OIDC server: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		waitForHealth(t, client, issuer, &serverOutput)
		return issuer, client
	}

	unregistered, client := start(t, "")
	resp, err := client.Get(unregistered + "/provider/sign-in")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("provider sign-in without a registered provider client = %d, want 404", resp.StatusCode)
	}

	issuer, client := start(t, "trstctl-provider-console")
	page, err := client.Get(issuer + "/provider/sign-in")
	if err != nil {
		t.Fatal(err)
	}
	pageBody := readBody(page)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(pageBody, "op-1@provider.test") || !strings.Contains(pageBody, "provider-admin") {
		t.Fatalf("provider sign-in page = %d body=%s", page.StatusCode, pageBody)
	}
	marker := `name="nonce" value="`
	i := strings.Index(pageBody, marker)
	if i < 0 {
		t.Fatalf("sign-in page carries no form nonce: %s", pageBody)
	}
	nonce := pageBody[i+len(marker):]
	nonce = nonce[:strings.Index(nonce, `"`)]

	mint := func(nonce string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, issuer+"/provider/token", strings.NewReader(url.Values{"nonce": {nonce}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	minted := mint(nonce)
	if minted.StatusCode != http.StatusOK {
		body := readBody(minted)
		t.Fatalf("provider token = %d body=%s", minted.StatusCode, body)
	}
	var tokenBody struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	decodeJSON(t, minted.Body, &tokenBody)
	_ = minted.Body.Close()
	if tokenBody.TokenType != "Bearer" || tokenBody.AccessToken == "" {
		t.Fatalf("provider token body = %+v", tokenBody)
	}
	claims := jwtClaims(t, tokenBody.AccessToken)
	for key, want := range map[string]string{"iss": issuer, "aud": "trstctl-provider-console", "sub": "op-1", "email": "op-1@provider.test"} {
		if got, _ := claims[key].(string); got != want {
			t.Errorf("operator token claim %s = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]string{"roles": "provider-admin", "amr": "mfa"} {
		list, _ := claims[key].([]any)
		if len(list) != 1 || list[0] != want {
			t.Errorf("operator token claim %s = %v, want [%s]", key, claims[key], want)
		}
	}
	if _, tenantScoped := claims["tenant"]; tenantScoped {
		t.Error("operator token must not carry the tenant login claim")
	}

	replay := mint(nonce)
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed sign-in nonce = %d, want 400", replay.StatusCode)
	}
}
