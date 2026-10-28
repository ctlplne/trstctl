// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const providerKeycloakImage = "quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"

// A222 live proof: an operator signs in to the Provider console through a
// real Keycloak with the code flow and ends with an HttpOnly session cookie;
// no token reaches a cookie the page can read. Docker and the pinned image are
// required; TRSTCTL_REQUIRE_KEYCLOAK=1 turns a skip into a failure. The lab
// realm asserts amr=mfa with a hardcoded mapper, since the lab user has no
// second factor.
func TestProviderOIDCLoginWithKeycloak(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err == nil {
		err = exec.Command(docker, "image", "inspect", providerKeycloakImage).Run() // #nosec G204 -- pinned image, local docker client (CWE-78)
	}
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_KEYCLOAK") != "" {
			t.Fatalf("TRSTCTL_REQUIRE_KEYCLOAK is set but docker or %s is unavailable: %v", providerKeycloakImage, err)
		}
		t.Skipf("the Keycloak lab needs docker and the pinned image (docker pull %s)", providerKeycloakImage)
	}
	var login *OIDCLogin
	var handler http.Handler
	var callbackCookies []*http.Cookie
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if r.URL.Path == "/provider/v1/auth/oidc/callback" {
			callbackCookies = rec.Result().Cookies()
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(srv.Close)
	callback := srv.URL + "/provider/v1/auth/oidc/callback"

	realm := fmt.Sprintf(`{"realm":"provider","enabled":true,"sslRequired":"none","groups":[{"name":"trstctl-admins"}],
	 "users":[{"username":"dana","enabled":true,"email":"dana@provider.example","emailVerified":true,"firstName":"Dana","lastName":"Ops",
	   "credentials":[{"type":"password","value":"lab-password","temporary":false}],"groups":["/trstctl-admins"]}],
	 "clients":[{"clientId":"trstctl-provider-console","enabled":true,"publicClient":false,"secret":"lab-client-secret",
	   "standardFlowEnabled":true,"directAccessGrantsEnabled":false,"redirectUris":[%q],
	   "attributes":{"pkce.code.challenge.method":"S256"},
	   "protocolMappers":[
	     {"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
	      "config":{"claim.name":"groups","full.path":"false","id.token.claim":"true","access.token.claim":"true"}},
	     {"name":"lab-amr","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper",
	      "config":{"claim.name":"amr","claim.value":"[\"mfa\"]","jsonType.label":"JSON","id.token.claim":"true","access.token.claim":"true"}}]}]}`, callback)
	importDir := filepath.Join(t.TempDir(), "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil { // #nosec G301 -- the container's keycloak user must read the import directory (CWE-276)
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(importDir, "provider-realm.json"), []byte(realm), 0o644); err != nil { // #nosec G306 -- lab realm with lab-only credentials, read by the container (CWE-276)
		t.Fatal(err)
	}
	name := fmt.Sprintf("trstctl-a222-keycloak-%d", time.Now().UnixNano())
	if out, err := exec.Command(docker, "run", "-d", "--name", name, "-p", "127.0.0.1::8080", // #nosec G204 -- pinned image, fixed arguments (CWE-78)
		"-v", importDir+":/opt/keycloak/data/import:ro", providerKeycloakImage, "start-dev", "--import-realm").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(docker, "rm", "-f", name).Run() }) // #nosec G204 -- removes the container this test started (CWE-78)
	port, err := exec.Command(docker, "port", name, "8080/tcp").Output()   // #nosec G204 -- reads this test's container port (CWE-78)
	if err != nil {
		t.Fatal(err)
	}
	base := "http://localhost:" + strings.TrimSpace(string(port))[strings.LastIndex(strings.TrimSpace(string(port)), ":")+1:]
	issuer := base + "/realms/provider"
	client := &http.Client{Timeout: 20 * time.Second}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		resp, err := client.Get(issuer + "/.well-known/openid-configuration")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command(docker, "logs", "--tail", "40", name).CombinedOutput() // #nosec G204 -- this test's container logs (CWE-78)
			t.Fatalf("Keycloak did not become ready: %v\n%s", err, logs)
		}
		time.Sleep(time.Second)
	}
	certs, err := client.Get(issuer + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal(err)
	}
	var keySet struct {
		Keys []map[string]any `json:"keys"`
	}
	raw, _ := io.ReadAll(certs.Body)
	_ = certs.Body.Close()
	if err := json.Unmarshal(raw, &keySet); err != nil {
		t.Fatal(err)
	}
	signing := keySet.Keys[:0]
	for _, key := range keySet.Keys {
		if key["use"] != "enc" {
			signing = append(signing, key)
		}
	}
	pinned, _ := json.Marshal(map[string]any{"keys": signing})
	jwks, err := crypto.ParseJWKS(pinned)
	if err != nil {
		t.Fatalf("pin Keycloak's signing keys: %v", err)
	}
	login = NewOIDCLogin(OIDCLoginConfig{
		Verifier: OIDCAuthenticatorConfig{Issuer: issuer, JWKS: jwks, RoleClaim: "groups",
			AdminValues: []string{"trstctl-admins"}, MFAClaim: "amr", MFAValues: []string{"mfa"}},
		AuthorizationEndpoint: issuer + "/protocol/openid-connect/auth", TokenEndpoint: issuer + "/protocol/openid-connect/token",
		ClientID: "trstctl-provider-console", ClientSecret: []byte("lab-client-secret"), RedirectURL: callback,
		HTTPClient: client, SessionSecret: []byte("a222-keycloak-lab-session-secret!"),
	})
	if login == nil {
		t.Fatal("the lab sign-in did not build")
	}
	handler = NewHandler(Config{License: providerLicense(t, 10), Authenticator: AnyAuthenticator{login}, OIDCLogin: login})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	page, err := browser.Get(srv.URL + "/provider/v1/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	action := regexp.MustCompile(`id="kc-form-login"[^>]*action="([^"]+)"|action="([^"]+)"[^>]*id="kc-form-login"`).FindStringSubmatch(string(body))
	if page.StatusCode != http.StatusOK || action == nil {
		t.Fatalf("Keycloak login page = %d; no login form in %.400s", page.StatusCode, body)
	}
	formURL := html.UnescapeString(action[1] + action[2])
	signedIn, err := browser.PostForm(formURL, url.Values{"username": {"dana"}, "password": {"lab-password"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = signedIn.Body.Close()
	var session *http.Cookie
	for _, c := range callbackCookies {
		if strings.Contains(c.Value, "eyJ") && c.Name != providerDevOIDCSessionCookie {
			t.Fatalf("cookie %s carries a JWT", c.Name)
		}
		if c.Name == providerDevOIDCSessionCookie {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Domain != "" {
		t.Fatalf("callback cookies = %+v; want an HttpOnly, Strict, host-only Provider session", callbackCookies)
	}
	me, err := browser.Get(srv.URL + "/provider/v1/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	who, _ := io.ReadAll(me.Body)
	_ = me.Body.Close()
	if me.StatusCode != http.StatusOK || !strings.Contains(string(who), `"role":"admin"`) || strings.Contains(string(who), "eyJ") {
		t.Fatalf("session after the Keycloak sign-in = %d %s; want the admin operator and no token", me.StatusCode, who)
	}
	t.Logf("signed in through Keycloak 26.8.1: %s", who)
}
