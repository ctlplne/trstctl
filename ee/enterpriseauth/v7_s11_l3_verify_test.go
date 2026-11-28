// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

// CR-022 regression: a directory account has one subject even when the LDAP
// server accepts several case spellings of its bind DN. The test uses the
// package's disposable OpenLDAP fixture.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type v7LDAPServed struct {
	t       *testing.T
	baseURL string
	admin   string
}

func v7StartLDAPServed(t *testing.T, ldapURL, tenantID string, mode config.LDAP) (*v7LDAPServed, *store.Store) {
	t.Helper()
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)
	bindPasswordFile := filepath.Join(t.TempDir(), "ldap-bind.secret")
	if err := os.WriteFile(bindPasswordFile, []byte("admin-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mode
	cfg.Enabled, cfg.URL = true, ldapURL
	cfg.BindDN, cfg.BindPasswordFile = "cn=admin,dc=example,dc=org", bindPasswordFile
	cfg.GroupSearchBaseDN, cfg.GroupFilter, cfg.GroupNameAttribute = "ou=groups,dc=example,dc=org", "(member={user_dn})", "cn"
	cfg.EmailAttribute = "mail"
	cfg.SessionSecretFile, cfg.SessionTTL, cfg.LoginRedirect = filepath.Join(t.TempDir(), "ldap-session.secret"), "1h", "/"
	cfg.TenantMappings = []config.TenantMapping{{Group: "trstctl-admins", TenantID: tenantID, Roles: []string{"admin"}}}
	srv := buildLDAPServer(t, ctx, dsn, tenantID, cfg)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	return &v7LDAPServed{t: t, baseURL: "http://" + ln.Addr().String(), admin: seedServedScopedToken(t, st, tenantID, "*")}, st
}

// login signs in with the directory password and returns the cookie jar.
func (s *v7LDAPServed) login(username string) (int, http.CookieJar) {
	s.t.Helper()
	jar, _ := cookiejar.New(nil)
	resp, err := noFollowClient(jar).Post(s.baseURL+"/auth/ldap/login", "application/json",
		bytes.NewReader([]byte(`{"username":"`+username+`","password":"alice-password"}`)))
	if err != nil {
		s.t.Fatalf("login %s: %v", username, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, jar
}

func (s *v7LDAPServed) session(jar http.CookieJar, method, path, key string, body any) (int, string) {
	s.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, s.baseURL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Idempotency-Key", key)
		u, _ := url.Parse(s.baseURL)
		for _, c := range jar.Cookies(u) {
			if c.Name == "trstctl_csrf" {
				req.Header.Set("X-CSRF-Token", c.Value)
			}
		}
	}
	resp, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(out)
}

func (s *v7LDAPServed) adminCall(method, path, body string) (int, string) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.baseURL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+s.admin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", servedFixtureKey(method, path, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(out)
}

// Case variants of one directory identity must share dual-control, role, and
// offboarding decisions in the served LDAP path.
func TestLDAPTemplateCaseVariantsHonorMemberFences(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded PostgreSQL and an OpenLDAP container")
	}
	const tenantID = "33333333-3333-3333-3333-333333333333"
	const alice = "uid=alice,ou=people,dc=example,dc=org"
	ldapURL := startOpenLDAPContainer(t)
	s, _ := v7StartLDAPServed(t, ldapURL, tenantID, config.LDAP{UserDNTemplate: "uid={username},ou=people,dc=example,dc=org"})

	code, lower := s.login("alice")
	if code != http.StatusFound {
		t.Fatalf("alice login = %d", code)
	}
	code, upper := s.login("ALICE")
	if code != http.StatusFound {
		t.Fatalf("ALICE login = %d", code)
	}
	_, meLower := s.session(lower, http.MethodGet, "/auth/me", "", nil)
	_, meUpper := s.session(upper, http.MethodGet, "/auth/me", "", nil)
	t.Logf("one directory account, two sessions:\n  alice -> %.200s\n  ALICE -> %.200s", meLower, meUpper)

	// A. Dual control by one person.
	status, body := s.session(lower, http.MethodPost, "/api/v1/profiles", "v7-l3-governed", map[string]any{
		"name": "v7-l3-governed", "spec": map[string]any{"requires_approval": true, "max_validity": "24h"}})
	var accepted struct {
		ApprovalID string `json:"approval_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal([]byte(body), &accepted) != nil || accepted.ApprovalID == "" {
		t.Fatalf("A: governed profile request as alice = %d %s", status, body)
	}
	t.Logf("A: alice files a governed profile edit -> %d approval %s", status, accepted.ApprovalID)
	if status, body := s.session(lower, http.MethodPost, "/api/v1/profiles/approvals/"+accepted.ApprovalID+"/approvals", "v7-l3-self", map[string]any{"reason": "self"}); status == http.StatusOK {
		t.Fatalf("A control: alice approved her own request: %s", body)
	} else {
		t.Logf("A control: alice approves her own request -> %d %.140s", status, body)
	}
	status, body = s.session(upper, http.MethodPost, "/api/v1/profiles/approvals/"+accepted.ApprovalID+"/approvals", "v7-l3-upper", map[string]any{"reason": "looks right"})
	if status == http.StatusOK {
		t.Errorf("A: one person satisfied dual control by signing in as ALICE: %.400s", body)
	} else {
		t.Logf("A: ALICE approves alice's request -> %d %.200s", status, body)
	}

	// B. Member-record role narrowing.
	if code, out := s.adminCall(http.MethodPut, "/api/v1/access/members/"+alice, `{"display_name":"Alice","roles":["viewer"]}`); code != http.StatusOK {
		t.Fatalf("B: narrow alice to viewer = %d %s", code, out)
	}
	waitFor := func(jar http.CookieJar, path string, want int) int {
		var got int
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			got, _ = s.session(jar, http.MethodGet, path, "", nil)
			if got == want {
				return got
			}
			time.Sleep(250 * time.Millisecond)
		}
		return got
	}
	_, narrowed := s.login("alice")
	if got := waitFor(narrowed, "/api/v1/audit/events", http.StatusForbidden); got != http.StatusForbidden {
		t.Fatalf("B control: narrowed alice GET /api/v1/audit/events = %d, want 403", got)
	}
	t.Log("B control: alice narrowed to viewer -> GET /api/v1/audit/events 403")
	_, widened := s.login("ALICE")
	if got, out := s.session(widened, http.MethodGet, "/api/v1/audit/events", "", nil); got == http.StatusOK {
		t.Errorf("B: the member record narrowed alice to viewer, but signing in as ALICE restores the directory mapping's admin: GET /api/v1/audit/events 200 (%d bytes)", len(out))
	} else {
		t.Logf("B: ALICE GET /api/v1/audit/events -> %d", got)
	}

	// C. Offboarding, with API authority checked on guarded routes.
	if code, out := s.adminCall(http.MethodPost, "/api/v1/access/members/"+alice+"/offboard", `{"reason":"left the company"}`); code != http.StatusOK {
		t.Fatalf("C: offboard alice = %d %s", code, out)
	}
	if _, jar := s.login("alice"); true {
		if got, _ := s.session(jar, http.MethodGet, "/api/v1/access/members", "", nil); got == http.StatusOK {
			t.Fatalf("C control: offboarded alice still reads members")
		} else {
			t.Logf("C control: offboarded alice GET /api/v1/access/members -> %d", got)
		}
	}
	_, after := s.login("Alice")
	got, out := s.session(after, http.MethodGet, "/api/v1/access/members?include_offboarded=true", "", nil)
	if got == http.StatusOK {
		t.Errorf("C: offboarded alice signed in as \"Alice\" and reads the tenant's members (her own record says offboarded): 200 %.300s", out)
	} else {
		t.Logf("C: Alice GET /api/v1/access/members -> %d", got)
	}
	mint, mintBody := s.session(after, http.MethodPost, "/api/v1/access/api-tokens", "v7-l3-mint", map[string]any{"subject": "svc-after-offboarding", "scopes": []string{"*"}})
	t.Logf("C: offboarded alice (as Alice) mints a wildcard API token -> %d (token withheld; %d-byte response)", mint, len(mintBody))
	if mint == http.StatusCreated {
		t.Errorf("C: offboarded alice minted a wildcard API token after offboarding")
	}
}

// Control for the fix family: in search mode (user_filter) the subject is the
// directory's own DN for the entry, whatever case the user typed.
func TestV7LDAPSearchModeSubjectIsTheDirectoryDN(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded PostgreSQL and an OpenLDAP container")
	}
	const tenantID = "33333333-3333-3333-3333-333333333333"
	ldapURL := startOpenLDAPContainer(t)
	s, _ := v7StartLDAPServed(t, ldapURL, tenantID, config.LDAP{UserSearchBaseDN: "ou=people,dc=example,dc=org", UserFilter: "(uid={username})"})
	code, jar := s.login("ALICE")
	if code != http.StatusFound {
		t.Fatalf("ALICE login (search mode) = %d", code)
	}
	_, me := s.session(jar, http.MethodGet, "/auth/me", "", nil)
	t.Logf("search mode, typed ALICE: /auth/me %.200s", me)
	if !strings.Contains(me, `"subject":"uid=alice,ou=people,dc=example,dc=org"`) {
		t.Errorf("search mode did not canonicalize the subject: %s", me)
	}
}
