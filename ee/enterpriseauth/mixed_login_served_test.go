// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// Exercise the actual builders together: a later WithAuth must never overwrite
// OIDC or another enabled method. Each successful login must create a durable
// session and lose guarded API access when that exact session is revoked.
func TestServedMixedTenantLoginMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real PostgreSQL, NATS and optional OpenLDAP")
	}
	for _, tc := range []struct {
		name       string
		saml, ldap bool
	}{
		{"oidc-saml", true, false}, {"oidc-ldap", false, true}, {"oidc-saml-ldap", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const tenant = "11111111-1111-1111-1111-111111111111"
			st := newServerTestStore(t)
			if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "mixed-login"}); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			base := "http://" + ln.Addr().String()
			oidc := newMockIdP(t, "mixed-login")
			oidc.registerUser("oidc-alice", "oidc-alice", map[string]any{"email": "oidc-alice@example.test"})
			d := server.Deps{Store: st, TenantAuthFactory: Build}
			d.OIDC = config.OIDC{Enabled: true, Issuer: oidc.issuer, ClientID: "mixed-login", AuthEndpoint: oidc.issuer + "/authorize", TokenEndpoint: oidc.issuer + "/token", RedirectURI: base + "/auth/callback", JWKSJSON: oidc.jwksJSON(t), SessionSecretFile: filepath.Join(t.TempDir(), "oidc-session"), SessionTTL: "1h", TenantMappings: []config.TenantMapping{{Subject: "oidc-alice", TenantID: tenant, Roles: []string{"admin"}}}}
			var saml *mockSAMLIdP
			if tc.saml {
				saml = newMockSAMLIdP(t)
				d.SAML = config.SAML{Enabled: true, EntityID: base + "/auth/saml/metadata", MetadataURL: base + "/auth/saml/metadata", ACSURL: base + "/auth/saml/acs", IDPMetadataXML: saml.metadataXML(t), SessionSecretFile: filepath.Join(t.TempDir(), "saml-session"), SessionTTL: "1h", EmailAttribute: "email", TenantMappings: []config.TenantMapping{{Subject: "saml-alice@example.test", TenantID: tenant, Roles: []string{"admin"}}}}
				saml.spEntityID = d.SAML.EntityID
				saml.spMetadataURL = d.SAML.MetadataURL
				saml.registerUser("alice", "saml-alice@example.test", "saml-alice@example.test", tenant, []string{"admins"})
			}
			if tc.ldap {
				endpoint := startOpenLDAPContainer(t)
				password := filepath.Join(t.TempDir(), "bind-password")
				if err := writeSecretFile(password, []byte("admin-password")); err != nil {
					t.Fatal(err)
				}
				d.LDAP = config.LDAP{Enabled: true, URL: endpoint, UserDNTemplate: "uid={username},ou=people,dc=example,dc=org", BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: password, GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn", EmailAttribute: "mail", SessionSecretFile: filepath.Join(t.TempDir(), "ldap-session"), SessionTTL: "1h", TenantMappings: []config.TenantMapping{{Group: "trstctl-admins", TenantID: tenant, Roles: []string{"admin"}}}}
			}
			d.Log, err = events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			srv, err := server.Build(ctx, d)
			if err != nil {
				_ = d.Log.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
			httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
			go func() { _ = httpSrv.Serve(ln) }()
			t.Cleanup(func() { _ = httpSrv.Close() })
			resp, err := http.Get(base + "/auth/methods")
			if err != nil {
				t.Fatal(err)
			}
			var methods struct {
				OIDC bool `json:"oidc"`
				SAML bool `json:"saml"`
				LDAP bool `json:"ldap"`
			}
			err = json.NewDecoder(resp.Body).Decode(&methods)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || !methods.OIDC || methods.SAML != tc.saml || methods.LDAP != tc.ldap {
				t.Fatalf("methods=%+v status=%d error=%v", methods, resp.StatusCode, err)
			}
			jar, _ := cookiejar.New(nil)
			loginMixedOIDC(t, base, jar)
			assertDurableMixedSession(t, st, base, jar, tenant, 1)
			count := 1
			if tc.saml {
				jar, _ = cookiejar.New(nil)
				saml.nextUser = "alice"
				assertSAMLSPInitiatedSession(t, base, jar, tenant)
				count++
				assertDurableMixedSession(t, st, base, jar, tenant, count)
			}
			if tc.ldap {
				jar, _ = cookiejar.New(nil)
				client := noFollowClient(jar)
				resp, err := client.Post(base+"/auth/ldap/login", "application/json", bytes.NewBufferString(`{"username":"alice","password":"alice-password"}`))
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("LDAP login=%d %s", resp.StatusCode, body)
				}
				count++
				assertDurableMixedSession(t, st, base, jar, tenant, count)
			}
		})
	}
}

func loginMixedOIDC(t *testing.T, base string, jar http.CookieJar) {
	t.Helper()
	client := noFollowClient(jar)
	resp, err := client.Get(base + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("OIDC login=%d", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("login_as", "oidc-alice")
	u.RawQuery = query.Encode()
	resp, err = client.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP authorize=%d", resp.StatusCode)
	}
	resp, err = client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("OIDC callback=%d %s", resp.StatusCode, body)
	}
}

func assertDurableMixedSession(t *testing.T, st *store.Store, base string, jar http.CookieJar, tenant string, wantCount int) {
	t.Helper()
	assertAuthMeTenant(t, base, jar, tenant)
	assertSessionCanReadAccessRoles(t, base, jar)
	var count int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM browser_sessions WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != wantCount {
		t.Fatalf("durable sessions=%d, want %d", count, wantCount)
	}
	var hash string
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT session_hash FROM browser_sessions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`, tenant).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeBrowserSession(t.Context(), tenant, hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Jar: jar}).Get(base + "/api/v1/access/roles")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked durable session retained API access: %d", resp.StatusCode)
	}
}
