// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const atlasLabGroup = "5f1e2d3c4b5a69788796a5b4"

// atlasStandIn follows the Admin API v2 database-user endpoints and the service
// account token endpoint as Atlas's documentation describes them.
type atlasStandIn struct {
	mu    sync.Mutex
	users map[string]map[string]any
	calls []string
}

func newAtlasStandIn(t *testing.T) (*atlasStandIn, *httptest.Server) {
	t.Helper()
	lab := &atlasStandIn{users: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.calls = append(lab.calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/api/oauth/token" {
			if id, secret, ok := r.BasicAuth(); !ok || id != "mdb_sa_id_lab" || secret != "mdb_sa_sk_lab" { // #nosec G101 -- fabricated stand-in service account (CWE-798)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "atlas-lab-token", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer atlas-lab-token" || r.Header.Get("Accept") != atlasAccept {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		users := "/api/atlas/v2/groups/" + atlasLabGroup + "/databaseUsers"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			var user map[string]any
			_ = json.NewDecoder(r.Body).Decode(&user)
			if _, exists := lab.users[user["username"].(string)]; exists {
				w.WriteHeader(http.StatusConflict)
				return
			}
			lab.users[user["username"].(string)] = user
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, users+"/admin/"):
			var user map[string]any
			_ = json.NewDecoder(r.Body).Decode(&user)
			lab.users[strings.TrimPrefix(r.URL.Path, users+"/admin/")] = user
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, users+"/admin/"):
			name := strings.TrimPrefix(r.URL.Path, users+"/admin/")
			if _, ok := lab.users[name]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(lab.users, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabAtlas(t *testing.T, srv *httptest.Server, now time.Time) *MongoDBAtlasBackend {
	t.Helper()
	b, err := NewMongoDBAtlasBackend(MongoDBAtlasConfig{
		Endpoint: srv.URL, GroupID: atlasLabGroup, ClientID: "mdb_sa_id_lab", ClientSecret: []byte("mdb_sa_sk_lab"),
		RoleBindings: map[string]string{"reader": "read on orders,inventory"}, MaxLifetime: time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestMongoDBAtlasLeaseIsADatabaseUserAtlasDeletesA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	lab, srv := newAtlasStandIn(t)
	b := newLabAtlas(t, srv, now)
	req := GenerateRequest{Role: "reader", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Username        string    `json:"username"`
		Password        string    `json:"password"`
		DeleteAfterDate time.Time `json:"delete_after_date"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 || !got.DeleteAfterDate.Equal(now.Add(time.Hour)) {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	stored := lab.users[user]
	roles, _ := json.Marshal(stored["roles"])
	if stored["password"] != got.Password || stored["databaseName"] != "admin" || stored["deleteAfterDate"] != "2026-11-02T16:00:00Z" ||
		string(roles) != `[{"databaseName":"orders","roleName":"read"},{"databaseName":"inventory","roleName":"read"}]` {
		t.Fatalf("stored user %v", stored)
	}
	// A retry finds the user (409) and updates it instead of adding one.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	if err != nil || again != user || len(lab.users) != 1 {
		t.Fatalf("retry: %q (%v), users %d", again, err, len(lab.users))
	}
	var got2 struct {
		Password string `json:"password"`
	}
	_ = json.Unmarshal(credential2, &got2)
	if lab.users[user]["password"] != got2.Password {
		t.Fatal("the retry's password is not the stored one")
	}
	if err := b.Revoke(context.Background(), user); err != nil || len(lab.users) != 0 {
		t.Fatalf("revoke: %v, users %d", err, len(lab.users))
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a deleted user: %v", err)
	}
	for _, foreign := range []string{"admin", "app_reader_1", "trstctl/../x"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("deleted %q, a user this provider did not create", foreign)
		}
	}
}

func TestMongoDBAtlasConfigA239(t *testing.T) {
	roles, err := ParseAtlasRoles("readWrite on orders, inventory")
	if err != nil || len(roles) != 2 || roles[1] != (AtlasRole{RoleName: "readWrite", DatabaseName: "inventory"}) {
		t.Fatalf("roles %+v (%v)", roles, err)
	}
	for _, bad := range []string{"read", "read on ", "read-write on orders", "read on or ders", `read on "x"`} {
		if _, err := ParseAtlasRoles(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	base := MongoDBAtlasConfig{GroupID: atlasLabGroup, ClientID: "id", ClientSecret: []byte("s"), MaxLifetime: time.Hour, HTTPClient: http.DefaultClient}
	if b, err := NewMongoDBAtlasBackend(base); err != nil || b.endpoint != "https://cloud.mongodb.com" {
		t.Fatalf("defaults: %v", err)
	}
	for name, mutate := range map[string]func(*MongoDBAtlasConfig){
		"bad group":     func(c *MongoDBAtlasConfig) { c.GroupID = "project-x" },
		"no secret":     func(c *MongoDBAtlasConfig) { c.ClientSecret = nil },
		"over a week":   func(c *MongoDBAtlasConfig) { c.MaxLifetime = 8 * 24 * time.Hour },
		"plain http":    func(c *MongoDBAtlasConfig) { c.Endpoint = "http://cloud.example" },
		"bad role spec": func(c *MongoDBAtlasConfig) { c.RoleBindings = map[string]string{"r": "read"} },
	} {
		c := base
		mutate(&c)
		if _, err := NewMongoDBAtlasBackend(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
