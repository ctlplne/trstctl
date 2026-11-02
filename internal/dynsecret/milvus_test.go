// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// milvusStandIn follows the RESTful API v2 user endpoints as Milvus 2.6
// answers them: HTTP 200 with a result code; creating a user that exists is
// code 1100; dropping a user that is gone succeeds; granting a role that does
// not exist is code 1100.
type milvusStandIn struct {
	mu    sync.Mutex
	users map[string]string
	roles map[string][]string
	known map[string]bool
	calls []string
}

func newMilvusStandIn(t *testing.T) (*milvusStandIn, *httptest.Server) {
	t.Helper()
	lab := &milvusStandIn{users: map[string]string{}, roles: map[string][]string{}, known: map[string]bool{"orders_reader": true, "audit": true}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.calls = append(lab.calls, r.URL.Path)
		reply := func(code int, message string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "data": map[string]any{}})
		}
		if r.Header.Get("Authorization") != "Bearer root:lab-root-password" { // #nosec G101 -- fabricated stand-in administrator (CWE-798)
			reply(1800, "user hasn't authenticated")
			return
		}
		var in struct{ UserName, Password, RoleName string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v2/vectordb/users/create":
			if _, exists := lab.users[in.UserName]; exists {
				reply(1100, "user already exists: "+in.UserName+": invalid parameter")
				return
			}
			lab.users[in.UserName] = in.Password
		case "/v2/vectordb/users/drop":
			delete(lab.users, in.UserName)
			delete(lab.roles, in.UserName)
		case "/v2/vectordb/users/grant_role":
			if !lab.known[in.RoleName] {
				reply(1100, "not found the role, maybe the role isn't existed or internal system error: invalid parameter")
				return
			}
			lab.roles[in.UserName] = append(lab.roles[in.UserName], in.RoleName)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		reply(0, "")
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabMilvus(t *testing.T, srv *httptest.Server, bindings map[string]string) *MilvusBackend {
	t.Helper()
	b, err := NewMilvusBackend(MilvusConfig{
		Endpoint: srv.URL, AdminUser: "root", AdminPassword: []byte("lab-root-password"), RoleBindings: bindings,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestMilvusLeaseIsAUserMilvusDropsA239(t *testing.T) {
	lab, srv := newMilvusStandIn(t)
	b := newLabMilvus(t, srv, map[string]string{"reader": "orders_reader, audit", "broken": "no_such_role"})
	req := GenerateRequest{Role: "reader", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Username, Password string }
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 || len(user) > 32 {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	if lab.users[user] != got.Password || !slices.Equal(lab.roles[user], []string{"orders_reader", "audit"}) {
		t.Fatalf("Milvus user %q roles %v", lab.users[user], lab.roles[user])
	}
	// A retry of the same lease replaces the user (Milvus cannot reset its
	// password without the old one); it adds no user and grants each role once.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	var got2 struct{ Password string }
	_ = json.Unmarshal(credential2, &got2)
	if err != nil || again != user || len(lab.users) != 1 || lab.users[user] != got2.Password || got2.Password == got.Password ||
		!slices.Equal(lab.roles[user], []string{"orders_reader", "audit"}) {
		t.Fatalf("retry: %q (%v); users %v roles %v", again, err, lab.users, lab.roles)
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "broken", LeaseID: "lease-0002"}); err == nil || len(lab.users) != 1 {
		t.Fatalf("a failed grant: %v, users %v", err, lab.users)
	}
	if err := b.Revoke(context.Background(), user); err != nil || len(lab.users) != 0 {
		t.Fatalf("revoke: %v, users %v", err, lab.users)
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a dropped user: %v", err)
	}
	for _, foreign := range []string{"root", "admin_1", "trstctl/../x", "trstctl"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("dropped %q, a user this provider did not create", foreign)
		}
	}
}

func TestMilvusConfigA239(t *testing.T) {
	if roles, err := ParseMilvusRoles("orders_reader, _ops"); err != nil || !slices.Equal(roles, []string{"orders_reader", "_ops"}) {
		t.Fatalf("roles %v (%v)", roles, err)
	}
	for _, bad := range []string{"", "orders reader", "1role", "orders-reader", strings.Repeat("a", 33), "a,,b"} {
		if _, err := ParseMilvusRoles(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	base := MilvusConfig{Endpoint: "https://milvus.example:19530", AdminUser: "root", AdminPassword: []byte("pw"),
		RoleBindings: map[string]string{"r": "orders_reader"}, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*MilvusConfig){
		"plain http":     func(c *MilvusConfig) { c.Endpoint = "http://milvus.example:19530" },
		"no admin":       func(c *MilvusConfig) { c.AdminUser = "" },
		"colon in admin": func(c *MilvusConfig) { c.AdminUser = "root:x" },
		"no password":    func(c *MilvusConfig) { c.AdminPassword = nil },
		"no roles":       func(c *MilvusConfig) { c.RoleBindings = nil },
		"bad role":       func(c *MilvusConfig) { c.RoleBindings = map[string]string{"r": "orders reader"} },
	} {
		c := base
		mutate(&c)
		if b, err := NewMilvusBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}
