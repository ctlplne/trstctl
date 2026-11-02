// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// couchbaseStandIn follows the management REST API's local-user endpoints as
// Couchbase Server 8.0 answers them: PUT creates or replaces (200), DELETE
// answers 200, and 404 "Unknown user." for a user that is gone.
type couchbaseStandIn struct {
	mu    sync.Mutex
	users map[string]url.Values
	calls []string
}

func newCouchbaseStandIn(t *testing.T) (*couchbaseStandIn, *httptest.Server) {
	t.Helper()
	lab := &couchbaseStandIn{users: map[string]url.Values{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.calls = append(lab.calls, r.Method+" "+r.URL.Path)
		if user, pass, ok := r.BasicAuth(); !ok || user != "lab_admin" || pass != "lab-admin-password" { // #nosec G101 -- fabricated stand-in administrator (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name, found := strings.CutPrefix(r.URL.Path, "/settings/rbac/users/local/")
		switch {
		case !found:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPut:
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || len(r.PostForm.Get("password")) < 6 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			lab.users[name] = r.PostForm
			_, _ = w.Write([]byte(`""`))
		case r.Method == http.MethodDelete:
			if _, ok := lab.users[name]; !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`"Unknown user."`))
				return
			}
			delete(lab.users, name)
			_, _ = w.Write([]byte(`""`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabCouchbase(t *testing.T, srv *httptest.Server) *CouchbaseBackend {
	t.Helper()
	b, err := NewCouchbaseBackend(CouchbaseConfig{
		Endpoint: srv.URL, AdminUser: "lab_admin", AdminPassword: []byte("lab-admin-password"),
		RoleBindings: map[string]string{"orders": "bucket_full_access on orders"}, AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestCouchbaseLeaseIsALocalUserCouchbaseDeletesA239(t *testing.T) {
	lab, srv := newCouchbaseStandIn(t)
	b := newLabCouchbase(t, srv)
	req := GenerateRequest{Role: "orders", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Username, Password string }
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	stored := lab.users[user]
	if stored.Get("password") != got.Password || stored.Get("roles") != "bucket_full_access[orders]" {
		t.Fatalf("stored user %v", stored)
	}
	// A retry of the same lease replaces the password; it adds no user.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	var got2 struct{ Password string }
	_ = json.Unmarshal(credential2, &got2)
	if err != nil || again != user || len(lab.users) != 1 || lab.users[user].Get("password") != got2.Password || got2.Password == got.Password {
		t.Fatalf("retry: %q (%v), users %v", again, err, lab.users)
	}
	if err := b.Revoke(context.Background(), user); err != nil || len(lab.users) != 0 {
		t.Fatalf("revoke: %v, users %v", err, lab.users)
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a deleted user: %v", err)
	}
	for _, foreign := range []string{"admin", "lab_admin", "app_reader_1", "trstctl/../x"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("deleted %q, a user this provider did not create", foreign)
		}
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "admin", LeaseID: "lease-0002"}); err == nil {
		t.Fatal("issued an unbound role")
	}
}

func TestCouchbaseConfigA239(t *testing.T) {
	roles, err := ParseCouchbaseRoles("data_reader,query_select on orders, inventory:catalog:items")
	if err != nil || roles != "data_reader[orders],data_reader[inventory:catalog:items],query_select[orders],query_select[inventory:catalog:items]" {
		t.Fatalf("roles %q (%v)", roles, err)
	}
	for _, bad := range []string{"bucket_full_access", "bucket_full_access on ", "Data_Reader on orders", "data_reader on or ders",
		"data_reader on a:b:c:d", "data_reader on orders]", "data_reader on orders,admin[x"} {
		if _, err := ParseCouchbaseRoles(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if got := string(appendFormEscaped(nil, []byte("a-Z_9.~ &=%+"))); got != "a-Z_9.~%20%26%3D%25%2B" {
		t.Fatalf("form escape %q", got)
	}
	base := CouchbaseConfig{Endpoint: "https://cb.example:18091", AdminUser: "admin", AdminPassword: []byte("pw"),
		RoleBindings: map[string]string{"r": "bucket_full_access on orders"}, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*CouchbaseConfig){
		"plain http":     func(c *CouchbaseConfig) { c.Endpoint = "http://cb.example:8091" },
		"no admin":       func(c *CouchbaseConfig) { c.AdminUser = "" },
		"no password":    func(c *CouchbaseConfig) { c.AdminPassword = nil },
		"no roles":       func(c *CouchbaseConfig) { c.RoleBindings = nil },
		"bad role spec":  func(c *CouchbaseConfig) { c.RoleBindings = map[string]string{"r": "admin"} },
		"no HTTP client": func(c *CouchbaseConfig) { c.HTTPClient = nil },
	} {
		c := base
		mutate(&c)
		if b, err := NewCouchbaseBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}
