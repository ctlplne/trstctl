// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type rabbitmqLab struct {
	mu          sync.Mutex
	users       map[string]string            // user -> password
	permissions map[string]map[string]string // vhost/user -> configure/write/read
	connections []map[string]string
	closed      []string
	failPerms   bool
	// noPerUser is a broker without GET /api/connections/username/{user};
	// listedAll counts reads of the whole connection listing (A239-L9).
	noPerUser bool
	listedAll int
}

func newRabbitMQLab(t *testing.T) (*rabbitmqLab, *httptest.Server) {
	t.Helper()
	lab := &rabbitmqLab{users: map[string]string{}, permissions: map[string]map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "lab_admin" || pass != "lab-admin-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		path := r.URL.EscapedPath()
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/users/"):
			var request struct {
				Password string `json:"password"`
			}
			_ = json.Unmarshal(body, &request)
			user := strings.TrimPrefix(path, "/api/users/")
			_, existed := lab.users[user]
			lab.users[user] = request.Password
			if existed {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/permissions/"):
			if lab.failPerms {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var request map[string]string
			_ = json.Unmarshal(body, &request)
			lab.permissions[strings.TrimPrefix(path, "/api/permissions/")] = request
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/users/"):
			user := strings.TrimPrefix(path, "/api/users/")
			if _, ok := lab.users[user]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(lab.users, user)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/connections/username/") && !lab.noPerUser:
			user, _ := url.PathUnescape(strings.TrimPrefix(path, "/api/connections/username/"))
			mine := []map[string]string{}
			for _, c := range lab.connections {
				if c["user"] == user {
					mine = append(mine, map[string]string{"name": c["name"]})
				}
			}
			_ = json.NewEncoder(w).Encode(mine)
		case r.Method == http.MethodGet && path == "/api/connections":
			lab.listedAll++
			_ = json.NewEncoder(w).Encode(lab.connections)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/connections/"):
			lab.closed = append(lab.closed, strings.TrimPrefix(path, "/api/connections/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabRabbitMQ(t *testing.T, srv *httptest.Server) *RabbitMQBackend {
	t.Helper()
	b, err := NewRabbitMQBackend(RabbitMQConfig{
		Endpoint: srv.URL, AdminUser: "lab_admin", AdminPassword: []byte("lab-admin-password"),
		RoleBindings:          map[string]string{"reader": "read on orders,orders.dlq in /", "writer": "write,read on orders in prod"},
		AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestRabbitMQLeaseIsAUserWithItsVHostPermissionsA239(t *testing.T) {
	lab, srv := newRabbitMQLab(t)
	b := newLabRabbitMQ(t, srv)
	req := GenerateRequest{Role: "reader", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Username string `json:"username"`
		Password string `json:"password"`
		VHost    string `json:"vhost"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || got.VHost != "/" || lab.users[user] != got.Password || len(got.Password) != 48 {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	perms := lab.permissions["%2F/"+user]
	if perms["configure"] != "^$" || perms["write"] != "^$" || perms["read"] != `^(orders|orders\.dlq)$` {
		t.Fatalf("permissions %v", perms)
	}
	// A retry of the same lease replaces the same user's password.
	again, _, err := b.CreateCredential(context.Background(), req)
	if err != nil || again != user || len(lab.users) != 1 {
		t.Fatalf("retry created %q (%v); users %d", again, err, len(lab.users))
	}
	lab.connections = []map[string]string{{"name": "127.0.0.1:5000 -> 127.0.0.1:5672", "user": user}, {"name": "other", "user": "app"}}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, ok := lab.users[user]; ok || len(lab.closed) != 1 || lab.closed[0] != "127.0.0.1:5000%20-%3E%20127.0.0.1:5672" {
		t.Fatalf("revoke left the user (%v) or closed %v", ok, lab.closed)
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a deleted user: %v", err)
	}
	for _, foreign := range []string{"guest", "lab_admin", "trstctl/x", "app_reader_1"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("deleted %q, a user this provider did not create", foreign)
		}
	}
}

func TestRabbitMQFailedPermissionsDeleteTheUserA239(t *testing.T) {
	lab, srv := newRabbitMQLab(t)
	lab.failPerms = true
	b := newLabRabbitMQ(t, srv)
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "writer", LeaseID: "lease-0002"}); err == nil {
		t.Fatal("failed permissions issued a credential")
	}
	if len(lab.users) != 0 {
		t.Fatalf("a failed grant left users %v", lab.users)
	}
}

func TestRabbitMQGrantGrammarA239(t *testing.T) {
	grant, err := ParseRabbitMQGrant("configure, write on events.in in /prod")
	if err != nil || grant.VHost != "/prod" || grant.Configure != `^(events\.in)$` || grant.Write != `^(events\.in)$` || grant.Read != "^$" {
		t.Fatalf("grant %+v (%v)", grant, err)
	}
	for _, bad := range []string{"read on orders", "read in /", "admin on orders in /", "read on .* in /", "read on orders in /a b", "read on a|b in /"} {
		if _, err := ParseRabbitMQGrant(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A239-L9: revoking a user closes its connections from a listing of that
// user's connections only; a broker without the per-user listing (404) falls
// back to filtering the whole listing. Either way another user's connection
// stays open.
func TestRabbitMQRevokeListsOnlyTheUsersConnectionsA239L9(t *testing.T) {
	for _, perUser := range []bool{true, false} {
		lab, srv := newRabbitMQLab(t)
		lab.noPerUser = !perUser
		b := newLabRabbitMQ(t, srv)
		user, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-l9"})
		if err != nil {
			t.Fatal(err)
		}
		lab.connections = []map[string]string{
			{"name": "10.0.0.1:5000 -> 10.0.0.2:5672", "user": user},
			{"name": "10.0.0.3:6000 -> 10.0.0.2:5672", "user": "app"},
			{"name": "10.0.0.4:7000 -> 10.0.0.2:5672", "user": user},
		}
		if err := b.Revoke(context.Background(), user); err != nil {
			t.Fatal(err)
		}
		wantAll := 0
		if !perUser {
			wantAll = 1
		}
		if len(lab.closed) != 2 || strings.Contains(strings.Join(lab.closed, " "), "6000") || lab.listedAll != wantAll {
			t.Fatalf("per-user listing %v: closed %v, whole listing read %d times (want %d)", perUser, lab.closed, lab.listedAll, wantAll)
		}
	}
}
