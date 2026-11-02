// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type clickHouseLab struct {
	mu         sync.Mutex
	statements []string
	fail       string // a statement prefix to fail, echoing the statement like ClickHouse does
}

func newClickHouseLab(t *testing.T) (*clickHouseLab, *httptest.Server) {
	t.Helper()
	lab := &clickHouseLab{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "lab_admin" || pass != "lab-admin-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.statements = append(lab.statements, string(body))
		if lab.fail != "" && strings.HasPrefix(string(body), lab.fail) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Code: 497. DB::Exception: denied while executing " + string(body) + ". (ACCESS_DENIED)"))
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabClickHouse(t *testing.T, srv *httptest.Server, now time.Time) *ClickHouseBackend {
	t.Helper()
	b, err := NewClickHouseBackend(ClickHouseConfig{
		Endpoint: srv.URL, AdminUser: "lab_admin", AdminPassword: []byte("lab-admin-password"),
		RoleBindings: map[string]string{"reader": "orders_reader"}, MaxLifetime: time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestClickHouseLeaseIsAUserWithItsRoleUntilItsLifetimeA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 14, 0, 0, 0, time.UTC)
	lab, srv := newClickHouseLab(t)
	b := newLabClickHouse(t, srv, now)
	req := GenerateRequest{Role: "reader", TTL: 10 * time.Minute, LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		ValidUntil string `json:"valid_until"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 || got.ValidUntil != "2026-11-02T15:00:00Z" {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	if !clickHouseIdentifier.MatchString(user) || !strings.HasPrefix(user, "trstctl_reader_") {
		t.Fatalf("user %q", user)
	}
	want := []string{
		"CREATE USER OR REPLACE " + user + " IDENTIFIED WITH sha256_password BY '" + got.Password + "' VALID UNTIL '2026-11-02T15:00:00Z'",
		"GRANT orders_reader TO " + user,
		"SET DEFAULT ROLE orders_reader TO " + user,
	}
	if strings.Join(lab.statements, "\n") != strings.Join(want, "\n") {
		t.Fatalf("statements:\n%s\nwant:\n%s", strings.Join(lab.statements, "\n"), strings.Join(want, "\n"))
	}
	// A retry of the same lease replaces the same user rather than adding one.
	again, _, err := b.CreateCredential(context.Background(), req)
	if err != nil || again != user {
		t.Fatalf("retry created %q (%v), want the same user %q", again, err, user)
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if last := lab.statements[len(lab.statements)-1]; last != "DROP USER IF EXISTS "+user {
		t.Fatalf("revoke sent %q", last)
	}
	for _, foreign := range []string{"default", "lab_admin", "trstctl_x; DROP USER lab_admin", "other_reader_1"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("revoke dropped %q, a user this provider did not create", foreign)
		}
	}
}

func TestClickHouseFailureNeverEchoesThePasswordA239(t *testing.T) {
	lab, srv := newClickHouseLab(t)
	lab.fail = "CREATE USER"
	b := newLabClickHouse(t, srv, time.Now())
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-0002"})
	if err == nil {
		t.Fatal("a refused CREATE USER issued a credential")
	}
	if regexp.MustCompile(`[0-9a-f]{48}`).MatchString(err.Error()) || !strings.Contains(err.Error(), "error code 497") {
		t.Fatalf("error %q leaks the statement or drops the code", err)
	}
	lab.fail = "GRANT"
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-0003"}); err == nil {
		t.Fatal("a failed grant issued a credential")
	}
	if last := lab.statements[len(lab.statements)-1]; !strings.HasPrefix(last, "DROP USER IF EXISTS trstctl_reader_") {
		t.Fatalf("a failed grant left its user behind: last statement %q", last)
	}
}

func TestClickHouseConfigA239(t *testing.T) {
	base := ClickHouseConfig{Endpoint: "https://ch.example:8443", AdminUser: "admin", AdminPassword: []byte("x"),
		MaxLifetime: time.Hour, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*ClickHouseConfig){
		"plain http":     func(c *ClickHouseConfig) { c.Endpoint = "http://ch.example:8123" },
		"quoted admin":   func(c *ClickHouseConfig) { c.AdminUser = "ad`min" },
		"no password":    func(c *ClickHouseConfig) { c.AdminPassword = nil },
		"no lifetime":    func(c *ClickHouseConfig) { c.MaxLifetime = 0 },
		"injected role":  func(c *ClickHouseConfig) { c.RoleBindings = map[string]string{"r": "reader TO x; DROP USER y"} },
		"missing client": func(c *ClickHouseConfig) { c.HTTPClient = nil },
	} {
		c := base
		mutate(&c)
		if _, err := NewClickHouseBackend(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewClickHouseBackend(base); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
}
