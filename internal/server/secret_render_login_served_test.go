// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
)

// A238-L1 Done-when: a renderer signs in as its workload instead of holding
// an API token. With the workload's own credential (here the built-in token
// method) it gets a machine session, renders the secret the session may read
// and reports the delivery as its consumer. When the control plane ends the
// session, the next pass signs in again — reading the credential file again —
// and renders the rotated value; a credential the method refuses leaves the
// rendered file as it was and reads as unauthenticated; closing the renderer's
// client ends its session.
func TestServedSecretRenderSignsInAsItsWorkloadA238L1(t *testing.T) {
	authSecret := []byte("render-render-render-render-a238l1")
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, authSecret))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a238l1-admin", "secrets:read", "secrets:write")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, admin, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(http.MethodPost, "/api/v1/secrets/store", "a238l1-create", map[string]any{"name": "a238l1/app/db", "value": "db-one-a238l1"}, http.StatusCreated)

	workload := authmethod.TokenMethod{Secret: authSecret, TenantID: h.tenant, Scopes: map[string][]string{"render-a238l1": {"secrets:read"}}}
	issue := func() []byte {
		t.Helper()
		cred, err := workload.Issue("render-a238l1", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return []byte(cred)
	}
	dir := t.TempDir()
	credentialFile := filepath.Join(dir, "credential")
	if err := os.WriteFile(credentialFile, issue(), 0o600); err != nil {
		t.Fatal(err)
	}
	session, err := secretrender.NewSessionClient(h.ts.URL, h.tenant, "token", credentialFile, h.ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "app.env")
	renderer, err := secretrender.New(secretrender.Config{
		Server: h.ts.URL, Tenant: h.tenant, LoginMethod: "token", LoginCredentialFile: credentialFile,
		Consumer: "render-a238l1", StateDir: filepath.Join(dir, "state"), Interval: time.Second,
		Templates: []secretrender.Template{{Name: "app", Destination: destination, Text: `DB={{ secret "a238l1/app/db" }}`}},
	}, session, session, nil)
	if err != nil {
		t.Fatal(err)
	}
	rendered := func() string {
		t.Helper()
		raw, err := os.ReadFile(destination) // #nosec G304 -- the test's own temp file (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	activeSession := func() string {
		t.Helper()
		var list struct {
			Items []struct {
				ID        string `json:"id"`
				Principal string `json:"principal"`
				Status    string `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(call(http.MethodGet, "/api/v1/secrets/sessions?limit=100", "", nil, http.StatusOK), &list); err != nil {
			t.Fatal(err)
		}
		for _, s := range list.Items {
			if s.Principal == "render-a238l1" && s.Status == "active" {
				return s.ID
			}
		}
		return ""
	}

	renderer.Once(t.Context())
	if got := rendered(); got != "DB=db-one-a238l1" {
		t.Fatalf("first render = %q", got)
	}
	var deliveries struct {
		Consumers []struct {
			Consumer        string `json:"consumer"`
			InjectedVersion int    `json:"injected_version"`
		} `json:"consumers"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/secrets/deliveries?name=a238l1/app/db", "", nil, http.StatusOK), &deliveries); err != nil {
		t.Fatal(err)
	}
	if len(deliveries.Consumers) != 1 || deliveries.Consumers[0].Consumer != "render-a238l1" || deliveries.Consumers[0].InjectedVersion != 1 {
		t.Fatalf("the delivery report = %+v; want render-a238l1 injected at version 1", deliveries.Consumers)
	}
	first := activeSession()
	if first == "" {
		t.Fatal("no active machine session for the renderer's workload")
	}

	// The control plane ends the session; the next pass signs in again.
	call(http.MethodPost, "/api/v1/secrets/sessions/"+first+"/revoke", "a238l1-revoke-1", nil, http.StatusOK)
	call(http.MethodPut, "/api/v1/secrets/store/a238l1/app/db", "a238l1-rotate", map[string]any{"value": "db-two-a238l1"}, http.StatusOK)
	renderer.Once(t.Context())
	if got := rendered(); got != "DB=db-two-a238l1" {
		t.Fatalf("after the session ended the render = %q, want the rotated value", got)
	}
	second := activeSession()
	if second == "" || second == first {
		t.Fatalf("the renderer did not sign in again: first %s, now %s", first, second)
	}

	// A credential the method refuses: the file stays as rendered.
	if err := os.WriteFile(credentialFile, []byte("not-a-workload-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/api/v1/secrets/sessions/"+second+"/revoke", "a238l1-revoke-2", nil, http.StatusOK)
	call(http.MethodPut, "/api/v1/secrets/store/a238l1/app/db", "a238l1-rotate-2", map[string]any{"value": "db-three-a238l1"}, http.StatusOK)
	renderer.Once(t.Context())
	if got := rendered(); got != "DB=db-two-a238l1" {
		t.Fatalf("with a refused credential the render changed to %q", got)
	}
	if _, _, err := session.Fetch(t.Context(), "a238l1/app/db"); !errors.Is(err, secretrender.ErrUnauthenticated) {
		t.Fatalf("a fetch with a refused credential = %v, want ErrUnauthenticated", err)
	}

	// A good credential again; closing the client ends its session.
	if err := os.WriteFile(credentialFile, issue(), 0o600); err != nil {
		t.Fatal(err)
	}
	renderer.Once(t.Context())
	if got := rendered(); got != "DB=db-three-a238l1" {
		t.Fatalf("with a good credential again the render = %q", got)
	}
	if activeSession() == "" {
		t.Fatal("no active session after signing in again")
	}
	if err := session.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if id := activeSession(); id != "" {
		t.Fatalf("closing the client left session %s active", id)
	}
}
