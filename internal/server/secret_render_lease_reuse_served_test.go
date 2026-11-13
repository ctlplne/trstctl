// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A238-L4 Done-when (served): a running renderer keeps its lease through static
// rotations. Against the real lease API and a database stand-in, the file is
// written again with each new value and the same login: the database sees one
// login created and none revoked, and the control plane's lease stays active.
func TestServedSecretRenderKeepsItsLeaseThroughStaticRotationsA238L4(t *testing.T) {
	backend := &renderLeaseBackend{active: map[string]string{}, revoked: map[string]bool{}}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), withPreviewDynamicSecretProvider(backend))
	registerServedTenant(t, h, "A238-L4 lease reuse tenant")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a238l4-lease-agent", "secrets:read", "secrets:write")
	// Issuance and revocation run through the outbox: keep the dispatcher going.
	dispatcherCtx, cancelDispatcher := context.WithCancel(context.Background())
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		h.srv.RunDispatcher(dispatcherCtx)
	}()
	t.Cleanup(func() {
		cancelDispatcher()
		<-dispatcherDone
	})
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "a238l4-lease-app",
		map[string]any{"name": "lease238l4/app/name", "value": "billing"}); status != http.StatusCreated {
		t.Fatalf("seed: HTTP %d %s", status, raw)
	}
	file := filepath.Join(t.TempDir(), "db.env")
	stateDir := filepath.Join(t.TempDir(), "state")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := secretrender.NewHTTPClient(h.ts.URL, "", tokenFile, h.ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	r, err := secretrender.New(secretrender.Config{
		Server: h.ts.URL, TokenFile: tokenFile, Consumer: "billing-l4/app", StateDir: stateDir,
		Templates: []secretrender.Template{{
			Name: "db", Destination: file, LeaseTTL: 15 * time.Minute,
			Text: "app={{ secret \"lease238l4/app/name\" }} pass={{ lease \"payments-db/readonly-reporting\" \"password\" }}\n",
		}},
	}, client, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(client)
	t.Cleanup(r.Close)
	read := func() string {
		raw, _ := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		return string(raw)
	}
	r.Once(t.Context())
	if got := read(); got != "app=billing pass=lease-pw-1\n" {
		t.Fatalf("first file %q", got)
	}
	for i, value := range []string{"billing-v2", "billing-v3"} {
		if status, raw := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/lease238l4/app/name", operator,
			fmt.Sprintf("a238l4-rotate-%d", i), map[string]any{"value": value}); status != http.StatusOK {
			t.Fatalf("rotate: HTTP %d %s", status, raw)
		}
		r.Once(t.Context())
		if got := read(); got != "app="+value+" pass=lease-pw-1\n" {
			t.Fatalf("after rotation %d the file is %q; want the new value with the same login", i+1, got)
		}
	}
	// The state file names the lease (never its credential); the control plane
	// still holds it active, and the database saw one login and no revocation.
	raw, err := os.ReadFile(filepath.Join(stateDir, "db.json")) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "lease-pw-") {
		t.Fatal("the state file holds a credential")
	}
	var state struct {
		Leases map[string]struct {
			ID string `json:"id"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	id := state.Leases["payments-db/readonly-reporting"].ID
	lease, err := h.store.GetDynamicSecretLease(t.Context(), h.tenant, id)
	if err != nil || lease.State != store.DynamicSecretLeaseActive {
		t.Fatalf("the control plane's lease %q: %+v %v", id, lease, err)
	}
	backend.mu.Lock()
	events := strings.Join(backend.events, ",")
	backend.mu.Unlock()
	if events != "create login-1" || !backend.accepts("lease-pw-1") {
		t.Fatalf("the database saw %q; want one login created and kept", events)
	}
	t.Logf("A238L4_LEASE_KEPT %s lease=%s", events, id)
	// Served tests share a tenant: revoke the lease while its provider is here.
	revokeServedRenderLease(t, client, backend, id, "login-1")
}

// revokeServedRenderLease revokes a test's lease and waits until the
// database stand-in has dropped its login, so no lease outlives the test's
// provider for a later test's expiry sweep.
func revokeServedRenderLease(t *testing.T, client *secretrender.HTTPClient, backend *renderLeaseBackend, id, login string) {
	t.Helper()
	if err := client.RevokeLease(t.Context(), id, id+"/test-cleanup"); err != nil {
		t.Fatalf("revoke %s: %v", id, err)
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		backend.mu.Lock()
		done := backend.revoked[login]
		backend.mu.Unlock()
		if done {
			return
		}
	}
	t.Fatalf("the database never dropped %s", login)
}
