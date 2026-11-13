// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

// cappedServedDynamicProvider is a preview provider with its own maximum
// lifetime, which sets its leases' hard expiry.
type cappedServedDynamicProvider struct {
	previewServedDynamicProvider
	max time.Duration
}

func (p cappedServedDynamicProvider) MaximumTTL() time.Duration { return p.max }

// A238-L5 Done-when (served): against the real lease API, renewing a lease
// brings it to expire one TTL after the renewal, never past its hard expiry.
// Two leases of 30 seconds: one from a provider whose leases live at most 40
// seconds, one from a provider allowing an hour. When a third of them is left,
// the first is renewed up to its hard expiry (not refused and replaced) and the
// second to 30 seconds after the renewal (not 30 seconds after its old expiry).
func TestServedSecretRenderRenewsALeaseToItsTTLA238L5(t *testing.T) {
	brief := &renderLeaseBackend{active: map[string]string{}, revoked: map[string]bool{}}
	steady := &renderLeaseBackend{active: map[string]string{}, revoked: map[string]bool{}}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DynamicSecretProviders = []dynsecret.Provider{
			cappedServedDynamicProvider{previewServedDynamicProvider{Provider: dynsecret.NewProvider("brief-db", brief),
				providerType: "postgresql", roles: []string{"app"}, revision: "a238l5-brief"}, 40 * time.Second},
			cappedServedDynamicProvider{previewServedDynamicProvider{Provider: dynsecret.NewProvider("steady-db", steady),
				providerType: "postgresql", roles: []string{"app"}, revision: "a238l5-steady"}, time.Hour},
		}
	})
	registerServedTenant(t, h, "A238-L5 lease renewal tenant")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a238l5-lease-agent", "secrets:read", "secrets:write")
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
		Server: h.ts.URL, TokenFile: tokenFile, Consumer: "renewal-l5/app", StateDir: stateDir,
		Templates: []secretrender.Template{{
			Name: "db", Destination: file, LeaseTTL: 30 * time.Second,
			Text: "a={{ lease \"brief-db/app\" \"password\" }} b={{ lease \"steady-db/app\" \"password\" }}\n",
		}},
	}, client, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(client)
	t.Cleanup(r.Close)
	leaseIDs := func() (string, string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(stateDir, "db.json")) // #nosec G304 -- the test's own temp file (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		var state struct {
			Leases map[string]struct {
				ID string `json:"id"`
			} `json:"leases"`
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		return state.Leases["brief-db/app"].ID, state.Leases["steady-db/app"].ID
	}
	lease := func(id string) store.DynamicSecretLease {
		t.Helper()
		l, err := h.store.GetDynamicSecretLease(t.Context(), h.tenant, id)
		if err != nil || l.State != store.DynamicSecretLeaseActive {
			t.Fatalf("lease %s: %+v %v", id, l, err)
		}
		return l
	}
	r.Once(t.Context())
	if raw, _ := os.ReadFile(file); string(raw) != "a=lease-pw-1 b=lease-pw-1\n" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("first file %q", raw)
	}
	briefID, steadyID := leaseIDs()
	first := lease(briefID)
	if got := first.HardExpiresAt.Sub(first.ExpiresAt); got != 10*time.Second {
		t.Fatalf("the brief lease's hard expiry is %s past its expiry, want 10s", got)
	}
	// Wait until less than a third of the 30 seconds is left.
	time.Sleep(time.Until(first.ExpiresAt.Add(-9 * time.Second)))
	at := time.Now()
	r.Once(t.Context())

	if b, s := leaseIDs(); b != briefID || s != steadyID {
		t.Fatalf("a lease was replaced: brief %s -> %s, steady %s -> %s", briefID, b, steadyID, s)
	}
	if got := lease(briefID); !got.ExpiresAt.Equal(got.HardExpiresAt) {
		t.Fatalf("the brief lease expires at %s, want its hard expiry %s", got.ExpiresAt, got.HardExpiresAt)
	}
	if left := lease(steadyID).ExpiresAt.Sub(at); left < 28*time.Second || left > 33*time.Second {
		t.Fatalf("the renewed steady lease lives %s past the renewal, want about its 30-second TTL", left)
	}
	for name, b := range map[string]*renderLeaseBackend{"brief": brief, "steady": steady} {
		b.mu.Lock()
		events := strings.Join(b.events, ",")
		b.mu.Unlock()
		if events != "create login-1" {
			t.Fatalf("the %s database saw %q; want its one login kept", name, events)
		}
	}
	if raw, _ := os.ReadFile(file); string(raw) != "a=lease-pw-1 b=lease-pw-1\n" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("file after the renewals %q", raw)
	}
	t.Log("A238L5_RENEWED_TO_TTL")
	// Served tests share a tenant: revoke the leases while their providers are here.
	revokeServedRenderLease(t, client, brief, briefID, "login-1")
	revokeServedRenderLease(t, client, steady, steadyID, "login-1")
}
