// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestDeletedTenantCannotCreateACMEAccountsOrOrders(t *testing.T) {
	var suspended atomic.Bool
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	}, func(d *Deps) {
		d.TenantServiceCheck = func(context.Context, string) error {
			if suspended.Load() {
				return tenancy.ErrServiceUnavailable
			}
			return nil
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	assertRefused := func(action string, err error) {
		t.Helper()
		var protocolErr *xacme.Error
		if !errors.As(err, &protocolErr) || protocolErr.StatusCode != http.StatusForbidden {
			t.Errorf("%s after deletion: %v, want definitive HTTP403", action, err)
		}
	}
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("active.example.test")); err != nil {
		t.Fatal(err)
	}
	suspended.Store(true)
	pausedHead, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AuthorizeOrder(ctx, xacme.DomainIDs("suspended.example.test"))
	assertRefused("suspended account order", err)
	if after, err := h.log.LastSequence(ctx); err != nil || after != pausedHead {
		t.Errorf("suspension accepted protocol events: %d -> %d, %v", pausedHead, after, err)
	}
	suspended.Store(false)
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("resumed.example.test")); err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	offboardServedTestTenant(t, h)
	head, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AuthorizeOrder(ctx, xacme.DomainIDs("after-delete.example.test"))
	assertRefused("existing account order", err)
	fresh, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fresh.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
	assertRefused("new account", err)
	if after, err := h.log.LastSequence(ctx); err != nil || after != head {
		t.Errorf("deleted tenant accepted new protocol events: before=%d after=%d err=%v", head, after, err)
	}
}

func TestACMERequestAdmissionExcludesTenantLifecycle(t *testing.T) {
	var hold atomic.Bool
	var once sync.Once
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	h := newOperatingServedHarness(t, config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}, func(d *Deps) {
		d.TenantServiceCheck = func(ctx context.Context, _ string) error {
			if !hold.Load() {
				return nil
			}
			once.Do(func() { close(entered) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	hold.Store(true)
	done := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.ts.URL+"/directory", nil)
		if err != nil {
			done <- err
			return
		}
		response, err := h.ts.Client().Do(req)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = errors.New("admitted directory request failed")
			}
		}
		done <- err
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("request skipped admission: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { return nil }); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Errorf("in-flight ACME request did not exclude lifecycle: %v", err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", func(context.Context) error { return nil }); err != nil {
		t.Errorf("another tenant was blocked: %v", err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("completed request retained service fence: %v", err)
	}
}

func TestReregisteredTenantRejectsPreviousACMEAccount(t *testing.T) {
	protocols := config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}
	h := newOperatingServedHarness(t, protocols)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	old, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	oldOrder, err := old.AuthorizeOrder(ctx, xacme.DomainIDs("original.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	var retained []events.Event
	if err := h.log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.TenantID == h.tenant && (ev.Type == "acme.account.upserted" || ev.Type == "acme.order.created") {
			retained = append(retained, ev)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	offboardServedTestTenant(t, h)
	registerServedTenant(t, h, "Replacement ACME tenant")
	// Model an event publish completing after its producer lost its database
	// session: preserve the observed producer binding but give each delayed
	// envelope a distinct delivery identity, so broker dedupe cannot hide it.
	for _, ev := range retained {
		ev.ID += "-late"
		ev.Sequence = 0
		if _, err := h.log.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := h.srv.acmeOperatorPlan(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ValidationActivity) != 0 {
		t.Errorf("replacement operator sees old authorizations: %+v", plan.ValidationActivity)
	}
	check := func(t *testing.T, baseURL string) *xacme.Client {
		t.Helper()
		prior := &xacme.Client{Key: old.Key, KID: old.KID, DirectoryURL: baseURL + "/directory"}
		before, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = prior.AuthorizeOrder(ctx, xacme.DomainIDs("old-account.example.test"))
		var protocolErr *xacme.Error
		if !errors.As(err, &protocolErr) || protocolErr.StatusCode < 400 || protocolErr.StatusCode >= 500 {
			t.Errorf("previous registration's ACME account accepted: %v", err)
		}
		if err := h.log.Replay(ctx, before+1, func(ev events.Event) error {
			if ev.TenantID == h.tenant && (ev.Type == "acme.order.created" || ev.Type == "acme.account.upserted") {
				t.Errorf("previous account appended authority event: %s at %d", ev.Type, ev.Sequence)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		fresh, err := acmekey.NewClient(baseURL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.GetOrder(ctx, rewriteServedBaseURL(t, oldOrder.URI, baseURL)); err == nil {
			t.Error("replacement account can read prior registration's order")
		}
		if fresh.KID == old.KID {
			t.Error("account URL reused across tenant registrations")
		}
		if _, err := fresh.AuthorizeOrder(ctx, xacme.DomainIDs("replacement.example.test")); err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	var liveFresh *xacme.Client
	t.Run("live", func(t *testing.T) { liveFresh = check(t, h.ts.URL) })
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: protocols})
	if err != nil {
		t.Fatal(err)
	}
	cleanupServedServer(t, restarted)
	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	t.Run("restart", func(t *testing.T) { check(t, ts.URL) })
	if liveFresh == nil {
		t.Fatal("replacement registration did not complete")
	}
	restored := &xacme.Client{Key: liveFresh.Key, KID: liveFresh.KID, DirectoryURL: ts.URL + "/directory"}
	if _, err := restored.AuthorizeOrder(ctx, xacme.DomainIDs("retained-replacement.example.test")); err != nil {
		t.Fatalf("current account lost on restart: %v", err)
	}
}
