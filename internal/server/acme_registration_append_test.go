// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

type capturedACMEAppend struct {
	ctx   context.Context
	event events.Event
}
type capturingACMERegistrationLog struct {
	acmeRegistrationLog
	captured chan capturedACMEAppend
}

func (l capturingACMERegistrationLog) Append(ctx context.Context, event events.Event) (events.Event, error) {
	result, err := l.acmeRegistrationLog.Append(ctx, event)
	if err == nil {
		l.captured <- capturedACMEAppend{context.WithoutCancel(ctx), event}
	}
	return result, err
}

func TestACMEStateAppendRejectsLostRegistrationAndLifecycleBarrier(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	state := acmeRegistrationLog{log: h.log, store: h.store, tenantID: h.tenant}
	captured := make(chan capturedACMEAppend, 1)
	protocol, err := acme.New(nil, nil).WithStateScope(state.scope).WithStateLog(ctx, h.tenant,
		capturingACMERegistrationLog{state, captured})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(tenantProtocolAdmission(h.store.BeginTenantService, h.srv.tenantServiceCheck, h.tenant, protocol))
	t.Cleanup(ts.Close)
	client, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	var original capturedACMEAppend
	select {
	case original = <-captured:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	head, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Append(ctx, original.event); err == nil {
		t.Error("unbound state append accepted")
	}
	foreign := original.event
	foreign.TenantID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := state.Append(original.ctx, foreign); err == nil {
		t.Error("cross-tenant append accepted")
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error {
		_, err := state.Append(original.ctx, original.event)
		if !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Errorf("append crossed lifecycle barrier: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if after, err := h.log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("refused append changed history: %d -> %d, %v", head, after, err)
	}
	offboardServedTestTenant(t, h)
	if _, err := state.Append(original.ctx, original.event); err == nil {
		t.Error("erased registration accepted late append")
	}
	registerServedTenant(t, h, "Replacement late ACME registration")
	head, err = h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Append(original.ctx, original.event); err == nil {
		t.Error("replacement registration accepted old append")
	}
	issuer := &protocolIssuer{store: h.store, log: h.log}
	if _, err := issuer.issueProtocolLeaf(original.ctx, h.tenant, "acme", "old", nil, time.Minute, custody.OriginRequester); !errors.Is(err, errACMERegistrationChanged) {
		t.Errorf("old issuance reached signer/idempotency path: %v", err)
	}
	if err := issuer.revokeProtocolLeaf(original.ctx, h.tenant, "acme", "old", "old", 0, nil); !errors.Is(err, errACMERegistrationChanged) {
		t.Errorf("old revocation reached idempotency path: %v", err)
	}

	if err := state.Replay(original.ctx, 1, func(events.Event) error { t.Error("old replay reached retained events"); return nil }); err == nil {
		t.Error("old replay scope accepted")
	}
	if after, err := h.log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("late append changed replacement history: %d -> %d, %v", head, after, err)
	}
}
