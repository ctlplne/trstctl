// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/acme"
)

type servedEABQuotaBarrier struct {
	acmeRegistrationLog
	arrivals atomic.Int32
	release  chan struct{}
	once     sync.Once
}

func (l *servedEABQuotaBarrier) pause(ctx context.Context, typ string) error {
	if typ != "acme.order.created" {
		return nil
	}
	if l.arrivals.Add(1) == 2 {
		l.once.Do(func() { close(l.release) })
	}
	select {
	case <-l.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *servedEABQuotaBarrier) Append(ctx context.Context, event events.Event) (events.Event, error) {
	if err := l.pause(ctx, event.Type); err != nil {
		return events.Event{}, err
	}
	return l.acmeRegistrationLog.Append(ctx, event)
}

func (l *servedEABQuotaBarrier) AppendAtSubjectPosition(ctx context.Context, event events.Event, position events.AppendSubjectPosition) (events.Event, error) {
	if err := l.pause(ctx, event.Type); err != nil {
		return events.Event{}, err
	}
	return l.acmeRegistrationLog.AppendAtSubjectPosition(ctx, event, position)
}

func TestServedACMEEABOrderQuotaIsAtomicAcrossReplicas(t *testing.T) {
	key := bytes.Repeat([]byte{0x73}, 32)
	h := acmeEABScopedHarness(t, []config.ACMEExternalAccountBindingKey{{KeyID: "one-order", HMACKey: key, MaxOrders: 1}})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	state := acmeRegistrationLog{log: h.log, store: h.store, tenantID: h.tenant}
	barrier := &servedEABQuotaBarrier{acmeRegistrationLog: state, release: make(chan struct{})}
	build := func() *acme.Server {
		t.Helper()
		protocol, err := acme.New(nil, acme.DefaultValidators()).WithExternalAccountBindings(true,
			[]acme.ExternalAccountBindingKey{{KeyID: "one-order", HMACKey: key, Policy: acme.EABPolicy{MaxOrders: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		protocol, err = protocol.WithStateScope(state.scope).WithStateLog(ctx, h.tenant, barrier)
		if err != nil {
			t.Fatal(err)
		}
		return protocol
	}
	first, second := build(), build()
	firstHTTP := httptest.NewServer(tenantProtocolAdmission(h.store.BeginTenantService, h.srv.tenantServiceCheck, h.tenant, first))
	secondHTTP := httptest.NewServer(tenantProtocolAdmission(h.store.BeginTenantService, h.srv.tenantServiceCheck, h.tenant, second))
	t.Cleanup(firstHTTP.Close)
	t.Cleanup(secondHTTP.Close)
	firstClient, err := acmekey.NewClient(firstHTTP.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstClient.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{
		KID: "one-order", Key: key,
	}}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	secondClient := &xacme.Client{Key: firstClient.Key, DirectoryURL: secondHTTP.URL + "/directory", KID: firstClient.KID}
	results := make(chan error, 2)
	go func() {
		_, err := firstClient.AuthorizeOrder(ctx, xacme.DomainIDs("first.example.test"))
		results <- err
	}()
	go func() {
		_, err := secondClient.AuthorizeOrder(ctx, xacme.DomainIDs("second.example.test"))
		results <- err
	}()
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "quota") {
			t.Fatalf("losing order did not name its exhausted EAB quota: %v", err)
		}
	}
	if barrier.arrivals.Load() != 2 || successes != 1 {
		t.Fatalf("one EAB grant admitted %d orders; append arrivals=%d", successes, barrier.arrivals.Load())
	}
	for _, protocol := range []*acme.Server{first, second} {
		statuses, err := protocol.EABCredentialsContext(ctx)
		if err != nil || len(statuses) != 1 || statuses[0].OrdersCreated != 1 {
			t.Fatalf("served replica quota projection = %+v, %v", statuses, err)
		}
	}
}
