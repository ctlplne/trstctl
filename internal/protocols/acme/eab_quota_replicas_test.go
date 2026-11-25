// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// quotaBarrierLog makes both replicas pass their local quota check before
// either order event can enter the shared journal. The broker then decides
// which of the two may spend the one remaining grant.
type quotaBarrierLog struct {
	log      *events.Log
	arrivals atomic.Int32
	release  chan struct{}
	once     sync.Once
}

func (l *quotaBarrierLog) pause(ctx context.Context, typ string) error {
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

func (l *quotaBarrierLog) Append(ctx context.Context, event events.Event) (events.Event, error) {
	if err := l.pause(ctx, event.Type); err != nil {
		return events.Event{}, err
	}
	return l.log.Append(ctx, event)
}

func (l *quotaBarrierLog) Replay(ctx context.Context, from uint64, apply func(events.Event) error) error {
	return l.log.Replay(ctx, from, apply)
}

func (l *quotaBarrierLog) LastSequence(ctx context.Context) (uint64, error) {
	return l.log.LastSequence(ctx)
}

func (l *quotaBarrierLog) ObserveAppendSubject(ctx context.Context, tenantID, typ string) (events.AppendSubjectPosition, error) {
	return l.log.ObserveAppendSubject(ctx, tenantID, typ)
}

func (l *quotaBarrierLog) AppendAtSubjectPosition(ctx context.Context, event events.Event, position events.AppendSubjectPosition) (events.Event, error) {
	if err := l.pause(ctx, event.Type); err != nil {
		return events.Event{}, err
	}
	return l.log.AppendAtSubjectPosition(ctx, event, position)
}

func TestEABOrderQuotaIsAtomicAcrossReplicas(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	log := openACMEStateLog(t)
	const tenantID = "eab-concurrent-quota"
	registration, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tenantID, Data: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	scope := func(context.Context) (acmesrv.StateScope, error) {
		return acmesrv.StateScope{Identity: registration.ID, FirstSequence: registration.Sequence}, nil
	}
	barrier := &quotaBarrierLog{log: log, release: make(chan struct{})}
	key := bytes.Repeat([]byte{0x71}, 32)
	build := func() *acmesrv.Server {
		t.Helper()
		srv, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithExternalAccountBindings(true,
			[]acmesrv.ExternalAccountBindingKey{{KeyID: "one-order", HMACKey: key, Policy: acmesrv.EABPolicy{MaxOrders: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		srv, err = srv.WithStateScope(scope).WithStateLog(ctx, tenantID, barrier)
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}
	first, second := build(), build()
	firstHTTP, secondHTTP := httptest.NewServer(first), httptest.NewServer(second)
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
		}
	}
	if barrier.arrivals.Load() != 2 {
		t.Fatalf("both replicas did not reach the order event: %d", barrier.arrivals.Load())
	}
	if successes != 1 {
		t.Fatalf("one lifetime EAB grant admitted %d simultaneous orders, want one", successes)
	}
	for _, replica := range []*acmesrv.Server{first, second} {
		statuses, err := replica.EABCredentialsContext(ctx)
		if err != nil || len(statuses) != 1 || statuses[0].OrdersCreated != 1 {
			t.Fatalf("replica quota projection = %+v, %v; want one order", statuses, err)
		}
	}
}
