// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// countingLog is the shared log as a replica sees it, counting the catch-up
// replays it serves.
type countingLog struct {
	log     *events.Log
	replays atomic.Int64
}

func (l *countingLog) Append(ctx context.Context, e events.Event) (events.Event, error) {
	return l.log.Append(ctx, e)
}

func (l *countingLog) Replay(ctx context.Context, from uint64, fn func(events.Event) error) error {
	l.replays.Add(1)
	return l.log.Replay(ctx, from, fn)
}

func (l *countingLog) LastSequence(ctx context.Context) (uint64, error) {
	return l.log.LastSequence(ctx)
}

// P15-L1: two scoped servers on one state log serve each other's state with
// no affinity: an account registered on A orders on B, A validates the
// challenge of B's order, B reports the order ready, A issues, and B serves
// the certificate. A replica that already caught up to the log's head reads
// nothing more before serving.
func TestScopedServersOnOneLogServeEachOthersStateP15L1(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	const tenantID = "tenant-acme-replicas"
	registration, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tenantID, Data: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	scope := func(context.Context) (acmesrv.StateScope, error) {
		return acmesrv.StateScope{Identity: "registration-p15l1", FirstSequence: registration.Sequence}, nil
	}
	logA, logB := &countingLog{log: log}, &countingLog{log: log}
	a, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateScope(scope).WithStateLog(ctx, tenantID, logA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateScope(scope).WithStateLog(ctx, tenantID, logB)
	if err != nil {
		t.Fatal(err)
	}
	var onB atomic.Bool
	balancer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onB.Load() {
			b.ServeHTTP(w, r)
			return
		}
		a.ServeHTTP(w, r)
	}))
	t.Cleanup(balancer.Close)
	client, err := acmekey.NewRSAClient(balancer.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register on A: %v", err)
	}
	onB.Store(true)
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("replicas.acme.test"))
	if err != nil {
		t.Fatalf("order on B with A's account: %v", err)
	}
	if id := order.URI[strings.LastIndex(order.URI, "/")+1:]; len(strings.Split(id, "-")) != 3 {
		t.Fatalf("a scoped order ID %q has no random part", id)
	}
	onB.Store(false)
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("A reads B's authorization: %v", err)
	}
	for _, chal := range authz.Challenges {
		if chal.Type == "http-01" {
			if _, err := client.Accept(ctx, chal); err != nil {
				t.Fatalf("A takes the challenge of B's order: %v", err)
			}
		}
	}
	onB.Store(true)
	if order, err = client.WaitOrder(ctx, order.URI); err != nil || order.Status != xacme.StatusReady {
		t.Fatalf("B's order after A validated it = %+v %v", order, err)
	}
	onB.Store(false)
	der, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, "replicas.acme.test", []string{"replicas.acme.test"}), true)
	if err != nil || len(der) == 0 {
		t.Fatalf("A finalizes B's order: %v", err)
	}
	onB.Store(true)
	fetched, err := client.FetchCert(ctx, certURL, false)
	if err != nil || len(fetched) == 0 || string(fetched[0]) != string(der[0]) {
		t.Fatalf("B serves A's certificate: %d %v", len(fetched), err)
	}

	// Caught up to the head: B reads nothing more before serving again.
	before := logB.replays.Load()
	if _, err := client.FetchCert(ctx, certURL, false); err != nil {
		t.Fatal(err)
	}
	if logB.replays.Load() != before {
		t.Fatal("a replica at the log's head replayed again")
	}
}
