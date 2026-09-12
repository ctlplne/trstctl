// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

type accountRetirementValidator struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (v *accountRetirementValidator) Validate(ctx context.Context, _, _, _, _ string) error {
	v.once.Do(func() { close(v.entered) })
	select {
	case <-v.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAccountRetirementRefusesInFlightWorkWithoutBlockingOtherAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v := &accountRetirementValidator{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(v.release) })
	s := acmesrv.New(mustBuiltin(t), v)
	ts := httptest.NewServer(s)
	defer ts.Close()
	newClient := func() *xacme.Client {
		c, err := acmekey.NewClient(ts.URL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
			t.Fatal(err)
		}
		// x/crypto normally retries 503. Disable that so the bounded refusal
		// itself is observable, rather than waiting for this test's release.
		c.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return -1 }
		return c
	}
	client, other := newClient(), newClient()
	o, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("busy-account.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	az, err := client.GetAuthorization(ctx, o.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() { _, err := client.Accept(ctx, az.Challenges[0]); accepted <- err }()
	select {
	case <-v.entered:
	case <-ctx.Done():
		t.Fatal("validator was not entered")
	}
	err = client.DeactivateReg(ctx)
	var problem *xacme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusServiceUnavailable || problem.Header.Get("Retry-After") != "1" {
		t.Fatalf("busy retirement must refuse promptly: %v", err)
	}
	if _, err = other.AuthorizeOrder(ctx, xacme.DomainIDs("unaffected-account.example.test")); err != nil {
		t.Fatalf("busy account blocked another account: %v", err)
	}
	release.Do(func() { close(v.release) })
	if err := <-accepted; err != nil {
		t.Fatalf("admitted validation failed: %v", err)
	}
	if err := client.DeactivateReg(ctx); err != nil {
		t.Fatalf("retirement after operation finished: %v", err)
	}
	_, err = client.GetOrder(ctx, o.URI)
	requireInactiveACMEAccount(t, err)
	for _, activity := range s.DomainValidationActivities(10) {
		if activity.Domain == "busy-account.example.test" && activity.OrderStatus != "invalid" {
			t.Fatalf("validated order remained usable: %+v", activity)
		}
	}
}
