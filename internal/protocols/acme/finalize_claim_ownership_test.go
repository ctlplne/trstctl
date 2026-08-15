// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestNonOwnerFinalizeCannotDisturbTheOwnersOrder is the regression guard for
// AUD-201 follow-up G1/V15. finalize used to CLAIM the order (statusReady ->
// statusProcessing) inside the lock and verify account ownership only after
// unlocking, so a non-owner — order IDs are sequential and guessable — could
// repeatedly flip a victim's ready order into processing: the ownership 404
// came too late, the deferred release restored ready only after the handler
// finished, and the victim's own concurrent finalize saw 403 orderNotReady. A
// race-window cross-account DoS. With the ownership check inside the locked
// block BEFORE the claim, a hammering non-owner cannot make the owner's
// finalize fail even once.
func TestNonOwnerFinalizeCannotDisturbTheOwnersOrder(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME finalize-claim CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	ctx := context.Background()
	newAccount := func(t *testing.T) *xacme.Client {
		t.Helper()
		c, err := acmekey.NewRSAClient(ts.URL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
			t.Fatalf("register: %v", err)
		}
		return c
	}
	victim := newAccount(t)
	attacker := newAccount(t)

	order, err := victim.AuthorizeOrder(ctx, xacme.DomainIDs("claim-victim.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	finalizeURL := order.FinalizeURL
	order = validateOrder(t, ctx, victim, order)
	if order.FinalizeURL != "" {
		finalizeURL = order.FinalizeURL
	}

	// The attacker hammers finalize on the victim's ready order while the
	// victim performs its one legitimate finalize. Every attacker attempt must
	// bounce off the ownership check WITHOUT claiming the order, so the victim
	// can never observe orderNotReady.
	attackerCSR := buildCSR(t, "claim-victim.test", []string{"claim-victim.test"})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if der, _, err := attacker.CreateOrderCert(ctx, finalizeURL, attackerCSR, false); err == nil {
				t.Errorf("attacker finalized another account's order and got %d bytes", len(der))
				return
			}
		}
	}()

	victimCSR := buildCSR(t, "claim-victim.test", []string{"claim-victim.test"})
	der, _, err := victim.CreateOrderCert(ctx, finalizeURL, victimCSR, true)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("the owner's finalize failed while a non-owner hammered the order: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("the owner got no certificate")
	}
}
