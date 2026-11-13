// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// MSP-8 Done-when (served, Pax8 stand-in written from the public developer
// reference): after a client-credentials sign-in, each customer's signed
// period uploads lines for its own subscription and billing month (A's to
// A's, B's to B's), a lost answer retried the same day without a second
// line; an unknown subscription stores nothing; a held period never reaches
// Pax8; the client secret never appears in the debug log.
func TestServedPax8UsageLinesPerSubscriptionMSP8(t *testing.T) {
	logs := captureDebugLog(t)
	const clientID, secret, audience = "trstctl-vendor-app", "pax8-served-client-secret", "api://p8p.client" // #nosec G101 -- test-only values (CWE-798)
	const subA, subB = "0f5c5b1e-9a3c-4d0b-8b1a-1a2b3c4d5e6f", "1e6d6c2f-8b4d-4e1c-9c2b-2b3c4d5e6f70"
	const product = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	p := psatest.NewPax8(clientID, secret, audience)
	t.Cleanup(p.Close)
	p.AddSubscription(subA)
	p.AddSubscription(subB)
	target := config.ProviderBillingTarget{ID: "pax8", Type: "pax8", Endpoint: p.URL(), AllowInsecureLoopback: true,
		Pax8: &config.Pax8BillingTarget{TokenURL: p.TokenURL(), ClientID: clientID, ClientSecretRef: writeServedCredentialFile(t, "pax8-secret", secret),
			Products: map[string]config.Pax8Product{"certificates_current": {ProductID: product, UnitOfMeasurement: "Certificate"}}}}
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b08"
	u := newUsageOnlyHarness(t, target, customerB, subA, subB)
	u.queue(t, u.h.tenant, u.push(time.October, subA, 42))
	u.queue(t, u.h.tenant, u.push(time.September, subA, 40))
	u.queue(t, customerB, u.push(time.October, subB, 7))
	p.FailWritesAfterApplying(1)
	u.drainUntil(t, "the three periods", func() bool {
		return u.status(u.h.tenant, time.September) == store.BillingSyncDelivered && u.status(u.h.tenant, time.October) == store.BillingSyncDelivered &&
			u.status(customerB, time.October) == store.BillingSyncDelivered
	})
	byKey := map[string]float64{}
	for _, l := range p.Lines() {
		byKey[l.Subscription+" "+l.BillingPeriod] += l.Quantity
		if l.ProductID != product || l.SummaryKey != "trstctl-certificates_current" {
			t.Fatalf("a line = %+v", l)
		}
	}
	if len(p.Lines()) != 3 || byKey[subA+" 2026-09"] != 40 || byKey[subA+" 2026-10"] != 42 || byKey[subB+" 2026-10"] != 7 {
		t.Fatalf("lines = %+v, want one per subscription and month (the retry overwrote)", p.Lines())
	}
	u.mapCompany(t, customerB, "9e9e9e9e-0000-4000-8000-000000000000")
	u.queue(t, customerB, u.push(time.November, "9e9e9e9e-0000-4000-8000-000000000000", 9))
	u.attempted(t, customerB, time.November)
	if len(p.Lines()) != 3 || u.status(customerB, time.November) == store.BillingSyncDelivered {
		t.Fatal("an unknown subscription's usage was stored or recorded delivered")
	}
	posts, _ := p.Counts()
	held := u.push(time.December, subA, 1)
	held.EvidenceJWS, held.Lines, held.Reason = "", nil, "metering coverage has a gap in this period"
	if ok, err := u.h.srv.orch.HoldBillingSyncPush(context.Background(), u.h.tenant, held); err != nil || !ok {
		t.Fatalf("hold December = %v %v", ok, err)
	}
	if err := u.h.srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after, _ := p.Counts(); after != posts {
		t.Fatal("a held period reached Pax8")
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("the debug log carries the client secret")
	}
}
