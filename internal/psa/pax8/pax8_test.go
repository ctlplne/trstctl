// SPDX-License-Identifier: BUSL-1.1

package pax8_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/pax8"
	"trstctl.com/trstctl/internal/psa/psatest"
)

const (
	pax8ClientID = "trstctl-vendor-app"
	pax8Secret   = `pax8-client-secret "quoted"\value` // #nosec G101 -- a test-only value with characters JSON must escape (CWE-798)
	pax8Audience = "api://p8p.client"
	subAlpha     = "0f5c5b1e-9a3c-4d0b-8b1a-1a2b3c4d5e6f"
	subBeta      = "1e6d6c2f-8b4d-4e1c-9c2b-2b3c4d5e6f70"
	certProduct  = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	agentProduct = "6b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e"
)

func newClient(t *testing.T, s *psatest.Pax8, secret string) *pax8.Client {
	t.Helper()
	c, err := pax8.New(pax8.Config{BaseURL: s.URL(), TokenURL: s.TokenURL(), Audience: pax8Audience, ClientID: pax8ClientID,
		Products: map[string]pax8.Product{"certificates_current": {ProductID: certProduct, UnitOfMeasurement: "Certificate"},
			"agents": {ProductID: agentProduct, UnitOfMeasurement: "Agent"}}},
		http.DefaultClient, pax8.Credentials{ClientSecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func period(subscription string, certs, agents int64) psa.UsagePeriod {
	start := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	return psa.UsagePeriod{CustomerID: "customer", ExternalCompanyID: subscription, PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
		Lines: []psa.UsageLine{{Meter: "certificates_current", Value: certs}, {Meter: "agents", Value: agents}}}
}

// MSP-8 Done-when (usage, connector): after a client-credentials sign-in, a
// period uploads one line per configured product for the customer's own
// subscription and billing period, with a stable summary key, so a retry the
// same day overwrites rather than adds; another subscription's lines are
// untouched; an unknown subscription and a refused sign-in are refused
// before anything is stored; no error names the secret.
func TestPushUsageUploadsLinesPerSubscriptionMSP8(t *testing.T) {
	ctx := context.Background()
	s := psatest.NewPax8(pax8ClientID, pax8Secret, pax8Audience)
	t.Cleanup(s.Close)
	s.AddSubscription(subAlpha)
	s.AddSubscription(subBeta)
	s.FailWritesAfterApplying(1)
	_, err := newClient(t, s, pax8Secret).PushUsage(ctx, period(subAlpha, 42, 3))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	out, err := newClient(t, s, pax8Secret).PushUsage(ctx, period(subAlpha, 42, 3))
	if err != nil || strings.Join(out.Set, ",") != "agents,certificates_current" {
		t.Fatalf("retry = %+v %v", out, err)
	}
	if _, err := newClient(t, s, pax8Secret).PushUsage(ctx, period(subBeta, 7, 1)); err != nil {
		t.Fatal(err)
	}
	var alpha, beta []psatest.Pax8Line
	for _, l := range s.Lines() {
		if l.BillingPeriod != "2026-10" {
			t.Fatalf("a line for billing period %s", l.BillingPeriod)
		}
		if l.Subscription == subAlpha {
			alpha = append(alpha, l)
		} else {
			beta = append(beta, l)
		}
	}
	if len(alpha) != 2 || len(beta) != 2 {
		t.Fatalf("lines: Alpha %+v, Beta %+v; want two each (the retry overwrote)", alpha, beta)
	}
	for _, l := range alpha {
		if (l.SummaryKey == "trstctl-certificates_current" && (l.Quantity != 42 || l.ProductID != certProduct || l.UnitOfMeasurement != "Certificate")) ||
			(l.SummaryKey == "trstctl-agents" && (l.Quantity != 3 || l.ProductID != agentProduct)) {
			t.Fatalf("Alpha's line = %+v", l)
		}
	}
	posts, _ := s.Counts()
	for _, refused := range []struct {
		subscription, secret string
	}{{"not-a-uuid", pax8Secret}, {"9e9e9e9e-0000-4000-8000-000000000000", pax8Secret}, {subAlpha, "not-the-secret"}} {
		_, err := newClient(t, s, refused.secret).PushUsage(ctx, period(refused.subscription, 1, 1))
		if !errors.Is(err, psa.ErrBeforeWrite) || strings.Contains(err.Error(), "pax8-client-secret") || strings.Contains(err.Error(), "not-the-secret") {
			t.Fatalf("%+v = %v", refused, err)
		}
	}
	if after, _ := s.Counts(); after != posts {
		t.Fatal("a refused upload was stored")
	}
}
