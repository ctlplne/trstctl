// SPDX-License-Identifier: BUSL-1.1

package gradient_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/gradient"
	"trstctl.com/trstctl/internal/psa/psatest"
)

const gradientToken = "gradient-vendor-partner-token" // #nosec G101 -- a test-only value (CWE-798)

func period(account string, certs, agents int64) psa.UsagePeriod {
	start := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	return psa.UsagePeriod{CustomerID: "customer", ExternalCompanyID: account, PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
		Lines: []psa.UsageLine{{Meter: "certificates_current", Value: certs}, {Meter: "agents", Value: agents}}}
}

func newClient(t *testing.T, s *psatest.Gradient, token string) *gradient.Client {
	t.Helper()
	c, err := gradient.New(gradient.Config{BaseURL: s.URL(), Services: map[string]string{"certificates_current": "svc-certs", "agents": "svc-agents"}},
		http.DefaultClient, gradient.Credentials{Token: []byte(token)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-7 Done-when (usage, connector): a period posts each service's absolute
// count for the customer's own account; a retry after a lost answer posts
// the same number (never added to); another account's counts are untouched;
// an account the MSP has not mapped in Gradient is refused with nothing
// counted; a wrong token is refused before anything counts; no error names
// the token.
func TestPushUsagePostsAbsoluteCountsPerAccountMSP7(t *testing.T) {
	ctx := context.Background()
	s := psatest.NewGradient(gradientToken)
	t.Cleanup(s.Close)
	for _, service := range []string{"svc-certs", "svc-agents"} {
		s.MapAccount(service, "alpha-dental")
		s.MapAccount(service, "beta-logistics")
	}
	c := newClient(t, s, gradientToken)
	s.FailWritesAfterApplying(1)
	_, err := c.PushUsage(ctx, period("alpha-dental", 42, 3))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	if _, err := c.PushUsage(ctx, period("alpha-dental", 42, 3)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count("svc-certs", "alpha-dental"); n != 42 {
		t.Fatalf("certificates = %d", n)
	}
	if n, _ := s.Count("svc-agents", "alpha-dental"); n != 3 {
		t.Fatalf("agents = %d", n)
	}
	if _, err := c.PushUsage(ctx, period("beta-logistics", 7, 1)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count("svc-certs", "alpha-dental"); n != 42 {
		t.Fatalf("Beta's period changed Alpha's count to %d", n)
	}
	posts, _ := s.Counts()
	_, err = c.PushUsage(ctx, period("unmapped-customer", 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || !strings.Contains(err.Error(), "No account map found") {
		t.Fatalf("an unmapped account = %v", err)
	}
	if after, _ := s.Counts(); after != posts {
		t.Fatal("an unmapped account was counted")
	}
	_, err = newClient(t, s, "not-the-token").PushUsage(ctx, period("alpha-dental", 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || strings.Contains(err.Error(), "not-the-token") || strings.Contains(err.Error(), gradientToken) {
		t.Fatalf("a wrong token = %v", err)
	}
	if n, _ := s.Count("svc-certs", "alpha-dental"); n != 42 {
		t.Fatalf("a refused token changed a count to %d", n)
	}
	if _, err := c.OpenTicket(ctx, psa.TicketOpen{}); !errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("Gradient opened a ticket: %v", err)
	}
}
