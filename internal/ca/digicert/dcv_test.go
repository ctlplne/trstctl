// SPDX-License-Identifier: BUSL-1.1

package digicert_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
)

// zone is an in-memory DNS provider: what the publisher writes, the CA reads.
type zone struct {
	mu       sync.Mutex
	records  map[string][]string
	written  []string
	refuse   error
	tenantID string
}

func (z *zone) PublishTXT(_ context.Context, tenantID, _, recordName, value string) (func(context.Context) error, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.refuse != nil {
		return nil, z.refuse
	}
	z.tenantID = tenantID
	z.records[recordName] = append(z.records[recordName], value)
	z.written = append(z.written, recordName)
	return func(context.Context) error {
		z.mu.Lock()
		defer z.mu.Unlock()
		delete(z.records, recordName)
		return nil
	}, nil
}

func (z *zone) resolve(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.records[name]...)
}

// A165: with a DNS publisher, CertCentral's DNS TXT validation completes with no
// human step — the order's random value is published at _dnsauth.<name> for
// every requested name, CertCentral checks it, the certificate issues, and the
// records are retracted. A publisher that cannot publish stops the order with
// that reason and issues nothing.
func TestPluginCompletesCertCentralDCVUnattended(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	z := &zone{records: map[string][]string{}}
	srv.RequireDCV(z.resolve)
	p := digicert.New("digicert", srv.URL(), []byte(srv.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}), digicert.WithDCVPublisher(z))
	names := []string{"svc.digicert.test", "*.apps.digicert.test"}
	cert, err := p.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: digicertCSR(t, names[0]), DNSNames: names, TTL: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("Issue with DCV: %v", err)
	}
	if len(cert.CertificatePEM) == 0 {
		t.Fatal("no certificate after DCV")
	}
	if strings.Join(z.written, ",") != "_dnsauth.svc.digicert.test,_dnsauth.apps.digicert.test" || z.tenantID != "t1" {
		t.Fatalf("published %v for tenant %q; want each name's _dnsauth record for t1", z.written, z.tenantID)
	}
	if len(z.records) != 0 {
		t.Fatalf("DCV records left behind: %v", z.records)
	}

	z.refuse = errors.New("no DNS-01 provider config covers this zone")
	if _, err := p.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: digicertCSR(t, "other.digicert.test"), DNSNames: []string{"other.digicert.test"}, TTL: 24 * time.Hour}); err == nil ||
		!strings.Contains(err.Error(), "no DNS-01 provider config") {
		t.Fatalf("Issue with a publisher that cannot publish = %v; want the publisher's reason", err)
	}
}

// A165-L4: CertCentral is asked until it sees the records or the validation
// budget runs out — not a fixed ten times — so a record that appears only
// after the tenth check still validates, and one that never appears fails
// naming the budget.
func TestPluginWaitsOutSlowDNSWithinTheDCVBudgetA165L4(t *testing.T) {
	srv, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	z := &zone{records: map[string][]string{}}
	var checks atomic.Int32
	srv.RequireDCV(func(name string) []string {
		if checks.Add(1) <= 11 {
			return nil
		}
		return z.resolve(name)
	})
	p := digicert.New("digicert", srv.URL(), []byte(srv.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
		digicert.WithDCVPublisher(z), digicert.WithPollInterval(time.Millisecond), digicert.WithDCVTimeout(30*time.Second))
	if _, err := p.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: digicertCSR(t, "slow.digicert.test"),
		DNSNames: []string{"slow.digicert.test"}, TTL: 24 * time.Hour}); err != nil || checks.Load() <= 10 {
		t.Fatalf("a record seen after the tenth check = %v (%d checks)", err, checks.Load())
	}

	never, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(never.Close)
	never.RequireDCV(func(string) []string { return nil })
	q := digicert.New("digicert", never.URL(), []byte(never.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
		digicert.WithDCVPublisher(&zone{records: map[string][]string{}}), digicert.WithPollInterval(time.Millisecond), digicert.WithDCVTimeout(50*time.Millisecond))
	if _, err := q.Issue(context.Background(), ca.IssueRequest{TenantID: "t1", CSR: digicertCSR(t, "never.digicert.test"),
		DNSNames: []string{"never.digicert.test"}, TTL: 24 * time.Hour}); err == nil || !strings.Contains(err.Error(), "within 50ms") {
		t.Fatalf("a record never seen = %v; want the budget named", err)
	}
}

// A165-L4: the backoff starts at the poll interval and doubles to 30 seconds.
func TestDCVBackoffDoublesToThirtySecondsA165L4(t *testing.T) {
	for attempt, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		if got := ca.DCVBackoff(time.Second, attempt); got != want {
			t.Fatalf("attempt %d waits %s, want %s", attempt, got, want)
		}
	}
	if got := ca.DCVBackoff(0, 0); got != 500*time.Millisecond {
		t.Fatalf("an unset interval starts at %s, want 500ms", got)
	}
}
