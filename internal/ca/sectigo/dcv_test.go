// SPDX-License-Identifier: BUSL-1.1

package sectigo_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/sectigo/sectigofake"
)

type zone struct {
	mu      sync.Mutex
	records map[string][]string
	written []string
	refuse  error
}

func (z *zone) PublishTXT(_ context.Context, _, _, recordName, value string) (func(context.Context) error, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.refuse != nil {
		return nil, z.refuse
	}
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

// A165: with a DNS publisher, SCM's TXT validation completes before enrollment
// with no human step, and the records are retracted; without validation SCM
// refuses the enrollment, and a publisher that cannot publish stops it first.
func TestPluginCompletesSCMDCVUnattended(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	z := &zone{records: map[string][]string{}}
	srv.RequireDCV(z.resolve)
	ctx := context.Background()
	req := func(names ...string) ca.IssueRequest {
		return ca.IssueRequest{TenantID: "t1", CSR: sectigoCSR(t, names[0]), DNSNames: names, TTL: 90 * 24 * time.Hour}
	}
	plain := sectigo.New(config(srv), sectigo.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	if _, err := plain.Issue(ctx, req("svc.sectigo.test")); err == nil {
		t.Fatal("SCM issued for a domain nobody validated")
	}
	p := sectigo.New(config(srv), sectigo.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}), sectigo.WithPollInterval(time.Millisecond), sectigo.WithDCVPublisher(z))
	cert, err := p.Issue(ctx, req("svc.sectigo.test", "*.apps.sectigo.test"))
	if err != nil {
		t.Fatalf("Issue with DCV: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || len(z.written) != 2 || len(z.records) != 0 {
		t.Fatalf("issued %d bytes after publishing %v; records left %v", len(cert.CertificatePEM), z.written, z.records)
	}
	z.refuse = errors.New("no DNS-01 provider config covers this zone")
	if _, err := p.Issue(ctx, req("other.sectigo.test")); err == nil || !strings.Contains(err.Error(), "no DNS-01 provider config") {
		t.Fatalf("Issue with a publisher that cannot publish = %v; want the publisher's reason", err)
	}
}

// observingZone is a zone that also records validation outcomes, as the
// server's DNS-01 binding does.
type observingZone struct {
	*zone
	mu       sync.Mutex
	outcomes []ca.DomainValidation
}

func (o *observingZone) ObserveDomainValidation(_ context.Context, _ string, out ca.DomainValidation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcomes = append(o.outcomes, out)
}

// A165-L2: each domain SCM validates through the published TXT record is
// reported as a fresh dns-txt validation, and a domain SCM already holds
// validated is reported as a reuse with nothing published, the way upstream
// ACME authorizations are reported.
func TestPluginReportsSCMValidationsAndReuse(t *testing.T) {
	srv, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	z := &observingZone{zone: &zone{records: map[string][]string{}}}
	srv.RequireDCV(z.resolve)
	ctx := context.Background()
	p := sectigo.New(config(srv), sectigo.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}), sectigo.WithPollInterval(time.Millisecond), sectigo.WithDCVPublisher(z))
	issue := func(name string) {
		t.Helper()
		if _, err := p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: sectigoCSR(t, name), DNSNames: []string{name}, TTL: 90 * 24 * time.Hour}); err != nil {
			t.Fatalf("Issue %s: %v", name, err)
		}
	}
	issue("svc.sectigo.test")
	issue("svc.sectigo.test")
	z.mu.Lock()
	defer z.mu.Unlock()
	if len(z.outcomes) != 2 ||
		z.outcomes[0] != (ca.DomainValidation{Identifier: "svc.sectigo.test", Method: ca.DomainValidationMethodDNSTXT}) ||
		z.outcomes[1] != (ca.DomainValidation{Identifier: "svc.sectigo.test", Reused: true}) {
		t.Fatalf("reported validations = %+v; want one dns-txt validation, then one reuse", z.outcomes)
	}
	if len(z.written) != 1 {
		t.Fatalf("published %v; the reuse must publish nothing", z.written)
	}
}
