// SPDX-License-Identifier: BUSL-1.1

package digicert_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
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
