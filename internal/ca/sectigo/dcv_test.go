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
