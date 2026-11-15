// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// persistZone is a small authoritative TXT store: what trstctl's ACME server
// resolves, and where the test solver publishes.
type persistZone struct {
	mu     sync.Mutex
	txt    map[string][]string
	writes int
}

func (z *persistZone) LookupTXT(_ context.Context, name string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[name]...), nil
}

func (z *persistZone) set(name, value string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[name] = []string{value}
	z.writes++
}

func (z *persistZone) remove(name string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.txt, name)
}

func (z *persistZone) snapshot(name string) ([]string, int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[name]...), z.writes
}

// persistSolver answers dns-persist-01 the way the draft describes: publish
// "<issuer-domain-name>; accounturi=<account>" unless it already stands.
type persistSolver struct {
	zone    *persistZone
	publish bool
}

func (s *persistSolver) SolvableChallenges() []string {
	return []string{acmekey.ChallengeDNSPersist01}
}

func (s *persistSolver) Solve(_ context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	if req.Type != acmekey.ChallengeDNSPersist01 || len(req.IssuerDomainNames) == 0 || req.AccountURI == "" {
		return nil, errors.New("persistSolver: not a dns-persist-01 request with issuer and account")
	}
	name := acmesrv.DNSPersistRecordName(req.Identifier)
	accountRef := req.AccountURI
	if req.AccountHashPrefix != "" {
		// P1-ACCOUNTURI: the authority advertised accountHashPrefix.
		hashed, err := acmesrv.DNSPersistHashedAccountURI(req.AccountHashPrefix,
			strings.TrimPrefix(name, "_validation-persist."), req.AccountKeyThumbprint, req.AccountURI)
		if err != nil {
			return nil, err
		}
		accountRef = hashed
	}
	want := acmesrv.DNSPersistRecordValue(req.IssuerDomainNames[0], accountRef, strings.HasPrefix(req.Identifier, "*."))
	if current, _ := s.zone.snapshot(name); s.publish && (len(current) != 1 || current[0] != want) {
		s.zone.set(name, want)
	}
	return nil, nil
}

// P1: trstctl's ACME client, implementing the draft, gets a certificate from
// trstctl's ACME server through dns-persist-01; the second order reuses the
// standing record with no DNS change; with the record deleted, or naming
// another account, the next order fails.
func TestDNSPersistAgainstTrstctlsACMEServer(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl P1 CA")
	if err != nil {
		t.Fatal(err)
	}
	zone := &persistZone{txt: map[string][]string{}}
	server := acmesrv.New(builtin, acmesrv.DefaultValidators()).
		WithDNSPersist([]string{"ca.p1.test"}, acmesrv.DNSPersistValidator{Resolver: zone})
	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)
	solver := &persistSolver{zone: zone, publish: true}
	plugin := newSolvingPlugin(t, ts.URL+"/directory", solver)
	const domain = "app.p1.test"
	name := acmesrv.DNSPersistRecordName(domain)
	issue := func() error {
		issued, err := plugin.Issue(context.Background(), ca.IssueRequest{
			TenantID: "tenant-a", CSR: buildCSR(t, domain, []string{domain}), DNSNames: []string{domain},
		})
		if err == nil && len(issued.CertificatePEM) == 0 {
			return errors.New("no certificate")
		}
		return err
	}

	if err := issue(); err != nil {
		t.Fatalf("first order: %v", err)
	}
	record, writes := zone.snapshot(name)
	if writes != 1 || len(record) != 1 || !strings.HasPrefix(record[0], "ca.p1.test; accounturi="+ts.URL+"/acme/acct/") {
		t.Fatalf("standing record = %q after %d writes", record, writes)
	}
	if err := issue(); err != nil {
		t.Fatalf("second order on the same record: %v", err)
	}
	if _, writes := zone.snapshot(name); writes != 1 {
		t.Fatalf("the second order changed DNS: %d writes", writes)
	}

	solver.publish = false // the operator removed the record; nothing republishes it
	zone.remove(name)
	if err := issue(); err == nil || !strings.Contains(causeOf(err), "no TXT record at "+name+" names this CA") {
		t.Fatalf("an order after the record was deleted: %v (%s)", err, causeOf(err))
	}
	zone.set(name, acmesrv.DNSPersistRecordValue("ca.p1.test", ts.URL+"/acme/acct/999", false))
	if err := issue(); err == nil || !strings.Contains(causeOf(err), "names a different ACME account") {
		t.Fatalf("an order with another account's record: %v (%s)", err, causeOf(err))
	}
}

// causeOf joins every error in err's chain: the plugin keeps the authority's
// problem text out of Error but leaves it unwrappable.
func causeOf(err error) string {
	var texts []string
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		texts = append(texts, e.Error())
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, inner := range u.Unwrap() {
				walk(inner)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return strings.Join(texts, " | ")
}

// TestDNSPersistHashedAccountURIAgainstTrstctlsACMEServerP1ACCOUNTURI: a
// server taking draft-ietf-acme-dns-persist-02's hashed accounturi advertises
// accountHashPrefix; the upstream client reads it, publishes the record with
// the hashed accounturi of its account key and URL, and the order issues; a
// second order reuses it with no DNS change; a record naming the account by
// its URL is refused, saying so.
func TestDNSPersistHashedAccountURIAgainstTrstctlsACMEServerP1ACCOUNTURI(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl P1-ACCOUNTURI CA")
	if err != nil {
		t.Fatal(err)
	}
	zone := &persistZone{txt: map[string][]string{}}
	server := acmesrv.New(builtin, acmesrv.DefaultValidators()).
		WithDNSPersist([]string{"ca.p1.test"}, acmesrv.DNSPersistValidator{Resolver: zone}).
		WithDNSPersistHashedAccountURI(true)
	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)
	solver := &persistSolver{zone: zone, publish: true}
	plugin := newSolvingPlugin(t, ts.URL+"/directory", solver)
	const domain = "hashed.p1.test"
	name := acmesrv.DNSPersistRecordName(domain)
	issue := func() error {
		issued, err := plugin.Issue(context.Background(), ca.IssueRequest{
			TenantID: "tenant-a", CSR: buildCSR(t, domain, []string{domain}), DNSNames: []string{domain},
		})
		if err == nil && len(issued.CertificatePEM) == 0 {
			return errors.New("no certificate")
		}
		return err
	}
	if err := issue(); err != nil {
		t.Fatalf("first order: %v (%s)", err, causeOf(err))
	}
	record, writes := zone.snapshot(name)
	if writes != 1 || len(record) != 1 || !strings.HasPrefix(record[0], "ca.p1.test; accounturi="+ts.URL+"/acme/account-hash/sha-256/") {
		t.Fatalf("standing record = %q after %d writes", record, writes)
	}
	if err := issue(); err != nil {
		t.Fatalf("second order on the same record: %v", err)
	}
	if _, writes := zone.snapshot(name); writes != 1 {
		t.Fatalf("the second order changed DNS: %d writes", writes)
	}
	// The account URL in place of its hash is refused. The server numbers
	// accounts from 1, and this test registers one.
	solver.publish = false
	hashedRecord := record[0]
	zone.set(name, "ca.p1.test; accounturi="+ts.URL+"/acme/acct/1")
	if err := issue(); err == nil || !strings.Contains(causeOf(err), "names the account by its URL") {
		t.Fatalf("an order on an account-URL record: %v (%s)", err, causeOf(err))
	}
	t.Logf("P1ACCOUNTURI_OK record=%q", hashedRecord)
}
