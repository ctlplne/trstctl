// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// P1: the standing record validates only for this CA and this account, a
// wildcard needs policy=wildcard, a passed persistUntil refuses, and a
// record for another CA is ignored.
func TestDNSPersistValidatorChecksIssuerAccountPolicyAndExpiry(t *testing.T) {
	const account = "https://acme.example.test/acme/acct/41"
	issuers := []string{"ca.example.test"}
	now := time.Unix(1_900_000_000, 0)
	validate := func(domain string, records ...string) error {
		return acmesrv.DNSPersistValidator{
			Resolver: fakeResolver{records: map[string][]string{acmesrv.DNSPersistRecordName(domain): records}},
			Now:      func() time.Time { return now },
		}.ValidatePersist(context.Background(), domain, account, issuers)
	}
	ok := acmesrv.DNSPersistRecordValue("CA.example.test.", account, false)
	if ok != "ca.example.test; accounturi="+account {
		t.Fatalf("record value = %q", ok)
	}
	if err := validate("app.example.test", "other-ca.test; accounturi=x", ok); err != nil {
		t.Fatalf("a record for this CA and account was refused: %v", err)
	}
	if err := validate("app.example.test", "CA.EXAMPLE.TEST.;AccountURI="+account+";persistUntil=1900000001"); err != nil {
		t.Fatalf("case, spacing and a future persistUntil should not matter: %v", err)
	}
	for name, tc := range map[string]struct {
		domain  string
		records []string
		want    string
	}{
		"no record":         {"app.example.test", nil, "no TXT record"},
		"another CA only":   {"app.example.test", []string{"other-ca.test; accounturi=" + account}, "no TXT record"},
		"another account":   {"app.example.test", []string{"ca.example.test; accounturi=https://acme.example.test/acme/acct/42"}, "different ACME account"},
		"no accounturi":     {"app.example.test", []string{"ca.example.test; policy=wildcard"}, "no accounturi"},
		"wildcard needs it": {"*.example.test", []string{"ca.example.test; accounturi=" + account}, "policy=wildcard"},
		"persistUntil past": {"app.example.test", []string{"ca.example.test; accounturi=" + account + "; persistUntil=1899999999"}, "persistUntil"},
		"malformed until":   {"app.example.test", []string{"ca.example.test; accounturi=" + account + "; persistUntil=soon"}, "not a Unix time"},
	} {
		err := validate(tc.domain, tc.records...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	if err := validate("*.example.test", acmesrv.DNSPersistRecordValue("ca.example.test", account, true)); err != nil {
		t.Fatalf("a wildcard record with policy=wildcard was refused: %v", err)
	}
	if acmesrv.DNSPersistRecordName("*.example.test") != "_validation-persist.example.test" {
		t.Fatal("a wildcard does not validate at its base domain")
	}
	lookupErr := acmesrv.DNSPersistValidator{Resolver: fakeResolver{err: errors.New("SERVFAIL")}}.
		ValidatePersist(context.Background(), "app.example.test", account, issuers)
	if lookupErr == nil || !strings.Contains(lookupErr.Error(), "SERVFAIL") {
		t.Fatalf("a lookup failure must refuse: %v", lookupErr)
	}
	if err := (acmesrv.DNSPersistValidator{Resolver: fakeResolver{}}).ValidatePersist(context.Background(), "app.example.test", account, nil); err == nil {
		t.Fatal("no configured issuer domain name must refuse")
	}
}

// askedResolver records every name the validator reads.
type askedResolver struct {
	records map[string][]string
	errs    map[string]error
	asked   []string
}

func (r *askedResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.asked = append(r.asked, name)
	if err := r.errs[name]; err != nil {
		return nil, err
	}
	return r.records[name], nil
}

// P1-L2: a policy=wildcard record authorizes every subdomain of its domain
// (draft-ietf-acme-dns-persist-02 §5.1, §6): the name's own record is read
// first, then its parents nearest first, never above the registrable domain.
// Without policy=wildcard a record authorizes its own name only.
func TestDNSPersistPolicyWildcardCoversSubdomainsP1L2(t *testing.T) {
	const account = "https://acme.example.test/acme/acct/41"
	issuers := []string{"ca.example.test"}
	wild := acmesrv.DNSPersistRecordValue("ca.example.test", account, true)
	plain := acmesrv.DNSPersistRecordValue("ca.example.test", account, false)
	check := func(v acmesrv.DNSPersistValidator, domain string) error {
		return v.ValidatePersist(context.Background(), domain, account, issuers)
	}
	validator := func(r *askedResolver) acmesrv.DNSPersistValidator {
		return acmesrv.DNSPersistValidator{Resolver: r}
	}

	parent := &askedResolver{records: map[string][]string{"_validation-persist.example.test": {wild}}}
	for _, domain := range []string{"www.example.test", "a.b.example.test", "*.api.example.test", "example.test", "*.example.test"} {
		parent.asked = nil
		if err := check(validator(parent), domain); err != nil {
			t.Fatalf("%s under a policy=wildcard record at its parent: %v", domain, err)
		}
	}
	parent.asked = nil
	if err := check(validator(parent), "a.b.example.test"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(parent.asked, ","); got != "_validation-persist.a.b.example.test,_validation-persist.b.example.test,_validation-persist.example.test" {
		t.Fatalf("read %s, want the name's own record, then its parents nearest first", got)
	}

	noPolicy := &askedResolver{records: map[string][]string{"_validation-persist.example.test": {plain}}}
	err := check(validator(noPolicy), "www.example.test")
	if err == nil || !strings.Contains(err.Error(), "the record at _validation-persist.example.test names this CA, but it does not allow subdomains (policy=wildcard)") {
		t.Fatalf("a parent record without policy=wildcard: %v", err)
	}
	if err := check(validator(noPolicy), "example.test"); err != nil {
		t.Fatalf("a record without policy=wildcard still authorizes its own name: %v", err)
	}

	// Never above the registrable domain: a record at a public suffix
	// authorizes nothing, and is not even read.
	suffix := &askedResolver{records: map[string][]string{"_validation-persist.co.uk": {wild}, "_validation-persist.test": {wild}}}
	err = check(validator(suffix), "www.example.co.uk")
	if err == nil || !strings.Contains(err.Error(), "no TXT record at _validation-persist.www.example.co.uk names this CA, nor at a parent domain up to _validation-persist.example.co.uk") {
		t.Fatalf("a record at a public suffix: %v", err)
	}
	if got := strings.Join(suffix.asked, ","); got != "_validation-persist.www.example.co.uk,_validation-persist.example.co.uk" {
		t.Fatalf("read %s, want nothing above example.co.uk", got)
	}
	suffix.asked = nil
	if err := check(validator(suffix), "www.nowhere.test"); err == nil {
		t.Fatal("a record above the registrable domain authorized a name")
	}
	for _, name := range suffix.asked {
		if name == "_validation-persist.test" {
			t.Fatal("read a record above the registrable domain")
		}
	}

	// The upstream client reads the name's own record only.
	parent.asked = nil
	if err := check(acmesrv.DNSPersistValidator{Resolver: parent, ExactNameOnly: true}, "www.example.test"); err == nil {
		t.Fatal("ExactNameOnly honored a parent's record")
	}
	if got := strings.Join(parent.asked, ","); got != "_validation-persist.www.example.test" {
		t.Fatalf("ExactNameOnly read %s", got)
	}

	// Each record is its own authorization: a refused record at the name
	// does not hide a parent's that passes, and a name with no record at
	// all (NXDOMAIN) reads on.
	both := &askedResolver{records: map[string][]string{
		"_validation-persist.www.example.test": {"ca.example.test; accounturi=https://acme.example.test/acme/acct/42"},
		"_validation-persist.example.test":     {wild},
	}}
	if err := check(validator(both), "www.example.test"); err != nil {
		t.Fatalf("another account's record at the name hid the parent's: %v", err)
	}
	nx := &askedResolver{
		records: map[string][]string{"_validation-persist.example.test": {wild}},
		errs:    map[string]error{"_validation-persist.www.example.test": &net.DNSError{Err: "no such host", Name: "_validation-persist.www.example.test", IsNotFound: true}},
	}
	if err := check(validator(nx), "www.example.test"); err != nil {
		t.Fatalf("NXDOMAIN at the name: %v", err)
	}
	// Any other lookup failure refuses (fail closed).
	servfail := &askedResolver{errs: map[string]error{"_validation-persist.example.test": errors.New("SERVFAIL")}}
	if err := check(validator(servfail), "www.example.test"); err == nil || !strings.Contains(err.Error(), "lookup _validation-persist.example.test: SERVFAIL") {
		t.Fatalf("a parent's lookup failure: %v", err)
	}

	// Bounded: at most MaxDNSPersistLookups names in all.
	labels := make([]string, 0, acmesrv.MaxDNSPersistLookups)
	for i := 1; i < acmesrv.MaxDNSPersistLookups; i++ {
		labels = append(labels, "l"+strconv.Itoa(i))
	}
	deep := strings.Join(labels, ".") + ".example.test" // 15 labels: its 15 parents end at the apex
	parent.asked = nil
	if err := check(validator(parent), deep); err != nil {
		t.Fatalf("a name %d labels below the record: %v", len(labels), err)
	}
	if len(parent.asked) != acmesrv.MaxDNSPersistLookups {
		t.Fatalf("%d lookups, want %d", len(parent.asked), acmesrv.MaxDNSPersistLookups)
	}
	parent.asked = nil
	if err := check(validator(parent), "l0."+deep); err == nil {
		t.Fatal("a record past the lookup bound was read")
	}
	if len(parent.asked) != acmesrv.MaxDNSPersistLookups {
		t.Fatalf("%d lookups past the bound, want %d", len(parent.asked), acmesrv.MaxDNSPersistLookups)
	}
}
