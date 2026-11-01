// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"errors"
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
