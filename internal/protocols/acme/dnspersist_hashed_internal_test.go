// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// The worked example of draft-ietf-acme-dns-persist-02 §10.2: the RFC 7638
// §3.1 example key's thumbprint, the account URL, and the hashed URIs bound
// to example.com and to no name.
const (
	draftThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	draftAccountURL = "https://ca.example/acct/123"
	draftPrefix     = "https://ca.example/account-hash/"
	draftDomainURI  = "https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
	draftAnyNameURI = "https://ca.example/account-hash/sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"
)

// rfc7638Key is the RFC 7638 §3.1 example public key, whose thumbprint is
// draftThumbprint.
const rfc7638Key = `{"kty":"RSA","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}`

// rfc7517Key is the RFC 7517 Appendix A.1 example P-256 public key.
const rfc7517Key = `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`

type hashedZone map[string][]string

func (z hashedZone) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := z[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// TestDNSPersistHashedAccountURIIsTheDraftsP1ACCOUNTURI: the hashed accounturi
// reproduces draft-ietf-acme-dns-persist-02's §10.2 vectors exactly, for the
// domain and for "*", and refuses what has no hashed form.
func TestDNSPersistHashedAccountURIIsTheDraftsP1ACCOUNTURI(t *testing.T) {
	for _, tc := range []struct{ domain, want string }{
		{"example.com", draftDomainURI},
		{"Example.COM.", draftDomainURI},
		{"*", draftAnyNameURI},
	} {
		got, err := DNSPersistHashedAccountURI(draftPrefix, tc.domain, draftThumbprint, draftAccountURL)
		if err != nil || got != tc.want {
			t.Fatalf("hashed accounturi for %q = %q %v, want %q", tc.domain, got, err, tc.want)
		}
	}
	for name, args := range map[string][4]string{
		"no prefix":      {"", "example.com", draftThumbprint, draftAccountURL},
		"no thumbprint":  {draftPrefix, "example.com", "", draftAccountURL},
		"no account":     {draftPrefix, "example.com", draftThumbprint, ""},
		"domain too big": {draftPrefix, strings.Repeat("a", 256), draftThumbprint, draftAccountURL},
	} {
		if _, err := DNSPersistHashedAccountURI(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatalf("%s: a hashed accounturi was made", name)
		}
	}
	if key, err := jose.ACMEKeyFromJWK([]byte(rfc7638Key)); err != nil || key.Thumbprint() != draftThumbprint {
		t.Fatalf("the RFC 7638 example key's thumbprint = %v, want %s", err, draftThumbprint)
	}
}

// TestDNSPersistValidatorTakesEachAccountURIFormP1ACCOUNTURI: with an account
// hash prefix the validator takes the record's hashed accounturi (bound to the
// name it stands at or to "*", under any key the account has held) and
// refuses the account URL; without one it takes the account URL as before.
func TestDNSPersistValidatorTakesEachAccountURIFormP1ACCOUNTURI(t *testing.T) {
	issuers := []string{"authority.example"}
	record := func(accountURI string) string { return DNSPersistRecordValue("authority.example", accountURI, false) }
	validate := func(prefix string, acct DNSPersistAccount, txt string) error {
		return DNSPersistValidator{
			Resolver:          hashedZone{"_validation-persist.example.com": {txt}},
			AccountHashPrefix: prefix,
		}.ValidatePersistAccount(context.Background(), "example.com", acct, issuers)
	}
	current := DNSPersistAccount{URL: draftAccountURL, KeyThumbprints: []string{draftThumbprint}}
	if err := validate(draftPrefix, current, record(draftDomainURI)); err != nil {
		t.Fatalf("the draft's record was refused: %v", err)
	}
	if err := validate(draftPrefix, current, record(draftAnyNameURI)); err != nil {
		t.Fatalf("a record bound to no name was refused: %v", err)
	}
	rolled := DNSPersistAccount{URL: draftAccountURL, KeyThumbprints: []string{"another-current-key-thumbprint", draftThumbprint}}
	if err := validate(draftPrefix, rolled, record(draftDomainURI)); err != nil {
		t.Fatalf("a record under a key the account held before was refused: %v", err)
	}
	for name, tc := range map[string]struct {
		acct DNSPersistAccount
		txt  string
		want string
	}{
		"account URL":       {current, record(draftAccountURL), "names the account by its URL"},
		"another key":       {DNSPersistAccount{URL: draftAccountURL, KeyThumbprints: []string{"another-key"}}, record(draftDomainURI), "different ACME account"},
		"another account":   {DNSPersistAccount{URL: "https://ca.example/acct/124", KeyThumbprints: []string{draftThumbprint}}, record(draftDomainURI), "different ACME account"},
		"another name":      {current, record(strings.Replace(draftDomainURI, "5SQm7n6t", "5SQm7n6u", 1)), "different ACME account"},
		"another prefix":    {current, record(strings.Replace(draftDomainURI, "account-hash", "other-hash", 1)), "different ACME account"},
		"no key thumbprint": {DNSPersistAccount{URL: draftAccountURL}, record(draftDomainURI), "different ACME account"},
	} {
		if err := validate(draftPrefix, tc.acct, tc.txt); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// The account URL form, as Pebble 2.10 takes it: a hashed record names
	// no account it knows.
	if err := validate("", current, record(draftAccountURL)); err != nil {
		t.Fatalf("the account URL form was refused without a hash prefix: %v", err)
	}
	if err := validate("", current, record(draftDomainURI)); err == nil {
		t.Fatal("a hashed record validated without a hash prefix")
	}
}

// TestAccountKeyRolloverKeepsItsEarlierThumbprintsP1ACCOUNTURI: replaying an
// account's events keeps the thumbprint of each key it rolled over from, so a
// hashed record made under an earlier key still validates, and a server
// taking the hashed form advertises accountHashPrefix and derives it from the
// account's URL.
func TestAccountKeyRolloverKeepsItsEarlierThumbprintsP1ACCOUNTURI(t *testing.T) {
	s := New(nil, AcceptAll{})
	first, err := jose.ACMEKeyFromJWK([]byte(rfc7638Key))
	if err != nil {
		t.Fatal(err)
	}
	second, err := jose.ACMEKeyFromJWK([]byte(rfc7517Key))
	if err != nil {
		t.Fatal(err)
	}
	const url = "https://ca.example/acme/acct/7"
	for _, key := range []struct {
		jwk string
		k   *jose.ACMEKey
	}{{rfc7638Key, first}, {rfc7517Key, second}} {
		if err := s.applyAccountEventLocked(acmeAccountEvent{ID: key.k.Thumbprint(), URL: url, JWK: json.RawMessage(key.jwk), Status: statusValid}); err != nil {
			t.Fatal(err)
		}
	}
	acct := s.accounts[url]
	if acct == nil || acct.id != second.Thumbprint() || len(acct.priorThumbprints) != 1 || acct.priorThumbprints[0] != draftThumbprint {
		t.Fatalf("after a rollover the account is %+v", acct)
	}
	prefix := DNSPersistAccountHashPrefix("https://ca.example")
	old, err := DNSPersistHashedAccountURI(prefix, "app.example.com", draftThumbprint, url)
	if err != nil {
		t.Fatal(err)
	}
	s.WithDNSPersist([]string{"authority.example"}, DNSPersistValidator{
		Resolver: hashedZone{"_validation-persist.app.example.com": {DNSPersistRecordValue("authority.example", old, false)}},
	}).WithDNSPersistHashedAccountURI(true)
	if err := s.validateDNSPersist(context.Background(), "app.example.com", acct); err != nil {
		t.Fatalf("a hashed record under the account's earlier key was refused: %v", err)
	}
	if meta := s.directoryMeta("https://ca.example"); meta["accountHashPrefix"] != prefix {
		t.Fatalf("directory meta = %v, want accountHashPrefix %s", meta, prefix)
	}
	if s.WithDNSPersistHashedAccountURI(false); s.directoryMeta("https://ca.example")["accountHashPrefix"] != nil {
		t.Fatal("the account URL form advertised an account hash prefix")
	}
	if err := s.validateDNSPersist(context.Background(), "app.example.com", acct); err == nil {
		t.Fatal("the account URL form took a hashed record")
	}
}
