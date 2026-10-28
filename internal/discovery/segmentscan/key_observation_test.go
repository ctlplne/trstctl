// SPDX-License-Identifier: BUSL-1.1

package segmentscan

import (
	"strings"
	"testing"
)

// The Part 4 fields admit only lowercase hex hashes and key identifiers, a
// bounded served chain with matching hash lists, and known check codes: a
// relay's report carries no free text.
func TestKeyObservationFieldsAreClosed(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	good := Finding{SPKISHA256: hash, AuthorityKeyID: "34eaea0c", ChainSPKISHA256: []string{hash}, ChainCertSHA256: []string{hash}, WeakKeyChecks: []string{"ec_small_scalar", "key_size"}}
	if err := validateKeyObservation(good); err != nil {
		t.Fatalf("good observation: %v", err)
	}
	for name, bad := range map[string]Finding{
		"uppercase hash":      {SPKISHA256: strings.ToUpper(hash)},
		"short hash":          {SPKISHA256: "abcd"},
		"odd key identifier":  {AuthorityKeyID: "abc"},
		"text key identifier": {AuthorityKeyID: "not hex at all"},
		"unequal chain lists": {ChainSPKISHA256: []string{hash}},
		"long chain":          {ChainSPKISHA256: make([]string, 9), ChainCertSHA256: make([]string, 9)},
		"free-text check":     {WeakKeyChecks: []string{"the key looks weak to me"}},
	} {
		if err := validateKeyObservation(bad); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// A211: the certificate bytes a relay keeps are bounded and follow the served
// chain: issuers only behind a leaf, no more issuers than hashes, at most four,
// none empty or over 16 KiB.
func TestKeptCertificateBytesAreBounded(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	leaf := make([]byte, 600)
	issuer := make([]byte, 700)
	good := Finding{CertificateDER: leaf, ChainDER: [][]byte{issuer}, ChainSPKISHA256: []string{hash}, ChainCertSHA256: []string{hash}}
	if err := validateKeyObservation(good); err != nil {
		t.Fatalf("good kept bytes: %v", err)
	}
	hashes := []string{hash, hash, hash, hash, hash}
	for name, bad := range map[string]Finding{
		"oversized leaf":        {CertificateDER: make([]byte, 16<<10+1)},
		"issuer without a leaf": {ChainDER: [][]byte{issuer}, ChainSPKISHA256: []string{hash}, ChainCertSHA256: []string{hash}},
		"more issuers than hashes": {CertificateDER: leaf, ChainDER: [][]byte{issuer, issuer},
			ChainSPKISHA256: []string{hash}, ChainCertSHA256: []string{hash}},
		"five issuers": {CertificateDER: leaf, ChainDER: [][]byte{issuer, issuer, issuer, issuer, issuer},
			ChainSPKISHA256: hashes, ChainCertSHA256: hashes},
		"empty issuer": {CertificateDER: leaf, ChainDER: [][]byte{{}}, ChainSPKISHA256: []string{hash}, ChainCertSHA256: []string{hash}},
	} {
		if err := validateKeyObservation(bad); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
