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
