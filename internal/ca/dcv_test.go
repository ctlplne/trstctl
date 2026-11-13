// SPDX-License-Identifier: BUSL-1.1

package ca_test

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/ca"
)

// A165-L3: an order's names become the base names a vendor validates, once
// each and in order, with every base a wildcard asked for marked — so the
// publisher can hold it to the wildcard rules.
func TestDCVBaseNamesMarksWildcardsA165L3(t *testing.T) {
	bases, wildcard := ca.DCVBaseNames([]string{" App.Example.com ", "*.example.com", "example.com", "*.app.example.com", "", "*."})
	if want := []string{"app.example.com", "example.com"}; !reflect.DeepEqual(bases, want) {
		t.Fatalf("bases = %q, want %q", bases, want)
	}
	if !wildcard["example.com"] || !wildcard["app.example.com"] {
		t.Fatalf("wildcards = %v, want both marked", wildcard)
	}
	if bases, wildcard := ca.DCVBaseNames([]string{"plain.example.com"}); len(bases) != 1 || wildcard["plain.example.com"] {
		t.Fatalf("a plain name = %q %v", bases, wildcard)
	}
}
