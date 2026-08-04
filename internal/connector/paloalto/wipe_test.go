// SPDX-License-Identifier: MPL-2.0

// The rest of this connector's tests live in the external paloalto_test package,
// which is where they belong: they drive the connector the way the relay does.
// This one file is in-package out of necessity. AN-8 requires the API key to be
// zeroed when the one-shot connector is done with it, and the key is a private
// copy of the caller's bytes, so nothing outside the package can observe whether
// Close wiped it or merely dropped the reference. Externally the two are
// identical; in memory they are not, and the second leaves the key readable in a
// heap dump or a swapped page for as long as the allocation survives. Proving
// the difference is the only reason this file exists.

package paloalto

import "testing"

func TestCloseZeroesTheAPIKey(t *testing.T) {
	key := []byte("pan-os-api-key-do-not-log")
	c := New("https://fw.example", key)

	// Aliases the connector's own buffer before Close nils the field, which is
	// the only handle on it that survives the call.
	buf := c.apiKey
	if len(buf) != len(key) {
		t.Fatalf("connector holds %d key bytes, want %d", len(buf), len(key))
	}

	c.Close()

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("Close left key material in memory at byte %d; buffer=%q", i, buf)
		}
	}
	// New must copy rather than alias, or Close would have destroyed a buffer the
	// caller still owns.
	if string(key) != "pan-os-api-key-do-not-log" {
		t.Errorf("Close wiped the caller's slice: %q", key)
	}
}
