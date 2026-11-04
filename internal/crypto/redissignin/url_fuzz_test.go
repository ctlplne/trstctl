// SPDX-License-Identifier: BUSL-1.1

package redissignin

import "testing"

// FuzzParseURL: no credential URL panics the parser, and a parsed one has an
// address, a user and a password.
func FuzzParseURL(f *testing.F) {
	for _, seed := range []string{"redis://u:p@h:1/0", "rediss://u%40x:p%3A@[::1]:6379/15", "redis://u:p@h:1", "redis://@", "redis://u:%@h:1"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, credential []byte) {
		target, err := ParseURL(credential)
		if err != nil {
			return
		}
		defer target.Wipe()
		if target.Address == "" || target.User == "" || len(target.Password) == 0 {
			t.Fatalf("parsed %q as %+v", credential, target)
		}
	})
}
