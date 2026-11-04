// SPDX-License-Identifier: BUSL-1.1

package mysqlsignin

import "testing"

// FuzzParseHandshake: no server handshake panics the parser, and a parsed one
// has a 20-byte scramble.
func FuzzParseHandshake(f *testing.F) {
	if seed, err := ClientHandshake(serverHandshake()); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'n', 'o'})
	f.Fuzz(func(t *testing.T, p []byte) {
		h, err := ParseHandshake(p)
		if err == nil && len(h.Scramble) != 20 {
			t.Fatalf("scramble of %d bytes from %q", len(h.Scramble), p)
		}
	})
}

// FuzzParseClientResponse: no client handshake response panics the parser.
func FuzzParseClientResponse(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add(append(make([]byte, 32), "u\x00\x03abcdb\x00"...))
	f.Fuzz(func(t *testing.T, p []byte) { _, _ = ParseClientResponse(p) })
}

// FuzzParseDSN: no DSN panics the parser, and a parsed one has an address,
// a user and a password.
func FuzzParseDSN(f *testing.F) {
	f.Add([]byte("u:p@tcp(h:1)/db"))
	f.Add([]byte("u:p@tcp(h:1)/"))
	f.Fuzz(func(t *testing.T, dsn []byte) {
		target, err := ParseDSN(dsn)
		if err != nil {
			return
		}
		defer target.Wipe()
		if target.Address == "" || target.User == "" || len(target.Password) == 0 {
			t.Fatalf("parsed %q as %+v", dsn, target)
		}
	})
}
