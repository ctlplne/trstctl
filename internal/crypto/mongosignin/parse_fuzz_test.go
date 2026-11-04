// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import "testing"

// FuzzParseURI: no credential panics the parser, and a parsed one has hosts,
// a user, a password and an auth database.
func FuzzParseURI(f *testing.F) {
	for _, seed := range []string{"mongodb://u:p@h/orders?authSource=orders", "mongodb://u:p%40@a:1,b:2/?tls=true&tlsCAFile=/ca.pem",
		"mongodb+srv://u:p@h/db", "mongodb://u:p@[::1]/db?authMechanism=SCRAM-SHA-1", "mongodb://@h"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, credential []byte) {
		target, err := ParseURI(credential)
		if err != nil {
			return
		}
		defer target.Wipe()
		if len(target.Hosts) == 0 || target.User == "" || len(target.Password) == 0 || target.AuthSource == "" {
			t.Fatalf("parsed %q as %+v", credential, target)
		}
	})
}

// FuzzElements: no document panics the reader, and every element it returns
// lies inside the document.
func FuzzElements(f *testing.F) {
	f.Add(Encode([]E{{"hello", int32(1)}, {"client", []E{{"name", "x"}}}, {"list", A{{"0", true}}}, {"payload", []byte("n,,n=u")}}))
	f.Add([]byte{5, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, doc []byte) {
		elems, err := Elements(doc)
		if err != nil {
			return
		}
		total := 5
		for _, e := range elems {
			total += len(e.Raw)
			_, _ = e.Number()
			_, _ = e.Text()
			_, _ = e.Binary()
		}
		if total != len(doc) {
			t.Fatalf("elements cover %d of %d bytes", total, len(doc))
		}
	})
}
