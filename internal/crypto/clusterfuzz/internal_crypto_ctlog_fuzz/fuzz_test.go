// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

func FuzzCTLog(f *testing.F) {
	// Valid seeds so the corpus also reaches the success paths.
	f.Add(ctlogtest.GetSTHBody(42))
	if der, _, err := ctlogtest.IssueCert("seed", "seed.example.com"); err == nil {
		f.Add(ctlogtest.GetEntriesBody(ctlogtest.X509Entry(der)))
	}
	// Malformed / hostile seeds spanning each decode stage.
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("not json"))
	f.Add([]byte(`{"tree_size":-1}`))                                                    // negative tree size
	f.Add([]byte(`{"entries":[{"leaf_input":"@@@","extra_data":""}]}`))                  // leaf_input not base64
	f.Add([]byte(`{"entries":[{"leaf_input":"AAAB","extra_data":""}]}`))                 // decodes but framing truncated
	f.Add([]byte(`{"entries":[{"leaf_input":"AAAAAAAAAAAAAAD/////","extra_data":""}]}`)) // 24-bit length overflow

	f.Fuzz(func(t *testing.T, body []byte) {
		// ParseSTH must never panic and must never accept a negative tree size.
		if sth, err := ctlog.ParseSTH(body); err == nil {
			if sth.TreeSize < 0 {
				t.Fatalf("ParseSTH accepted a negative tree size: %d", sth.TreeSize)
			}
		}
		// ParseEntries must never panic; if it succeeds, the framing and the
		// embedded certificate were well-formed, so the result is self-consistent.
		entries, err := ctlog.ParseEntries(0, body)
		if err != nil {
			return
		}
		for i, e := range entries {
			if e.Index != int64(i) {
				t.Fatalf("entry %d parsed with non-contiguous index %d", i, e.Index)
			}
			if e.FingerprintSHA256 == "" {
				t.Fatalf("entry %d parsed with an empty fingerprint", i)
			}
		}
	})
}
