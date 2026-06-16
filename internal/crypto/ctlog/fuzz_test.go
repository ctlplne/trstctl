package ctlog_test

import (
	"encoding/binary"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

// FuzzCTLog drives arbitrary bytes through the RFC 6962 response parsers — both
// ParseSTH (JSON) and ParseEntries (JSON → base64 → MerkleTreeLeaf framing →
// embedded X.509 via certinfo). CLAUDE.md §6 requires every untrusted-input
// parser to be fuzzed: a malformed or hostile CT log must fail closed (return an
// error), never panic the monitor and never silently accept impossible data.
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

// TestParseEntriesRejectsHostileFraming plants a battery of malformed
// MerkleTreeLeaf framings and asserts each is rejected (an error, never a panic
// and never a parsed entry) — the directed companion to the fuzz target.
func TestParseEntriesRejectsHostileFraming(t *testing.T) {
	// ts is an 8-byte big-endian timestamp placeholder for the framings that need
	// to advance past the timestamp field.
	ts := func() []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, 1700000000000); return b }

	cases := map[string][]byte{
		"unsupported version":     {9, 0}, // version != V1
		"unsupported leaf type":   {0, 9}, // leaf type != timestamped
		"truncated before ts":     {0, 0}, // no room for the 8-byte timestamp
		"unknown entry type":      append(append([]byte{0, 0}, ts()...), 0x00, 0x99),
		"x509 length overflow":    append(append([]byte{0, 0}, ts()...), 0x00, 0x00, 0xFF, 0xFF, 0xFF), // claims 0xFFFFFF bytes, none present
		"precert empty extradata": append(append([]byte{0, 0}, ts()...), 0x00, 0x01),                   // precert with no extra_data
	}
	for name, leaf := range cases {
		body := ctlogtest.GetEntriesBody(ctlogtest.LogEntry{LeafInput: leaf, ExtraData: nil})
		if _, err := ctlog.ParseEntries(0, body); err == nil {
			t.Errorf("%s: ParseEntries accepted hostile framing, want an error", name)
		}
	}

	// leaf_input that is not valid base64 must also fail closed (raw JSON, since
	// the helper would otherwise base64-encode for us).
	if _, err := ctlog.ParseEntries(0, []byte(`{"entries":[{"leaf_input":"@@@","extra_data":""}]}`)); err == nil {
		t.Error("non-base64 leaf_input was accepted, want an error")
	}
}
