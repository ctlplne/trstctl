// SPDX-License-Identifier: MPL-2.0

package ctlog_test

import (
	"encoding/binary"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

// FuzzCTLog drives arbitrary bytes through the RFC 6962 response parsers — both
// ParseSTH (JSON) and ParseEntries (JSON → base64 → MerkleTreeLeaf framing →
// embedded X.509 via certinfo). TEST-FUZZASSERT-001 requires every untrusted-input
// parser to be fuzzed: a malformed or hostile CT log must fail closed (return an
// error), never panic the monitor and never silently accept impossible data.

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
