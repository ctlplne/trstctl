// SPDX-License-Identifier: BUSL-1.1

package cryptorisk

import (
	"testing"
	"time"
)

// The deadlines are IR 8547's tables (initial public draft, Tables 2 and 4): at
// 112 bits of security strength a quantum-vulnerable algorithm is deprecated
// after 2030 and disallowed after 2035; at 128 bits or more it is disallowed
// after 2035; below 112 bits it is outside the tables and replaced now.
func TestDeadlinesFollowIR8547Tables(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		algorithm         string
		bits              int
		status            string
		strength          int
		deprecated, until int
		assumed           bool
	}{
		{"RSA", 1024, DeadlineReplaceNow, 0, 0, 0, false},
		{"RSA", 2048, DeadlineUpcoming, 112, 2030, 2035, false},
		{"RSA", 3072, DeadlineUpcoming, 128, 0, 2035, false},
		{"RSA", 4096, DeadlineUpcoming, 128, 0, 2035, false},
		{"ECDSA", 224, DeadlineUpcoming, 112, 2030, 2035, false},
		{"ECDSA", 256, DeadlineUpcoming, 128, 0, 2035, false},
		{"ECDSA P-384", 384, DeadlineUpcoming, 192, 0, 2035, false},
		{"ECDH", 160, DeadlineReplaceNow, 0, 0, 0, false},
		{"Ed25519", 256, DeadlineUpcoming, 128, 0, 2035, false},
		{"Ed448", 456, DeadlineUpcoming, 224, 0, 2035, false},
		{"X25519", 0, DeadlineUpcoming, 128, 0, 2035, false},
		{"DH", 2048, DeadlineUpcoming, 112, 2030, 2035, false},
		{"RSA", 0, DeadlineUpcoming, 112, 2030, 2035, true},
		{"DSA", 2048, DeadlineReplaceNow, 0, 0, 0, false},
		{"ML-DSA-65", 0, DeadlineNone, 0, 0, 0, false},
		{"ML-KEM-768", 0, DeadlineNone, 0, 0, 0, false},
		{"AES-256-GCM", 256, DeadlineNone, 0, 0, 0, false},
	} {
		d := DeadlineFor(tc.algorithm, tc.bits, false, now)
		if d.Status != tc.status || d.SecurityBits != tc.strength || d.DeprecatedAfter != tc.deprecated ||
			d.DisallowedAfter != tc.until || (d.Assumed != "") != tc.assumed || d.Source != IR8547Source || d.Rule == "" {
			t.Errorf("%s/%d = %+v", tc.algorithm, tc.bits, d)
		}
	}
	if d := DeadlineFor("Mystery", 0, false, now); d.Status != DeadlineNone || d.Assumed == "" {
		t.Fatalf("an unrecognized algorithm must say it applied no rule: %+v", d)
	}
}

// The status moves with time: past the deprecation year a 112-bit key is
// deprecated, past the disallow year any quantum-vulnerable key is replaced now,
// and a weak key is replaced now whatever its size.
func TestDeadlineStatusMovesWithTime(t *testing.T) {
	at := func(year int) time.Time { return time.Date(year, 6, 1, 0, 0, 0, 0, time.UTC) }
	if d := DeadlineFor("RSA", 2048, false, at(2030)); d.Status != DeadlineUpcoming {
		t.Fatalf("2030: %+v", d)
	}
	if d := DeadlineFor("RSA", 2048, false, at(2031)); d.Status != DeadlineDeprecated {
		t.Fatalf("2031: %+v", d)
	}
	if d := DeadlineFor("RSA", 4096, false, at(2031)); d.Status != DeadlineUpcoming {
		t.Fatalf("a 128-bit key is not deprecated in 2031: %+v", d)
	}
	if d := DeadlineFor("ECDSA", 256, false, at(2036)); d.Status != DeadlineReplaceNow {
		t.Fatalf("2036: %+v", d)
	}
	if d := DeadlineFor("RSA", 4096, true, at(2026)); d.Status != DeadlineReplaceNow {
		t.Fatalf("a weak key: %+v", d)
	}
}
