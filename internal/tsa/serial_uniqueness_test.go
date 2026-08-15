// SPDX-License-Identifier: MPL-2.0

package tsa

import (
	"encoding/json"
	"testing"
	"time"
)

// TestSerialsDoNotRestartFromZeroAcrossAuthorities is the regression guard for
// duplicate token serials.
//
// The counter started at zero, in memory, persisted nowhere, so every process
// restart reissued serials 1, 2, 3 — two genuinely different timestamp tokens
// with the same serial. RFC 3161 §2.4.2 requires the serial to be unique for each
// token a given TSA issues; uniqueness is what lets an archived token be
// referenced unambiguously years later, which is the whole point of timestamping.
//
// A fresh Authority stands in for a restart.
func TestSerialsDoNotRestartFromZeroAcrossAuthorities(t *testing.T) {
	clock := func() time.Time { return time.Unix(1_900_000_000, 0).UTC() }

	const restarts = 12
	seen := make(map[uint64]int, restarts*3)
	for restart := 0; restart < restarts; restart++ {
		a, _ := newTSA(t, clock)
		for i := 0; i < 3; i++ {
			tok, err := a.Timestamp(t.Context(), imprintOf("data"))
			if err != nil {
				t.Fatalf("restart %d: timestamp: %v", restart, err)
			}
			if prev, dup := seen[tok.Info.SerialNumber]; dup {
				t.Fatalf("serial %d was issued by two different authority instances "+
					"(restart %d and %d); a restart reuses serials and two distinct tokens "+
					"become indistinguishable by serial", tok.Info.SerialNumber, prev, restart)
			}
			seen[tok.Info.SerialNumber] = restart
			if tok.Info.SerialNumber == 0 {
				t.Fatal("a token was issued with serial 0")
			}
		}
	}
}

// TestSerialsIncreaseWithinOneAuthority keeps the in-process property: seeding
// randomly must not make serials arbitrary within a single run, where monotonic
// ordering is genuinely useful.
func TestSerialsIncreaseWithinOneAuthority(t *testing.T) {
	a, _ := newTSA(t, func() time.Time { return time.Unix(1_900_000_000, 0).UTC() })
	var prev uint64
	for i := 0; i < 5; i++ {
		tok, err := a.Timestamp(t.Context(), imprintOf("data"))
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && tok.Info.SerialNumber != prev+1 {
			t.Fatalf("serial went %d → %d; within one run serials must increment", prev, tok.Info.SerialNumber)
		}
		prev = tok.Info.SerialNumber
	}
}

// TestSerialStaysExactlyRepresentableInJSON is the guard for the regression this
// randomisation caused the first time.
//
// A 63-bit seed looked fine and broke long-term validation: the token manifest is
// JSON, an audit anchor is exported and re-verified through the CLI, and on that
// path a number can pass through a float64. Above 2^53 that is lossy, so the
// re-encoded manifest stopped matching the bytes that were signed and verification
// failed with nothing more useful than "ECDSA signature invalid".
func TestSerialStaysExactlyRepresentableInJSON(t *testing.T) {
	for i := 0; i < 256; i++ {
		seed, err := randomSerialSeed()
		if err != nil {
			t.Fatal(err)
		}
		if seed == 0 {
			t.Fatal("seed of 0 restarts the counter from the beginning")
		}
		if seed >= maxJSONExactInteger {
			t.Fatalf("seed %d is at or above 2^53, where a JSON round trip through a float64 "+
				"rounds it and manifest verification fails", seed)
		}
		// Round-tripping through the widening decoders a real pipeline uses must
		// return the same value.
		if float64(seed) != float64(uint64(float64(seed))) || uint64(float64(seed)) != seed {
			t.Fatalf("seed %d does not survive a float64 round trip", seed)
		}
	}
}

// TestIssuedSerialSurvivesAJSONRoundTrip exercises the real path: a token
// manifest decoded through a widening decoder must re-encode to the same bytes,
// or its signature will not verify.
func TestIssuedSerialSurvivesAJSONRoundTrip(t *testing.T) {
	a, _ := newTSA(t, func() time.Time { return time.Unix(1_900_000_000, 0).UTC() })
	tok, err := a.Timestamp(t.Context(), imprintOf("anchor"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(tok.Info)
	if err != nil {
		t.Fatal(err)
	}
	// The widening decode a generic pipeline performs.
	var loose map[string]any
	if err := json.Unmarshal(encoded, &loose); err != nil {
		t.Fatal(err)
	}
	widened, ok := loose["serial_number"].(float64)
	if !ok {
		t.Fatalf("serial_number decoded as %T, not a JSON number", loose["serial_number"])
	}
	if uint64(widened) != tok.Info.SerialNumber {
		t.Fatalf("serial %d became %d after a widening JSON decode; the re-encoded manifest "+
			"will not match what was signed", tok.Info.SerialNumber, uint64(widened))
	}
}
