// SPDX-License-Identifier: BUSL-1.1

package rfc2136

import (
	"context"
	"errors"
	"testing"
)

// TestProviderFailsClosedWhenTransactionIDIsUnavailable is guard DNS-001. The
// DNS transaction id is the only thing update() checks on an unauthenticated
// UDP response before it reads the rcode, so a predictable id is an off-path
// spoofing surface. randomID draws from internal/crypto and has no fallback:
// when the draw fails the provider must surface that error and put nothing on
// the wire rather than emit a guessable id.
func TestProviderFailsClosedWhenTransactionIDIsUnavailable(t *testing.T) {
	t.Parallel()

	errNoEntropy := errors.New("entropy source unavailable")
	fx := &recordingExchange{}
	p := New("127.0.0.1:5353", "example.com", Credentials{},
		WithExchange(fx),
		WithID(func() (uint16, error) { return 0, errNoEntropy }))

	if err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "digest"); !errors.Is(err, errNoEntropy) {
		t.Fatalf("DNS-001: PresentTXT err = %v, want %v", err, errNoEntropy)
	}
	if err := p.CleanupTXT(context.Background(), "_acme-challenge.example.com", "digest"); !errors.Is(err, errNoEntropy) {
		t.Fatalf("DNS-001: CleanupTXT err = %v, want %v", err, errNoEntropy)
	}
	if len(fx.messages) != 0 {
		t.Fatalf("DNS-001: provider exchanged %d message(s) after the id draw failed; want 0", len(fx.messages))
	}
}

// TestRandomIDHasNoClockFallback pins the production draw itself: randomID must
// succeed against the real entropy source and must never hand back a
// clock-derived, and therefore guessable, transaction id.
func TestRandomIDHasNoClockFallback(t *testing.T) {
	t.Parallel()

	seen := make(map[uint16]struct{}, 64)
	for i := 0; i < 64; i++ {
		id, err := randomID()
		if err != nil {
			t.Fatalf("DNS-001: randomID: %v", err)
		}
		seen[id] = struct{}{}
	}
	if len(seen) < 32 {
		t.Fatalf("DNS-001: 64 draws produced only %d distinct ids; the transaction id source is not unpredictable", len(seen))
	}
}
