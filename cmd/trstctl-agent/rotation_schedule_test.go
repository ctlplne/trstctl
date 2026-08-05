// SPDX-License-Identifier: MPL-2.0

package main

import (
	"math/rand"
	"testing"
	"time"
)

// An agent must never sleep through its own expiry (epic A5).
//
// The rotate timer was the configured interval and nothing else, so the agent's
// credential lifetime had no say in when it next tried to renew. That is fine
// until it is not, and the cases where it is not are ordinary: an operator sets
// --rotate-every longer than the certificate lifetime; a control-plane outage
// spans a whole interval so the single attempt inside it fails and the next is
// a full interval away; an agent restarts holding a credential already most of
// the way through its life.
//
// Each ends the same way — the agent wakes after its certificate expired and
// can no longer authenticate to renew it, which needs a human on the box. For a
// fleet whose value is not needing one, that is the failure that matters.

func TestTheAgentNeverSleepsPastItsOwnExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewSource(1)) // #nosec G404 -- jitter spread, not a security decision (CWE-338)

	cases := []struct {
		name        string
		rotateEvery time.Duration
		remaining   time.Duration
	}{
		{"interval far longer than the credential lifetime", 12 * time.Hour, 30 * time.Minute},
		{"interval a little longer than what is left", time.Hour, 50 * time.Minute},
		{"restarted holding a nearly-dead credential", 12 * time.Hour, 2 * time.Minute},
		{"comfortable margin", time.Hour, 90 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notAfter := now.Add(tc.remaining)
			delay := nextRotationDelay(tc.rotateEvery, notAfter, now, rng)
			if delay >= tc.remaining {
				t.Fatalf("next attempt in %v with only %v of credential life left: the agent "+
					"wakes up expired and can no longer authenticate to renew itself",
					delay, tc.remaining)
			}
			if delay <= 0 {
				t.Fatalf("delay = %v; a non-positive delay spins the rotate loop", delay)
			}
		})
	}
}

// The configured cadence still governs when there is plenty of life left — the
// expiry bound is a ceiling, not a replacement.
func TestTheConfiguredCadenceStillGovernsAHealthyCredential(t *testing.T) {
	t.Parallel()
	now := time.Now()
	rng := rand.New(rand.NewSource(2)) // #nosec G404 -- jitter spread (CWE-338)
	// 90 days left, 12-hour cadence: two thirds of the remaining life is 60
	// days, so the cadence is what should apply.
	delay := nextRotationDelay(12*time.Hour, now.Add(90*24*time.Hour), now, rng)
	if delay > 13*time.Hour {
		t.Fatalf("delay = %v; a healthy credential must still rotate on its configured cadence", delay)
	}
	if delay < 10*time.Hour {
		t.Fatalf("delay = %v; jitter must not collapse the configured cadence", delay)
	}
}

// An already-expired credential retries promptly rather than waiting a cadence.
func TestAnExpiredCredentialRetriesPromptly(t *testing.T) {
	t.Parallel()
	now := time.Now()
	rng := rand.New(rand.NewSource(3)) // #nosec G404 -- jitter spread (CWE-338)
	delay := nextRotationDelay(12*time.Hour, now.Add(-time.Hour), now, rng)
	if delay > 5*time.Second {
		t.Fatalf("delay = %v after expiry; the agent must try again promptly rather than "+
			"waiting out a full cadence with a dead credential", delay)
	}
}

// No known expiry falls back to the cadence rather than inventing urgency.
func TestAnUnknownExpiryFallsBackToTheCadence(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(4)) // #nosec G404 -- jitter spread (CWE-338)
	if got := nextRotationDelay(90*time.Minute, time.Time{}, time.Now(), rng); got != 90*time.Minute {
		t.Fatalf("delay = %v with no known expiry, want the configured cadence", got)
	}
}

// Jitter must actually spread a fleet that enrolled together.
//
// Ten thousand agents installed by the same automation hold near-identical
// expiry times. Without jitter they renew in the same second, and the herd
// arrives exactly during recovery from the outage that synchronised them.
func TestJitterSpreadsAFleetThatEnrolledTogether(t *testing.T) {
	t.Parallel()
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		rng := rand.New(rand.NewSource(int64(i))) // #nosec G404 -- jitter spread (CWE-338)
		seen[nextRotationDelay(12*time.Hour, notAfter, now, rng)] = true
	}
	if len(seen) < 50 {
		t.Fatalf("200 identically-configured agents produced only %d distinct wake times; a "+
			"fleet that enrolled together would stampede the control plane", len(seen))
	}
}
