// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Real source/runtime, no new goroutine or test key material. This exercises the
// no-queue readiness bulkhead and release after canceled verification; the
// separate served cases exercise actual active file-key loss and recovery.
func TestEventProtectionProbeRejectsBusyAndCanceledChecksWithoutLeakingCustody(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protection.Close() })
	t.Cleanup(func() { _ = log.Close() })
	if err := protection.probeCurrentCustody(t.Context()); err != nil {
		t.Fatal(err)
	}
	protection.probeSlots <- struct{}{}
	started := time.Now()
	busy := protection.probeCurrentCustody(t.Context())
	if busy == nil || time.Since(started) >= loadSensitiveProbeBudget {
		t.Fatal("busy custody probe queued or reported healthy")
	}
	<-protection.probeSlots
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	canceled := protection.probeCurrentCustody(ctx)
	if canceled == nil {
		t.Fatal("canceled custody verification reported ready")
	}
	for _, failure := range []error{busy, canceled} {
		if failure.Error() != "event-key custody cannot be verified yet" || strings.Contains(failure.Error(), cfg.Privacy.EventProtection.KeyDirectory) {
			t.Fatal("public probe result leaked private cause or location")
		}
	}
	if err := protection.probeCurrentCustody(t.Context()); err != nil {
		t.Fatalf("failed probe retained its only slot: %v", err)
	}
}
