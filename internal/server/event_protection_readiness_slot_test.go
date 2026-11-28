// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/observ"
)

func TestCurrentCustodyProbeContentionKeepsReadinessAvailable(t *testing.T) {
	runtime := &eventProtectionRuntime{
		reader: &eventprivacy.SourceKeys{}, probeSlots: make(chan struct{}, 1),
	}
	runtime.probeSlots <- struct{}{}
	err := runtime.probeCurrentCustody(t.Context())
	var degraded observ.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("busy custody probe = %v, want degraded readiness", err)
	}
}
