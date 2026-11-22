// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"
)

// A business-clock jump used to simulate an old account must not schedule an
// extra background scan beside an operator's explicit scan of the same tenant.
func TestPAMAccountFlagScanCadenceUsesElapsedTime(t *testing.T) {
	lastScan := time.Now()
	s := &pamService{
		clock:        func() time.Time { return lastScan.Add(91 * 24 * time.Hour) },
		lastFlagScan: lastScan,
	}
	defer func() {
		if problem := recover(); problem != nil {
			t.Fatalf("business-clock jump started an unexpected background scan: %v", problem)
		}
	}()
	s.scanAccountFlags(t.Context())
	if !s.lastFlagScan.Equal(lastScan) {
		t.Fatalf("worker scan cadence changed from %s to %s", lastScan, s.lastFlagScan)
	}
}
