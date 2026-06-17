//go:build chaos

package signing_test

import "testing"

// TestChaosMemoryPressureSignerBulkhead is the RESIL-003 memory-pressure fault
// direction in the chaos gate. It reuses the served-path UDS flood assertion from
// the normal signer suite: a saturated signer sheds excess Sign RPCs with
// RESOURCE_EXHAUSTED while Health still answers, so expensive signing work cannot
// consume unbounded memory or strand the process.
func TestChaosMemoryPressureSignerBulkhead(t *testing.T) {
	testSignerShedsFloodOverUDS(t)
}
