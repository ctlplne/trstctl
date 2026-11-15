// SPDX-License-Identifier: BUSL-1.1

package transport_test

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
)

// TestNoRebindBindingRefusalIsPermanentBeforeContactA166L2T1: a relay's
// refusal of a rollback whose target names no re-bind binding is decided
// locally, before any connection, and fails the same way on every attempt
// until the target is reconfigured (a new revision is a new job), so the
// job leaves the queue instead of redeeming again on every poll.
func TestNoRebindBindingRefusalIsPermanentBeforeContactA166L2T1(t *testing.T) {
	reason := transport.RollbackRefusedNoRebindBinding
	if transport.RollbackReasonContactedTarget(reason) {
		t.Fatal("the missing-binding refusal classifies as having contacted the target")
	}
	if !transport.RollbackReasonIsPermanent(reason) {
		t.Fatal("the missing-binding refusal would be retried on every poll")
	}
}
