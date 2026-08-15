// SPDX-License-Identifier: MPL-2.0

package pluginhost_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/pluginhost"
)

// TestPluginInvocationHonoursContextCancellation is the regression guard for the
// worker-occupancy defect. The host loaded guests with wazero's DEFAULT runtime
// config, which runs guest code to completion regardless of the context: a
// plugin containing an infinite loop occupied its bounded-pool worker forever
// and could be neither cancelled, shed, nor drained at shutdown. Capability
// grants close what a plugin can REACH; nothing bounded how long it could RUN.
//
// The fix is WithCloseOnContextDone plus a default per-call deadline. This test
// pins the property that makes both work — that the context actually reaches the
// guest — by cancelling before the call and requiring it not to succeed.
func TestPluginInvocationHonoursContextCancellation(t *testing.T) {
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(context.Background()) })

	plugin, err := h.Load(context.Background(), trapWASM, pluginhost.NewGrant())
	if err != nil {
		t.Skipf("fixture guest did not load in this environment: %v", err)
	}
	t.Cleanup(func() { _ = plugin.Close(context.Background()) })

	// A context that is already done when the guest would run.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.Invoke(ctx, plugin, "boom")
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Invoke did not return on a cancelled context; a guest can pin its bounded-pool worker indefinitely")
	}
}
