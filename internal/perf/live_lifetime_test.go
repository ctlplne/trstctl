// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"context"
	"testing"
	"time"
)

// The stack outlives its startup deadline: the signer child and the server run
// until Close. Bound to the startup context, the supervisor interrupted the
// signer when the deadline passed and every issuance after it failed closed
// ("signer unavailable"), which ended each nightly captured soak 90 s in
// (CI 41297454391, 41433560187, 41622602020).
func TestLiveStackOutlivesItsStartupDeadline(t *testing.T) {
	timeout, err := LiveHarnessTimeout()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stack, err := startLiveEvalStack(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer stack.Close()
	cancel() // the startup deadline has passed
	time.Sleep(2 * time.Second)

	client := stack.signer.Client()
	check, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if client == nil || !client.Healthy(check) {
		t.Fatal("the signer stopped serving when the startup deadline passed")
	}
	if err := stack.signerRPCOverUDS(); err != nil {
		t.Fatalf("a signer RPC after the startup deadline: %v", err)
	}
	if err := stack.issueOverServedAPI(); err != nil {
		t.Fatalf("an issuance after the startup deadline: %v", err)
	}
}
