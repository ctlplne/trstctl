// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"reflect"
	"testing"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestUnknownTaskFencePausesOnlyDependentClaimsA267(t *testing.T) {
	s, e := reportstate.Open(t.TempDir(), "owned-claim-fence")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	task := windependents.Task{Path: "\\owned\\task", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Enabled: true, LogonType: 1, ActionCount: 1}
	lost := &taskRecoveryLostStart{}
	_, _ = s.ExecuteTaskOnce(t.Context(), 771, "forward", task, lost)
	ch := relayChannel{pending: s}
	requested := []string{servicedependents.RotationDestination, servicedependents.InventoryDestination}
	kinds, paused, e := ch.dependentTaskClaimKinds(t.Context(), requested)
	if e != nil || !paused || !reflect.DeepEqual(kinds, []string{servicedependents.InventoryDestination}) || requested[0] != servicedependents.RotationDestination {
		t.Fatal("unknown start did not isolate dependent work", e)
	}
	kinds, paused, e = ch.dependentTaskClaimKinds(t.Context(), []string{servicedependents.RotationDestination})
	if e != nil || !paused || len(kinds) != 0 {
		t.Fatal("empty filtered list could become an unrestricted claim", e)
	}
	if kinds, paused, e = ch.dependentTaskClaimKinds(t.Context(), nil); e != nil || !paused || len(kinds) != 0 {
		t.Fatal("wildcard claim bypassed unknown task fence", e)
	}
	remoteCalls := 0
	served := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	}, func(remote *receiptRetryChannelServer) {
		remote.claim = func(_ context.Context, req *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			remoteCalls++
			if !reflect.DeepEqual(req.Kinds, []string{servicedependents.InventoryDestination}) {
				t.Error("unsafe dependent or wildcard claim reached server")
			}
			return &transport.ClaimJobsResponse{}, nil
		}
	})
	served.pending = s
	if _, e := served.ClaimJobs(t.Context(), []string{servicedependents.RotationDestination}, 1, 60); e != nil || remoteCalls != 0 {
		t.Fatal("filtered empty list became a wildcard claim", e)
	}
	if _, e := served.ClaimJobs(t.Context(), requested, 1, 60); e != nil || remoteCalls != 1 {
		t.Fatal("unrelated host work was blocked", e)
	}
	observer := &taskRecoveryObserver{}
	if _, e = s.ReconcileTaskExecution(t.Context(), 771, "forward", "a1234567-1234-1234-1234-123456789abc", "owned-admin", "observe terminal task before inverse", observer); e != nil {
		t.Fatal(e)
	}
	kinds, paused, e = ch.dependentTaskClaimKinds(t.Context(), requested)
	if e != nil || paused || !reflect.DeepEqual(kinds, requested) || lost.runs != 1 {
		t.Fatal("exact terminal closure did not resume separately authorized work", e)
	}
}
