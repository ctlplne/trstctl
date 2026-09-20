// SPDX-License-Identifier: BUSL-1.1

package breakglass

import (
	"testing"
	"time"
)

func TestBreakglassNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
}

func TestBreakglassReasonRequired(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.IssueOffline(EmergencyRequest{
		ID: "e", Subject: "s", CSRDer: emergencyCSR(t), Approvals: []string{"op1", "op2"},
	}, time.Hour); err == nil {
		t.Error("emergency issuance without a reason accepted")
	}
}

func TestQuorumVerifyEdges(t *testing.T) {
	q := Quorum{Threshold: 2, Operators: []string{"a", "b", "c"}}
	if q.Verify([]string{"a", "a"}) == nil {
		t.Error("a duplicate approver was counted toward quorum")
	}
	if err := q.Verify([]string{"a", "b"}); err != nil {
		t.Errorf("valid quorum rejected: %v", err)
	}
	if err := q.Verify([]string{"a", "b", "c", "a"}); err != nil {
		t.Errorf("quorum with a duplicate-but-sufficient distinct set rejected: %v", err)
	}
	if (Quorum{Threshold: 0, Operators: []string{"a"}}).Verify([]string{"a"}) == nil {
		t.Error("zero threshold accepted")
	}
}
