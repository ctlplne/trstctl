// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
)

func TestCMDBSweepProducerRejectsPoisonEventsBeforeAppendAUD46(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	expected := 2
	intent := ownership.CMDBSyncIntent{ // #nosec G101 -- TokenRef is a non-secret locator in a deterministic fixture (CWE-798).
		InstanceURL: "https://cmdb.example", TokenRef: "secret://cmdb/token", PageLimit: 2,
		SweepID: "22222222-2222-4222-8222-222222222222",
	}
	next := intent
	next.AfterSysID = "ci-2"
	next.ReadCount = 2
	next.ExpectedCount = &expected
	page := projections.CMDBSweepPageObserved{
		Intent: intent, ObservedAt: time.Now().UTC(), ReadCount: 2, ExpectedCount: &expected,
		Observations: []projections.CMDBCIObservation{{SourceRef: "ci-1"}, {SourceRef: "ci-2"}},
		Complete:     false, Unattributed: 2, NextIntent: &next,
	}
	if err := validateCMDBSweepPageEvent(tenantID, "result-1", page); err != nil {
		t.Fatalf("valid bounded page: %v", err)
	}

	poison := page
	badNext := next
	badNext.AfterSysID = "ci-1"
	poison.NextIntent = &badNext
	if err := validateCMDBSweepPageEvent(tenantID, "result-1", poison); err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("mismatched continuation = %v, want pre-append refusal", err)
	}
	poison = page
	poison.Intent.SweepID = "not-a-uuid"
	if err := validateCMDBSweepPageEvent(tenantID, "result-1", poison); err == nil || !strings.Contains(err.Error(), "intent") {
		t.Fatalf("non-UUID sweep identity = %v, want pre-append refusal", err)
	}
	poison = page
	poison.Complete = true
	poison.Intent.PageLimit = 3
	if err := validateCMDBSweepPageEvent(tenantID, "result-1", poison); err == nil || !strings.Contains(err.Error(), "continuation") {
		t.Fatalf("terminal page with next command = %v, want pre-append refusal", err)
	}
}
