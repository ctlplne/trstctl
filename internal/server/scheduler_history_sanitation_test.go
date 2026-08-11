// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/schedulerhistory"
)

func TestSchedulerHistoryTransformIsNarrowAndSecretFree(t *testing.T) {
	secret := "https://user:provider-token@example.invalid"
	before := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","new_ref":"version:2","error":"` + secret + `"}`)
	after, changed, err := schedulerHistoryTransform(
		schedulerhistory.EventType, schedulerhistory.LegacySchemaVersion, before,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || bytes.Equal(before, after) {
		t.Fatal("unsafe v1 scheduler event was not rewritten")
	}
	if strings.Contains(string(after), secret) {
		t.Fatal("rewritten event retained provider-controlled data")
	}
	if err := schedulerHistoryPairValidator(
		schedulerhistory.EventType, schedulerhistory.LegacySchemaVersion, before, after,
	); err != nil {
		t.Fatal(err)
	}

	unrelated := []byte(`{"error":"leave-this-byte-exact"}`)
	next, changed, err := schedulerHistoryTransform("unrelated.event", 1, unrelated)
	if err != nil || changed || !bytes.Equal(next, unrelated) {
		t.Fatalf("unrelated transform = (%s, %v, %v)", next, changed, err)
	}
}

func TestSchedulerHistoryPairValidatorRejectsWrongSchema(t *testing.T) {
	if err := schedulerHistoryPairValidator("unrelated.event", 1, []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("pair validator accepted a changed event outside the sanitation profile")
	}
}
