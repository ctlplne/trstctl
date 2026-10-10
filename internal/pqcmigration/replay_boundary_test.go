// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestRunReplayBoundarySurvivesColdProjectionAndResets(t *testing.T) {
	ctx := context.Background()
	started, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{Type: projections.EventLicensedCryptoMigrationStarted,
		TenantID: "tenant-a", Sequence: 4096, Data: started}
	for _, projection := range []*ProgressProjection{NewProgressProjection(nil), NewProgressProjection(nil)} {
		if got := projection.RunStartSequence("tenant-a", "run-a"); got != 0 {
			t.Fatalf("unreplayed run start = %d, want zero for safe full replay", got)
		}
		if err := projection.Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		if got := projection.RunStartSequence("tenant-a", "run-a"); got != 4096 {
			t.Fatalf("run start = %d, want exact inclusive sequence", got)
		}
		if got := projection.RunStartSequence("tenant-b", "run-a"); got != 0 {
			t.Fatalf("other tenant run start = %d, want zero", got)
		}
		if err := projection.Reset(ctx); err != nil {
			t.Fatal(err)
		}
		if got := projection.RunStartSequence("tenant-a", "run-a"); got != 0 {
			t.Fatalf("reset run start = %d, want zero", got)
		}
	}
}
