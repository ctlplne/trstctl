// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

func TestSourceLifetimeHistoricalDuplicatesKeepFirstCanonicalOffboard(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "exact"
		if changed {
			name = "conflicting-payload"
		}
		t.Run(name, func(t *testing.T) {
			log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "events")}, events.WithDuplicateWindowForTesting(100*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			appendSource(t, log, "duplicate-registration", "tenant.registered", time.Now().UTC().Add(-time.Second), struct {
				Name string `json:"name"`
			}{"fixture"})
			first := appendSource(t, log, "duplicate-offboard", "tenant.offboarded", time.Now().UTC(), struct {
				RowsDeleted int `json:"rows_deleted"`
			}{0})
			time.Sleep(150 * time.Millisecond)
			repeat := first
			repeat.Sequence = 0
			if changed {
				repeat.Data, _ = json.Marshal(struct {
					RowsDeleted int `json:"rows_deleted"`
				}{1})
			}
			second, err := log.Append(t.Context(), repeat)
			if err != nil {
				t.Fatal(err)
			}
			if second.Sequence <= first.Sequence {
				t.Fatal("fixture did not publish beyond broker dedup")
			}
			life, err := (eventprivacy.SourcePolicy{Log: log}).LatestLifetime(t.Context(), sourceTenant)
			if changed {
				if !errors.Is(err, eventprivacy.ErrSource) {
					t.Fatalf("conflicting historical duplicate accepted: %v", err)
				}
				return
			}
			if err != nil || life.Offboard == nil || life.Offboard.Sequence != first.Sequence || !life.Offboard.Time.Equal(first.Time) {
				t.Fatalf("exact duplicate lost its first canonical authority: %v", err)
			}
		})
	}
}
