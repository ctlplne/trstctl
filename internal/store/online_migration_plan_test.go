// SPDX-License-Identifier: MPL-2.0

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestHistoricalOnlinePlansAreBoundToShippedBytes(t *testing.T) {
	for _, name := range []string{"0211_connector_rollback_projection_order.sql", "0219_notification_delivery_routing.sql"} {
		t.Run(name, func(t *testing.T) {
			body, err := migrationFS.ReadFile("migrations/" + name)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := historicalOnlinePlan(name, body)
			if err != nil || plan == nil {
				t.Fatalf("shipped plan: %v", err)
			}
			if !strings.Contains(plan.createSQL, "CREATE INDEX CONCURRENTLY") || strings.Contains(plan.createSQL, "IF NOT EXISTS") {
				t.Fatal("index plan lost online build or exact recovery")
			}
			changed := append(append([]byte{}, body...), []byte("-- changed\n")...)
			if _, err := historicalOnlinePlan(name, changed); !errors.Is(err, ErrMigrationChecksumMismatch) {
				t.Fatalf("edited historical file accepted: %v", err)
			}
		})
	}
	if p, err := historicalOnlinePlan("0220_unrecognized.sql", []byte("CREATE INDEX unsafe ON facts(id)")); err != nil || p != nil {
		t.Fatalf("unknown migration silently rewritten: %v %v", p, err)
	}
}
