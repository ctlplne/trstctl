// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestHistoricalOnlinePlansAreBoundToShippedBytes(t *testing.T) {
	for _, name := range []string{"0211_connector_rollback_projection_order.sql", "0219_notification_delivery_routing.sql", "0253_pam_early_revocation.sql", "0416_pam_discovery_outbox.sql", "0417_service_account_rotation.sql", "0504_ticket_intake_source.sql"} {
		t.Run(name, func(t *testing.T) {
			body, err := migrationFS.ReadFile("migrations/" + name)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := historicalOnlinePlan(name, body)
			if err != nil || plan == nil {
				t.Fatalf("shipped plan: %v", err)
			}
			wantIndex := "CREATE INDEX CONCURRENTLY"
			if plan.unique {
				wantIndex = "CREATE UNIQUE INDEX CONCURRENTLY"
			}
			if !strings.Contains(plan.createSQL, wantIndex) || strings.Contains(plan.createSQL, "IF NOT EXISTS") {
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
