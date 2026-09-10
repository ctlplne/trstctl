// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// This executes PostgreSQL's capture query. Comparing two Go table lists alone
// did not catch six restore-owned tables missing from the actual saved payload.
func TestSnapshotCaptureIncludesEveryRestoreTableAndTenantRows(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	expected := make(map[string]map[string]map[string]any)
	for _, tenantID := range []string{tenantA, tenantB} {
		expected[tenantID] = make(map[string]map[string]any)
		// These are isolated read-model fixtures through the existing projector
		// writers. This test proves capture, not event ingestion or live Kubernetes.
		policy := store.NotificationRoutingPolicy{
			ID: uuid(tenantID, 9101), TenantID: tenantID, Name: "snapshot-routing",
			ScopeKind: "global", ChannelsBySeverity: map[string][]string{"critical": {"email"}},
			DefaultChannels: []string{"email"}, OwnerRef: "owner/" + tenantID,
			OwnerEmail: "snapshot@example.test", DigestInterval: 3600,
			DigestTimezone: "UTC", CreatedAt: at, UpdatedAt: at,
		}
		posture := store.KubernetesControllerPosture{
			TenantID: tenantID, ControllerID: uuid(tenantID, 9102),
			ClusterID:  "sha256:" + strings.Repeat("a", 64),
			Capability: store.KubernetesPostureCertificateSigningRequests,
			ReportID:   uuid(tenantID, 9103), ReconcileComplete: true,
			ReconcileIntervalSeconds: 30, ReportedAt: at, EventSequence: 7,
			Resources: []store.KubernetesPostureResource{{
				Name: "snapshot-csr", UID: tenantID, ResourceVersion: "17",
				State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
			}},
		}
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if err := s.ApplyNotificationRoutingPolicyUpsertedTx(ctx, tx, policy); err != nil {
				return err
			}
			if err := s.ApplyKubernetesControllerPostureTx(ctx, tx, posture); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `
SELECT 'notification_routing_policies', to_jsonb(t.*)
FROM notification_routing_policies t WHERE tenant_id = $1
UNION ALL
SELECT 'kubernetes_controller_posture', to_jsonb(t.*)
FROM kubernetes_controller_posture t WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var table string
				var raw []byte
				if err := rows.Scan(&table, &raw); err != nil {
					return err
				}
				var row map[string]any
				if err := json.Unmarshal(raw, &row); err != nil {
					return err
				}
				if _, duplicate := expected[tenantID][table]; duplicate {
					t.Fatalf("duplicate fixture row for %s/%s", tenantID, table)
				}
				expected[tenantID][table] = row
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("seed tenant-scoped capture fixtures: %v", err)
		}
		if len(expected[tenantID]) != 2 {
			t.Fatalf("fixture inventory for %s = %d, want two nonempty tables", tenantID, len(expected[tenantID]))
		}
	}
	if count, err := s.WriteReadModelSnapshots(ctx); err != nil || count != 2 {
		t.Fatalf("actual snapshot capture count=%d err=%v, want two tenants", count, err)
	}
	tables := store.SnapshotTablesForCaptureTest()
	for _, tenantID := range []string{tenantA, tenantB} {
		var raw []byte
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT payload FROM read_model_snapshots
WHERE tenant_id = $1 AND format_version = $2`, tenantID, store.SnapshotFormatVersion).Scan(&raw)
		}); err != nil {
			t.Fatalf("read actual tenant snapshot: %v", err)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("decode saved PostgreSQL payload: %v", err)
		}
		for _, table := range tables {
			array, present := payload[table]
			if !present {
				t.Errorf("tenant %s snapshot omits restore-owned table %s", tenantID, table)
				continue
			}
			var rows []map[string]any
			if err := json.Unmarshal(array, &rows); err != nil || rows == nil {
				t.Errorf("tenant %s table %s is not a non-null row array: %v", tenantID, table, err)
				continue
			}
			for _, row := range rows {
				if row["tenant_id"] != tenantID {
					t.Errorf("tenant %s snapshot table %s contains a neighbor row", tenantID, table)
				}
			}
			if want, seeded := expected[tenantID][table]; seeded {
				if len(rows) != 1 || !reflect.DeepEqual(rows[0], want) {
					t.Errorf("tenant %s table %s did not preserve its complete nonempty row", tenantID, table)
				}
			}
		}
		if len(payload) != len(tables)+1 {
			t.Errorf("tenant %s payload has %d keys, want %d tables plus capture metadata", tenantID, len(payload), len(tables))
		}
	}
}

// A fixed capture query cannot repair an already saved incomplete payload.
// Exercise the ordinary startup migration against the last shipped format,
// whose incomplete payload must not be selected for a new restore. This does not
// prove repair of a prior restore or fencing an older binary running Migrate.
func TestSnapshotUpgradePurgesPayloadsThatOmitRestoreTables(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// This isolated database fixture represents a pre-upgrade cache. No live
	// tenant state or product lifecycle decision is manufactured by the test.
	if _, err := s.SystemPool().Exec(ctx, `
		ALTER TABLE read_model_snapshots
		DROP CONSTRAINT read_model_snapshots_format_floor_v22;
		INSERT INTO read_model_snapshots (tenant_id, covered_seq, format_version, payload)
		VALUES ('11111111-1111-4111-8111-111111111111', 42, 36, '{"owners":[]}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM read_model_snapshots`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("startup retained an incomplete format-36 snapshot instead of requiring replay")
	}
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO read_model_snapshots (tenant_id, covered_seq, format_version, payload)
		VALUES ('11111111-1111-4111-8111-111111111111', 42, 36, '{"owners":[]}'::jsonb)`); err == nil {
		t.Fatal("the current startup floor accepted an incomplete format-36 insert")
	}
}
