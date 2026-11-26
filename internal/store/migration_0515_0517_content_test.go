// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testMigration0515HeldExternalCAProfileStartsUnknown(t *testing.T) {
	const stable = `SELECT tenant_id::text, authority_id, ca_request_id::text,
		issue_key, request_binding, key_origin, dns_names::text, status, serial,
		held_at::text, COALESCE(resolved_at::text, ''), event_sequence::text
		FROM external_ca_held_issues ORDER BY tenant_id, authority_id, ca_request_id`
	runPopulatedDefaultMigrationHarness(t, 515, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for i, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `INSERT INTO external_ca_held_issues
					(tenant_id, authority_id, ca_request_id, issue_key,
					 request_binding, key_origin, dns_names, held_at, event_sequence)
					VALUES ($1, 'adcs-lab', $2, $3, $4, 'requester', $5,
					 '2026-10-01T00:00:00Z', $6)`,
					tenantID, i+1, fmt.Sprintf("pre-0515-issue-%d", i),
					fmt.Sprintf("binding-%d", i), []string{fmt.Sprintf("legacy-%d.example.test", i)}, int64(i+1)); err != nil {
					t.Fatalf("seed pre-0515 held issue for %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var unknown bool
			if err := pool.QueryRow(ctx, `SELECT count(*), bool_and(
				NOT profile_binding_known AND profile_name = '' AND profile_version = 0
				AND profile_digest = '' AND protocol = ''
				AND cardinality(ip_addresses) = 0 AND cardinality(email_addresses) = 0
				AND cardinality(uris) = 0 AND cardinality(requested_ekus) = 0
				AND subject_spki_sha256 = '')
				FROM external_ca_held_issues WHERE tenant_id IN ($1, $2)`, tenantA, tenantB).
				Scan(&rows, &unknown); err != nil {
				t.Fatal(err)
			}
			if rows != want || !unknown {
				t.Fatalf("0515 fabricated profile evidence for held issues: rows=%d want=%d unknown=%t", rows, want, unknown)
			}
		})
}

func testMigration0516DeploymentTargetConfigurersStartUnknown(t *testing.T) {
	const stable = `SELECT tenant_id::text, 'target', id::text, revision_id,
		name, type, config::text, enabled::text, created_at::text
		FROM deployment_targets
		UNION ALL
		SELECT tenant_id::text, 'revision', target_id::text, revision_id,
		name, type, config::text, enabled::text, created_at::text
		FROM deployment_target_revisions ORDER BY 1, 2, 3`
	runPopulatedDefaultMigrationHarness(t, 516, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for i, tenantID := range []string{tenantA, tenantB} {
				id := fmt.Sprintf("51600000-0000-4000-8000-%012d", i+1)
				revision := fmt.Sprintf("pre-0516-revision-%d", i)
				name := fmt.Sprintf("legacy-deployer-%d", i)
				config := fmt.Sprintf(`{"namespace":"tenant-%d"}`, i)
				if _, err := pool.Exec(ctx, `INSERT INTO deployment_targets
					(id, tenant_id, name, type, config, created_at, revision_id)
					VALUES ($1,$2,$3,'kubernetes',$4::jsonb,'2026-10-01T00:00:00Z',$5)`,
					id, tenantID, name, config, revision); err != nil {
					t.Fatalf("seed pre-0516 target for %s: %v", tenantID, err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO deployment_target_revisions
					(tenant_id, target_id, revision_id, name, type, config, created_at)
					VALUES ($1,$2,$3,$4,'kubernetes',$5::jsonb,'2026-10-01T00:00:00Z')`,
					tenantID, id, revision, name, config); err != nil {
					t.Fatalf("seed pre-0516 target revision for %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			for _, table := range []string{"deployment_targets", "deployment_target_revisions"} {
				var rows int
				var unknown bool
				query := `SELECT count(*), bool_and(configured_by = '' AND configured_by_ref = '')
					FROM ` + table + ` WHERE tenant_id IN ($1,$2)`
				if err := pool.QueryRow(ctx, query, tenantA, tenantB).Scan(&rows, &unknown); err != nil {
					t.Fatal(err)
				}
				if rows != want/2 || !unknown {
					t.Fatalf("0516 fabricated %s configurer: rows=%d want=%d unknown=%t", table, rows, want/2, unknown)
				}
			}
		})
}

func testMigration0517TicketIntakeConfigurerStartsUnknown(t *testing.T) {
	const stable = `SELECT tenant_id::text, system, name, instance_url,
		token_ref, sn_table, query, subject_field, profile_field,
		interval_seconds::text, enabled::text, last_error, updated_at::text
		FROM ticket_intake_schedules ORDER BY tenant_id, system`
	runPopulatedDefaultMigrationHarness(t, 517, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for i, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `INSERT INTO ticket_intake_schedules
					(tenant_id, system, name, instance_url, token_ref, sn_table,
					 subject_field, profile_field, interval_seconds, enabled)
					VALUES ($1,'servicenow',$2,'https://tickets.example.test',
					 'secret://legacy/ticket-intake','sc_req_item','u_subject',
					 'u_profile',3600,true)`, tenantID, fmt.Sprintf("legacy-intake-%d", i)); err != nil {
					t.Fatalf("seed pre-0517 ticket intake for %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var unknown bool
			if err := pool.QueryRow(ctx, `SELECT count(*),
				bool_and(configured_by = '' AND config_revision = '')
				FROM ticket_intake_schedules WHERE tenant_id IN ($1,$2)`, tenantA, tenantB).
				Scan(&rows, &unknown); err != nil {
				t.Fatal(err)
			}
			if rows != want || !unknown {
				t.Fatalf("0517 fabricated legacy ticket authority: rows=%d want=%d unknown=%t", rows, want, unknown)
			}
		})
}
