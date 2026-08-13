// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

var sourceTreeSignerAuthSecret = filepath.Join("data", "signer", "sign-auth.bin")

// seedApplicationSecretFixture is a test-only direct database fixture. Production
// code intentionally exposes no Store mutator that can bypass the authoritative
// application-secret event projector.
func seedApplicationSecretFixture(
	t *testing.T,
	s *store.Store,
	tenantID, name string,
	sealed []byte,
) store.Secret {
	t.Helper()
	ctx := context.Background()
	var out store.Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version)
			VALUES ($1, $2, $3, 1)
			RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantID, name, sealed).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
			VALUES ($1, $2, 1, $3, $4)`, tenantID, name, sealed, out.UpdatedAt)
		return err
	})
	if err != nil {
		t.Fatalf("seed application-secret fixture %s: %v", name, err)
	}
	out.Sealed = append([]byte(nil), sealed...)
	return out
}

func assertNoSourceTreeSignerAuthSecret(t *testing.T, phase string) {
	t.Helper()
	if _, err := os.Stat(sourceTreeSignerAuthSecret); err == nil {
		t.Fatalf("%s wrote signer authentication material into the source tree: %s", phase, sourceTreeSignerAuthSecret)
	} else if !os.IsNotExist(err) {
		t.Fatalf("inspect source-tree signer authentication path after %s: %v", phase, err)
	}
}

var serverTestPG struct {
	once sync.Once
	dsn  string
	stop func() error
	dir  string
	err  error
}

func TestMain(m *testing.M) {
	code := 1
	if _, err := os.Stat(sourceTreeSignerAuthSecret); os.IsNotExist(err) {
		code = m.Run()
	} else if err == nil {
		fmt.Fprintf(os.Stderr, "server tests refuse source-tree signer authentication material: %s\n", sourceTreeSignerAuthSecret)
	} else {
		fmt.Fprintf(os.Stderr, "server tests could not inspect source-tree signer authentication path %s: %v\n", sourceTreeSignerAuthSecret, err)
	}
	if serverTestPG.stop != nil {
		_ = serverTestPG.stop()
	}
	if serverTestPG.dir != "" {
		_ = os.RemoveAll(serverTestPG.dir)
	}
	if _, err := os.Stat(sourceTreeSignerAuthSecret); err == nil {
		fmt.Fprintf(os.Stderr, "server tests wrote signer authentication material into the source tree: %s\n", sourceTreeSignerAuthSecret)
		code = 1
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "server tests could not inspect source-tree signer authentication path %s: %v\n", sourceTreeSignerAuthSecret, err)
		code = 1
	}
	os.Exit(code)
}

func serverTestPostgresDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	serverTestPG.once.Do(func() {
		dir, err := os.MkdirTemp("", "trstctl-server-pg")
		if err != nil {
			serverTestPG.err = err
			return
		}
		serverTestPG.dir = dir
		started := time.Now()
		dsn, stop, err := startBundledPostgres(config.Postgres{
			Mode:    config.PostgresBundled,
			DataDir: dir,
			Port:    freeTCPPort(t),
		})
		if err != nil {
			_ = os.RemoveAll(dir)
			serverTestPG.dir = ""
			serverTestPG.err = fmt.Errorf("shared embedded postgres start after %s: %w", time.Since(started).Round(time.Millisecond), err)
			return
		}
		serverTestPG.dsn = dsn
		serverTestPG.stop = stop
	})
	if serverTestPG.err != nil {
		t.Fatalf("server test postgres: %v", serverTestPG.err)
	}
	return serverTestPG.dsn
}

func newServerTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)
	return st
}

func resetServerTestStore(t *testing.T, st *store.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := st.SystemPool().Exec(ctx,
		`TRUNCATE tenants, idempotency_keys, outbox, rate_limits,
		          owners, issuers, identities, identity_transitions, deployment_target_revisions, deployment_targets,
		          agents, agent_cert_revocations, agent_bootstrap_tokens, kubernetes_controller_posture, policy_bindings, tenant_members, attestations, api_tokens, certificates,
		          ca_authorities, ca_key_ceremonies, ca_ceremony_approvals,
		          ca_issued_certs, ca_crls, ca_ocsp_responders, ssh_keys, ct_watched_domains, ct_log_checkpoints,
		          crypto_assets, credentials, audit_checkpoints, certificate_profiles,
		          secret_sync_workload_identity_sources, workload_attester_trust_sources,
		          discovery_sources, discovery_schedules, discovery_runs, discovery_findings,
		          notification_channels, notification_reads, notification_threshold_deliveries, notification_test_operations,
		          notification_delivery_receipts, notification_routing_policies,
		          connector_delivery_receipts, lifecycle_rotation_runs, remediation_playbook_runs,
		          outbox_reconciliation_conflicts, incident_executions, incident_fleet_reissuance_runs,
		          pam_sessions, nhi_access_review_campaigns, nhi_access_review_items,
		          access_change_requests, access_change_request_decisions, compliance_report_schedules,
		          privacy_subject_erasure_preparations, privacy_subject_erasure_operations,
		          privacy_subject_erasures, privacy_retention_runs, privacy_archive_erasure_attestations,
		          secret_shares, secret_store, secret_rotation_schedule_ticks, secret_rotation_schedule_scan_cursors, secret_rotation_schedule_commands, secret_rotation_schedules, approved_target_event_fences, application_secret_mutation_fences, application_secret_tenant_epochs, application_secret_mutation_receipts,
		          dynamic_secret_operations, dynamic_secret_leases, secret_sync_jobs, read_model_snapshots,
		          managed_key_operations, managed_keys, code_signing_operations,
		          operation_approval_decisions, operation_approval_requests,
		          issuance_approval_requests, issuance_approvals,
		          agent_job_credential_redemptions, agent_job_receipts, adcs_template_posture,
		          cmdb_reconcile_schedules, cmdb_ci_inventory, owner_ownership_conflicts,
		          ticket_intake_schedules, issuance_requests,
		          enrollment_diagnostic_observations, enrollment_diagnostics,
		          mdm_scep_policies, mdm_poll_schedules, mdm_device_correlations, agent_upgrade_campaigns,
		          provider_breakglass_grants, provider_tenants, provider_operator_delegations,
		          provider_tenant_quotas, provider_usage_coverage, provider_usage_meters
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset shared server postgres: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = 0, failed_seq = NULL, last_error = NULL,
		        failed_at = NULL, updated_at = now()
		  WHERE id = 1`); err != nil {
		t.Fatalf("reset projection checkpoint: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("reset outbox reconciliation checkpoint: %v", err)
	}
}
