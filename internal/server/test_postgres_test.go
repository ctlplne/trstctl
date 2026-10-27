// SPDX-License-Identifier: BUSL-1.1

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
		dir, err := os.MkdirTemp(serverTestPostgresTempRoot(), "trstctl-server-pg")
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

// serverTestPostgresTempRoot separates database state from the host-visible DoD
// receipt mount. Docker Desktop may map files in that bind mount to root even
// though the proof runner is non-root; PostgreSQL correctly rejects that owner
// mismatch. The runner's /tmp is a private, non-executable tmpfs.
func serverTestPostgresTempRoot() string {
	if os.Getenv("TRSTCTL_DOD_RUNTIME_TEMP_ROOT") == "/dod-tmp" {
		return "/tmp"
	}
	return ""
}

func TestServerTestPostgresUsesContainerOwnedScratchInDODRunner(t *testing.T) {
	t.Setenv("TRSTCTL_DOD_RUNTIME_TEMP_ROOT", "/dod-tmp")
	if got := serverTestPostgresTempRoot(); got != "/tmp" {
		t.Fatalf("DoD Postgres temp root = %q, want container-owned /tmp", got)
	}
	t.Setenv("TRSTCTL_DOD_RUNTIME_TEMP_ROOT", "")
	if got := serverTestPostgresTempRoot(); got != "" {
		t.Fatalf("ordinary test Postgres temp root = %q, want Go default", got)
	}
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
		`TRUNCATE tenants, browser_sessions, idempotency_keys, outbox, rate_limits,
		          owners, issuers, identities, identity_transitions, deployment_target_revisions, deployment_targets,
		          agents, agent_cert_revocations, agent_role_grants, kmip_clients, agent_removal_commands, agent_bootstrap_tokens, kubernetes_controller_posture, kubernetes_trust_rollout_clusters, kubernetes_trust_rollouts, audit_anchors, tsa_certificates, policy_bindings, tenant_members, attestations, api_tokens, api_token_revocation_commands, oidc_session_locators, oidc_logout_receipts, certificates, acme_upstream_ari, certificate_metadata_watermarks, certificate_metadata_receipts,
		          identity_terminal_commands, identity_terminal_receipts,
		          ca_authorities, ca_key_ceremonies, ca_ceremony_approvals, ca_ceremony_cancel_commands, ca_ceremony_effect_commands,
		          certificate_revocation_authority_commands, certificate_revocation_authority_fences,
		          ca_issued_certs, ca_crls, ca_ocsp_responders, ssh_keys, ct_watched_domains, ct_log_checkpoints,
		          crypto_assets, credentials, audit_checkpoints, certificate_profiles,
		          secret_sync_workload_identity_sources, workload_attester_trust_sources, workload_attester_trust_commands, workload_attester_trust_receipts,
		          discovery_segments, discovery_sources, discovery_schedules, discovery_runs, discovery_findings,
		          revocation_endpoint_health, tenant_control_plane_keygen,
		          notification_channels, notification_reads, notification_threshold_deliveries, notification_test_operations,
		          notification_delivery_receipts, notification_routing_policies,
		          endpoint_verifications, connector_delivery_receipts, lifecycle_rotation_runs, remediation_playbook_runs,
		          outbox_reconciliation_conflicts, incident_executions, incident_fleet_reissuance_runs,
		          pam_sessions, nhi_access_review_campaigns, nhi_access_review_items,
		          access_change_requests, access_change_request_decisions, compliance_report_schedules,
		          privacy_subject_erasure_preparations, privacy_subject_erasure_operations,
		          privacy_subject_erasures, privacy_retention_runs, privacy_archive_erasure_attestations,
		          transit_keyrings, transit_key_facts, tenant_key_domains,
		          secret_shares, vault_cubbyhole, secret_store, secret_rotation_schedule_ticks, secret_rotation_schedule_scan_cursors, secret_rotation_schedule_commands, secret_static_rotation_commands, secret_rotation_schedules, approved_target_event_fences, application_secret_mutation_fences, application_secret_tenant_epochs, application_secret_mutation_receipts,
		          dynamic_secret_operations, dynamic_secret_leases, secret_sync_jobs, read_model_snapshots,
		          managed_key_operations, managed_keys, code_signing_operations,
		          operation_approval_decisions, operation_approval_requests,
		          issuance_approval_requests, issuance_approvals,
		          agent_job_credential_redemptions, agent_job_receipts, agent_job_attempt_bindings, agent_job_appliance_references, adcs_template_posture,
		          cmdb_reconcile_schedules, cmdb_ci_inventory, owner_ownership_conflicts,
		          ticket_intake_schedules, issuance_requests,
		          enrollment_diagnostic_observations, enrollment_diagnostics,
		          acme_dns01_provider_configs,
		          audit_feed_deliveries, audit_feed_destinations,
		          mdm_scep_policies, mdm_poll_schedules, mdm_device_correlations, agent_upgrade_campaigns,
		          provider_breakglass_grants, provider_tenants, provider_operator_delegations, provider_suspend_commands,
		          provider_tenant_quotas, provider_usage_coverage, provider_usage_meters
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset shared server postgres: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = 0, failed_seq = NULL, last_error = NULL,
		        failed_at = NULL, breakglass_issue_checked_through = NULL,
		        breakglass_authority_checked_through = NULL,
		        ca_reprotection_name_checked_through = NULL, updated_at = now()
		  WHERE id = 1`); err != nil {
		t.Fatalf("reset projection checkpoint: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("reset outbox reconciliation checkpoint: %v", err)
	}
}

func TestServerFixtureResetsCAReprotectionNameCursor(t *testing.T) {
	st := newServerTestStore(t)
	if _, err := st.SystemPool().Exec(t.Context(),
		`UPDATE projection_checkpoint SET ca_reprotection_name_checked_through = 9 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	resetServerTestStore(t, st)
	var checkedThrough *int64
	if err := st.SystemPool().QueryRow(t.Context(),
		`SELECT ca_reprotection_name_checked_through FROM projection_checkpoint WHERE id = 1`).
		Scan(&checkedThrough); err != nil {
		t.Fatal(err)
	}
	if checkedThrough != nil {
		t.Fatalf("fresh event stream retained CA re-protection name cursor %d", *checkedThrough)
	}
}
