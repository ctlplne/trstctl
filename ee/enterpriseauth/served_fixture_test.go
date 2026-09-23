// SPDX-License-Identifier: LicenseRef-trstctl-EE
package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// Authenticate and unpack PostgreSQL once per test process. Each served test
// still gets its own database, so prior setup cannot hide authentication defects.
var sharedAuthPostgres struct {
	once       sync.Once
	dsn        string
	dir        string
	stop       func() error
	err        error
	databaseID atomic.Uint64
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedAuthPostgres.stop != nil {
		if err := sharedAuthPostgres.stop(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "stop authentication test PostgreSQL:", err)
			code = 1
		}
	}
	if sharedAuthPostgres.dir != "" {
		if err := os.RemoveAll(sharedAuthPostgres.dir); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "remove owned authentication test PostgreSQL directory:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func serverTestPostgresDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an authenticated PostgreSQL fixture; skipped in -short")
	}
	sharedAuthPostgres.once.Do(func() {
		sharedAuthPostgres.dir, sharedAuthPostgres.err = os.MkdirTemp("", "trstctl-enterprise-auth-pg-")
		if sharedAuthPostgres.err == nil {
			sharedAuthPostgres.dsn, sharedAuthPostgres.stop, sharedAuthPostgres.err = startVerifiedAuthPostgres(sharedAuthPostgres.dir)
		}
	})
	if sharedAuthPostgres.err != nil {
		t.Fatal(sharedAuthPostgres.err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, sharedAuthPostgres.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	name := fmt.Sprintf("auth_test_%d", sharedAuthPostgres.databaseID.Add(1))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// Databases live only in this process-owned cluster. TestMain stops it and
	// removes its exact temporary directory after every test has closed its pools.
	return sharedAuthPostgres.dsn + "/" + name
}

func startVerifiedAuthPostgres(dir string) (string, func() error, error) {
	raw, err := os.ReadFile("../../deploy/supply-chain/embedded-postgres.json")
	if err != nil {
		return "", nil, err
	}
	var manifest struct {
		PostgresVersion string `json:"postgresVersion"`
		Archives        []struct {
			Arch   string `json:"arch"`
			SHA256 string `json:"txz_sha256"`
		} `json:"archives"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", nil, err
	}
	arch := runtime.GOARCH
	if arch == "arm64" {
		arch = "arm64v8"
	}
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		arch += "-alpine"
	}
	identity := embeddedpostgres.ArchiveIdentity{OS: runtime.GOOS, Arch: arch, Version: embeddedpostgres.PostgresVersion(manifest.PostgresVersion)}
	for _, entry := range manifest.Archives {
		if entry.Arch == runtime.GOOS+"-"+arch {
			identity.SHA256 = entry.SHA256
		}
	}
	if identity.SHA256 == "" {
		return "", nil, fmt.Errorf("no committed PostgreSQL pin for %s/%s", runtime.GOOS, arch)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if port < 1 || port > 65535 {
		_ = ln.Close()
		return "", nil, errors.New("invalid fixture TCP port")
	}
	if err := ln.Close(); err != nil {
		return "", nil, err
	}
	cache, err := embeddedpostgres.OpenVerifiedCache(os.TempDir(), "trstctl-pg-archives", identity.OS+"-"+identity.Arch+"-"+manifest.PostgresVersion+"-"+identity.SHA256)
	if err != nil {
		return "", nil, err
	}
	archive := filepath.Join(os.TempDir(), "trstctl-pg-bin", fmt.Sprintf("embedded-postgres-binaries-%s-%s-%s.txz", identity.OS, identity.Arch, manifest.PostgresVersion))
	pg, err := embeddedpostgres.NewVerifiedDatabase(embeddedpostgres.DefaultConfig().Version(identity.Version).Port(uint32(port)).DataPath(filepath.Join(dir, "db")).CachePath(cache.Path()).ArchiveSourcePath(archive).StartParameters(map[string]string{"listen_addresses": "127.0.0.1", "unix_socket_directories": ""}).Logger(io.Discard).StartTimeout(90*time.Second), identity)
	if err != nil {
		return "", nil, errors.Join(err, cache.Close())
	}
	if err := pg.Start(); err != nil {
		return "", nil, errors.Join(err, cache.Close())
	}
	if err := cache.Close(); err != nil {
		return "", nil, errors.Join(err, pg.Stop())
	}
	return fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d", port), pg.Stop, nil
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
		          agents, agent_cert_revocations, agent_bootstrap_tokens, kubernetes_controller_posture, policy_bindings, tenant_members, attestations, api_tokens, certificates, certificate_metadata_watermarks, certificate_metadata_receipts,
		          ca_authorities, ca_key_ceremonies, ca_ceremony_approvals,
		          ca_issued_certs, ca_crls, ca_ocsp_responders, ssh_keys, ct_watched_domains, ct_log_checkpoints,
		          crypto_assets, credentials, audit_checkpoints, certificate_profiles,
		          secret_sync_workload_identity_sources, workload_attester_trust_sources,
		          discovery_segments, discovery_sources, discovery_schedules, discovery_runs, discovery_findings,
		          notification_channels, notification_reads, notification_threshold_deliveries, notification_test_operations,
		          notification_delivery_receipts, notification_routing_policies,
		          endpoint_verifications, connector_delivery_receipts, lifecycle_rotation_runs, remediation_playbook_runs,
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
		          acme_dns01_provider_configs,
		          audit_feed_deliveries, audit_feed_destinations,
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
func seedServedAPIToken(t *testing.T, ctx context.Context, st *store.Store, tenantID, subject string, scopes []string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate API token: %v", err)
	}
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantID, TokenHash: hash, Subject: subject, Scopes: scopes}); err != nil {
		t.Fatalf("seed API token: %v", err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}

func doBearer(t *testing.T, ts *httptest.Server, method, path, token, idem string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}
