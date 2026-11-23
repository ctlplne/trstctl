// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	authpkg "trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	secretvault "trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	deploymentKEKOperatorTenant = "71717171-7171-4171-8171-717171717171"
	deploymentKEKLegacyTenant   = "72727272-7272-4272-8272-727272727272"
)

// TestServedDeploymentKEKRotationRewrapsEveryDataKeyWhileServing drives A198
// through the default-binary composition. A tenant still on the deployment
// KEK has secrets, a credential, a transit keyring and event history sealed
// under the key file, and a deployment file is sealed under it too. Only the
// operator tenant may rotate. While the rotation runs, reads and writes keep
// working and new data is wrapped under the next generation. When it
// completes, every stored data key read back from PostgreSQL, the event
// history and the file is in the new generation, the key file alone opens
// none of them, the credentials still open through the wrapper, and they stop
// opening when the wrapper goes away.
func TestServedDeploymentKEKRotationRewrapsEveryDataKeyWhileServing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st := newServerRewrapStore(t)
	for _, tenant := range []store.Tenant{
		{TenantID: deploymentKEKOperatorTenant, Name: "deployment-kek-operator", EventSeq: 1},
		{TenantID: deploymentKEKLegacyTenant, Name: "deployment-kek-legacy", EventSeq: 1},
	} {
		if err := st.UpsertTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	operator := seedScopedToken(t, st, deploymentKEKOperatorTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")
	legacy := seedScopedToken(t, st, deploymentKEKLegacyTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "deployment-kek")
	cfg.Secrets.KEKOperatorTenantID = deploymentKEKOperatorTenant
	cfg.Secrets.KEKRotationSettle = "0s"
	cfg.Protocols.RAKeyFile = filepath.Join(root, "protocol-ra.sealed")
	wrappers := map[string]string{}
	for id, fill := range map[string]byte{"deploy-wrap-1": 0x61, "deploy-wrap-2": 0x62} {
		path := filepath.Join(root, id+".key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		wrappers[id] = path
		cfg.Secrets.TenantSealLocalWrappers = append(cfg.Secrets.TenantSealLocalWrappers, config.TenantSealLocalWrapper{ID: id, File: path})
	}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	var ingressAccess tenantseal.Access
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(root, "nats")}, st, auditKey,
		restoreEventIngressOptionWithCustody(st, func() tenantseal.Access { return ingressAccess }))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(secrets.Close)
	keyFile, ok := secrets.kek.(*seal.LocalKEK)
	if !ok {
		t.Fatalf("run secrets hold %T, want the key file", secrets.kek)
	}
	// Sealed before the server starts, under the key file: a credential, and a
	// deployment-scoped file.
	if err := authpkg.StoreOIDCClientSecret(ctx, secretvault.NewVault(keyFile, st), deploymentKEKLegacyTenant, "primary", []byte("legacy-oidc-secret")); err != nil {
		t.Fatal(err)
	}
	raSealed, err := seal.Seal(keyFile, []byte("protocol RA identity"), []byte(protocolRAAAD))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Protocols.RAKeyFile, raSealed, 0o600); err != nil {
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner{}, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	ingressAccess = deps.TenantCrypto
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	if deps.DeploymentKEK == nil {
		t.Fatal("the default composition has no deployment KEK rotation")
	}

	for _, request := range []struct{ token, key, body string }{
		{operator, "deployment-kek-op-secret", `{"name":"db/password","value":"operator-secret"}`},
		{legacy, "deployment-kek-legacy-secret", `{"name":"db/password","value":"legacy-secret"}`},
	} {
		if rec := servedTenantSealRequest(t, srv, request.token, http.MethodPost, "/api/v1/secrets/store", request.key, []byte(request.body)); rec.Code != http.StatusCreated {
			t.Fatalf("create secret = %d body=%s", rec.Code, rec.Body.String())
		}
	}
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodPost, "/api/v1/transit/keys", "deployment-kek-transit",
		[]byte(`{"name":"payments","kind":"aead"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("create transit key = %d body=%s", rec.Code, rec.Body.String())
	}
	const staleJobID = "11111111-1111-4111-8111-111111111806"
	staleValue := []byte("stale-deployment-candidate")
	staleSealed, err := sealTenantValue(ctx, deps.TenantCrypto, deps.KEK,
		deploymentKEKLegacyTenant, staleValue,
		secretSyncAAD(deploymentKEKLegacyTenant, "durable-target", staleJobID, "STALE"))
	if err != nil {
		t.Fatal(err)
	}
	staleEpoch, err := st.ApplicationSecretTenantEpoch(ctx, deploymentKEKLegacyTenant)
	if err != nil {
		t.Fatal(err)
	}
	stalePayload, err := json.Marshal(projections.SecretSyncQueued{
		TenantEpoch: staleEpoch, ID: staleJobID, SecretName: "db/password", SecretVersion: 1,
		Target: "durable-target", RemoteKey: "STALE", ValueDigest: crypto.SHA256Hex(staleValue),
		IdempotencyKey: "stale-deployment-key", RequestBinding: "stale-deployment-request", Sealed: staleSealed,
	})
	if err != nil {
		t.Fatal(err)
	}

	status := servedDeploymentKEKStatus(t, srv, legacy)
	if status.Generation != 0 || status.Custody != "key_file" || status.CanRotate || status.RotationAuthority != "another_tenant" {
		t.Fatalf("initial status for a tenant = %+v", status)
	}
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-not-operator",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"deploy-wrap-1"}`)); rec.Code != http.StatusForbidden {
		t.Fatalf("a tenant that is not the operator rotated = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-bad-kind",
		[]byte(`{"wrapper_kind":"vault","wrapper_id":"deploy-wrap-1"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown wrapper kind = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-unknown",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"not-configured"}`)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unconfigured wrapper = %d body=%s", rec.Code, rec.Body.String())
	}
	marker := store.RestoreMarker{
		OperationID:    "77777777-7777-4777-8777-777777777701",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 1, DeploymentID: "deployment-rotation-restore-order",
	}
	if err := st.BeginFullRestore(ctx, marker); err != nil {
		rows, queryErr := st.SystemPool().Query(ctx, `SELECT tenant_id::text,activity_kind,lane,count(*)
			FROM trstctl_recovery.restore_activity_tokens WHERE phase='started'
			GROUP BY tenant_id,activity_kind,lane ORDER BY tenant_id,activity_kind,lane`)
		if queryErr == nil {
			for rows.Next() {
				var tenantID, kind, lane string
				var count int
				if scanErr := rows.Scan(&tenantID, &kind, &lane, &count); scanErr == nil {
					t.Logf("unresolved activity before restore marker: tenant=%s kind=%s lane=%s count=%d", tenantID, kind, lane, count)
				}
			}
			rows.Close()
		}
		t.Fatalf("arm restore marker before deployment rotation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 AND operation_id=$2`,
			store.RestoreControlTenantID, marker.OperationID)
	})
	if _, err := deps.DeploymentKEK.Begin(ctx, deploymentKEKOperatorTenant,
		tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "deploy-wrap-1"}); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("deployment rotation under restore marker = %v, want preflight refusal", err)
	}
	if gate, found, err := st.GetTenantApplicationSecretRewrapGate(ctx, deploymentKEKLegacyTenant); err != nil || found && gate.InProgress {
		t.Fatalf("deployment rotation armed a tenant gate behind restore marker: gate=%+v found=%t err=%v", gate, found, err)
	}
	if tag, err := st.SystemPool().Exec(ctx,
		`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 AND operation_id=$2`,
		store.RestoreControlTenantID, marker.OperationID); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("clear exact test restore marker: rows=%d err=%v", tag.RowsAffected(), err)
	}
	started := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-rotate-1",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"deploy-wrap-1"}`))
	if started.Code != http.StatusAccepted {
		rows, queryErr := st.SystemPool().Query(ctx, `SELECT tenant_id::text,activity_kind,lane,count(*)
			FROM trstctl_recovery.restore_activity_tokens WHERE phase='started'
			GROUP BY tenant_id,activity_kind,lane ORDER BY tenant_id,activity_kind,lane`)
		if queryErr == nil {
			for rows.Next() {
				var tenantID, kind, lane string
				var count int
				if scanErr := rows.Scan(&tenantID, &kind, &lane, &count); scanErr == nil {
					t.Logf("unresolved restore activity: tenant=%s kind=%s lane=%s count=%d", tenantID, kind, lane, count)
				}
			}
			rows.Close()
		}
		t.Fatalf("rotate = %d body=%s", started.Code, started.Body.String())
	}
	var begun api.DeploymentKEKStatus
	if err := json.Unmarshal(started.Body.Bytes(), &begun); err != nil {
		t.Fatal(err)
	}
	if begun.Rotation == nil || begun.Rotation.Status != "running" || begun.Rotation.Stage != "settling" ||
		begun.Rotation.NextGeneration != 1 || begun.Generation != 0 || !begun.CanRotate {
		t.Fatalf("rotation started = %+v", begun)
	}
	if err := st.BeginFullRestore(ctx, marker); !errors.Is(err, store.ErrRestoreActivityUnresolved) {
		t.Fatalf("restore between deployment rewrap steps = %v, want armed-gate refusal", err)
	}
	if replay := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-rotate-1",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"deploy-wrap-1"}`)); replay.Code != http.StatusAccepted || !bytes.Equal(replay.Body.Bytes(), started.Body.Bytes()) {
		t.Fatalf("replayed rotate = %d body=%s", replay.Code, replay.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-other-wrapper",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"deploy-wrap-2"}`)); rec.Code != http.StatusConflict {
		t.Fatalf("a second rotation to another wrapper while one runs = %d body=%s", rec.Code, rec.Body.String())
	}
	var unresolvedBegins int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND activity_kind='maintenance' AND lane='deployment-kek-begin' AND phase='started'`,
		store.RestoreControlTenantID).Scan(&unresolvedBegins); err != nil || unresolvedBegins != 0 {
		t.Fatalf("conflicting no-effect rotation left %d unresolved begin tokens: %v", unresolvedBegins, err)
	}

	// A command that arrives during the rewrap must retry after the gate
	// closes; it cannot publish a mutation against a moving key domain.
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodPost, "/api/v1/secrets/store", "deployment-kek-during",
		[]byte(`{"name":"db/during","value":"written-during-rotation"}`)); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "rewrap_in_progress") {
		t.Fatalf("write during the rotation must be retryable = %d body=%s", rec.Code, rec.Body.String())
	}
	servedStepDeploymentKEK(t, deps, func(step int) {
		// Every step serves reads of existing data under either generation.
		for _, read := range []struct{ token, path, want string }{
			{legacy, "/api/v1/secrets/store/db/password", "legacy-secret"},
			{operator, "/api/v1/secrets/store/db/password", "operator-secret"},
		} {
			if rec := servedTenantSealRequest(t, srv, read.token, http.MethodGet, read.path, "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), read.want) {
				t.Fatalf("read during rotation step %d = %d body=%s", step, rec.Code, rec.Body.String())
			}
		}
	})
	if opened, err := openTenantValue(ctx, deps.TenantCrypto, deps.KEK,
		deploymentKEKLegacyTenant, staleSealed,
		secretSyncAAD(deploymentKEKLegacyTenant, "durable-target", staleJobID, "STALE")); err == nil {
		secret.Wipe(opened)
		t.Fatal("retired deployment wrapper still opens stale sealed candidate")
	}
	staleEventID := store.SecretSyncQueuedEventID(deploymentKEKLegacyTenant, staleJobID)
	if _, err := log.Append(ctx, events.Event{ID: staleEventID, Type: projections.EventSecretSyncQueued,
		TenantID: deploymentKEKLegacyTenant, SchemaVersion: projections.SecretSyncEventSchemaVersion,
		Data: stalePayload}); err == nil {
		t.Fatal("stale sealed secret-sync candidate appended after deployment rotation")
	}
	if _, found, err := log.EventByID(ctx, staleEventID); err != nil || found {
		t.Fatalf("stale deployment candidate found=%t err=%v, want no NATS event", found, err)
	}
	var unresolvedIngress int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*)
		FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND activity_kind='ingress'
		AND lane='event-append' AND event_id=$2 AND phase='started'`, deploymentKEKLegacyTenant, staleEventID).
		Scan(&unresolvedIngress); err != nil || unresolvedIngress != 0 {
		t.Fatalf("refused deployment candidate left %d unresolved ingress tokens: %v", unresolvedIngress, err)
	}
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodPost, "/api/v1/secrets/store", "deployment-kek-during",
		[]byte(`{"name":"db/during","value":"written-during-rotation"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("write after rotation retry = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodGet, "/api/v1/secrets/store/db/during", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "written-during-rotation") {
		t.Fatalf("read after rotation retry = %d body=%s", rec.Code, rec.Body.String())
	}

	done := servedDeploymentKEKStatus(t, srv, operator)
	if done.Generation != 1 || done.Custody != "local_file" || done.WrapperID != "deploy-wrap-1" || done.PreviousGeneration != 0 ||
		done.Rotation == nil || done.Rotation.Status != "completed" || done.Rotation.ContainersRewrapped == 0 ||
		done.Rotation.HistoryEventsRewrapped == 0 || done.Rotation.FilesRewrapped != 1 || done.Rotation.ContainersVerified == 0 ||
		done.Rotation.VerifyPasses != 0 || done.Rotation.VerifiedAt == nil {
		t.Fatalf("completed status = %+v rotation=%+v", done, done.Rotation)
	}

	// The census, read back independently of the rotation's own counts.
	for _, tenantID := range []string{deploymentKEKOperatorTenant, deploymentKEKLegacyTenant} {
		hot := servedDeploymentHotStateContainers(t, st, tenantID)
		if len(hot) == 0 {
			t.Fatalf("tenant %s has no stored containers to check", tenantID)
		}
		servedRequireDeploymentGeneration(t, keyFile, "hot state of "+tenantID, hot, 1)
	}
	history := servedDeploymentHistoryContainers(t, log, deploymentKEKLegacyTenant)
	if len(history) == 0 {
		t.Fatal("the legacy tenant's history holds no containers to check")
	}
	servedRequireDeploymentGeneration(t, keyFile, "history", history, 1)
	raAfter, err := os.ReadFile(cfg.Protocols.RAKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	servedRequireDeploymentGeneration(t, keyFile, "the RA identity file", [][]byte{raAfter}, 1)
	if plain, err := seal.Open(deps.KEK, raAfter, []byte(protocolRAAAD)); err != nil || string(plain) != "protocol RA identity" {
		t.Fatalf("the re-wrapped file does not open through the deployment KEK: %v", err)
	}
	if _, err := seal.Open(deps.KEK, raSealed, []byte(protocolRAAAD)); err == nil {
		t.Fatal("the retired key file still opens through the deployment KEK")
	}

	// Credentials still open, through the wrapper only.
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "legacy-secret") {
		t.Fatalf("read after the rotation = %d body=%s", rec.Code, rec.Body.String())
	}
	oidc, err := buildOIDCClientSecretSource(config.OIDC{ClientSecretTenant: deploymentKEKLegacyTenant, ClientSecretRef: "primary"}, st, deps.KEK, deps.TenantCrypto)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := oidc(ctx); err != nil || string(opened) != "legacy-oidc-secret" {
		t.Fatalf("the credential after the rotation = %q, %v", opened, err)
	}
	moved := wrappers["deploy-wrap-1"] + ".away"
	if err := os.Rename(wrappers["deploy-wrap-1"], moved); err != nil {
		t.Fatal(err)
	}
	if rec := servedTenantSealRequest(t, srv, legacy, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "legacy-secret") {
		t.Fatalf("a secret opened without its wrapper = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := os.Rename(moved, wrappers["deploy-wrap-1"]); err != nil {
		t.Fatal(err)
	}

	// A second rotation moves everything onto the other wrapper; the first
	// wrapper is then not needed.
	if rec := servedTenantSealRequest(t, srv, operator, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-rotate-2",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"deploy-wrap-2"}`)); rec.Code != http.StatusAccepted {
		t.Fatalf("second rotate = %d body=%s", rec.Code, rec.Body.String())
	}
	servedStepDeploymentKEK(t, deps, nil)
	if again := servedDeploymentKEKStatus(t, srv, operator); again.Generation != 2 || again.WrapperID != "deploy-wrap-2" || again.PreviousGeneration != 1 {
		t.Fatalf("second rotation status = %+v", again)
	}
	if err := os.Remove(wrappers["deploy-wrap-1"]); err != nil {
		t.Fatal(err)
	}
	for _, read := range []struct{ token, path, want string }{
		{legacy, "/api/v1/secrets/store/db/password", "legacy-secret"},
		{operator, "/api/v1/secrets/store/db/password", "operator-secret"},
	} {
		if rec := servedTenantSealRequest(t, srv, read.token, http.MethodGet, read.path, "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), read.want) {
			t.Fatalf("read after moving off the first wrapper = %d body=%s", rec.Code, rec.Body.String())
		}
	}
	servedRequireDeploymentGeneration(t, keyFile, "hot state after the second rotation",
		servedDeploymentHotStateContainers(t, st, deploymentKEKLegacyTenant), 2)
}

// servedStepDeploymentKEK drives the leader worker's steps to completion,
// calling between after each one.
func servedStepDeploymentKEK(t *testing.T, deps Deps, between func(step int)) {
	t.Helper()
	ctx := context.Background()
	for step := 0; step < 200; step++ {
		current, _, err := deps.DeploymentKEK.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !current.Rotating() {
			return
		}
		if current.OperationStatus == store.DeploymentKEKOperationFailed {
			t.Fatalf("the rotation failed: %s (%s)", current.LastErrorCode, current.LastError)
		}
		if _, err := deps.DeploymentKEK.Step(ctx); err != nil {
			t.Fatalf("rotation step %d: %v", step, err)
		}
		if between != nil {
			between(step)
		}
	}
	t.Fatal("the rotation did not complete in 200 steps")
}

func servedDeploymentKEKStatus(t *testing.T, srv *Server, token string) api.DeploymentKEKStatus {
	t.Helper()
	rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/platform/deployment-kek", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deployment KEK status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out api.DeploymentKEKStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// servedDeploymentHotStateContainers reads every sealed container in the
// tenant's ciphertext columns back from PostgreSQL.
func servedDeploymentHotStateContainers(t *testing.T, st *store.Store, tenantID string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, stage := range store.TenantKeyDomainCiphertextMigrationStages() {
		table, column, _ := strings.Cut(stage, ".")
		if err := st.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(context.Background(),
				`SELECT `+column+` FROM `+table+` WHERE tenant_id = $1 AND `+column+` IS NOT NULL`, tenantID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var value []byte
				if err := rows.Scan(&value); err != nil {
					return err
				}
				out = append(out, servedSealedContainers(value, 0)...)
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("read %s: %v", stage, err)
		}
	}
	return out
}

// servedDeploymentHistoryContainers reads every sealed container in one
// tenant's retained event history.
func servedDeploymentHistoryContainers(t *testing.T, log *events.Log, tenantID string) [][]byte {
	t.Helper()
	var out [][]byte
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.TenantID == tenantID {
			out = append(out, servedSealedContainers(e.Data, 0)...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// servedSealedContainers finds CSL containers stored raw or inside JSON,
// including base64-encoded nested JSON.
func servedSealedContainers(data []byte, depth int) [][]byte {
	if depth > 8 {
		return nil
	}
	if bytes.HasPrefix(data, []byte("CSL1")) {
		return [][]byte{data}
	}
	var value any
	if !json.Valid(data) || json.Unmarshal(data, &value) != nil {
		return nil
	}
	var out [][]byte
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case string:
			if decoded, err := base64.StdEncoding.DecodeString(typed); err == nil {
				out = append(out, servedSealedContainers(decoded, depth+1)...)
			}
		}
	}
	walk(value)
	return out
}

// servedRequireDeploymentGeneration requires every unlabeled container's data
// key to be in generation want, which the key file alone cannot unwrap.
func servedRequireDeploymentGeneration(t *testing.T, keyFile *seal.LocalKEK, where string, containers [][]byte, want uint32) {
	t.Helper()
	checked := 0
	for _, container := range containers {
		if label, err := seal.Domain(container); err != nil || label != nil {
			continue
		}
		wrapped, _, err := seal.ContainerWrappedDEK(container)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		generation, inner, err := seal.WrappedGeneration(wrapped)
		if err != nil || generation != want {
			t.Fatalf("%s: a data key is in generation %d (%v), want %d", where, generation, err, want)
		}
		if dek, err := keyFile.UnwrapDEK(inner); err == nil {
			t.Fatalf("%s: the key file alone unwrapped a generation-%d data key (%d bytes)", where, want, len(dek))
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("%s: no deployment KEK container to check", where)
	}
}
