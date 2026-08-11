// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	cryptoseal "trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// TestServedManualStaticSecretRotationFailsClosedBeforeProviderEffect proves the
// request path cannot enter an in-memory stage/cutover/rollback chain. A future
// implementation must move those phases behind one durable worker receiver.
func TestServedManualStaticSecretRotationFailsClosedBeforeProviderEffect(t *testing.T) {
	rotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{"postgresql": rotator}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	command := map[string]any{"provider": "postgresql", "key": "db/reporting", "old_ref": "role:old"}
	const idempotencyKey = "manual-static-fails-closed"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey, command)
	if status != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), "manual static-provider rotation is unavailable") {
		t.Fatalf("manual static refusal: status=%d body=%s, want typed 503", status, body)
	}
	first := append([]byte(nil), body...)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey, command)
	if status != http.StatusServiceUnavailable || !bytes.Equal(body, first) {
		t.Fatalf("manual static replay: status=%d body=%s, want identical %s", status, body, first)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey,
		map[string]any{"provider": "postgresql", "key": "db/changed", "old_ref": "role:old"})
	if status != http.StatusConflict {
		t.Fatalf("manual static changed-command replay: status=%d body=%s, want binding conflict", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		"bare-connector-fails-closed", map[string]any{
			"provider": "connector", "target": "ci", "key": "db/reporting", "old_ref": "role:old",
		})
	if status != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), "manual static-provider rotation is unavailable") {
		t.Fatalf("bare connector response: status=%d body=%s, want zero-effect provider refusal", status, body)
	}
	if rotator.calls != 0 {
		t.Fatalf("manual static refusal invoked provider stage %d times, want zero", rotator.calls)
	}
	if h.hasEvent(t, "secret.rotation.queued") || h.hasEvent(t, "secret.rotation.completed") {
		t.Fatal("manual static refusal emitted false rotation evidence")
	}
}

func TestServedScheduledStaticSecretRotationFailsClosedBeforeProviderEffect(t *testing.T) {
	ctx := context.Background()
	dsn, stop := startRotationPostgres(t)
	defer stop()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS cap_secr_06_smoke(id int primary key); INSERT INTO cap_secr_06_smoke(id) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}

	oldRef, oldSecret := createRotationPostgresCredential(t, ctx, dsn, "capsecr06_old")
	publisher := rotation.NewMemoryCredentialPublisher()
	publisher.Put("db/reporting", oldRef, oldSecret)
	rotator, err := rotation.NewPostgresRotator(rotation.PostgresConfig{
		DSN: []byte(dsn), Database: "postgres", Schema: "public", UsernamePrefix: "capsecr06", Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{"postgresql": rotator}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	dueAt := time.Now().Add(-time.Minute).UTC()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
		map[string]any{
			"name": "reporting-hourly", "provider": "postgresql", "key": "db/reporting",
			"old_ref": oldRef, "interval_seconds": 3600, "enabled": true,
			"next_run_at": dueAt.Format(time.RFC3339Nano),
		})
	if status != http.StatusServiceUnavailable || !strings.Contains(string(body), "scheduled static-provider rotation is unavailable") {
		t.Fatalf("static schedule response: status=%d body=%s, want fail-closed 503", status, body)
	}
	activeRef, activeSecret, err := publisher.ReadCredential(ctx, "db/reporting")
	if err != nil {
		t.Fatal(err)
	}
	if activeRef != oldRef {
		t.Fatalf("rejected schedule changed active ref=%q, want %q", activeRef, oldRef)
	}
	assertPostgresCredentialWorks(t, ctx, activeSecret, "cap_secr_06_smoke")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list rotation schedules: status %d body %s", status, body)
	}
	var list struct {
		Items []secretRotationScheduleValue `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode schedule list: %v (%s)", err, body)
	}
	if len(list.Items) != 0 {
		t.Fatalf("rejected static schedule persisted rows: %+v", list.Items)
	}
	if h.hasEvent(t, "secret.rotation_schedule.upserted") || h.hasEvent(t, "secret.rotation_schedule.ran") {
		t.Fatal("rejected static schedule emitted schedule/run events")
	}
	if h.logContains(t, string(oldSecret)) {
		t.Fatal("rejected schedule leaked PostgreSQL credential material")
	}
}

// TestServedSecretRotationCoversConnectorAndDynamicBackendsTRACE008 proves the
// connector path queues one durable worker effect and the incomplete dynamic-lease
// phase machine fails closed before it can mint or revoke anything. Responses and
// event payloads stay metadata-only.
func TestServedSecretRotationCoversConnectorAndDynamicBackendsTRACE008(t *testing.T) {
	connector := newRotationCapturePusher()
	dynamicBackend := newRotationDynamicBackend()
	dynamicProvider := dynsecret.NewProvider("postgresql", dynamicBackend)
	injectedDynamicRotator := &countingRotationRotator{}
	ignoredTTLRotator := &countingRotationRotator{}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.DynamicSecretProviders = []dynsecret.Provider{dynamicProvider}
			d.SecretRotators = map[string]rotation.Rotator{
				"dynamic-lease:postgresql": injectedDynamicRotator,
				"ttl-static":               ignoredTTLRotator,
			}
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	registerServedTenant(t, h, "served connector and dynamic rotation tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/connector", "value": "connector-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create connector source secret: status %d body %s", status, body)
	}
	connector.put("rotation/connector", []byte("connector-v1"))

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "connector:ci", "key": "rotation/connector", "old_ref": "version:1"})
	if status != http.StatusOK {
		t.Fatalf("connector rotation: status %d body %s", status, body)
	}
	var connectorRotated secretRotationValue
	if err := json.Unmarshal(body, &connectorRotated); err != nil {
		t.Fatalf("decode connector rotation: %v (%s)", err, body)
	}
	if connectorRotated.Completed || !connectorRotated.Queued || connectorRotated.NewRef != "version:2" {
		t.Fatalf("connector rotation = %+v, want queued version:2", connectorRotated)
	}
	if got := connector.successfulPushes("rotation/connector"); got != 0 {
		t.Fatalf("connector request path pushed %d times, want worker-only delivery", got)
	}
	drainCtx, cancelDrain := context.WithTimeout(t.Context(), 10*time.Second)
	if err := h.srv.proj.ProjectCatchUp(drainCtx, h.log); err != nil {
		cancelDrain()
		t.Fatalf("catch up connector rotation projection: %v", err)
	}
	if err := h.srv.Drain(drainCtx); err != nil {
		cancelDrain()
		t.Fatalf("drain queued connector rotation: %v", err)
	}
	cancelDrain()
	connectorValue := connector.value("rotation/connector")
	if connectorValue == "" || connectorValue == "connector-v1" {
		t.Fatalf("connector target value = %q, want a rotated value", connectorValue)
	}
	if strings.Contains(string(body), connectorValue) || h.logContains(t, connectorValue) || h.logContains(t, "connector-v1") {
		t.Fatal("connector rotation leaked secret material in response or event log")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/rollback", "value": "connector-rollback-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create rollback source secret: status %d body %s", status, body)
	}
	connector.put("rotation/rollback", []byte("connector-rollback-v1"))
	connector.failNext("rotation/rollback")
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "connector:ci", "key": "rotation/rollback", "old_ref": "version:1"})
	if status != http.StatusOK {
		t.Fatalf("connector durable retry rotation: status %d body %s", status, body)
	}
	var connectorQueued secretRotationValue
	if err := json.Unmarshal(body, &connectorQueued); err != nil {
		t.Fatalf("decode connector durable retry: %v (%s)", err, body)
	}
	if connectorQueued.Completed || !connectorQueued.Queued || connectorQueued.NewRef != "version:2" || connectorQueued.RollbackAttempted || connectorQueued.RolledBack {
		t.Fatalf("connector durable retry = %+v, want queued version:2 without compensating write", connectorQueued)
	}
	if got := connector.value("rotation/rollback"); got != "connector-rollback-v1" {
		t.Fatalf("connector failed first delivery changed remote value = %q, want old value retained", got)
	}
	local, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/rollback")
	if err != nil || local.Version != 2 {
		t.Fatalf("connector failed first delivery lost committed local rotation: %+v err=%v", local, err)
	}
	jobs, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", store.SecretSyncJobPending, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	foundDurableRetry := false
	for _, job := range jobs {
		foundDurableRetry = foundDurableRetry || job.SecretName == "rotation/rollback" && job.SecretVersion == 2
	}
	if !foundDurableRetry {
		t.Fatalf("connector delivery failure left no durable pending retry: %+v", jobs)
	}
	retryCtx, cancelRetry := context.WithTimeout(t.Context(), 10*time.Second)
	if err := h.srv.Drain(retryCtx); err != nil {
		cancelRetry()
		t.Fatalf("drain durable connector retry before dynamic rotation: %v", err)
	}
	cancelRetry()

	workerCtx, stopWorker := context.WithCancel(t.Context())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		h.srv.RunDispatcher(workerCtx)
	}()
	t.Cleanup(func() {
		stopWorker()
		<-workerDone
	})

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases", tok,
		map[string]any{"provider": "postgresql", "role": "readonly", "ttl_seconds": 600})
	if status != http.StatusCreated {
		t.Fatalf("issue initial dynamic lease: status %d body %s", status, body)
	}
	var initialLease dynamicLeaseValue
	if err := json.Unmarshal(body, &initialLease); err != nil {
		t.Fatalf("decode initial dynamic lease: %v (%s)", err, body)
	}
	if initialLease.ID == "" || initialLease.Credential == "" {
		t.Fatalf("initial lease = %+v, want one-time credential", initialLease)
	}
	connector.put("dynamic/readonly", []byte(initialLease.Credential))
	issuedBefore := dynamicBackend.issuedCount()
	jobsBeforeDynamic, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	dynamicLeaseEvents := func() int {
		t.Helper()
		count := 0
		if err := h.log.Replay(context.Background(), 1, func(event events.Event) error {
			if event.Type == projections.EventDynamicSecretLeasePending || event.Type == projections.EventDynamicSecretLeaseIssued {
				count++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	dynamicEventsBefore := dynamicLeaseEvents()
	const dynamicRotationKey = "dynamic-rotation-fails-closed"
	dynamicCommand := map[string]any{
		"provider":    "dynamic-lease:postgresql",
		"key":         "readonly",
		"old_ref":     initialLease.ID,
		"target":      "ci",
		"remote_key":  "dynamic/readonly",
		"ttl_seconds": 600,
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, dynamicRotationKey,
		dynamicCommand)
	if status != http.StatusServiceUnavailable || !strings.Contains(string(body), "dynamic-lease rotation is unavailable") {
		t.Fatalf("dynamic lease rotation fail-closed response: status %d body %s", status, body)
	}
	firstFailure := append([]byte(nil), body...)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, dynamicRotationKey,
		dynamicCommand)
	if status != http.StatusServiceUnavailable || string(body) != string(firstFailure) {
		t.Fatalf("dynamic lease rotation replay: status %d body %s, want identical %s", status, body, firstFailure)
	}
	if dynamicBackend.issuedCount() != issuedBefore || dynamicBackend.revokedCount() != 0 {
		t.Fatalf("fail-closed dynamic rotation provider issued/revoked=%d/%d, want %d/0",
			dynamicBackend.issuedCount(), dynamicBackend.revokedCount(), issuedBefore)
	}
	if injectedDynamicRotator.calls != 0 {
		t.Fatalf("fail-closed dynamic rotation invoked injected rotator %d times, want zero", injectedDynamicRotator.calls)
	}
	if got := dynamicLeaseEvents(); got != dynamicEventsBefore {
		t.Fatalf("fail-closed dynamic rotation created %d successor events, want zero", got-dynamicEventsBefore)
	}
	if got := connector.successfulPushes("dynamic/readonly"); got != 0 {
		t.Fatalf("fail-closed dynamic rotation delivered %d connector effects, want zero", got)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+initialLease.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get fail-closed predecessor: status %d body %s", status, body)
	}
	var oldLease dynamicLeaseValue
	if err := json.Unmarshal(body, &oldLease); err != nil || oldLease.State != "active" {
		t.Fatalf("fail-closed predecessor=%+v decode_err=%v, want active", oldLease, err)
	}
	jobsAfterDynamic, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", "", "", 100)
	if err != nil || len(jobsAfterDynamic) != len(jobsBeforeDynamic) {
		t.Fatalf("fail-closed dynamic rotation changed sync jobs before=%+v after=%+v err=%v",
			jobsBeforeDynamic, jobsAfterDynamic, err)
	}
	for i := range jobsBeforeDynamic {
		if jobsBeforeDynamic[i].ID != jobsAfterDynamic[i].ID || jobsBeforeDynamic[i].Status != jobsAfterDynamic[i].Status {
			t.Fatalf("fail-closed dynamic rotation changed sync job[%d]: before=%+v after=%+v", i, jobsBeforeDynamic[i], jobsAfterDynamic[i])
		}
	}
	var revokeIntents int
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, dynamicSecretRevokeDestination).Scan(&revokeIntents); err != nil {
		t.Fatal(err)
	}
	if revokeIntents != 0 {
		t.Fatalf("fail-closed dynamic rotation revoke intents=%d, want zero", revokeIntents)
	}
	for _, ttl := range []int{600, 0} {
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
			fmt.Sprintf("static-rotation-rejects-ignored-ttl-%d", ttl), map[string]any{
				"provider": "ttl-static", "key": "database/password", "old_ref": "old-ref", "ttl_seconds": ttl,
			})
		if status != http.StatusServiceUnavailable || !strings.Contains(string(body), "manual static-provider rotation is unavailable") {
			t.Fatalf("static supplied TTL %d response: status=%d body=%s", ttl, status, body)
		}
	}
	if ignoredTTLRotator.calls != 0 {
		t.Fatalf("static ignored TTL invoked rotator %d times, want zero", ignoredTTLRotator.calls)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
		"dynamic-rotation-schedule-fails-closed",
		map[string]any{
			"name": "unsupported-dynamic", "provider": "dynamic-lease:postgresql",
			"key": "readonly", "old_ref": initialLease.ID, "interval_seconds": 60,
		})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("dynamic rotation schedule status=%d body=%s, want fail-closed 503", status, body)
	}
	schedules, err := h.store.ListSecretRotationSchedulesPage(context.Background(), h.tenant, store.ZeroUUID, 100)
	if err != nil || len(schedules) != 0 {
		t.Fatalf("fail-closed dynamic schedule persisted rows=%+v err=%v", schedules, err)
	}
	if !h.hasEvent(t, "secret.rotation.queued") || !h.hasEvent(t, projections.EventApplicationSecretRotated) {
		t.Fatal("connector rotation audit evidence is missing")
	}
}

type countingRotationRotator struct{ calls int }

func (r *countingRotationRotator) Stage(context.Context, string) (string, error) {
	r.calls++
	return "unexpected-successor", nil
}
func (*countingRotationRotator) Cutover(context.Context, string, string) error { return nil }
func (*countingRotationRotator) Verify(context.Context, string) error          { return nil }
func (*countingRotationRotator) Retire(context.Context, string, string) error  { return nil }
func (*countingRotationRotator) Rollback(context.Context, string, string) error {
	return nil
}

type retireFailureRotationRotator struct{ stageCalls int }

func (r *retireFailureRotationRotator) Stage(context.Context, string) (string, error) {
	r.stageCalls++
	return "live-successor", nil
}
func (*retireFailureRotationRotator) Cutover(context.Context, string, string) error { return nil }
func (*retireFailureRotationRotator) Verify(context.Context, string) error          { return nil }
func (*retireFailureRotationRotator) Retire(context.Context, string, string) error {
	return errors.New("fixture predecessor retirement failed")
}
func (*retireFailureRotationRotator) Rollback(context.Context, string, string) error { return nil }

type stageFailureRotationRotator struct{ calls int }

func (r *stageFailureRotationRotator) Stage(context.Context, string) (string, error) {
	r.calls++
	return "never-live", errors.New("fixture stage failed")
}
func (*stageFailureRotationRotator) Cutover(context.Context, string, string) error { return nil }
func (*stageFailureRotationRotator) Verify(context.Context, string) error          { return nil }
func (*stageFailureRotationRotator) Retire(context.Context, string, string) error  { return nil }
func (*stageFailureRotationRotator) Rollback(context.Context, string, string) error {
	return nil
}

func TestServedConnectorRotationUsesExactSecretAuthorityAndProjectedOutbox(t *testing.T) {
	connector := newRotationCapturePusher()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-alice", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-bob", "secrets:write")
	if epoch, err := h.store.ApplicationSecretTenantEpoch(context.Background(), h.tenant); err != nil || epoch == "" {
		t.Fatalf("initialize application-secret tenant epoch: epoch=%q err=%v", epoch, err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "rotation/exact", "value": "connector-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed connector source: status=%d body=%s", status, body)
	}
	connector.put("rotation/exact", []byte("connector-v1"))

	const rotateKey = "connector-exact-rotation"
	command := map[string]any{
		"provider": "connector:ci", "key": "rotation/exact", "old_ref": "version:1",
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", requester, rotateKey, command)
	if status != http.StatusForbidden {
		t.Fatalf("connector rotation before approval status=%d body=%s, want 403", status, body)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/exact")
	if err != nil || current.Version != 1 || connector.value("rotation/exact") != "connector-v1" {
		t.Fatalf("unapproved connector rotation changed state: current=%+v target=%q err=%v", current, connector.value("rotation/exact"), err)
	}
	requests, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	var exact store.OperationApprovalRequest
	for _, request := range requests {
		if request.ResourceID == "secret:rotation/exact" && request.Action == "rotate" && request.TargetVersion == 1 {
			exact = request
			break
		}
	}
	if exact.ID == "" || exact.Requester != "rotation-alice" {
		t.Fatalf("connector rotation did not create exact requester authority: %+v", requests)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/store/approvals/rotation/exact", approver, "connector-exact-approve",
		map[string]any{"action": "rotate", "request_id": exact.ID, "intent_digest": exact.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("approve connector rotation: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", requester, rotateKey, command)
	if status != http.StatusOK {
		t.Fatalf("approved connector rotation: status=%d body=%s", status, body)
	}
	var queued secretRotationValue
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode approved connector rotation: %v (%s)", err, body)
	}
	if queued.Completed || !queued.Queued || queued.NewRef != "version:2" || connector.successfulPushes("rotation/exact") != 0 {
		t.Fatalf("approved connector rotation=%+v pushes=%d, want queued worker effect",
			queued, connector.successfulPushes("rotation/exact"))
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "rotation/exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("approved connector rotation current=%+v err=%v, want version 2", current, err)
	}
	spent, err := h.store.GetOperationApproval(context.Background(), h.tenant, exact.ID)
	if err != nil || spent.Status != store.ApprovalStatusConsumed || spent.ConsumedEventID == "" {
		t.Fatalf("connector rotation authority was not spent into one event: %+v err=%v", spent, err)
	}
	mutationEvents := 0
	if err := h.log.Replay(context.Background(), 1, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretRotated || event.SchemaVersion != projections.ApplicationSecretMutationSchemaVersion {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name == "rotation/exact" {
			mutationEvents++
			if payload.Surface != "rotation" || payload.Sync == nil || payload.Sync.Target != "ci" || len(payload.Sync.Sealed) == 0 {
				t.Fatalf("connector mutation omitted exact sealed sync intent: %+v", payload)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mutationEvents != 1 {
		t.Fatalf("connector rotation emitted %d authoritative mutations, want one", mutationEvents)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", requester, rotateKey, command)
	if status != http.StatusOK {
		t.Fatalf("connector exact replay status=%d body=%s", status, body)
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "rotation/exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("connector exact replay applied twice: current=%+v err=%v", current, err)
	}
}

func TestServedConnectorRotationRecoveryCollapsesProviderError(t *testing.T) {
	const (
		rotationKey   = "connector-terminal-error-recovery"
		providerError = "credential=super-secret subject=alice@example.test remote=vault/alice"
	)
	connector := newRotationCapturePusher()
	h := newServedHarness(t, config.Protocols{},
		withProtectedSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": "rotation/direct-terminal", "value": "direct-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed direct terminal source: status=%d body=%s", status, body)
	}
	connector.put("rotation/direct-terminal", []byte("direct-v1"))
	command := map[string]any{
		"provider": "connector:ci", "key": "rotation/direct-terminal", "old_ref": "version:1",
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations",
		token, rotationKey, command)
	if status != http.StatusOK {
		t.Fatalf("queue direct terminal rotation: status=%d body=%s", status, body)
	}
	var queued secretRotationValue
	if err := json.Unmarshal(body, &queued); err != nil || !queued.Queued ||
		queued.Completed || queued.NewRef != "version:2" {
		t.Fatalf("direct terminal rotation=%+v err=%v", queued, err)
	}
	jobs, err := h.store.ListSecretSyncJobsPage(
		context.Background(), h.tenant, "ci", store.SecretSyncJobPending, "", 10,
	)
	if err != nil {
		t.Fatalf("list direct terminal jobs: %v", err)
	}
	var job store.SecretSyncJob
	for _, candidate := range jobs {
		if candidate.SecretName == "rotation/direct-terminal" {
			job = candidate
			break
		}
	}
	if job.ID == "" {
		t.Fatalf("direct terminal rotation omitted sync job: %+v", jobs)
	}
	failedPayload, err := json.Marshal(projections.SecretSyncFailed{
		ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 10, Error: providerError,
	})
	if err != nil {
		t.Fatal(err)
	}
	failedEvent, err := h.log.Append(context.Background(), events.Event{
		ID: store.SecretSyncFailedEventID(h.tenant, job.ID), Type: projections.EventSecretSyncFailed,
		TenantID: h.tenant, SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: failedPayload,
	})
	if err != nil {
		t.Fatalf("append direct terminal sync event: %v", err)
	}
	if err := h.srv.proj.Apply(context.Background(), failedEvent); err != nil {
		t.Fatalf("project direct terminal sync event: %v", err)
	}
	failedJob, err := h.store.GetSecretSyncJob(context.Background(), h.tenant, job.ID)
	if err != nil || failedJob.Status != store.SecretSyncJobFailed || failedJob.LastError != providerError {
		t.Fatalf("direct terminal source fixture=%+v err=%v", failedJob, err)
	}
	// Remove only the generic HTTP receiver to force the direct route through
	// its canonical event/fence recovery path. The application-secret event and
	// failed delivery receipt remain authoritative.
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, rotationKey)
		return err
	}); err != nil {
		t.Fatalf("remove direct terminal outer receiver: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations",
		token, rotationKey, command)
	if status != http.StatusServiceUnavailable ||
		!bytes.Contains(body, []byte("connector delivery failed")) ||
		bytes.Contains(body, []byte(providerError)) {
		t.Fatalf("direct terminal recovery leaked provider error: status=%d body=%s", status, body)
	}
}

func TestServedScheduledConnectorRotationKeepsDueEdgeUntilExactApproval(t *testing.T) {
	connector := newRotationCapturePusher()
	healthyRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretRotators = map[string]rotation.Rotator{"healthy-static": healthyRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-alice", "secrets:read", "secrets:write")
	runnerB := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-charlie", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-bob", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		map[string]any{"name": "rotation/scheduled-exact", "value": "scheduled-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed scheduled connector source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-exact", []byte("scheduled-v1"))
	dueAt := time.Now().Add(-time.Minute).UTC()
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", requester,
		map[string]any{
			"name": "scheduled-exact", "provider": "connector:ci", "key": "rotation/scheduled-exact",
			"old_ref": "version:1", "interval_seconds": 3600, "enabled": true,
			"next_run_at": dueAt.Format(time.RFC3339Nano),
		})
	if status != http.StatusCreated {
		t.Fatalf("create scheduled connector rotation: status=%d body=%s", status, body)
	}
	var scheduled secretRotationScheduleValue
	if err := json.Unmarshal(body, &scheduled); err != nil {
		t.Fatal(err)
	}
	healthySchedule, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
		Name: "inherited-static-after-pending", Provider: "healthy-static", Key: "static/healthy",
		OldRef: "healthy-v1", IntervalSeconds: 3600, Enabled: true, NextRunAt: dueAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("seed inherited static schedule: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("unapproved scheduled connector run: status=%d body=%s, want non-blocking 200", status, body)
	}
	var waiting secretRotationDueRunValue
	if err := json.Unmarshal(body, &waiting); err != nil || waiting.Ran != 1 || len(waiting.Runs) != 1 ||
		waiting.Runs[0].ScheduleID != healthySchedule.ID || waiting.Runs[0].Status != "unsupported" ||
		waiting.Scanned != 2 || len(waiting.Deferred) != 1 ||
		waiting.Deferred[0].ScheduleID != scheduled.ID || waiting.Deferred[0].Reason != "approval_pending" {
		t.Fatalf("unapproved scheduled connector batch=%+v err=%v, want pending edge deferred and inherited static row disabled", waiting, err)
	}
	if healthyRotator.calls != 0 {
		t.Fatalf("inherited static scheduler invoked rotator %d times, want zero", healthyRotator.calls)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-exact")
	if err != nil || current.Version != 1 || connector.value("rotation/scheduled-exact") != "scheduled-v1" {
		t.Fatalf("unapproved scheduled connector run changed state: current=%+v target=%q err=%v",
			current, connector.value("rotation/scheduled-exact"), err)
	}
	pendingAfterTick, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, scheduled.ID)
	if err != nil || pendingAfterTick.LastRunID != nil || pendingAfterTick.LastRunStatus != "" ||
		!pendingAfterTick.NextRunAt.Equal(scheduled.NextRunAt) || pendingAfterTick.OldRef != "version:1" {
		t.Fatalf("pending approval due edge drifted after later work ran: %+v err=%v", pendingAfterTick, err)
	}
	healthyAfterTick, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, healthySchedule.ID)
	if err != nil || healthyAfterTick.LastRunStatus != "unsupported" || healthyAfterTick.OldRef != "healthy-v1" ||
		healthyAfterTick.Enabled || !healthyAfterTick.NextRunAt.After(time.Now()) {
		t.Fatalf("inherited static cadence did not fail closed and disable: %+v err=%v", healthyAfterTick, err)
	}
	pendingCommand, err := h.store.GetLatestSecretRotationScheduleCommand(
		context.Background(), h.tenant, scheduled.ID)
	if err != nil || pendingCommand.Status != "claimed" || pendingCommand.LeaseToken != "" {
		t.Fatalf("pending due-edge command after first runner=%+v err=%v", pendingCommand, err)
	}
	claimedCommand, acquired, err := h.store.ClaimSecretRotationScheduleCommand(
		context.Background(), pendingCommand, "overlap-runner-a", time.Minute)
	if err != nil || !acquired || claimedCommand.RunID != pendingCommand.RunID {
		t.Fatalf("hold overlap command=%+v acquired=%t err=%v", claimedCommand, acquired, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runnerB, "scheduled-overlap-runner-b", nil)
	var overlap secretRotationDueRunValue
	if status != http.StatusOK || json.Unmarshal(body, &overlap) != nil || overlap.Ran != 0 ||
		len(overlap.Deferred) != 1 || overlap.Deferred[0].ScheduleID != scheduled.ID ||
		overlap.Deferred[0].Reason != "command_claimed" {
		t.Fatalf("overlapping runner batch status=%d body=%s decoded=%+v", status, body, overlap)
	}
	if err := h.store.ReleaseSecretRotationScheduleCommandLease(
		context.Background(), h.tenant, scheduled.ID, pendingCommand.RunID,
		"overlap-runner-a"); err != nil {
		t.Fatalf("release overlap command: %v", err)
	}
	requests, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	var exact store.OperationApprovalRequest
	for _, request := range requests {
		if request.ResourceID == "secret:rotation/scheduled-exact" && request.Action == "rotate" && request.TargetVersion == 1 {
			exact = request
			break
		}
	}
	if exact.ID == "" || exact.Requester != "secret-rotation-schedule:"+scheduled.ID {
		t.Fatalf("scheduled connector run did not create exact authority: %+v", requests)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/store/approvals/rotation/scheduled-exact", approver, "scheduled-exact-approve",
		map[string]any{"action": "rotate", "request_id": exact.ID, "intent_digest": exact.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("approve scheduled connector rotation: status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runnerB, nil)
	if status != http.StatusOK {
		t.Fatalf("approved scheduled connector run: status=%d body=%s", status, body)
	}
	var run secretRotationDueRunValue
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatal(err)
	}
	if run.Ran != 1 || len(run.Runs) != 1 || run.Runs[0].ScheduleID != scheduled.ID ||
		run.Runs[0].Status != "queued" || run.Runs[0].Rotation.Completed || !run.Runs[0].Rotation.Queued ||
		run.Runs[0].Rotation.NewRef != "version:2" {
		t.Fatalf("approved scheduled connector run = %+v", run)
	}
	current, err = h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-exact")
	if err != nil || current.Version != 2 {
		t.Fatalf("approved scheduled connector run current=%+v err=%v, want version 2", current, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("list scheduled connector rotations: status=%d body=%s", status, body)
	}
	var list struct {
		Items []secretRotationScheduleValue `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	var connectorSchedule secretRotationScheduleValue
	for _, item := range list.Items {
		if item.ID == scheduled.ID {
			connectorSchedule = item
			break
		}
	}
	if len(list.Items) != 2 || connectorSchedule.ID == "" || connectorSchedule.OldRef != "version:2" ||
		connectorSchedule.LastRunStatus != "queued" || !connectorSchedule.NextRunAt.After(time.Now()) {
		t.Fatalf("scheduled connector cadence did not advance after approved effect: %+v", list.Items)
	}
}

func TestServedScheduledConnectorAuthoritySurvivesRunnerChangeAndRestart(t *testing.T) {
	connector := newRotationCapturePusher()
	targets := map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
	var secretKEK cryptoseal.KeyWrapper
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			secretKEK = d.KEK
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretSyncTargets = targets
		},
	)
	runnerA := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-runner-a", "secrets:read", "secrets:write")
	runnerB := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-runner-b", "secrets:read", "secrets:write")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-restart-approver", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runnerA,
		map[string]any{"name": "rotation/scheduled-authority-restart", "value": "scheduled-authority-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed scheduled authority source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-authority-restart", []byte("scheduled-authority-v1"))
	dueAt := time.Now().Add(-time.Minute).UTC()
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", runnerA,
		map[string]any{
			"name": "scheduled-authority-restart", "provider": "connector:ci",
			"key": "rotation/scheduled-authority-restart", "old_ref": "version:1",
			"interval_seconds": 3600, "enabled": true, "next_run_at": dueAt.Format(time.RFC3339Nano),
		})
	if status != http.StatusCreated {
		t.Fatalf("create scheduled authority: status=%d body=%s", status, body)
	}
	var scheduled secretRotationScheduleValue
	if err := json.Unmarshal(body, &scheduled); err != nil {
		t.Fatal(err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due",
		runnerA, "scheduled-authority-before-restart", nil)
	if status != http.StatusOK {
		t.Fatalf("open scheduled authority: status=%d body=%s", status, body)
	}
	var waiting secretRotationDueRunValue
	if err := json.Unmarshal(body, &waiting); err != nil || waiting.Ran != 0 || len(waiting.Deferred) != 1 ||
		waiting.Deferred[0].ScheduleID != scheduled.ID || waiting.Deferred[0].Reason != "approval_pending" {
		t.Fatalf("scheduled authority pre-restart evidence=%+v err=%v", waiting, err)
	}

	requests, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	var exact store.OperationApprovalRequest
	for _, request := range requests {
		if request.ResourceID == "secret:rotation/scheduled-authority-restart" && request.Action == "rotate" {
			exact = request
			break
		}
	}
	wantAuthority := "secret-rotation-schedule:" + scheduled.ID
	if exact.ID == "" || exact.Requester != wantAuthority {
		t.Fatalf("scheduled authority requester=%q request=%+v, want %q", exact.Requester, exact, wantAuthority)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/store/approvals/rotation/scheduled-authority-restart", approver,
		"scheduled-authority-approval", map[string]any{
			"action": "rotate", "request_id": exact.ID, "intent_digest": exact.IntentDigest,
		})
	if status != http.StatusOK {
		t.Fatalf("approve scheduled authority: status=%d body=%s", status, body)
	}

	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		RequireApproval: true, RequiredApprovals: 1, SecretSyncTargets: targets,
	})
	if err != nil {
		t.Fatalf("restart with approved scheduled authority: %v", err)
	}
	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2 := &servedHarness{ts: ts, srv: restarted, store: h.store, log: h.log, tenant: h.tenant}

	status, body = secretsReqKey(t, h2, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due",
		runnerB, "scheduled-authority-after-restart", nil)
	if status != http.StatusOK {
		t.Fatalf("run approved schedule as replacement runner: status=%d body=%s", status, body)
	}
	var ran secretRotationDueRunValue
	if err := json.Unmarshal(body, &ran); err != nil || ran.Ran != 1 || len(ran.Runs) != 1 ||
		ran.Runs[0].ScheduleID != scheduled.ID || ran.Runs[0].Status != "queued" ||
		!ran.Runs[0].Rotation.Queued || ran.Runs[0].Rotation.NewRef != "version:2" {
		t.Fatalf("post-restart scheduled authority run=%+v err=%v", ran, err)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-authority-restart")
	if err != nil || current.Version != 2 {
		t.Fatalf("post-restart scheduled authority current=%+v err=%v", current, err)
	}
	mutationEvents := 0
	if err := h.log.Replay(context.Background(), 1, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretRotated {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name != "rotation/scheduled-authority-restart" {
			return nil
		}
		mutationEvents++
		if event.Actor == nil || event.Actor.Subject != wantAuthority {
			t.Fatalf("scheduled mutation actor=%+v, want stable authority %q", event.Actor, wantAuthority)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mutationEvents != 1 {
		t.Fatalf("scheduled authority restart emitted %d mutations, want one", mutationEvents)
	}
}

func TestServedScheduledConnectorTerminalApprovalsAdvanceWithoutStarvingLaterWork(t *testing.T) {
	connector := newRotationCapturePusher()
	healthyRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretRotators = map[string]rotation.Rotator{"healthy-static": healthyRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-terminal-requester", "secrets:read", "secrets:write")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-terminal-reviewer", "approvals:review", "secrets:write")
	ctx := context.Background()
	for _, name := range []string{"rotation/scheduled-denied", "rotation/scheduled-expired"} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
			map[string]any{"name": name, "value": name + "-v1"})
		if status != http.StatusCreated {
			t.Fatalf("seed %s: status=%d body=%s", name, status, body)
		}
		connector.put(name, []byte(name+"-v1"))
	}

	dueAt := time.Now().Add(-2 * time.Minute).UTC()
	create := func(name, provider, key, oldRef string, at time.Time) secretRotationScheduleValue {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", requester,
			map[string]any{
				"name": name, "provider": provider, "key": key, "old_ref": oldRef,
				"interval_seconds": 3600, "enabled": true, "next_run_at": at.Format(time.RFC3339Nano),
			})
		if status != http.StatusCreated {
			t.Fatalf("create schedule %s: status=%d body=%s", name, status, body)
		}
		var scheduled secretRotationScheduleValue
		if err := json.Unmarshal(body, &scheduled); err != nil {
			t.Fatalf("decode schedule %s: %v", name, err)
		}
		return scheduled
	}
	deniedSchedule := create("scheduled-denied", "connector:ci", "rotation/scheduled-denied", "version:1", dueAt)
	expiredSchedule := create("scheduled-expired", "connector:ci", "rotation/scheduled-expired", "version:1", dueAt.Add(time.Second))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due",
		requester, "scheduled-terminal-authorities-first-tick", nil)
	if status != http.StatusOK {
		t.Fatalf("create scheduled approval authorities: status=%d body=%s", status, body)
	}
	var firstTick secretRotationDueRunValue
	if err := json.Unmarshal(body, &firstTick); err != nil || firstTick.Ran != 0 || len(firstTick.Runs) != 0 {
		t.Fatalf("first terminal-authority tick=%+v err=%v, want both due edges pending", firstTick, err)
	}

	requests, err := h.store.ListOperationApprovals(ctx, h.tenant, store.ApprovalStatusPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	byResource := make(map[string]store.OperationApprovalRequest)
	for _, request := range requests {
		if request.ResourceKind == "secret" && request.Action == "rotate" {
			byResource[request.ResourceID] = request
		}
	}
	denied := byResource["secret:rotation/scheduled-denied"]
	expired := byResource["secret:rotation/scheduled-expired"]
	if denied.ID == "" || expired.ID == "" {
		t.Fatalf("scheduled approval authorities missing: %+v", requests)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/approval-requests/"+denied.ID+"/denials", reviewer, "scheduled-terminal-denial",
		map[string]any{"intent_digest": denied.IntentDigest, "reason": "scheduled rotation denied by reviewer"})
	if status != http.StatusOK {
		t.Fatalf("deny scheduled authority: status=%d body=%s", status, body)
	}
	if _, err := h.store.SystemPool().Exec(ctx,
		`UPDATE operation_approval_requests
		    SET expires_at = now() - interval '1 second'
		  WHERE tenant_id = $1 AND id = $2`, h.tenant, expired.ID); err != nil {
		t.Fatalf("expire scheduled authority fixture: %v", err)
	}

	healthySchedule, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
		Name: "inherited-static-after-terminal-authorities", Provider: "healthy-static",
		Key: "static/healthy", OldRef: "healthy-v1", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: time.Now().Add(-time.Minute).UTC(),
	})
	if err != nil {
		t.Fatalf("seed inherited static schedule: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due",
		requester, "scheduled-terminal-authorities-second-tick", nil)
	if status != http.StatusOK {
		t.Fatalf("run terminal scheduled authorities: status=%d body=%s", status, body)
	}
	var secondTick secretRotationDueRunValue
	if err := json.Unmarshal(body, &secondTick); err != nil {
		t.Fatalf("decode terminal authority tick: %v (%s)", err, body)
	}
	if secondTick.Ran != 3 || len(secondTick.Runs) != 3 {
		t.Fatalf("terminal authority tick=%+v, want two failed and one unsupported run", secondTick)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(secondTick.Runs))
	for _, run := range secondTick.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[deniedSchedule.ID]; run.Status != "failed" || !strings.Contains(run.Error, "approval") || run.Rotation.Queued || run.Rotation.Completed {
		t.Fatalf("denied scheduled run=%+v", run)
	}
	if run := runs[expiredSchedule.ID]; run.Status != "failed" || !strings.Contains(run.Error, "approval") || run.Rotation.Queued || run.Rotation.Completed {
		t.Fatalf("expired scheduled run=%+v", run)
	}
	if run := runs[healthySchedule.ID]; run.Status != "unsupported" || run.Rotation.Completed ||
		run.Rotation.FailedPhase != "provider" {
		t.Fatalf("inherited static scheduled run=%+v", run)
	}
	if healthyRotator.calls != 0 {
		t.Fatalf("inherited static rotator calls=%d, want zero", healthyRotator.calls)
	}

	for _, want := range []struct {
		schedule  secretRotationScheduleValue
		errorWord string
	}{{deniedSchedule, "approval"}, {expiredSchedule, "approval"}} {
		got, err := h.store.GetSecretRotationSchedule(ctx, h.tenant, want.schedule.ID)
		if err != nil || got.LastRunStatus != "failed" || !strings.Contains(got.LastError, want.errorWord) ||
			got.OldRef != "version:1" || !got.NextRunAt.After(time.Now()) {
			t.Fatalf("terminal schedule %s did not record/advance: %+v err=%v", want.schedule.ID, got, err)
		}
	}
	for _, name := range []string{"rotation/scheduled-denied", "rotation/scheduled-expired"} {
		current, err := h.store.GetSecret(ctx, h.tenant, name)
		if err != nil || current.Version != 1 || connector.value(name) != name+"-v1" {
			t.Fatalf("terminal authority changed %s: current=%+v remote=%q err=%v", name, current, connector.value(name), err)
		}
	}
}

func TestServedScheduledConnectorInFlightCommandDefersWithoutStarvingLaterWork(t *testing.T) {
	connector := newRotationCapturePusher()
	healthyRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretRotators = map[string]rotation.Rotator{"healthy-static": healthyRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	runner := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-transient-runner", "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
		map[string]any{"name": "rotation/scheduled-in-flight", "value": "in-flight-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed in-flight source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-in-flight", []byte("in-flight-v1"))

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", runner,
		"manual-command-holds-secret-fence", map[string]any{
			"provider": "connector:ci", "key": "rotation/scheduled-in-flight", "old_ref": "version:1",
		})
	if status != http.StatusForbidden || !strings.Contains(string(body), "approval_required") {
		t.Fatalf("open competing command fence: status=%d body=%s", status, body)
	}

	dueAt := time.Now().Add(-2 * time.Minute).UTC()
	create := func(name, provider, key, oldRef string, at time.Time) secretRotationScheduleValue {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", runner,
			map[string]any{
				"name": name, "provider": provider, "key": key, "old_ref": oldRef,
				"interval_seconds": 3600, "enabled": true, "next_run_at": at.Format(time.RFC3339Nano),
			})
		if status != http.StatusCreated {
			t.Fatalf("create schedule %s: status=%d body=%s", name, status, body)
		}
		var scheduled secretRotationScheduleValue
		if err := json.Unmarshal(body, &scheduled); err != nil {
			t.Fatalf("decode schedule %s: %v", name, err)
		}
		return scheduled
	}
	deferredSchedule := create("scheduled-in-flight", "connector:ci", "rotation/scheduled-in-flight", "version:1", dueAt)
	healthySchedule, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
		Name: "inherited-static-after-in-flight", Provider: "healthy-static", Key: "static/healthy",
		OldRef: "healthy-v1", IntervalSeconds: 3600, Enabled: true, NextRunAt: dueAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("seed inherited static schedule: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runner,
		"run-due-in-flight-does-not-starve", nil)
	if status != http.StatusOK {
		t.Fatalf("run due with in-flight command: status=%d body=%s", status, body)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil || batch.Scanned != 2 || batch.Ran != 1 ||
		len(batch.Runs) != 1 || batch.Runs[0].ScheduleID != healthySchedule.ID ||
		batch.Runs[0].Status != "unsupported" || len(batch.Deferred) != 1 ||
		batch.Deferred[0].ScheduleID != deferredSchedule.ID || batch.Deferred[0].Reason != "command_in_flight" {
		t.Fatalf("in-flight scheduled batch=%+v err=%v", batch, err)
	}
	if healthyRotator.calls != 0 {
		t.Fatalf("inherited static schedule after in-flight row ran %d times, want zero", healthyRotator.calls)
	}
	deferredAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, deferredSchedule.ID)
	if err != nil || deferredAfter.LastRunID != nil || deferredAfter.LastRunStatus != "" ||
		!deferredAfter.NextRunAt.Equal(deferredSchedule.NextRunAt) || deferredAfter.OldRef != "version:1" {
		t.Fatalf("in-flight due edge changed instead of deferring: %+v err=%v", deferredAfter, err)
	}
}

func TestServedScheduledRotationScansPastFiftyDeferredRowsWithinBound(t *testing.T) {
	connector := newRotationCapturePusher()
	healthyRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretRotators = map[string]rotation.Rotator{"healthy-static": healthyRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	runner := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-page-runner", "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
		map[string]any{"name": "rotation/shared-deferred-source", "value": "shared-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed shared deferred source: status=%d body=%s", status, body)
	}
	connector.put("rotation/shared-deferred-source", []byte("shared-v1"))

	dueAt := time.Now().Add(-10 * time.Minute).UTC()
	deferredSchedules := make([]store.SecretRotationSchedule, 0, 50)
	for i := 0; i < 50; i++ {
		scheduled, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
			Name: fmt.Sprintf("deferred-%02d", i), Provider: "connector:ci",
			Key: "rotation/shared-deferred-source", OldRef: "version:1",
			IntervalSeconds: 3600, Enabled: true, NextRunAt: dueAt.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("seed deferred schedule %d: %v", i, err)
		}
		deferredSchedules = append(deferredSchedules, scheduled)
	}
	healthySchedule, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
		Name: "healthy-after-fifty-deferred", Provider: "healthy-static", Key: "static/healthy",
		OldRef: "healthy-v1", IntervalSeconds: 3600, Enabled: true,
		NextRunAt: dueAt.Add(50 * time.Second),
	})
	if err != nil {
		t.Fatalf("seed healthy schedule after deferred page: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runner,
		"run-due-pages-past-fifty-deferred", nil)
	if status != http.StatusOK {
		t.Fatalf("run paged due schedules: status=%d body=%s", status, body)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil || batch.Scanned != 51 || batch.Ran != 1 ||
		len(batch.Deferred) != 50 || len(batch.Runs) != 1 || batch.Runs[0].ScheduleID != healthySchedule.ID ||
		batch.Runs[0].Status != "unsupported" || batch.RunLimitReached || batch.ScanLimitReached {
		t.Fatalf("paged due batch=%+v err=%v, want 50 deferred plus fail-closed inherited static row 51", batch, err)
	}
	reasons := map[string]int{}
	for _, deferred := range batch.Deferred {
		reasons[deferred.Reason]++
	}
	if reasons["approval_pending"] != 1 || reasons["command_in_flight"] != 49 {
		t.Fatalf("deferred reasons=%v, want first approval pending plus 49 in-flight", reasons)
	}
	if healthyRotator.calls != 0 {
		t.Fatalf("inherited static row 51 ran %d provider calls, want zero", healthyRotator.calls)
	}
	oldest, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, deferredSchedules[0].ID)
	if err != nil || oldest.LastRunID != nil || !oldest.NextRunAt.Equal(deferredSchedules[0].NextRunAt) {
		t.Fatalf("oldest deferred edge changed: %+v err=%v", oldest, err)
	}
}

func TestServedScheduledRotationFairCursorReachesRow501AcrossRestartAUD113(t *testing.T) {
	connector := newRotationCapturePusher()
	historicalRotator := &countingRotationRotator{}
	var secretKEK cryptoseal.KeyWrapper
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			secretKEK = d.KEK
			d.RequireApproval = true
			d.RequiredApprovals = 1
			d.SecretRotators = map[string]rotation.Rotator{"historical-static": historicalRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	runner := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-row-501-runner", "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
		map[string]any{"name": "rotation/aud113-shared", "value": "shared-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed shared row-501 source: status=%d body=%s", status, body)
	}
	connector.put("rotation/aud113-shared", []byte("shared-v1"))

	ctx := context.Background()
	dueAt := time.Now().UTC().Truncate(time.Microsecond).Add(-10 * time.Minute)
	for index := 1; index <= 500; index++ {
		id := fmt.Sprintf("50000000-0000-4000-8000-%012d", index)
		if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
			ID: id, Name: fmt.Sprintf("aud113-deferred-%03d", index), Provider: "connector:ci",
			Key: "rotation/aud113-shared", OldRef: "version:1", IntervalSeconds: 3600,
			Enabled: true, NextRunAt: dueAt,
		}); err != nil {
			t.Fatalf("seed deferred row %d: %v", index, err)
		}
	}
	const row501ID = "50000000-0000-4000-8000-000000000999"
	if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
		ID: row501ID, Name: "aud113-row-501", Provider: "historical-static",
		Key: "rotation/aud113-static", OldRef: "static-v1", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: dueAt,
	}); err != nil {
		t.Fatalf("seed row 501: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, "aud113-first-500", nil)
	if status != http.StatusOK {
		t.Fatalf("first fair tick status=%d body=%s", status, body)
	}
	var first secretRotationDueRunValue
	if err := json.Unmarshal(body, &first); err != nil || first.Scanned != 500 || first.Ran != 0 ||
		len(first.Deferred) != 500 || first.RunLimitReached || !first.ScanLimitReached || first.Complete {
		t.Fatalf("first fair tick=%+v err=%v, want exactly 500 deferred scans and continuation", first, err)
	}
	cursor, err := h.store.GetSecretRotationScheduleScanCursor(ctx, h.tenant)
	if err != nil || cursor.AfterScheduleID != "50000000-0000-4000-8000-000000000500" || cursor.LeaseToken != "" {
		t.Fatalf("first fair cursor=%+v err=%v", cursor, err)
	}

	restarted, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		RequireApproval: true, RequiredApprovals: 1,
		SecretRotators:    map[string]rotation.Rotator{"historical-static": historicalRotator},
		SecretSyncTargets: map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)},
	})
	if err != nil {
		t.Fatalf("restart before row 501: %v", err)
	}
	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2 := &servedHarness{ts: ts, srv: restarted, store: h.store, log: h.log, tenant: h.tenant}
	status, body = secretsReqKey(t, h2, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, "aud113-row-501-after-restart", nil)
	if status != http.StatusOK {
		t.Fatalf("row-501 recovery tick status=%d body=%s", status, body)
	}
	var second secretRotationDueRunValue
	if err := json.Unmarshal(body, &second); err != nil || second.Ran != 1 || len(second.Runs) != 1 ||
		second.Runs[0].ScheduleID != row501ID || second.Runs[0].Status != "unsupported" ||
		second.Scanned != 500 || !second.ScanLimitReached || second.Complete {
		t.Fatalf("row-501 recovery tick=%+v err=%v", second, err)
	}
	if historicalRotator.calls != 0 {
		t.Fatalf("historical static row 501 invoked %d provider calls, want zero", historicalRotator.calls)
	}
	row501, err := h.store.GetSecretRotationSchedule(ctx, h.tenant, row501ID)
	if err != nil || row501.Enabled || row501.LastRunStatus != "unsupported" {
		t.Fatalf("row 501 did not terminalize safely after restart: %+v err=%v", row501, err)
	}
}

func TestServedScheduledRotationUsesOuterDatabaseCutoffNotHostClockAUD112(t *testing.T) {
	historicalRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{"historical-static": historicalRotator}
		},
	)
	runner := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-db-cutoff-runner", "secrets:read", "secrets:write")
	ctx := context.Background()
	const (
		scheduleID = "11200000-0000-4000-8000-000000000112"
		tickKey    = "aud112-database-owned-cutoff"
	)
	// This row is due according to the service host's wall clock, but it is newer
	// than the outer idempotency claim's database timestamp forced below. A handler
	// that recomputes time.Now() would execute it; the durable database cutoff must
	// leave it untouched for the next tick.
	scheduleDueAt := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Microsecond)
	if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
		ID: scheduleID, Name: "aud112-db-cutoff", Provider: "historical-static",
		Key: "rotation/aud112-cutoff", OldRef: "static-v1", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: scheduleDueAt,
	}); err != nil {
		t.Fatalf("seed host-due schedule: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_aud112_scheduler_database_cutoff()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		    IF NEW.key LIKE 'secret-rotation-schedule-tick:v3:%' THEN
		        NEW.created_at := clock_timestamp() - interval '1 hour';
		    END IF;
		    RETURN NEW;
		END
		$$;
		CREATE TRIGGER test_aud112_scheduler_database_cutoff_trigger
		BEFORE INSERT ON idempotency_keys
		FOR EACH ROW EXECUTE FUNCTION test_aud112_scheduler_database_cutoff()`); err != nil {
		t.Fatalf("install database-cutoff test trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS test_aud112_scheduler_database_cutoff_trigger ON idempotency_keys`)
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP FUNCTION IF EXISTS test_aud112_scheduler_database_cutoff()`)
	})

	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, tickKey, nil)
	if status != http.StatusOK {
		t.Fatalf("database-cutoff tick status=%d body=%s", status, body)
	}
	var receipt secretRotationDueRunValue
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Ran != 0 || receipt.Scanned != 0 ||
		len(receipt.Runs) != 0 || len(receipt.Deferred) != 0 || !receipt.Complete ||
		receipt.RunLimitReached || receipt.ScanLimitReached {
		t.Fatalf("database-cutoff receipt=%+v err=%v, want an under-budget empty tick", receipt, err)
	}
	var storedTickKey string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT idempotency_key
			   FROM secret_rotation_schedule_ticks
			  WHERE tenant_id = $1 AND terminal_body = $2
			  ORDER BY created_at DESC LIMIT 1`,
			h.tenant, body).Scan(&storedTickKey)
	}); err != nil {
		t.Fatalf("resolve database-cutoff scheduler tick: %v", err)
	}
	var outerCreatedAt time.Time
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT created_at FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, storedTickKey).Scan(&outerCreatedAt)
	}); err != nil {
		t.Fatalf("load outer database cutoff: %v", err)
	}
	tick, err := h.store.GetSecretRotationScheduleTick(ctx, h.tenant, storedTickKey)
	if err != nil || !tick.DueThrough.Equal(outerCreatedAt) || !scheduleDueAt.After(tick.DueThrough) {
		t.Fatalf("tick cutoff=%s outer=%s schedule=%s err=%v, want exact outer DB timestamp before schedule",
			tick.DueThrough, outerCreatedAt, scheduleDueAt, err)
	}
	retained, err := h.store.GetSecretRotationSchedule(ctx, h.tenant, scheduleID)
	if err != nil || !retained.Enabled || retained.LastRunID != nil || !retained.NextRunAt.Equal(scheduleDueAt) {
		t.Fatalf("host-fast tick changed row newer than DB cutoff: schedule=%+v err=%v", retained, err)
	}
	if historicalRotator.calls != 0 {
		t.Fatalf("host-fast tick invoked %d provider calls, want zero", historicalRotator.calls)
	}
}

func TestServedScheduledRotationSameKeyLiveContentionIsNotCachedAUD113(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	runner := seedScopedTokenSubject(t, h.store, h.tenant, "schedule-live-contender", "secrets:read", "secrets:write")
	ctx := context.Background()
	const (
		scheduleID = "11300000-0000-4000-8000-000000000113"
		tickKey    = "aud113-live-same-key"
		latchKey   = int64(113001)
	)
	if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
		ID: scheduleID, Name: "aud113-live-contention", Provider: "historical-static",
		Key: "rotation/aud113-live", OldRef: "static-v1", IntervalSeconds: 3600,
		Enabled: true, NextRunAt: time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed live-contention schedule: %v", err)
	}
	dropLatchTrigger := func() {
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS aud113_hold_schedule_projection ON secret_rotation_schedules;
			 DROP FUNCTION IF EXISTS aud113_hold_schedule_projection_fn()`)
	}
	dropLatchTrigger()
	t.Cleanup(dropLatchTrigger)
	if _, err := h.store.SystemPool().Exec(ctx,
		`CREATE FUNCTION aud113_hold_schedule_projection_fn() RETURNS trigger
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   IF NEW.id = '11300000-0000-4000-8000-000000000113'::uuid
		      AND NEW.last_run_id IS NOT NULL THEN
		     PERFORM pg_advisory_xact_lock(113001);
		   END IF;
		   RETURN NEW;
		 END $$;
		 CREATE TRIGGER aud113_hold_schedule_projection
		 BEFORE UPDATE ON secret_rotation_schedules
		 FOR EACH ROW EXECUTE FUNCTION aud113_hold_schedule_projection_fn()`); err != nil {
		t.Fatalf("install live-contention latch trigger: %v", err)
	}
	latch, err := h.store.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin live-contention latch: %v", err)
	}
	latchOpen := true
	t.Cleanup(func() {
		if latchOpen {
			_ = latch.Rollback(context.Background())
		}
	})
	if _, err := latch.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, latchKey); err != nil {
		t.Fatalf("acquire live-contention latch: %v", err)
	}

	doRunDue := func() (int, []byte) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", nil)
		req.Header.Set("Authorization", "Bearer "+runner)
		req.Header.Set("Idempotency-Key", tickKey)
		recorder := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(recorder, req)
		return recorder.Code, append([]byte(nil), recorder.Body.Bytes()...)
	}
	type response struct {
		status int
		body   []byte
	}
	firstDone := make(chan response, 1)
	go func() {
		status, body := doRunDue()
		firstDone <- response{status: status, body: body}
	}()

	var storedTickKey string
	deadline := time.Now().Add(5 * time.Second)
	for {
		if storedTickKey == "" {
			err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx,
					`SELECT active_tick_key
					   FROM secret_rotation_schedule_scan_cursors
					  WHERE tenant_id = $1 AND active_tick_key <> ''`,
					h.tenant).Scan(&storedTickKey)
			})
			if err != nil && !store.IsNotFound(err) {
				t.Fatalf("resolve live scheduler tick key: %v", err)
			}
		}
		if storedTickKey != "" {
			tick, err := h.store.GetSecretRotationScheduleTick(ctx, h.tenant, storedTickKey)
			if err == nil && tick.Phase == "row_started" {
				break
			}
			if err != nil && !store.IsNotFound(err) {
				t.Fatalf("observe live scheduler tick: %v", err)
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("first scheduler request never reached durable row_started state")
		}
		time.Sleep(10 * time.Millisecond)
	}
	contenderStatus, contenderBody := doRunDue()
	if contenderStatus != http.StatusServiceUnavailable ||
		!strings.Contains(string(contenderBody), "already running") ||
		strings.Contains(string(contenderBody), `"runs"`) {
		t.Fatalf("live same-key contender status=%d body=%s, want non-cacheable problem+json", contenderStatus, contenderBody)
	}
	var outerStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT status FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, storedTickKey).Scan(&outerStatus)
	}); err != nil || outerStatus != "bound" {
		t.Fatalf("live contention cached/deleted outer key: status=%q err=%v", outerStatus, err)
	}

	if err := latch.Commit(ctx); err != nil {
		t.Fatalf("release live-contention latch: %v", err)
	}
	latchOpen = false
	var first response
	select {
	case first = <-firstDone:
	case <-time.After(10 * time.Second):
		t.Fatal("first scheduler request did not finish after latch release")
	}
	if first.status != http.StatusOK {
		t.Fatalf("first scheduler owner status=%d body=%s", first.status, first.body)
	}
	replayStatus, replayBody := doRunDue()
	if replayStatus != http.StatusOK || !bytes.Equal(replayBody, first.body) || bytes.Equal(replayBody, contenderBody) {
		t.Fatalf("same-key terminal replay status=%d body=%s, want exact first body=%s", replayStatus, replayBody, first.body)
	}
}

func TestServedScheduledConnectorRotationMissingSourceDoesNotStarveLaterDueSchedule(t *testing.T) {
	connector := newRotationCapturePusher()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/scheduled-after-broken", "value": "scheduled-good-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed later scheduled source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-after-broken", []byte("scheduled-good-v1"))

	dueAt := time.Now().Add(-2 * time.Minute).UTC()
	createSchedule := func(name, key string, nextRunAt time.Time) secretRotationScheduleValue {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
			map[string]any{
				"name": name, "provider": "connector:ci", "key": key,
				"old_ref": "version:1", "interval_seconds": 3600, "enabled": true,
				"next_run_at": nextRunAt.Format(time.RFC3339Nano),
			})
		if status != http.StatusCreated {
			t.Fatalf("create schedule %s: status=%d body=%s", name, status, body)
		}
		var scheduled secretRotationScheduleValue
		if err := json.Unmarshal(body, &scheduled); err != nil {
			t.Fatalf("decode schedule %s: %v", name, err)
		}
		return scheduled
	}
	broken := createSchedule("scheduled-missing-source", "rotation/missing-source", dueAt)
	good := createSchedule("scheduled-after-broken", "rotation/scheduled-after-broken", dueAt.Add(time.Second))

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", tok, "run-due-missing-source-does-not-starve", nil)
	if status != http.StatusOK {
		t.Fatalf("run due schedules with missing source: status=%d body=%s", status, body)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil {
		t.Fatalf("decode due batch: %v (%s)", err, body)
	}
	if batch.Ran != 2 || len(batch.Runs) != 2 {
		t.Fatalf("due batch=%+v, want one failed run and one queued run", batch)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(batch.Runs))
	for _, run := range batch.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[broken.ID]; run.Status != "failed" || !strings.Contains(run.Error, "no such secret") || run.Rotation.Completed || run.Rotation.Queued {
		t.Fatalf("missing-source run=%+v, want durable failed metadata", run)
	}
	if run := runs[good.ID]; run.Status != "queued" || run.Rotation.Completed || !run.Rotation.Queued || run.Rotation.NewRef != "version:2" {
		t.Fatalf("later valid run=%+v, want queued version:2", run)
	}

	brokenAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, broken.ID)
	if err != nil || brokenAfter.LastRunStatus != "failed" || !strings.Contains(brokenAfter.LastError, "no such secret") || !brokenAfter.NextRunAt.After(time.Now()) {
		t.Fatalf("missing-source cadence did not record/advance: %+v err=%v", brokenAfter, err)
	}
	goodAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, good.ID)
	if err != nil || goodAfter.LastRunStatus != "queued" || goodAfter.OldRef != "version:2" || !goodAfter.NextRunAt.After(time.Now()) {
		t.Fatalf("later valid cadence did not queue/advance: %+v err=%v", goodAfter, err)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-after-broken")
	if err != nil || current.Version != 2 {
		t.Fatalf("later valid schedule did not commit local version 2: %+v err=%v", current, err)
	}
	if got := connector.successfulPushes("rotation/scheduled-after-broken"); got != 0 {
		t.Fatalf("request path performed %d connector pushes, want worker-only delivery", got)
	}
	jobs, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", store.SecretSyncJobPending, "", 10)
	if err != nil || len(jobs) != 1 || jobs[0].SecretName != "rotation/scheduled-after-broken" {
		t.Fatalf("later schedule sync jobs=%+v err=%v, want one canonical pending job", jobs, err)
	}
	record, err := h.srv.outbox.Get(context.Background(), h.tenant, jobs[0].OutboxID)
	wantReceiverKey := "secret.sync.ci:" + jobs[0].ID
	if err != nil || record.IdempotencyKey != wantReceiverKey {
		t.Fatalf("later schedule receiver key=%q err=%v, want %q", record.IdempotencyKey, err, wantReceiverKey)
	}
	mutationEvents := 0
	if err := h.log.Replay(context.Background(), 1, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretRotated {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name == "rotation/scheduled-after-broken" {
			mutationEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mutationEvents != 1 {
		t.Fatalf("later schedule emitted %d canonical mutation events, want one", mutationEvents)
	}
}

func TestServedScheduledConnectorRotationRemovedTargetDoesNotStarveLaterDueSchedule(t *testing.T) {
	connector := newRotationCapturePusher()
	targets := map[string]*secretsync.Target{
		"retired": secretsync.NewCITarget(connector),
		"ci":      secretsync.NewCITarget(connector),
	}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) { d.SecretSyncTargets = targets },
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	for _, key := range []string{"rotation/scheduled-removed-target", "rotation/scheduled-after-removed-target"} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
			map[string]any{"name": key, "value": key + "-v1"})
		if status != http.StatusCreated {
			t.Fatalf("seed %s: status=%d body=%s", key, status, body)
		}
		connector.put(key, []byte(key+"-v1"))
	}

	dueAt := time.Now().Add(-2 * time.Minute).UTC()
	createSchedule := func(name, provider, key string, nextRunAt time.Time) secretRotationScheduleValue {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
			map[string]any{
				"name": name, "provider": provider, "key": key,
				"old_ref": "version:1", "interval_seconds": 3600, "enabled": true,
				"next_run_at": nextRunAt.Format(time.RFC3339Nano),
			})
		if status != http.StatusCreated {
			t.Fatalf("create schedule %s: status=%d body=%s", name, status, body)
		}
		var scheduled secretRotationScheduleValue
		if err := json.Unmarshal(body, &scheduled); err != nil {
			t.Fatalf("decode schedule %s: %v", name, err)
		}
		return scheduled
	}
	broken := createSchedule("scheduled-removed-target", "connector:retired", "rotation/scheduled-removed-target", dueAt)
	good := createSchedule("scheduled-after-removed-target", "connector:ci", "rotation/scheduled-after-removed-target", dueAt.Add(time.Second))

	delete(targets, "retired")
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", tok, "run-due-removed-target-does-not-starve", nil)
	if status != http.StatusOK {
		t.Fatalf("run due schedules after target removal: status=%d body=%s", status, body)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil {
		t.Fatalf("decode due batch: %v (%s)", err, body)
	}
	if batch.Ran != 2 || len(batch.Runs) != 2 {
		t.Fatalf("due batch=%+v, want one terminal failed run and one queued run", batch)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(batch.Runs))
	for _, run := range batch.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[broken.ID]; run.Status != "failed" || !strings.Contains(run.Error, "target is not configured") {
		t.Fatalf("removed-target run=%+v, want durable failed metadata", run)
	}
	if run := runs[good.ID]; run.Status != "queued" || !run.Rotation.Queued || run.Rotation.Completed || run.Rotation.NewRef != "version:2" {
		t.Fatalf("later valid run=%+v, want queued version:2", run)
	}

	brokenAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, broken.ID)
	if err != nil || brokenAfter.LastRunStatus != "failed" || !strings.Contains(brokenAfter.LastError, "target is not configured") || !brokenAfter.NextRunAt.After(time.Now()) {
		t.Fatalf("removed-target cadence did not record/advance: %+v err=%v", brokenAfter, err)
	}
	goodAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, good.ID)
	if err != nil || goodAfter.LastRunStatus != "queued" || goodAfter.OldRef != "version:2" || !goodAfter.NextRunAt.After(time.Now()) {
		t.Fatalf("later valid cadence did not queue/advance: %+v err=%v", goodAfter, err)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-after-removed-target")
	if err != nil || current.Version != 2 {
		t.Fatalf("later valid schedule did not commit local version 2: %+v err=%v", current, err)
	}
	if got := connector.successfulPushes("rotation/scheduled-after-removed-target"); got != 0 {
		t.Fatalf("request path performed %d connector pushes, want worker-only delivery", got)
	}
}

func TestServedScheduledConnectorTerminalSyncDoesNotStarveLaterDueSchedule(t *testing.T) {
	const providerError = "credential=super-secret subject=alice@example.test remote=vault/alice"
	connector := newRotationCapturePusher()
	healthyRotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withProtectedSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{"healthy-static": healthyRotator}
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	runner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
		map[string]any{"name": "rotation/scheduled-terminal-sync", "value": "terminal-sync-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed terminal-sync source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-terminal-sync", []byte("terminal-sync-v1"))
	dueAt := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Minute)
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", runner,
		map[string]any{
			"name": "scheduled-terminal-sync", "provider": "connector:ci",
			"key": "rotation/scheduled-terminal-sync", "old_ref": "version:1",
			"interval_seconds": 3600, "enabled": true, "next_run_at": dueAt.Format(time.RFC3339Nano),
		})
	if status != http.StatusCreated {
		t.Fatalf("create terminal-sync schedule: status=%d body=%s", status, body)
	}
	var terminalSchedule secretRotationScheduleValue
	if err := json.Unmarshal(body, &terminalSchedule); err != nil {
		t.Fatal(err)
	}
	dropTerminalPrepareFailure := func() {
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS test_scheduler_terminal_prepare_failure_trigger
			    ON secret_rotation_schedule_commands`)
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP FUNCTION IF EXISTS test_scheduler_terminal_prepare_failure()`)
	}
	dropTerminalPrepareFailure()
	t.Cleanup(dropTerminalPrepareFailure)
	if _, err := h.store.SystemPool().Exec(context.Background(), `
		CREATE FUNCTION test_scheduler_terminal_prepare_failure() RETURNS trigger
		LANGUAGE plpgsql AS $fixture$
		BEGIN
			IF OLD.prepared_status = '' AND NEW.prepared_status <> '' THEN
				RAISE EXCEPTION 'injected scheduler terminal preparation failure';
			END IF;
			RETURN NEW;
		END
		$fixture$`); err != nil {
		t.Fatalf("create terminal preparation failure function: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(context.Background(), `
		CREATE TRIGGER test_scheduler_terminal_prepare_failure_trigger
		BEFORE UPDATE ON secret_rotation_schedule_commands
		FOR EACH ROW EXECUTE FUNCTION test_scheduler_terminal_prepare_failure()`); err != nil {
		t.Fatalf("create terminal preparation failure trigger: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runner,
		"terminal-sync-seed-command", nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("interrupt terminal sync command: status=%d body=%s", status, body)
	}
	var seeded secretRotationDueRunValue
	if err := json.Unmarshal(body, &seeded); err != nil || seeded.Ran != 0 || len(seeded.Runs) != 0 ||
		seeded.FailedScheduleID != terminalSchedule.ID || seeded.SystemError == "" ||
		strings.Contains(seeded.SystemError, "injected") {
		t.Fatalf("interrupted terminal-sync run=%+v err=%v", seeded, err)
	}
	dropTerminalPrepareFailure()
	jobs, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", store.SecretSyncJobPending, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("terminal-sync pending jobs=%+v err=%v", jobs, err)
	}
	job := jobs[0]
	failedPayload, err := json.Marshal(projections.SecretSyncFailed{
		ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 10, Error: providerError,
	})
	if err != nil {
		t.Fatal(err)
	}
	failedEvent, err := h.log.Append(context.Background(), events.Event{
		ID: store.SecretSyncFailedEventID(h.tenant, job.ID), Type: projections.EventSecretSyncFailed,
		TenantID: h.tenant, SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: failedPayload,
	})
	if err != nil {
		t.Fatalf("append terminal sync event: %v", err)
	}
	if err := h.srv.proj.Apply(context.Background(), failedEvent); err != nil {
		t.Fatalf("project terminal sync event: %v", err)
	}

	// The first tick committed the canonical application-secret mutation/job but
	// was interrupted before preparing its scheduler terminal event. Its exact due
	// edge therefore remains claimed and resumable while the worker receipt turns
	// terminal in a separate transaction.
	healthySchedule, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
		Name: "healthy-after-terminal-sync", Provider: "healthy-static", Key: "static/healthy",
		OldRef: "healthy-v1", IntervalSeconds: 3600, Enabled: true, NextRunAt: dueAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("seed schedule after terminal sync: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runner,
		"terminal-sync-does-not-starve", nil)
	if status != http.StatusOK {
		t.Fatalf("run terminal sync and later schedule: status=%d body=%s", status, body)
	}
	terminalBody := append([]byte(nil), body...)
	if bytes.Contains(terminalBody, []byte(providerError)) {
		t.Fatalf("scheduler response retained provider-controlled error: %s", terminalBody)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil || batch.Ran != 2 || len(batch.Runs) != 2 {
		t.Fatalf("terminal-sync batch=%+v err=%v", batch, err)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(batch.Runs))
	for _, run := range batch.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[terminalSchedule.ID]; run.Status != "delivery_failed" ||
		run.Rotation.FailedPhase != "delivery" || run.Rotation.NewRef != "version:2" ||
		run.Error != "connector delivery failed" {
		t.Fatalf("terminal-sync run=%+v", run)
	}
	if run := runs[healthySchedule.ID]; run.Status != "unsupported" || run.Rotation.Completed ||
		run.Rotation.FailedPhase != "provider" {
		t.Fatalf("inherited static run after terminal sync=%+v", run)
	}
	terminalAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, terminalSchedule.ID)
	if err != nil || terminalAfter.LastRunStatus != "delivery_failed" || terminalAfter.OldRef != "version:2" ||
		!terminalAfter.NextRunAt.After(time.Now()) {
		t.Fatalf("terminal-sync schedule did not explicitly advance committed ref: %+v err=%v", terminalAfter, err)
	}
	if healthyRotator.calls != 0 {
		t.Fatalf("inherited static schedule after terminal sync ran %d provider calls, want zero", healthyRotator.calls)
	}
	if got := connector.successfulPushes("rotation/scheduled-terminal-sync"); got != 0 {
		t.Fatalf("terminal sync retry performed %d connector effects, want zero", got)
	}

	command, err := h.store.GetLatestSecretRotationScheduleCommand(
		context.Background(), h.tenant, terminalSchedule.ID,
	)
	if err != nil {
		t.Fatalf("load terminal scheduler command: %v", err)
	}
	if command.Status != "delivery_failed" || command.Error != "connector delivery failed" ||
		strings.Contains(command.Error, providerError) || command.TerminalEventID == "" {
		t.Fatalf("terminal command retained unsafe error or incomplete receipt: %+v", command)
	}
	terminalEvent, found, err := h.log.EventByID(context.Background(), command.TerminalEventID)
	if err != nil || !found {
		t.Fatalf("load terminal scheduler event: found=%t err=%v", found, err)
	}
	if bytes.Contains(terminalEvent.Data, []byte(providerError)) ||
		!bytes.Contains(terminalEvent.Data, []byte("connector delivery failed")) {
		t.Fatalf("terminal scheduler event retained unsafe error: %s", terminalEvent.Data)
	}
	var terminalTickKey string
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT idempotency_key
			   FROM secret_rotation_schedule_ticks
			  WHERE tenant_id = $1 AND terminal_body = $2
			  ORDER BY created_at DESC LIMIT 1`,
			h.tenant, terminalBody).Scan(&terminalTickKey)
	}); err != nil {
		t.Fatalf("resolve terminal scheduler tick: %v", err)
	}
	tick, err := h.store.GetSecretRotationScheduleTick(
		context.Background(), h.tenant, terminalTickKey,
	)
	if err != nil {
		t.Fatalf("load terminal scheduler tick: %v", err)
	}
	if tick.TerminalHTTPStatus == nil || *tick.TerminalHTTPStatus != http.StatusOK ||
		!bytes.Equal(tick.TerminalBody, terminalBody) || bytes.Contains(tick.TerminalBody, []byte(providerError)) {
		t.Fatalf("terminal scheduler tick retained unsafe or divergent body: %+v", tick)
	}
	var resultCodec string
	var protectedResult []byte
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1 AND key = $2`,
		h.tenant, terminalTickKey).Scan(&resultCodec, &protectedResult); err != nil {
		t.Fatalf("load protected scheduler result: %v", err)
	}
	if resultCodec == "" || resultCodec == "raw-v0" || len(protectedResult) == 0 ||
		bytes.Contains(protectedResult, terminalBody) || bytes.Contains(protectedResult, []byte(providerError)) {
		t.Fatalf("scheduler result is not protected: codec=%q bytes=%q", resultCodec, protectedResult)
	}
	replayStatus, replayBody := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner,
		"terminal-sync-does-not-starve", nil)
	if replayStatus != http.StatusOK || !bytes.Equal(replayBody, terminalBody) ||
		bytes.Contains(replayBody, []byte(providerError)) {
		t.Fatalf("protected scheduler replay diverged or leaked provider text: status=%d replay=%s original=%s",
			replayStatus, replayBody, terminalBody)
	}
}

func TestServedInheritedStaticSchedulesDisableWithoutProviderPhase(t *testing.T) {
	retireFailure := &retireFailureRotationRotator{}
	stageFailure := &stageFailureRotationRotator{}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{
				"retire-failure": retireFailure,
				"stage-failure":  stageFailure,
			}
		},
	)
	runner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	dueAt := time.Now().Add(-2 * time.Minute).UTC()
	create := func(name, provider, oldRef string, at time.Time) store.SecretRotationSchedule {
		t.Helper()
		scheduled, err := h.srv.orch.UpsertSecretRotationSchedule(context.Background(), h.tenant, store.SecretRotationSchedule{
			Name: name, Provider: provider, Key: "static/" + name, OldRef: oldRef,
			IntervalSeconds: 3600, Enabled: true, NextRunAt: at,
		})
		if err != nil {
			t.Fatalf("seed inherited %s schedule: %v", name, err)
		}
		return scheduled
	}
	retireSchedule := create("retire-pending", "retire-failure", "retire-old", dueAt)
	stageSchedule := create("stage-failed", "stage-failure", "stage-old", dueAt.Add(time.Second))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", runner,
		"static-provider-fail-closed", nil)
	if status != http.StatusOK {
		t.Fatalf("run inherited static schedules: status=%d body=%s", status, body)
	}
	var batch secretRotationDueRunValue
	if err := json.Unmarshal(body, &batch); err != nil || batch.Ran != 2 || len(batch.Runs) != 2 {
		t.Fatalf("inherited static batch=%+v err=%v", batch, err)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(batch.Runs))
	for _, run := range batch.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[retireSchedule.ID]; run.Status != "unsupported" || run.Rotation.NewRef != "" ||
		run.Rotation.FailedPhase != "provider" || !strings.Contains(run.Error, "scheduled static-provider") {
		t.Fatalf("retire-provider inherited run=%+v", run)
	}
	if run := runs[stageSchedule.ID]; run.Status != "unsupported" || run.Rotation.NewRef != "" ||
		run.Rotation.FailedPhase != "provider" || !strings.Contains(run.Error, "scheduled static-provider") {
		t.Fatalf("stage-provider inherited run=%+v", run)
	}
	retireAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, retireSchedule.ID)
	if err != nil || retireAfter.OldRef != "retire-old" || retireAfter.LastRunStatus != "unsupported" || retireAfter.Enabled {
		t.Fatalf("retire-provider inherited schedule=%+v err=%v", retireAfter, err)
	}
	stageAfter, err := h.store.GetSecretRotationSchedule(context.Background(), h.tenant, stageSchedule.ID)
	if err != nil || stageAfter.OldRef != "stage-old" || stageAfter.LastRunStatus != "unsupported" || stageAfter.Enabled {
		t.Fatalf("stage-provider inherited schedule changed authority: %+v err=%v", stageAfter, err)
	}
	if retireFailure.stageCalls != 0 || stageFailure.calls != 0 {
		t.Fatalf("inherited static scheduler invoked provider phases: retire=%d stage=%d",
			retireFailure.stageCalls, stageFailure.calls)
	}
}

func TestServedScheduledConnectorPartial503IsStableAndNewKeyReconciles(t *testing.T) {
	connector := newRotationCapturePusher()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{"ci": secretsync.NewCITarget(connector)}
		},
	)
	runner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := context.Background()
	names := []string{"rotation/partial-first", "rotation/partial-crash", "rotation/partial-after"}
	for _, name := range names {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
			map[string]any{"name": name, "value": name + "-v1"})
		if status != http.StatusCreated {
			t.Fatalf("seed %s: status=%d body=%s", name, status, body)
		}
		connector.put(name, []byte(name+"-v1"))
	}

	const (
		firstID = "10600000-0000-4000-8000-000000000001"
		crashID = "10600000-0000-4000-8000-000000000002"
		afterID = "10600000-0000-4000-8000-000000000003"
	)
	dueAt := time.Now().UTC().Truncate(time.Microsecond).Add(-3 * time.Minute)
	for index, fixture := range []struct {
		id   string
		name string
	}{{firstID, names[0]}, {crashID, names[1]}, {afterID, names[2]}} {
		if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
			ID: fixture.id, Name: fixture.name, Provider: "connector:ci", Key: fixture.name,
			OldRef: "version:1", IntervalSeconds: 3600, Enabled: true,
			NextRunAt: dueAt.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("seed schedule %s: %v", fixture.name, err)
		}
	}
	dropFailureTrigger := func() {
		_, _ = h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS aud106_fail_schedule_projection ON secret_rotation_schedules;
			 DROP FUNCTION IF EXISTS aud106_fail_schedule_projection_fn()`)
	}
	dropFailureTrigger()
	t.Cleanup(dropFailureTrigger)
	if _, err := h.store.SystemPool().Exec(ctx,
		`CREATE FUNCTION aud106_fail_schedule_projection_fn() RETURNS trigger
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   IF NEW.id = '10600000-0000-4000-8000-000000000002'::uuid
		      AND NEW.last_run_id IS NOT NULL THEN
		     RAISE EXCEPTION 'AUD-106 injected terminal projection failure';
		   END IF;
		   RETURN NEW;
		 END $$;
		 CREATE TRIGGER aud106_fail_schedule_projection
		 BEFORE UPDATE ON secret_rotation_schedules
		 FOR EACH ROW EXECUTE FUNCTION aud106_fail_schedule_projection_fn()`); err != nil {
		t.Fatalf("install terminal projection failure: %v", err)
	}
	const firstTickKey = "scheduled-partial-system-failure"
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, firstTickKey, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("partial tick status=%d body=%s, want cached 503", status, body)
	}
	firstBody := append([]byte(nil), body...)
	var partial secretRotationDueRunValue
	if err := json.Unmarshal(body, &partial); err != nil || partial.Complete || !partial.Partial ||
		partial.Ran != 1 || len(partial.Runs) != 1 || partial.Runs[0].ScheduleID != firstID ||
		partial.FailedScheduleID != crashID ||
		partial.SystemError != store.SecretRotationScheduleTickProcessingError ||
		strings.Contains(string(body), "injected terminal projection failure") {
		t.Fatalf("truthful partial envelope=%+v err=%v", partial, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, firstTickKey, nil)
	if status != http.StatusServiceUnavailable || string(body) != string(firstBody) {
		t.Fatalf("same-key partial replay status=%d body=%s, want byte-identical %s", status, body, firstBody)
	}
	for index, name := range names {
		current, err := h.store.GetSecret(ctx, h.tenant, name)
		wantVersion := 1
		if index < 2 {
			wantVersion = 2
		}
		if err != nil || current.Version != wantVersion {
			t.Fatalf("%s version after same-key replay=%+v err=%v, want %d", name, current, err, wantVersion)
		}
	}
	crashedSchedule, err := h.store.GetSecretRotationSchedule(ctx, h.tenant, crashID)
	if err != nil || crashedSchedule.LastRunID != nil || !crashedSchedule.NextRunAt.Equal(dueAt.Add(time.Second)) {
		t.Fatalf("crash-gap schedule advanced without terminal projection: %+v err=%v", crashedSchedule, err)
	}

	dropFailureTrigger()
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, "scheduled-partial-system-recovery", nil)
	if status != http.StatusOK {
		t.Fatalf("new-key recovery tick status=%d body=%s", status, body)
	}
	var recovered secretRotationDueRunValue
	if err := json.Unmarshal(body, &recovered); err != nil || !recovered.Complete || recovered.Partial ||
		recovered.Ran != 2 || len(recovered.Runs) != 2 {
		t.Fatalf("new-key recovery envelope=%+v err=%v", recovered, err)
	}
	runs := make(map[string]secretRotationScheduleRunValue, len(recovered.Runs))
	for _, run := range recovered.Runs {
		runs[run.ScheduleID] = run
	}
	if run := runs[crashID]; run.Status != "queued" || !run.Reconciled || run.Rotation.NewRef != "version:2" {
		t.Fatalf("crash-gap run was not reconciled from deterministic terminal event: %+v", run)
	}
	if run := runs[afterID]; run.Status != "queued" || run.Reconciled || run.Rotation.NewRef != "version:2" {
		t.Fatalf("later untouched schedule did not progress under new key: %+v", run)
	}

	mutationCounts := map[string]int{}
	terminalCounts := map[string]int{}
	if err := h.log.Replay(ctx, 1, func(event events.Event) error {
		switch event.Type {
		case projections.EventApplicationSecretRotated:
			var payload projections.ApplicationSecretMutation
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return err
			}
			mutationCounts[payload.Name]++
		case projections.EventSecretRotationScheduleRan:
			var payload projections.SecretRotationScheduleRan
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return err
			}
			terminalCounts[payload.ScheduleID]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for index, name := range names {
		id := []string{firstID, crashID, afterID}[index]
		if mutationCounts[name] != 1 || terminalCounts[id] != 1 {
			t.Fatalf("%s retained mutation/terminal counts=%d/%d, want exactly one each",
				name, mutationCounts[name], terminalCounts[id])
		}
	}
}

func TestServedScheduledConnectorRotationOutboxSurvivesRestart(t *testing.T) {
	connector := newRotationCapturePusher()
	registry := SecretSyncTargetRegistry{
		servedTestTenant: {"ci": secretsync.NewCITarget(connector)},
	}
	var secretKEK cryptoseal.KeyWrapper
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		secretKEK = d.KEK
		d.TenantSecretSyncTargets = registry
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/scheduled-restart", "value": "scheduled-restart-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed scheduled restart source: status=%d body=%s", status, body)
	}
	connector.put("rotation/scheduled-restart", []byte("scheduled-restart-v1"))
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
		map[string]any{
			"name": "scheduled-restart", "provider": "connector:ci", "key": "rotation/scheduled-restart",
			"old_ref": "version:1", "interval_seconds": 3600, "enabled": true,
			"next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
		})
	if status != http.StatusCreated {
		t.Fatalf("create scheduled restart rotation: status=%d body=%s", status, body)
	}
	const runDueKey = "scheduled-connector-restart-run-due"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, runDueKey, nil)
	if status != http.StatusOK {
		t.Fatalf("run scheduled restart rotation: status=%d body=%s", status, body)
	}
	var initialRun secretRotationDueRunValue
	if err := json.Unmarshal(body, &initialRun); err != nil {
		t.Fatalf("decode scheduled restart run: %v (%s)", err, body)
	}
	if initialRun.Ran != 1 || len(initialRun.Runs) != 1 || initialRun.Runs[0].Status != "queued" ||
		initialRun.Runs[0].Rotation.Completed || !initialRun.Runs[0].Rotation.Queued {
		t.Fatalf("scheduled restart run=%+v, want one queued worker delivery", initialRun)
	}
	current, err := h.store.GetSecret(context.Background(), h.tenant, "rotation/scheduled-restart")
	if err != nil || current.Version != 2 {
		t.Fatalf("scheduled restart rotation did not commit local v2: current=%+v err=%v", current, err)
	}
	if got := connector.value("rotation/scheduled-restart"); got != "scheduled-restart-v1" {
		t.Fatalf("request path changed remote value=%q", got)
	}
	if got := connector.successfulPushes("rotation/scheduled-restart"); got != 0 {
		t.Fatalf("request path performed %d connector pushes, want worker-only delivery", got)
	}
	jobs, err := h.store.ListSecretSyncJobsPage(context.Background(), h.tenant, "ci", store.SecretSyncJobPending, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("pending scheduled restart jobs=%+v err=%v, want one", jobs, err)
	}
	job := jobs[0]
	if job.SecretName != "rotation/scheduled-restart" || job.SecretVersion != 2 {
		t.Fatalf("pending scheduled restart job is not bound to local v2: %+v", job)
	}
	queuedRecord, err := h.srv.outbox.Get(context.Background(), h.tenant, job.OutboxID)
	wantReceiverKey := "secret.sync.ci:" + job.ID
	if err != nil || queuedRecord.IdempotencyKey != wantReceiverKey {
		t.Fatalf("queued scheduled receiver key=%q err=%v, want %q", queuedRecord.IdempotencyKey, err, wantReceiverKey)
	}

	restarted, err := Build(context.Background(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		TenantSecretSyncTargets: registry,
	})
	if err != nil {
		t.Fatalf("restart with pending scheduled connector outbox: %v", err)
	}
	drainCtx, cancelDrain := context.WithTimeout(t.Context(), 10*time.Second)
	drainErr := restarted.Drain(drainCtx)
	cancelDrain()
	if drainErr != nil {
		t.Fatalf("restart drain scheduled connector outbox: %v", drainErr)
	}
	job, err = h.store.GetSecretSyncJob(context.Background(), h.tenant, job.ID)
	if err != nil || job.Status != store.SecretSyncJobDelivered || job.DeliveredAt == nil {
		t.Fatalf("restart did not deliver exact scheduled connector job: %+v err=%v", job, err)
	}
	record, err := restarted.outbox.Get(context.Background(), h.tenant, job.OutboxID)
	if err != nil || record.Status != "delivered" {
		t.Fatalf("restart did not complete scheduled connector outbox: %+v err=%v", record, err)
	}
	if got := connector.value("rotation/scheduled-restart"); got == "" || got == "scheduled-restart-v1" {
		t.Fatalf("restart did not deliver rotated value: %q", got)
	}
	if got := connector.successfulPushes("rotation/scheduled-restart"); got != 1 {
		t.Fatalf("scheduled connector effect ran %d times, want exactly once", got)
	}
	drainCtx, cancelDrain = context.WithTimeout(t.Context(), 10*time.Second)
	drainErr = restarted.Drain(drainCtx)
	cancelDrain()
	if drainErr != nil || connector.successfulPushes("rotation/scheduled-restart") != 1 {
		t.Fatalf("second drain redelivered completed connector effect: pushes=%d err=%v",
			connector.successfulPushes("rotation/scheduled-restart"), drainErr)
	}

	ts := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts.Close)
	h2 := &servedHarness{ts: ts, srv: restarted, store: h.store, log: h.log, tenant: h.tenant}
	status, body = secretsReq(t, h2, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("post-restart due scan: status=%d body=%s", status, body)
	}
	var rerun secretRotationDueRunValue
	if err := json.Unmarshal(body, &rerun); err != nil {
		t.Fatal(err)
	}
	if rerun.Ran != 0 || len(rerun.Runs) != 0 || connector.successfulPushes("rotation/scheduled-restart") != 1 {
		t.Fatalf("restart re-ran an already advanced schedule: %+v", rerun)
	}
	mutationEvents := 0
	if err := h.log.Replay(context.Background(), 1, func(event events.Event) error {
		if event.Type != projections.EventApplicationSecretRotated {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name == "rotation/scheduled-restart" {
			mutationEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mutationEvents != 1 {
		t.Fatalf("scheduled connector restart retained %d authoritative rotation events, want one", mutationEvents)
	}
}

type secretRotationValue struct {
	Key               string `json:"key"`
	OldRef            string `json:"old_ref"`
	NewRef            string `json:"new_ref"`
	Completed         bool   `json:"completed"`
	Queued            bool   `json:"queued"`
	RolledBack        bool   `json:"rolled_back"`
	RollbackAttempted bool   `json:"rollback_attempted"`
	RollbackFailed    bool   `json:"rollback_failed"`
	FailedPhase       string `json:"failed_phase,omitempty"`
	Error             string `json:"error,omitempty"`
}

type secretRotationScheduleValue struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Key             string    `json:"key"`
	OldRef          string    `json:"old_ref"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	NextRunAt       time.Time `json:"next_run_at"`
	LastRunID       *string   `json:"last_run_id,omitempty"`
	LastRunStatus   string    `json:"last_run_status"`
}

type secretRotationDueRunValue struct {
	Ran              int                                           `json:"ran"`
	Scanned          int                                           `json:"scanned"`
	Runs             []secretRotationScheduleRunValue              `json:"runs"`
	Deferred         []secretRotationScheduleDeferredResponseValue `json:"deferred"`
	RunLimitReached  bool                                          `json:"run_limit_reached"`
	ScanLimitReached bool                                          `json:"scan_limit_reached"`
	Complete         bool                                          `json:"complete"`
	Partial          bool                                          `json:"partial"`
	FailedScheduleID string                                        `json:"failed_schedule_id"`
	SystemError      string                                        `json:"system_error"`
}

type secretRotationScheduleDeferredResponseValue struct {
	ScheduleID string    `json:"schedule_id"`
	Reason     string    `json:"reason"`
	DueAt      time.Time `json:"due_at"`
	Error      string    `json:"error"`
}

type secretRotationScheduleRunValue struct {
	ScheduleID string              `json:"schedule_id"`
	RunID      string              `json:"run_id"`
	Status     string              `json:"status"`
	Error      string              `json:"error"`
	Rotation   secretRotationValue `json:"rotation"`
	Reconciled bool                `json:"reconciled"`
}

type dynamicLeaseValue struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Credential string `json:"credential,omitempty"`
}

type rotationCapturePusher struct {
	mu         sync.Mutex
	values     map[string][]byte
	failOnce   map[string]bool
	successful map[string]int
	blocked    map[string]chan struct{}
}

func newRotationCapturePusher() *rotationCapturePusher {
	return &rotationCapturePusher{
		values: map[string][]byte{}, failOnce: map[string]bool{}, successful: map[string]int{},
		blocked: map[string]chan struct{}{},
	}
}

func (p *rotationCapturePusher) Push(_ context.Context, key string, value []byte) error {
	p.mu.Lock()
	blocked := p.blocked[key]
	p.mu.Unlock()
	if blocked != nil {
		<-blocked
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failOnce[key] {
		delete(p.failOnce, key)
		return errors.New("connector rejected rotated secret")
	}
	p.values[key] = append([]byte(nil), value...)
	p.successful[key]++
	return nil
}

func (p *rotationCapturePusher) block(key string) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch := make(chan struct{})
	p.blocked[key] = ch
	return func() {
		p.mu.Lock()
		if p.blocked[key] == ch {
			delete(p.blocked, key)
			close(ch)
		}
		p.mu.Unlock()
	}
}

func (p *rotationCapturePusher) put(key string, value []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.values[key] = append([]byte(nil), value...)
}

func (p *rotationCapturePusher) failNext(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failOnce[key] = true
}

func (p *rotationCapturePusher) value(key string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.values[key])
}

func (p *rotationCapturePusher) successfulPushes(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.successful[key]
}

type rotationDynamicBackend struct {
	mu          sync.Mutex
	issued      int
	revokedRefs map[string]bool
}

func newRotationDynamicBackend() *rotationDynamicBackend {
	return &rotationDynamicBackend{revokedRefs: map[string]bool{}}
}

func (b *rotationDynamicBackend) Create(_ context.Context, role string) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.issued++
	ref := fmt.Sprintf("lease-%s-%d", role, b.issued)
	return ref, []byte(fmt.Sprintf("dynamic-secret-%d", b.issued)), nil
}

func (b *rotationDynamicBackend) Revoke(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revokedRefs[ref] = true
	return nil
}

func (b *rotationDynamicBackend) revokedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.revokedRefs)
}

func (b *rotationDynamicBackend) issuedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.issued
}

func startRotationPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freeRotationPort(t)
	dir, err := os.MkdirTemp("/private/tmp", "trstctl-rotation-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := dir + "/bin"
	runtime := dir + "/runtime"
	data := dir + "/data"
	for _, p := range []string{bin, runtime, data} {
		if err := os.MkdirAll(p, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

func freeRotationPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func createRotationPostgresCredential(t *testing.T, ctx context.Context, adminDSN, username string) (string, []byte) {
	t.Helper()
	password := username + "_pass"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE ROLE "+rotationTestPGIdent(username)+" LOGIN PASSWORD "+rotationTestPGLiteral(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT CONNECT ON DATABASE postgres TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	u := strings.Replace(adminDSN, "postgres:postgres@", username+":"+password+"@", 1)
	return username, []byte(u)
}

func assertPostgresCredentialWorks(t *testing.T, ctx context.Context, dsn []byte, smokeTable string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, string(dsn))
	if err != nil {
		t.Fatalf("credential did not log in: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var got int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.`+rotationTestPGIdent(smokeTable)).Scan(&got); err != nil {
		t.Fatalf("credential cannot read smoke table: %v", err)
	}
	if got != 1 {
		t.Fatalf("smoke count = %d, want 1", got)
	}
}

func assertPostgresCredentialRevoked(t *testing.T, ctx context.Context, dsn []byte) {
	t.Helper()
	if len(dsn) == 0 {
		t.Fatal("no credential supplied to revoked-login assertion")
	}
	conn, err := pgx.Connect(ctx, string(dsn))
	if err == nil {
		_ = conn.Close(ctx)
		t.Fatal("revoked PostgreSQL credential still logs in")
	}
}

func assertPostgresRoleAbsent(t *testing.T, ctx context.Context, adminDSN, role string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("staged rollback role %q still exists", role)
	}
}

func rotationTestPGIdent(v string) string {
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func rotationTestPGLiteral(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}
