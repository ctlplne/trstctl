// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PRIVACY-001 acceptance: subject erasure is served, event-sourced, and keeps the
// raw data subject out of tenant audit replay/export while preserving evidence
// bundle verification.
func TestServedPrivacySubjectErasureRedactsAuditAndExports(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const subject = "alice@example.com"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	subjectToken := seedServedAPIToken(t, ctx, st, tenantID, subject, []string{
		string(authz.OwnersWrite), string(authz.PrivacyWrite),
	})
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-admin", []string{
		string(authz.OwnersRead), string(authz.PrivacyRead), string(authz.AuditRead),
	})

	auditKey, err := jose.GenerateRSASigningKey("privacy-001-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		st,
		auditKey,
	)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", subjectToken, "owner-alice", map[string]string{
		"kind": "user", "name": subject, "email": subject,
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d, want 201; body=%s", code, body)
	}
	var ownerResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ownerResp); err != nil || ownerResp.ID == "" {
		t.Fatalf("decode owner response: id=%q err=%v body=%s", ownerResp.ID, err, body)
	}

	code, body = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", subjectToken, "erase-alice", map[string]string{
		"subject": subject, "reason": "data subject request",
	})
	if code != http.StatusCreated {
		t.Fatalf("erase subject = %d, want 201; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) {
		t.Fatalf("erasure response leaked raw subject: %s", body)
	}
	var erasureResp struct {
		SubjectRef string         `json:"subject_ref"`
		Counts     map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(body, &erasureResp); err != nil || erasureResp.SubjectRef == "" {
		t.Fatalf("decode erasure response: ref=%q err=%v body=%s", erasureResp.SubjectRef, err, body)
	}
	if erasureResp.Counts["api_tokens"] != 1 {
		t.Fatalf("api token erasure count = %d, want 1", erasureResp.Counts["api_tokens"])
	}

	owner, err := st.GetOwner(ctx, tenantID, ownerResp.ID)
	if err != nil {
		t.Fatalf("load owner after erasure: %v", err)
	}
	if owner.Email != "" || strings.Contains(owner.Name, subject) || !strings.HasPrefix(owner.Name, "erased:") {
		t.Fatalf("owner after erasure = name %q email %q", owner.Name, owner.Email)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", subjectToken, "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("erased subject token still authenticated = %d body=%s", code, body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/events?q="+url.QueryEscape(subject), adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit search by erased subject = %d body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) || !bytes.Contains(body, []byte(`"count":0`)) {
		t.Fatalf("audit search leaked or matched erased subject: %s", body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/events", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit events = %d body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) || !bytes.Contains(body, []byte("erased:")) {
		t.Fatalf("audit events did not redact erased subject: %s", body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit export = %d body=%s", code, body)
	}
	var exportResp struct {
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(body, &exportResp); err != nil || exportResp.Bundle == "" {
		t.Fatalf("decode export response: %v body=%s", err, body)
	}
	bundle, err := audit.VerifyBundle(exportResp.Bundle, auditKey.JWKS())
	if err != nil {
		t.Fatalf("verify export bundle: %v", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal verified bundle: %v", err)
	}
	if bytes.Contains(bundleJSON, []byte(subject)) || !bytes.Contains(bundleJSON, []byte("erased:")) {
		t.Fatalf("verified export bundle did not redact erased subject: %s", bundleJSON)
	}

	var sawErasureEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if bytes.Contains(ev.Data, []byte(subject)) {
			t.Fatalf("event %s payload leaked erased subject after storage rewrite: %s", ev.Type, ev.Data)
		}
		if ev.Actor != nil {
			if strings.Contains(ev.Actor.Subject, subject) {
				t.Fatalf("event %s actor leaked erased subject after storage rewrite: %+v", ev.Type, ev.Actor)
			}
			for _, role := range ev.Actor.Roles {
				if strings.Contains(role, subject) {
					t.Fatalf("event %s actor role leaked erased subject after storage rewrite: %+v", ev.Type, ev.Actor)
				}
			}
		}
		if ev.Type == projections.EventPrivacySubjectErased && ev.TenantID == tenantID {
			sawErasureEvent = true
			if !bytes.Contains(ev.Data, []byte(erasureResp.SubjectRef)) {
				t.Fatalf("privacy erasure event payload = %s; want subject_ref without raw subject", ev.Data)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawErasureEvent {
		t.Fatal("privacy.subject.erased event was not recorded")
	}
}

func TestBuildAutonomouslyCompletesPreparedPrivacyErasureBeforeRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "restart-only-subject@example.test"
	)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "privacy-restart"}); err != nil {
		t.Fatal(err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-prepared-restart")
	if err != nil {
		t.Fatal(err)
	}
	storeDir := t.TempDir()
	log, err := openHistoryAwareEventLog(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: storeDir,
	}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := log.ActiveGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fencePayload, err := json.Marshal(map[string]string{
		"name": "restart/" + subject, "action": "create",
	})
	if err != nil {
		t.Fatal(err)
	}
	const recoveryFenceEventID = "77952000-0000-4000-8000-000000000011"
	if _, err := st.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantID, Name: "restart/" + subject, Operation: "create",
		EventID: recoveryFenceEventID, EventType: projections.EventApplicationSecretCreated,
		SchemaVersion: 1, ApprovalRequired: true,
		RequesterSealed: []byte("tenant-sealed-requester"),
		RequesterRef:    privacy.SubjectRef(tenantID, subject),
		RequestBinding:  strings.Repeat("6", 64), Payload: fencePayload,
	}); err != nil {
		t.Fatal(err)
	}
	preparedAt := time.Now().UTC().Round(0)
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantID, SubjectRef: privacy.SubjectRef(tenantID, subject),
			Reason: "restart recovery", ErasedAt: preparedAt,
		},
		OperationID:        "sha256:" + strings.Repeat("7", 64),
		RequestBinding:     strings.Repeat("8", 64),
		EventID:            "privacy-prepared-restart-completion",
		RewriteOperationID: "privacy-no-op-rewrite",
		TargetGeneration:   generation,
		EventActor: &events.Actor{
			Subject: privacy.Placeholder(privacy.SubjectRef(tenantID, "privacy-admin")),
			Roles:   []string{"privacy-admin"},
		},
	}
	prepared, err := st.PreparePrivacySubjectErasure(ctx, tenantID, subject, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepared.RecoveryFences, []store.PrivacyRecoveryFenceDisposition{{
		Kind: store.PrivacyRecoveryFenceApplicationSecret, EventID: recoveryFenceEventID,
		Disposition: store.PrivacyRecoveryFenceDeleted,
	}}) {
		t.Fatalf("prepared recovery fence evidence = %+v", prepared.RecoveryFences)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openHistoryAwareEventLog(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: storeDir,
	}, st, auditKey)
	if err != nil {
		t.Fatalf("reopen event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: reopened, AuditSigningKey: auditKey})
	if err != nil {
		_ = reopened.Close()
		t.Fatalf("Build after prepared privacy restart: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	if _, err := st.GetPrivacySubjectErasurePreparation(ctx, tenantID, prepared.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("startup did not retire prepared privacy row: %v", err)
	}
	canonical, found, err := reopened.EventByID(ctx, prepared.EventID)
	if err != nil || !found {
		t.Fatalf("startup completion event = found %v err %v", found, err)
	}
	if canonical.Type != projections.EventPrivacySubjectErased ||
		canonical.TenantID != tenantID || !canonical.Time.Equal(preparedAt) ||
		bytes.Contains(canonical.Data, []byte(subject)) {
		t.Fatalf("startup completion event differs or leaks subject: %+v", canonical)
	}
	expectedData, err := json.Marshal(projections.PrivacySubjectErased{
		OperationID: prepared.OperationID, RequestBinding: prepared.RequestBinding,
		SubjectRef: prepared.SubjectRef, RequestedByRef: prepared.RequestedByRef,
		Reason: prepared.Reason, Selectors: prepared.Selectors, Counts: prepared.Counts,
		RecoveryFences:        prepared.RecoveryFences,
		SchedulerDispositions: prepared.SchedulerDispositions,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical.Data, expectedData) {
		t.Fatalf("EventByID payload differs from durable preparation:\n got %s\nwant %s",
			canonical.Data, expectedData)
	}
	var completion projections.PrivacySubjectErased
	if err := json.Unmarshal(canonical.Data, &completion); err != nil {
		t.Fatal(err)
	}
	if err := projections.ValidatePrivacySubjectErasedPayload(canonical, completion); err != nil {
		t.Fatalf("startup completion v3 contract: %v", err)
	}
	if !reflect.DeepEqual(completion.RecoveryFences, prepared.RecoveryFences) {
		t.Fatalf("canonical recovery fence evidence = %+v, want %+v",
			completion.RecoveryFences, prepared.RecoveryFences)
	}
	if !reflect.DeepEqual(completion.SchedulerDispositions, prepared.SchedulerDispositions) {
		t.Fatalf("canonical scheduler privacy evidence = %+v, want %+v",
			completion.SchedulerDispositions, prepared.SchedulerDispositions)
	}
	ready, checks := srv.readiness.Evaluate(ctx)
	if !ready {
		t.Fatalf("server remained unready after autonomous privacy completion: %+v", checks)
	}

	// Model a zero-state receiver replay: remove both projected rows, then apply
	// only the retained v3 event. The closed fence evidence stays canonical while
	// the same privacy operation/read model is reconstructed without preparation.
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM privacy_subject_erasure_operations
			WHERE tenant_id = $1 AND event_id = $2`, tenantID, prepared.EventID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM privacy_subject_erasures
			WHERE tenant_id = $1 AND subject_ref = $2`, tenantID, prepared.SubjectRef)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, canonical); err != nil {
		t.Fatalf("cold replay prepared privacy completion: %v", err)
	}
	rebuilt, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantID, prepared.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.OperationID != prepared.OperationID || rebuilt.RequestBinding != prepared.RequestBinding ||
		rebuilt.SubjectRef != prepared.SubjectRef || !reflect.DeepEqual(rebuilt.Selectors, prepared.Selectors) ||
		!reflect.DeepEqual(rebuilt.Counts, prepared.Counts) {
		t.Fatalf("cold-replayed privacy operation = %+v, want prepared %+v", rebuilt, prepared)
	}
}

func TestApplicationSecretAppendReloadsFenceAcrossPrivacyHistoryCutover(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "privacy-race-alice@example.test"
		name     = "privacy/race-secret"
	)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "privacy-race"}); err != nil {
		t.Fatal(err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-application-secret-race")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	secretKEK, err := kek.LoadOrCreate(filepath.Join(t.TempDir(), "privacy-race-kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey,
		KEK: secretKEK, EnableSecretsAPI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Finalize with no broker to model a process crash. The raw fence is loaded
	// by a second API instance while privacy owns the exclusive history-operation
	// lock; only its post-cutover reload may decide what actor is publishable.
	noLogBackend := srv.buildSecretsBackend(Deps{Store: st, KEK: secretKEK})
	noLogAPI := api.New(st, srv.idem, srv.orch,
		api.WithInsecureHeaderResolver(), api.WithSecrets(noLogBackend))
	raw, _ := json.Marshal(map[string]any{"name": name, "value": "race-v1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/store", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", subject)
	req.Header.Set("X-Roles", "admin,delegate:"+subject)
	req.Header.Set("Idempotency-Key", "privacy-race-create")
	rec := httptest.NewRecorder()
	noLogAPI.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("crash fixture status=%d body=%s, want 500", rec.Code, rec.Body.Bytes())
	}
	before, err := st.GetApplicationSecretMutationFence(ctx, tenantID, name)
	if err != nil || before.Actor == nil || before.Actor.Subject != subject || before.EventTime.IsZero() {
		t.Fatalf("raw finalized fence fixture=%+v err=%v", before, err)
	}
	wantRawRoles := append([]string(nil), before.Actor.Roles...)
	rawSource, _ := json.Marshal(map[string]string{"requester": subject})
	if _, err := log.Append(ctx, events.Event{
		Type: "privacy.race.source", TenantID: tenantID, Data: rawSource,
		Actor: &events.Actor{Subject: subject, Roles: append([]string(nil), wantRawRoles...)},
	}); err != nil {
		t.Fatal(err)
	}

	second, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	secondBackend := srv.buildSecretsBackend(Deps{Store: second, Log: log, KEK: secretKEK})
	secondAPI := api.New(second, srv.idem, srv.orch, api.WithSecrets(secondBackend))

	cutoverPaused := make(chan struct{})
	releaseCutover := make(chan struct{})
	privacyOrch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st),
		orchestrator.WithTenantDataRewriteOptions(
			events.WithTenantDataContinuity(historycontinuity.NewReceiptSigner(auditKey)),
			events.WithTenantDataCutoverPreparation(func(
				cutoverCtx context.Context,
				report events.TenantDataRewriteReport,
				proceed func(context.Context) error,
			) error {
				close(cutoverPaused)
				select {
				case <-releaseCutover:
				case <-cutoverCtx.Done():
					return context.Cause(cutoverCtx)
				}
				return st.PrepareTenantDataCutover(cutoverCtx, report, proceed)
			}),
			events.WithTenantDataAuditContinuity(historycontinuity.AuditCheckpointProvider(st)),
		))
	privacyDone := make(chan error, 1)
	go func() {
		_, eraseErr := privacyOrch.ErasePrivacySubject(ctx, tenantID, subject, "erase racing actor")
		privacyDone <- eraseErr
	}()
	select {
	case <-cutoverPaused:
	case <-ctx.Done():
		t.Fatal("privacy rewrite did not reach the held cutover")
	}
	reconcileDone := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, reconcileErr := secondAPI.ReconcileApplicationSecretMutationFences(ctx)
		reconcileDone <- struct {
			count int
			err   error
		}{count: count, err: reconcileErr}
	}()
	// WithApplicationSecretMutationPrivacyBarrier holds one second-Store pool
	// session while polling the shared advisory lock. Observing that continuous
	// lease proves reconciliation already listed/validated the raw fence and is
	// stopped exactly at the generation wall, rather than merely not scheduled.
	barrierDeadline := time.NewTimer(2 * time.Second)
	barrierPoll := time.NewTicker(10 * time.Millisecond)
	defer barrierDeadline.Stop()
	defer barrierPoll.Stop()
	barrierObserved := false
	for !barrierObserved {
		select {
		case result := <-reconcileDone:
			t.Fatalf("append crossed the held privacy operation: count=%d err=%v", result.count, result.err)
		case <-barrierPoll.C:
			if second.SystemPool().Stat().AcquiredConns() == 0 {
				continue
			}
			time.Sleep(50 * time.Millisecond)
			barrierObserved = second.SystemPool().Stat().AcquiredConns() > 0
		case <-barrierDeadline.C:
			t.Fatal("reconciliation did not reach the shared privacy barrier")
		}
	}
	stillRaw, err := st.GetApplicationSecretMutationFence(ctx, tenantID, name)
	if err != nil || stillRaw.Actor == nil || stillRaw.Actor.Subject != subject {
		t.Fatalf("pre-completion fence was not the raw captured generation: %+v err=%v", stillRaw, err)
	}
	close(releaseCutover)
	if err := <-privacyDone; err != nil {
		t.Fatalf("privacy rewrite: %v", err)
	}
	result := <-reconcileDone
	if result.err != nil || result.count != 1 {
		t.Fatalf("post-cutover reconciliation count=%d err=%v, want 1/nil", result.count, result.err)
	}

	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, subject))
	wantRoles := make([]string, len(wantRawRoles))
	for i, role := range wantRawRoles {
		wantRoles[i] = strings.ReplaceAll(role, subject, placeholder)
	}
	secretRow, err := st.GetSecret(ctx, tenantID, name)
	if err != nil || secretRow.Version != 1 {
		t.Fatalf("placeholder recovery did not project exact secret: %+v err=%v", secretRow, err)
	}
	if _, err := st.GetApplicationSecretMutationFence(ctx, tenantID, name); !store.IsNotFound(err) {
		t.Fatalf("projected privacy-race fence remains: %v", err)
	}
	targets := 0
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(subject)) || event.Actor != nil && event.Actor.Subject == subject {
			return errors.New("post-cutover history contains raw racing subject")
		}
		if event.Actor != nil {
			for _, role := range event.Actor.Roles {
				if strings.Contains(role, subject) {
					return errors.New("post-cutover history contains raw racing subject in actor role")
				}
			}
		}
		if event.Type != projections.EventApplicationSecretCreated {
			return nil
		}
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.Name != name {
			return nil
		}
		targets++
		if event.Actor == nil || event.Actor.Subject != placeholder ||
			!reflect.DeepEqual(event.Actor.Roles, wantRoles) {
			return fmt.Errorf("target actor=%+v, want placeholder with exact roles %v", event.Actor, wantRoles)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if targets != 1 {
		t.Fatalf("privacy race published %d target events, want exactly one", targets)
	}
}

// PRIVACY-004 hardening: the served erasure route must keep pace with newer PII
// catalog fixture classes, including discovery source config and finding metadata
// values that carry principals, IP addresses, and user agents.
func TestServedPrivacySubjectErasureRedactsDiscoveryJSONReadSurfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenantID  = "11111111-1111-1111-1111-111111111111"
		principal = "svc-privacy@example.com"
		ip        = "203.0.113.44"
		userAgent = "privacy-fixture-agent/1.0"
	)

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	seedSubjectErasureDiscoveryJSON(t, ctx, st, tenantID, principal, ip, userAgent)
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-admin", []string{
		string(authz.PrivacyRead), string(authz.PrivacyWrite), string(authz.AuditRead),
	})

	auditKey, err := jose.GenerateRSASigningKey("privacy-004-discovery-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		st,
		auditKey,
	)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for i, raw := range []string{principal, ip, userAgent} {
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, raw); hits == 0 {
			t.Fatalf("seeded discovery JSON does not contain %q before erasure", raw)
		}
		code, body := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", adminToken, "erase-discovery-json-"+string(rune('a'+i)), map[string]string{
			"subject": raw,
			"reason":  "data subject request",
		})
		if code != http.StatusCreated {
			t.Fatalf("erase discovery JSON subject %q = %d, want 201; body=%s", raw, code, body)
		}
		if bytes.Contains(body, []byte(raw)) {
			t.Fatalf("erasure response for %q leaked raw subject: %s", raw, body)
		}
		var erasureResp struct {
			SubjectRef string         `json:"subject_ref"`
			Counts     map[string]int `json:"counts"`
		}
		if err := json.Unmarshal(body, &erasureResp); err != nil || erasureResp.SubjectRef == "" {
			t.Fatalf("decode discovery erasure response for %q: ref=%q err=%v body=%s", raw, erasureResp.SubjectRef, err, body)
		}
		if erasureResp.Counts["discovery_sources"] != 1 || erasureResp.Counts["discovery_findings"] != 1 {
			t.Fatalf("discovery erasure counts for %q = sources:%d findings:%d, want 1/1; counts=%v",
				raw, erasureResp.Counts["discovery_sources"], erasureResp.Counts["discovery_findings"], erasureResp.Counts)
		}
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, raw); hits != 0 {
			t.Fatalf("served erasure left raw discovery JSON value %q in %d source config/finding metadata values", raw, hits)
		}
		placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, raw))
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, placeholder); hits == 0 {
			t.Fatalf("served erasure for %q did not write discovery JSON placeholder %q", raw, placeholder)
		}
		assertEventLogOmitsRawSubject(t, ctx, log, tenantID, raw)
	}
}

func TestServedPrivacyErasureDurableReceiverSurvivesRacesRetentionAndIdempotencyGC(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice+privacy@example.com"
		key      = "erase-durable-race"
	)
	escapedSubject := url.QueryEscape(subject)
	reason := "erase " + subject + " and escaped " + escapedSubject

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-admin", []string{
		string(authz.OwnersWrite), string(authz.PrivacyWrite),
	})
	auditKey, err := jose.GenerateRSASigningKey("privacy-durable-receiver-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		st,
		auditKey,
	)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", adminToken, "owner-durable-erasure", map[string]string{
		"kind": "user", "name": subject, "email": subject,
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d, want 201; body=%s", code, body)
	}

	command, err := json.Marshal(map[string]string{"subject": subject, "reason": reason})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		status int
		body   []byte
		err    error
	}
	invoke := func(payload []byte) result {
		requestCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(
			requestCtx,
			http.MethodPost,
			ts.URL+"/api/v1/privacy/subject-erasures",
			bytes.NewReader(payload),
		)
		if err != nil {
			return result{err: err}
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := ts.Client().Do(req)
		if err != nil {
			return result{err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		responseBody, err := io.ReadAll(resp.Body)
		return result{status: resp.StatusCode, body: responseBody, err: err}
	}

	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			results <- invoke(command)
		}()
	}
	close(start)
	first := <-results
	second := <-results
	for index, got := range []result{first, second} {
		if got.err != nil || got.status != http.StatusCreated {
			t.Fatalf("concurrent erasure %d = status %d err %v body=%s",
				index+1, got.status, got.err, got.body)
		}
	}
	if !bytes.Equal(first.body, second.body) {
		t.Fatalf("concurrent same-key responses differ:\nfirst=%s\nsecond=%s", first.body, second.body)
	}
	for _, raw := range []string{subject, escapedSubject} {
		if bytes.Contains(first.body, []byte(raw)) {
			t.Fatalf("canonical erasure response leaked %q: %s", raw, first.body)
		}
	}

	changed, err := json.Marshal(map[string]string{
		"subject": subject,
		"reason":  reason + " changed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := invoke(changed); got.err != nil || got.status != http.StatusConflict {
		t.Fatalf("same key with changed body = status %d err %v body=%s, want 409",
			got.status, got.err, got.body)
	}

	var (
		erasureEvent events.Event
		eventCount   int
	)
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.TenantID == tenantID && ev.Type == projections.EventPrivacySubjectErased {
			erasureEvent = ev
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay canonical erasure event: %v", err)
	}
	if eventCount != 1 || erasureEvent.ID == "" || erasureEvent.Sequence == 0 {
		t.Fatalf("privacy erasure events = %d canonical=%+v, want exactly one", eventCount, erasureEvent)
	}
	for _, raw := range []string{subject, escapedSubject} {
		if bytes.Contains(erasureEvent.Data, []byte(raw)) {
			t.Fatalf("post-rewrite erasure event leaked %q: %s", raw, erasureEvent.Data)
		}
	}
	operation, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantID, erasureEvent.ID)
	if err != nil {
		t.Fatalf("load durable erasure operation: %v", err)
	}
	for _, raw := range []string{subject, escapedSubject} {
		if strings.Contains(operation.Reason, raw) {
			t.Fatalf("durable operation reason leaked %q: %q", raw, operation.Reason)
		}
	}

	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			tenantID, key)
		return err
	}); err != nil {
		t.Fatalf("simulate idempotency GC: %v", err)
	}
	if err := log.Delete(ctx, erasureEvent.Sequence); err != nil {
		t.Fatalf("simulate live-event retention: %v", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("full read-model rebuild after live-event retention: %v", err)
	}
	if _, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantID, erasureEvent.ID); err != nil {
		t.Fatalf("independent erasure operation did not survive full rebuild: %v", err)
	}
	changedAfterGC := invoke(changed)
	if changedAfterGC.err != nil || changedAfterGC.status != http.StatusConflict {
		t.Fatalf("post-GC changed-body retry = status %d err %v body=%s, want 409",
			changedAfterGC.status, changedAfterGC.err, changedAfterGC.body)
	}
	var conflictingClaims int
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&conflictingClaims)
	}); err != nil {
		t.Fatalf("count post-conflict idempotency claims: %v", err)
	}
	if conflictingClaims != 0 {
		t.Fatalf("changed-body retry left %d bound claims after receiver conflict, want 0", conflictingClaims)
	}
	replayed := invoke(command)
	if replayed.err != nil || replayed.status != http.StatusCreated {
		t.Fatalf("post-retention retry = status %d err %v body=%s",
			replayed.status, replayed.err, replayed.body)
	}
	if !bytes.Equal(replayed.body, first.body) {
		t.Fatalf("post-retention canonical response changed:\nfirst=%s\nreplay=%s",
			first.body, replayed.body)
	}
}

func seedSubjectErasureDiscoveryJSON(t *testing.T, ctx context.Context, st *store.Store, tenantID, principal, ip, userAgent string) {
	t.Helper()
	now := time.Now().UTC()
	config := jsonText(t, map[string]any{
		"events": []any{
			map[string]any{
				"principal":  principal,
				"owner":      principal,
				"ip":         ip,
				"user_agent": userAgent,
			},
		},
	})
	metadata := jsonText(t, map[string]any{
		"principal":     principal,
		"owner":         principal,
		"ip":            ip,
		"user_agent":    userAgent,
		"evidence_refs": []any{principal},
	})
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000001', $1, 'nhi_behavior', 'privacy-discovery-json', $2::jsonb, $3, $3)`,
			tenantID, config, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, started_at, completed_at, created_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000002', $1, 'aaaaaaaa-0000-0000-0000-000000000001', 'succeeded', false, 'privacy-seed', $2, $2, $2)`,
			tenantID, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO discovery_findings
			        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at,
			         triage_status, triage_actor, triage_reason, triaged_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000003', $1, 'aaaaaaaa-0000-0000-0000-000000000002',
			         'aaaaaaaa-0000-0000-0000-000000000001', 'nhi_behavior_finding', 'ref-nhi-behavior',
			         'privacy:nhi_behavior', 'fp-privacy-discovery-json', 80, $2::jsonb, $3, 'open', '', '', NULL)`,
			tenantID, metadata, now)
		return err
	}); err != nil {
		t.Fatalf("seed discovery JSON privacy fixture: %v", err)
	}
}

func countSubjectErasureDiscoveryJSONHits(t *testing.T, ctx context.Context, st *store.Store, tenantID, raw string) int {
	t.Helper()
	var hits int
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM discovery_sources
			    WHERE tenant_id = $1
			      AND EXISTS (
			            SELECT 1 FROM jsonb_path_query(config, '$.**') AS v(value)
			             WHERE jsonb_typeof(v.value) = 'string' AND v.value #>> '{}' = $2
			          )) +
			  (SELECT count(*) FROM discovery_findings
			    WHERE tenant_id = $1
			      AND EXISTS (
			            SELECT 1 FROM jsonb_path_query(metadata, '$.**') AS v(value)
			             WHERE jsonb_typeof(v.value) = 'string' AND v.value #>> '{}' = $2
			          ))`,
			tenantID, raw).Scan(&hits)
	}); err != nil {
		t.Fatalf("count discovery JSON hits for %q: %v", raw, err)
	}
	return hits
}

func assertEventLogOmitsRawSubject(t *testing.T, ctx context.Context, log *events.Log, tenantID, raw string) {
	t.Helper()
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		if bytes.Contains(ev.Data, []byte(raw)) {
			t.Fatalf("event %s payload leaked erased subject %q after storage rewrite: %s", ev.Type, raw, ev.Data)
		}
		if ev.Actor != nil {
			if strings.Contains(ev.Actor.Subject, raw) {
				t.Fatalf("event %s actor leaked erased subject %q after storage rewrite: %+v", ev.Type, raw, ev.Actor)
			}
			for _, role := range ev.Actor.Roles {
				if strings.Contains(role, raw) {
					t.Fatalf("event %s actor role leaked erased subject %q after storage rewrite: %+v", ev.Type, raw, ev.Actor)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log after erasing %q: %v", raw, err)
	}
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	return string(b)
}
