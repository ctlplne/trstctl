// SPDX-License-Identifier: BUSL-1.1

package server

// R1 second verifier V2ND-4 (CR-031 / V3-N1). Standalone at the pin; it adds
// to V3's reproduction (a) a control chunk sealed AFTER each re-key, which
// must play back, so the harness and read path are shown to work, (b) the
// direct open error of the pre-re-key object, so the cause is the key
// lifecycle and not the digest/fixture, and (c) the tenant-domain Rotate path
// that V3 cited but did not run.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

func v2nd4CutoverStore(t *testing.T) *store.Store {
	t.Helper()
	admin := newServerTestStore(t)
	cutover := storetest.ProvisionRewrapCutover(t, admin, serverTestPostgresDSN(t))
	cr029AllowDisposablePeerLogin(t, admin, serverTestPostgresDSN(t), cutover.Cutover.NewLoginRole)
	st, err := store.Open(context.Background(), cutover.DSN, store.WithRewrapFleetCutover(cutover.Cutover))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.RequireRewrapFleetCutover(context.Background(), cutover.Cutover); err != nil {
		t.Fatal(err)
	}
	return st
}

// v2nd4StoreChunk stores chunk 0 of a session the way acceptRecordingChunk
// (pam_recording_uploads.go:209) and storeStagedRecordingChunk (:297-322) do:
// same seal call and AAD, same object name and digest, indexed in
// pam_session_recording_chunks (fixture row for the stored event's projection).
func v2nd4StoreChunk(t *testing.T, ctx context.Context, svc *pamService, tenantID, sessionID string) {
	t.Helper()
	chunk := []byte(`{"t":0,"d":"whoami"}` + "\n")
	sum := crypto.SHA256Sum(chunk)
	sumHex := hex.EncodeToString(sum)
	sealed, err := sealTenantValue(ctx, svc.recordings.access, svc.recordings.legacy, tenantID, chunk, recordingAAD(tenantID, sessionID, 0, sumHex))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := recordingChain("", sum)
	if err != nil {
		t.Fatal(err)
	}
	view, err := objectstore.ForTenant(ctx, svc.recordings.objects, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	rel := "recordings/" + sessionID + "/0-1-0"
	name, err := view.Name(rel)
	if err != nil {
		t.Fatal(err)
	}
	sealedSum := crypto.SHA256Sum(sealed)
	if _, err := view.Create(ctx, rel, bytes.NewReader(sealed), int64(len(sealed)), sealedSum); err != nil {
		t.Fatal(err)
	}
	if err := svc.appendDeterministic(ctx, tenantID, recordingChunkEventID(tenantID, sessionID, 1, 0),
		projections.EventPAMRecordingChunkStored, projections.PAMRecordingChunkStored{
			ID: sessionID, GatewayAgentID: uuid.NewString(), Ord: 0, Attempt: 1, Seq: 0,
			ObjectRef: name, SHA256: sumHex, SealedSHA256: hex.EncodeToString(sealedSum),
			Chain: chain, Size: len(chunk), StoredAt: time.Now().UTC(),
		}); err != nil {
		t.Fatal(err)
	}
}

// v2nd4Play is the production read path of playback/export/verify.
func v2nd4Play(ctx context.Context, svc *pamService, tenantID, sessionID string) (int, error) {
	frames, _, err := svc.recordingFrames(ctx, tenantID, sessionID, 0, 0, 1<<20)
	return len(frames), err
}

// v2nd4DirectOpen fetches the stored object (digest-checked by the store) and
// opens it with the production tenant cipher, returning the cipher's error.
func v2nd4DirectOpen(t *testing.T, ctx context.Context, svc *pamService, tenantID, sessionID string) error {
	t.Helper()
	chunks, err := svc.store.ListPAMRecordingChunks(ctx, tenantID, sessionID, 0, 1)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("list chunks n=%d err=%v", len(chunks), err)
	}
	view, err := objectstore.ForTenant(ctx, svc.recordings.objects, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if _, err := view.Get(ctx, recordingRel(view, chunks[0].ObjectRef), &sealed, recordingMaxChunk*2); err != nil {
		t.Fatalf("object get (digest-checked): %v", err)
	}
	if got := hex.EncodeToString(crypto.SHA256Sum(sealed.Bytes())); got != chunks[0].SealedSHA256 {
		t.Fatalf("stored object bytes changed: %s != %s", got, chunks[0].SealedSHA256)
	}
	_, err = openTenantValue(ctx, svc.recordings.access, svc.recordings.legacy, tenantID, sealed.Bytes(),
		recordingAAD(tenantID, sessionID, chunks[0].Ord, chunks[0].SHA256))
	return err
}

func v2nd4HistoryLog(t *testing.T, st *store.Store) (*events.Log, *jose.SigningKey, func(tenantseal.Access)) {
	t.Helper()
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	var admissionAccess tenantseal.Access
	admission := events.WithAppendAdmission(func(ctx context.Context, e events.Event, publish func(context.Context) (events.Event, error)) (events.Event, error) {
		if !events.SealedBearingEvent(e) {
			return publish(ctx)
		}
		return restoreEventIngressAdmissionWithCustody(st, func() tenantseal.Access { return admissionAccess })(ctx, e, publish)
	})
	log, err := openHistoryAwareEventLog(context.Background(),
		config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}, st, auditKey, admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, auditKey, func(access tenantseal.Access) { admissionAccess = access }
}

func TestV2ND4RecordingAcrossTenantMigrationAndRotation(t *testing.T) {
	ctx := context.Background()
	st := v2nd4CutoverStore(t)
	log, auditKey, setAdmission := v2nd4HistoryLog(t, st)
	const tenantID = "b2d4b2d4-0000-4000-8000-00000000b2d4"
	registerServerTestTenant(t, st, log, tenantID, "v2nd4-pam-recording")
	deployment, err := kek.LoadOrCreate(filepath.Join(t.TempDir(), "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deployment.Destroy)
	wrapperPath := filepath.Join(t.TempDir(), "v2nd4.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x4d}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "v2nd4", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(st, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}
	setAdmission(access)
	lifecycle, err := tenantseal.NewLifecycle(st, log, deployment, registry, historyRewriteProofOptions(st, auditKey)...)
	if err != nil {
		t.Fatal(err)
	}
	svc := &pamService{store: st, log: log, projector: projections.New(st, projections.WithCanonicalEventSource(log)), recordings: &pamRecordings{objects: s3test.NewServer(t).Open(t), access: access, legacy: deployment}}
	lifecycle.BindRecordingObjects(svc.recordings.objects)

	pre := uuid.NewString()
	v2nd4StoreChunk(t, ctx, svc, tenantID, pre)
	if n, err := v2nd4Play(ctx, svc, tenantID, pre); n != 1 || err != nil {
		t.Fatalf("before migration the recording plays: frames=%d err=%v", n, err)
	}
	if _, err := lifecycle.Migrate(ctx, tenantID, tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "v2nd4"}); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mid := uuid.NewString()
	v2nd4StoreChunk(t, ctx, svc, tenantID, mid)
	if n, err := v2nd4Play(ctx, svc, tenantID, mid); n != 1 || err != nil {
		t.Fatalf("control: a recording sealed after the migration plays: frames=%d err=%v", n, err)
	}
	t.Logf("control after migration: a newly sealed recording plays back (frames=1)")
	if n, err := v2nd4Play(ctx, svc, tenantID, pre); n != 1 || err != nil {
		oerr := v2nd4DirectOpen(t, ctx, svc, tenantID, pre)
		t.Errorf("V2ND-4 migrate: the pre-migration recording no longer plays (frames=%d): %v; direct open: %v (errors.Is seal.ErrDomain=%t)",
			n, err, oerr, errors.Is(oerr, seal.ErrDomain))
	}

	if _, err := lifecycle.Rotate(ctx, tenantID, tenantseal.WrapperRef{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if d, err := lifecycle.Status(ctx, tenantID); err == nil {
		t.Logf("after tenant-domain rotation: state=%s generation=%d op=%s/%s", d.State, d.Generation, d.OperationKind, d.OperationStatus)
	}
	post := uuid.NewString()
	v2nd4StoreChunk(t, ctx, svc, tenantID, post)
	if n, err := v2nd4Play(ctx, svc, tenantID, post); n != 1 || err != nil {
		t.Fatalf("control: a recording sealed after the rotation plays: frames=%d err=%v", n, err)
	}
	t.Logf("control after rotation: a newly sealed recording plays back (frames=1)")
	if n, err := v2nd4Play(ctx, svc, tenantID, mid); n != 1 || err != nil {
		oerr := v2nd4DirectOpen(t, ctx, svc, tenantID, mid)
		t.Errorf("V2ND-4 rotate: a recording sealed under domain generation 1 no longer plays after Rotate (frames=%d): %v; direct open: %v (errors.Is seal.ErrDomain=%t)",
			n, err, oerr, errors.Is(oerr, seal.ErrDomain))
	}
	if err := svc.projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild recording wraps from canonical events: %v", err)
	}
	for _, sessionID := range []string{pre, mid, post} {
		if n, err := v2nd4Play(ctx, svc, tenantID, sessionID); n != 1 || err != nil {
			t.Errorf("after rebuild recording %s: frames=%d err=%v", sessionID, n, err)
		}
	}
}

func TestV2ND4RecordingAcrossDeploymentKEKRotation(t *testing.T) {
	ctx := context.Background()
	st := v2nd4CutoverStore(t)
	log, auditKey, setAdmission := v2nd4HistoryLog(t, st)
	const tenantID = "b2d4b2d4-0000-4000-8000-00000000b2d5"
	registerServerTestTenant(t, st, log, tenantID, "v2nd4-pam-recording-legacy")
	local, err := kek.LoadOrCreate(filepath.Join(t.TempDir(), "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Destroy)
	nextPath := filepath.Join(t.TempDir(), "v2nd4-next.key")
	if err := os.WriteFile(nextPath, bytes.Repeat([]byte{0x4e}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "v2nd4-next", Path: nextPath}})
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := tenantseal.NewDeploymentKeyring(local, st, registry)
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(st, keyring, registry)
	if err != nil {
		t.Fatal(err)
	}
	setAdmission(access)
	rotation, err := tenantseal.NewDeploymentRotation(st, log, keyring, registry,
		tenantseal.WithDeploymentSettle(0), tenantseal.WithDeploymentHistoryRewriteOptions(historyRewriteProofOptions(st, auditKey)...))
	if err != nil {
		t.Fatal(err)
	}
	svc := &pamService{store: st, log: log, projector: projections.New(st, projections.WithCanonicalEventSource(log)), recordings: &pamRecordings{objects: s3test.NewServer(t).Open(t), access: access, legacy: keyring}}
	rotation.BindRecordingObjects(svc.recordings.objects)

	pre := uuid.NewString()
	v2nd4StoreChunk(t, ctx, svc, tenantID, pre)
	if n, err := v2nd4Play(ctx, svc, tenantID, pre); n != 1 || err != nil {
		t.Fatalf("before the rotation the recording plays: frames=%d err=%v", n, err)
	}
	if _, err := rotation.Begin(ctx, tenantID, tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "v2nd4-next"}); err != nil {
		t.Fatal(err)
	}
	for step := 0; ; step++ {
		if step > 200 {
			t.Fatal("deployment KEK rotation did not complete in 200 steps")
		}
		if _, err := rotation.Step(ctx); err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		state, found, err := rotation.Status(ctx)
		if err != nil || !found {
			t.Fatalf("status found=%t err=%v", found, err)
		}
		if state.OperationStatus == store.DeploymentKEKOperationCompleted {
			t.Logf("deployment KEK rotation completed: generation=%d previous=%d containers_rewrapped=%d containers_verified=%d stragglers=%d",
				state.Generation, state.PreviousGeneration, state.ContainersRewrapped, state.ContainersVerified, state.VerifyStragglers)
			break
		}
		if state.OperationStatus == store.DeploymentKEKOperationFailed {
			t.Fatalf("rotation failed: %s %s", state.LastErrorCode, state.LastError)
		}
	}
	post := uuid.NewString()
	v2nd4StoreChunk(t, ctx, svc, tenantID, post)
	if n, err := v2nd4Play(ctx, svc, tenantID, post); n != 1 || err != nil {
		t.Fatalf("control: a recording sealed after the rotation plays: frames=%d err=%v", n, err)
	}
	t.Logf("control after deployment rotation: a newly sealed recording plays back (frames=1)")
	if n, err := v2nd4Play(ctx, svc, tenantID, pre); n != 1 || err != nil {
		oerr := v2nd4DirectOpen(t, ctx, svc, tenantID, pre)
		t.Errorf("V2ND-4 deployment rotation: the legacy tenant's pre-rotation recording no longer plays (frames=%d): %v; direct open: %v (errors.Is ErrDeploymentGenerationNotLive=%t)",
			n, err, oerr, errors.Is(oerr, tenantseal.ErrDeploymentGenerationNotLive))
	}
	if err := svc.projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild deployment recording wraps from canonical events: %v", err)
	}
	if n, err := v2nd4Play(ctx, svc, tenantID, pre); n != 1 || err != nil {
		t.Errorf("after deployment rebuild recording: frames=%d err=%v", n, err)
	}
}

func TestCR031MigrationWaitsForAnUnprojectedRecordingObject(t *testing.T) {
	ctx := context.Background()
	st := v2nd4CutoverStore(t)
	log, auditKey, setAdmission := v2nd4HistoryLog(t, st)
	const tenantID = "b2d4b2d4-0000-4000-8000-00000000b2d6"
	registerServerTestTenant(t, st, log, tenantID, "cr031-staged-object")
	deployment, err := kek.LoadOrCreate(filepath.Join(t.TempDir(), "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deployment.Destroy)
	wrapperPath := filepath.Join(t.TempDir(), "tenant.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x5f}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "cr031", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(st, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}
	setAdmission(access)
	lifecycle, err := tenantseal.NewLifecycle(st, log, deployment, registry, historyRewriteProofOptions(st, auditKey)...)
	if err != nil {
		t.Fatal(err)
	}
	objects := s3test.NewServer(t).Open(t)
	lifecycle.BindRecordingObjects(objects)
	svc := &pamService{store: st, log: log, projector: projections.New(st, projections.WithCanonicalEventSource(log)),
		recordings: &pamRecordings{objects: objects, access: access, legacy: deployment}}
	sessionID := uuid.NewString()
	plain := []byte(`{"t":0,"d":"staged"}` + "\n")
	sum := crypto.SHA256Sum(plain)
	sumHex := hex.EncodeToString(sum)
	sealed, err := sealTenantValue(ctx, access, deployment, tenantID, plain, recordingAAD(tenantID, sessionID, 0, sumHex))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := recordingChain("", sum)
	if err != nil {
		t.Fatal(err)
	}
	u := store.PAMRecordingUpload{TenantID: tenantID, SessionID: sessionID, Attempt: 1, Seq: 0, Ord: 0,
		GatewayAgentID: uuid.NewString(), SHA256: sumHex, SealedSHA256: crypto.SHA256Hex(sealed),
		Chain: chain, Size: len(plain), Sealed: sealed, StagedAt: time.Now().UTC()}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error { return st.InsertPAMRecordingUploadTx(ctx, tx, u) }); err != nil {
		t.Fatal(err)
	}
	view, err := objectstore.ForTenant(ctx, objects, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	rel := "recordings/" + sessionID + "/0-1-0"
	if _, err := view.Create(ctx, rel, bytes.NewReader(sealed), int64(len(sealed)), crypto.SHA256Sum(sealed)); err != nil {
		t.Fatal(err)
	}
	ref := tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "cr031"}
	if _, err := lifecycle.Migrate(ctx, tenantID, ref); err == nil {
		t.Fatal("migration retired the old key before the already-written object was projected")
	}
	if gate, found, err := st.GetTenantApplicationSecretRewrapGate(ctx, tenantID); err != nil || found && gate.InProgress {
		t.Fatalf("rejected preflight left rewrap gate armed: found=%t gate=%+v err=%v", found, gate, err)
	}
	if err := svc.storeStagedRecordingChunk(ctx, u); err != nil {
		t.Fatalf("ordinary outbox upload could not reconcile the object: %v", err)
	}
	if _, err := lifecycle.Migrate(ctx, tenantID, ref); err != nil {
		t.Fatalf("migration after upload projection: %v", err)
	}
	if n, err := v2nd4Play(ctx, svc, tenantID, sessionID); n != 1 || err != nil {
		t.Fatalf("reconciled recording after migration: frames=%d err=%v", n, err)
	}
}
