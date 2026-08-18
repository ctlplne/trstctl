// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package intwire

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	eedecommission "trstctl.com/trstctl/ee/decommission"
	"trstctl.com/trstctl/ee/decommission/aggregate"
	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/jobmodel"
	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/ee/decommission/retirement"
	"trstctl.com/trstctl/ee/decommission/signerwiring"
	decstore "trstctl.com/trstctl/ee/decommission/store"
	vdecverify "trstctl.com/trstctl/ee/decommission/verify"
	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantWire       = "77777777-7777-7777-7777-777777777777"
	stableKeyWire    = "key://tenant-wire/root-ca"
	successorKeyWire = "key://tenant-wire/root-ca-successor"
	finalEpochWire   = uint64(7)
)

var (
	ciphertextDep = depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ct-live-1"}
	credentialDep = depstate.Dependent{Class: depstate.DependentCredential, ID: "cred-retired-1"}
	dataSetDep    = depstate.Dependent{Class: depstate.DependentDataSet, ID: "dataset-erasure-1"}
)

func TestVDEC_Wire_RetireKeyOfflineRecord_RealInfra(t *testing.T) {
	flow := runRetireFlow(t)

	if flow.aggregate.Commitment.TenantID != tenantWire || len(flow.aggregate.Commitment.Leaves) != 1 {
		t.Fatalf("aggregate record = %+v, want one tenant-scoped destruction leaf", flow.aggregate.Commitment)
	}
	if err := aggregate.VerifyRecord(flow.aggregate, publicKey(flow.aggregate.AttestationAlgorithm, flow.aggregate.AttestationPublicKeyDER)); err != nil {
		t.Fatalf("Verify aggregate record: %v", err)
	}
	assertOfflineVerdict(t, flow)
}

func TestVDEC_Wire_SystemGateRefusesUntilComplete_RealInfra(t *testing.T) {
	h := newHarness(t)
	h.seedRegistered(t)
	events := h.rebuildTenant(t)
	handle := h.generateSubjectHandle(t)

	req := h.gateRequest(t, handle, events)
	refused, err := h.signer.GatedDestroy(h.ctx, req)
	if err != nil {
		t.Fatalf("GatedDestroy refusal: %v", err)
	}
	if refused.Approved {
		t.Fatal("gate approved while real PG/NATS dependency state had unaccounted dependents")
	}
	artifact, err := gate.DecodeRefusalArtifact(refused.RefusalRecord)
	if err != nil {
		t.Fatalf("DecodeRefusalArtifact: %v", err)
	}
	if artifact.Body.UnaccountedCount != 3 || !hasDependent(artifact.Body.Unaccounted, ciphertextDep) {
		t.Fatalf("refusal body = %+v, want seeded unaccounted dependents", artifact.Body)
	}
	if _, err := h.signer.SignerForHandle(h.ctx, handle); err != nil {
		t.Fatalf("refused gated destroy removed signer-held key: %v", err)
	}
}

func TestVDEC_Wire_VerifierAcceptsRecordOffline(t *testing.T) {
	assertOfflineVerdict(t, runRetireFlow(t))
}

func TestVDEC_Wire_GateDestroyMintInRealSigner(t *testing.T) {
	flow := runRetireFlow(t)

	if !flow.destroyDecision.Approved || len(flow.destroyDecision.Evidence) == 0 {
		t.Fatalf("destroy decision = %+v, want real signer approval evidence", flow.destroyDecision)
	}
	if err := record.VerifyRecord(flow.record, publicKey(flow.record.AttestationAlgorithm, flow.record.AttestationPublicKeyDER)); err != nil {
		t.Fatalf("Verify signer-minted destruction record: %v", err)
	}
	if _, err := flow.h.signer.SignerForHandle(flow.h.ctx, flow.handle); status.Code(err) != codes.NotFound {
		t.Fatalf("destroyed signer handle lookup err = %v, want NotFound", err)
	}
}

func TestVDEC_ServedRetirementRefusesThenProjectsOfflineRecordAcrossRestart(t *testing.T) {
	h := newHarness(t)
	if err := h.store.UpsertTenant(h.ctx, corestore.Tenant{
		TenantID: h.tenant, Name: "VDEC served tenant", EventSeq: 1,
	}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	handle := "vdec-served-retirement-handle"
	if _, err := h.signer.GenerateKeyHandle(h.ctx, crypto.ECDSAP256, handle); err != nil {
		t.Fatalf("GenerateKeyHandle: %v", err)
	}
	authority, err := h.store.InsertCAAuthority(h.ctx, corestore.CAAuthority{
		TenantID: h.tenant, CommonName: "Retiring Root", Kind: "root", Status: "superseded",
		CertificatePEM: "public-test-certificate", SignerHandle: handle, Serial: "42",
	})
	if err != nil {
		t.Fatalf("InsertCAAuthority: %v", err)
	}
	h.keyID = authority.ID
	h.successorKeyID = authority.ID + ":successor"
	h.seedRegistered(t)
	h.rebuildTenant(t)

	outbox := orchestrator.NewOutbox(h.store)
	runtime, err := eedecommission.NewRuntime(eedecommission.RuntimeConfig{Store: h.store, Log: h.log})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	licensed, err := runtime.APIOptionsFactory(editionseam.LicensedAPIOptionsDeps{
		Store: h.store, Log: h.log, Outbox: outbox,
	})
	if err != nil {
		t.Fatalf("APIOptionsFactory: %v", err)
	}
	role := authz.Role{Name: "vdec-served-operator", Permissions: []authz.Permission{authz.KeysRead, authz.KeysWrite}}
	principal := authz.Principal{TenantID: h.tenant, Subject: "retirement-operator", Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: h.tenant}}}}
	opts := append([]coreapi.Option{
		coreapi.WithRoles(role),
		coreapi.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	}, licensed...)
	served := coreapi.New(h.store, orchestrator.NewIdempotency(h.store), nil, opts...)
	licensedHandler, err := runtime.RetirementOutboxFactory(editionseam.LicensedOutboxDeps{
		Store: h.store, Log: h.log, GatedDestruction: h.signer,
	})
	if err != nil {
		t.Fatalf("RetirementOutboxFactory: %v", err)
	}
	dispatch := func() {
		t.Helper()
		_, err := outbox.Dispatch(h.ctx, orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
			handled, err := licensedHandler.DeliverLicensed(ctx, message)
			if !handled {
				return fmt.Errorf("retirement handler did not own %q", message.Destination)
			}
			return err
		}))
		if err != nil {
			t.Fatalf("dispatch retirement: %v", err)
		}
	}
	postAt := func(key string, epoch uint64) *httptest.ResponseRecorder {
		t.Helper()
		body := []byte(fmt.Sprintf(`{"final_epoch":%d,"confirm_irreversible":true}`, epoch))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+h.keyID+"/retirement", bytes.NewReader(body))
		req.Header.Set("Idempotency-Key", key)
		rr := httptest.NewRecorder()
		served.ServeHTTP(rr, req)
		return rr
	}
	post := func(key string) []byte {
		t.Helper()
		rr := postAt(key, finalEpochWire)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("POST retirement = %d body=%s", rr.Code, rr.Body.String())
		}
		return append([]byte(nil), rr.Body.Bytes()...)
	}
	get := func() coreapi.RetirementChecklist {
		t.Helper()
		rr := httptest.NewRecorder()
		served.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/"+h.keyID+"/retirement", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET retirement = %d body=%s", rr.Code, rr.Body.String())
		}
		var checklist coreapi.RetirementChecklist
		if err := json.Unmarshal(rr.Body.Bytes(), &checklist); err != nil {
			t.Fatalf("decode checklist: %v", err)
		}
		return checklist
	}

	first := post("served-retirement-refusal")
	var firstReceipt retirement.Receipt
	if err := json.Unmarshal(first, &firstReceipt); err != nil {
		t.Fatalf("decode first retirement receipt: %v", err)
	}
	commandEvent, found, err := h.log.EventByID(h.ctx, firstReceipt.CommandEventID)
	if err != nil || !found {
		t.Fatalf("load frozen retirement command: found=%v err=%v", found, err)
	}
	frozen, err := retirement.DecodeRequested(commandEvent)
	if err != nil {
		t.Fatalf("decode frozen retirement command: %v", err)
	}
	if len(frozen.Approvals) != 1 || frozen.Approvals[0] != principal.Subject || frozen.KeyClass != retirement.KeyClass("") {
		t.Fatalf("frozen authorization = class %q approvals=%v, want fixed CA class and authenticated caller", frozen.KeyClass, frozen.Approvals)
	}
	if _, foreignFound, err := runtime.RetirementProjection.Fetch(h.ctx, "88888888-8888-8888-8888-888888888888", h.keyID); err != nil || foreignFound {
		t.Fatalf("foreign tenant saw retirement command: found=%v err=%v", foreignFound, err)
	}
	dispatch()
	refused := get()
	if refused.RetirementStatus != retirement.StatusRefused || refused.RefusalRecord == "" || refused.DestructionRecord != "" {
		t.Fatalf("refused checklist = %+v", refused)
	}
	if _, err := h.signer.SignerForHandle(h.ctx, handle); err != nil {
		t.Fatalf("signed refusal destroyed key: %v", err)
	}
	if replay := post("served-retirement-refusal"); !bytes.Equal(replay, first) {
		t.Fatalf("same-key replay changed response: first=%s replay=%s", first, replay)
	}

	h.completeDependents(t)
	h.rebuildTenant(t)
	stalePending := post("served-retirement-stale-pending")
	if sameSnapshot := post("served-retirement-stale-pending-new-http-key"); !bytes.Equal(sameSnapshot, stalePending) {
		t.Fatalf("same frozen command changed under a new HTTP idempotency key: first=%s second=%s", stalePending, sameSnapshot)
	}
	if conflict := postAt("served-retirement-conflicting-epoch", finalEpochWire+1); conflict.Code != http.StatusConflict {
		t.Fatalf("different command replaced a pending frozen command = %d body=%s, want 409", conflict.Code, conflict.Body.String())
	}
	h.appendPayload(t, depstate.DependencyReleasedV1{
		TenantID: h.tenant, KeyID: h.keyID, Dependent: credentialDep,
		Reason: "late durable release receipt supersedes the frozen command head",
	})
	h.rebuildTenant(t)
	freshPending := post("served-retirement-success")
	if bytes.Equal(stalePending, freshPending) {
		t.Fatalf("dependency change did not freeze a newer retirement command: stale=%s fresh=%s", stalePending, freshPending)
	}
	dispatch()
	destroyed := get()
	if destroyed.RetirementStatus != retirement.StatusDestroyed || destroyed.DestructionRecord == "" || destroyed.RefusalRecord != "" || destroyed.Blocked {
		t.Fatalf("destroyed checklist = %+v", destroyed)
	}
	rec, err := record.DecodeRecord([]byte(destroyed.DestructionRecord))
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if err := record.VerifyRecord(rec, crypto.PublicKey{Algorithm: rec.AttestationAlgorithm, DER: rec.AttestationPublicKeyDER}); err != nil {
		t.Fatalf("offline VerifyRecord: %v", err)
	}
	if _, err := h.signer.SignerForHandle(h.ctx, handle); status.Code(err) != codes.NotFound {
		t.Fatalf("destroyed signer handle lookup = %v", err)
	}

	restarted := retirement.NewProjection(h.store, outbox)
	if err := restarted.Reset(h.ctx); err != nil {
		t.Fatalf("restart projection reset: %v", err)
	}
	if err := h.log.Replay(h.ctx, 1, func(ev events.Event) error { return restarted.Apply(h.ctx, ev) }); err != nil {
		t.Fatalf("restart projection replay: %v", err)
	}
	state, found, err := restarted.Fetch(h.ctx, h.tenant, h.keyID)
	if err != nil || !found || state.Status != retirement.StatusDestroyed || len(state.DestructionRecord) == 0 {
		t.Fatalf("restart state = %+v found=%v err=%v", state, found, err)
	}
	if err := restarted.Apply(h.ctx, eventspec.Event{
		Type: projections.EventTenantOffboarded, TenantID: h.tenant, Sequence: state.LedgerPosition + 100,
	}); err != nil {
		t.Fatalf("project tenant offboard: %v", err)
	}
	if _, found, err := restarted.Fetch(h.ctx, h.tenant, h.keyID); err != nil || found {
		t.Fatalf("offboarded retirement state remained: found=%v err=%v", found, err)
	}
}

func TestVDEC_Restart_CompletionEvidenceSetSurvives(t *testing.T) {
	h := newHarness(t)
	h.seedRegistered(t)
	h.completeDependents(t)
	before := h.rebuildTenant(t)

	h.restartEventLog(t)
	after := h.rebuildTenant(t)
	if len(after) != len(before) {
		t.Fatalf("replayed events after restart = %d, want %d", len(after), len(before))
	}
	state := h.fetchState(t)
	if got := state.Unaccounted(); len(got) != 0 {
		t.Fatalf("unaccounted after restart = %+v, want none", got)
	}
	completions, err := h.repo.ListCompletionEvents(h.ctx, h.tenant, h.keyID)
	if err != nil {
		t.Fatalf("ListCompletionEvents after restart: %v", err)
	}
	if len(completions) != 1 || completions[0].Dependent != ciphertextDep {
		t.Fatalf("completion evidence after restart = %+v, want ciphertext completion", completions)
	}
}

func TestVDEC_Restart_DestroyedTerminalIrreversible(t *testing.T) {
	flow := runRetireFlow(t)

	flow.h.restartSigner(t)
	if _, err := flow.h.signer.SignerForHandle(flow.h.ctx, flow.handle); status.Code(err) != codes.NotFound {
		t.Fatalf("destroyed signer handle resurrected after restart: %v", err)
	}
}

func TestVDEC_Restart_ReprotectResumesIdempotent(t *testing.T) {
	h := newHarness(t)
	h.seedRegistered(t)
	registered := h.rebuildTenant(t)
	state := h.fetchState(t)
	jobs, err := jobmodel.PlanFromState(state)
	if err != nil {
		t.Fatalf("PlanFromState: %v", err)
	}
	job := jobFor(t, jobs, ciphertextDep)
	h.appendPayload(t, depstate.ReprotectionCompletedV1{
		TenantID:       h.tenant,
		KeyID:          h.keyID,
		JobID:          job.ID,
		Dependent:      ciphertextDep,
		SuccessorKeyID: h.successorKeyID,
	})

	h.restartEventLog(t)
	h.appendPayload(t, depstate.ReprotectionCompletedV1{
		TenantID:       h.tenant,
		KeyID:          h.keyID,
		JobID:          job.ID,
		Dependent:      ciphertextDep,
		SuccessorKeyID: h.successorKeyID,
	})
	h.appendReleaseAndErasure(t)
	replayed := h.rebuildTenant(t)
	if len(replayed) != len(registered)+4 {
		t.Fatalf("replayed event count = %d, want registered + duplicate completion + release/erasure", len(replayed))
	}
	completions, err := h.repo.ListCompletionEvents(h.ctx, h.tenant, h.keyID)
	if err != nil {
		t.Fatalf("ListCompletionEvents: %v", err)
	}
	if len(completions) != 1 {
		t.Fatalf("completion rows = %+v, want one idempotent row despite duplicate ledger completion", completions)
	}
	handle := h.generateSubjectHandle(t)
	approved, err := h.signer.GatedDestroy(h.ctx, h.gateRequest(t, handle, replayed))
	if err != nil {
		t.Fatalf("GatedDestroy after resumed completions: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("gate refused after idempotent resumed completions: %s", string(approved.RefusalRecord))
	}
}

type harness struct {
	ctx context.Context

	tenant         string
	keyID          string
	successorKeyID string

	store *corestore.Store
	repo  *decstore.Repo
	log   *events.Log

	natsDir string
	bin     string
	keyDir  string
	kekFile string

	signer   *signing.Client
	stopSign func()
}

type retireFlow struct {
	h *harness

	handle          string
	events          []eventspec.Event
	requiredDigest  []byte
	destroyDecision signing.GatedDestroyDecision
	record          record.SignedRecord
	aggregate       aggregate.SignedRecord
	completion      vdecverify.CompletionEvidence
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dsn, stopPG := startPostgres(t)
	t.Cleanup(stopPG)

	dbName := fmt.Sprintf("vdec_intwire_%d", time.Now().UTC().UnixNano())
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	_ = admin.Close(ctx)

	storeDSN := strings.TrimSuffix(dsn, "/postgres") + "/" + dbName
	st, err := corestore.Open(ctx, storeDSN)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	st.WithExtraMigrations(decstore.MigrationsFS())
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate core+VDEC store: %v", err)
	}

	h := &harness{
		ctx:            ctx,
		tenant:         tenantWire,
		keyID:          stableKeyWire,
		successorKeyID: successorKeyWire,
		store:          st,
		repo:           decstore.New(st),
		natsDir:        filepath.Join(t.TempDir(), "nats"),
		bin:            buildSignerBinary(t),
		keyDir:         filepath.Join(t.TempDir(), "signer-keys"),
		kekFile:        filepath.Join(t.TempDir(), "signer.kek"),
	}
	h.openEventLog(t)
	h.startSigner(t)
	t.Cleanup(func() {
		if h.stopSign != nil {
			h.stopSign()
			h.stopSign = nil
		}
		if h.signer != nil {
			_ = h.signer.Close()
		}
		if h.log != nil {
			_ = h.log.Close()
		}
		h.store.Close()
	})
	return h
}

func runRetireFlow(t *testing.T) retireFlow {
	t.Helper()
	h := newHarness(t)
	h.seedRegistered(t)
	events := h.rebuildTenant(t)
	handle := h.generateSubjectHandle(t)
	refused, err := h.signer.GatedDestroy(h.ctx, h.gateRequest(t, handle, events))
	if err != nil {
		t.Fatalf("initial GatedDestroy: %v", err)
	}
	if refused.Approved {
		t.Fatal("test setup: gate approved before completions")
	}

	h.completeDependents(t)
	events = h.rebuildTenant(t)
	req := h.gateRequest(t, handle, events)
	approved, err := h.signer.GatedDestroy(h.ctx, req)
	if err != nil {
		t.Fatalf("approved GatedDestroy: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("gate refused after completions: %s", string(approved.RefusalRecord))
	}

	completion := h.completionEvidence()
	rec := h.signDestructionRecord(t, req, events, approved, completion)
	agg := h.signAggregateRecord(t, rec, events)
	return retireFlow{
		h:               h,
		handle:          handle,
		events:          events,
		requiredDigest:  req.RequiredSetDigest,
		destroyDecision: approved,
		record:          rec,
		aggregate:       agg,
		completion:      completion,
	}
}

func (h *harness) seedRegistered(t *testing.T) {
	t.Helper()
	for _, dep := range []depstate.Dependent{ciphertextDep, credentialDep, dataSetDep} {
		h.appendPayload(t, depstate.DependencyRegisteredV1{
			TenantID:  h.tenant,
			KeyID:     h.keyID,
			Dependent: dep,
			Origin:    depstate.RegistrationOriginIssued,
		})
	}
}

func (h *harness) completeDependents(t *testing.T) {
	t.Helper()
	state := h.fetchStateFromEvents(t)
	jobs, err := jobmodel.PlanFromState(state)
	if err != nil {
		t.Fatalf("PlanFromState: %v", err)
	}
	job := jobFor(t, jobs, ciphertextDep)
	h.appendPayload(t, depstate.ReprotectionCompletedV1{
		TenantID:       h.tenant,
		KeyID:          h.keyID,
		JobID:          job.ID,
		Dependent:      ciphertextDep,
		SuccessorKeyID: h.successorKeyID,
	})
	h.appendReleaseAndErasure(t)
}

func (h *harness) appendReleaseAndErasure(t *testing.T) {
	t.Helper()
	h.appendPayload(t, depstate.DependencyReleasedV1{
		TenantID:  h.tenant,
		KeyID:     h.keyID,
		Dependent: credentialDep,
		Reason:    "credential superseded before VDEC retirement",
	})
	h.appendPayload(t, depstate.DependencyErasureDesignatedV1{
		TenantID:       h.tenant,
		KeyID:          h.keyID,
		Dependent:      dataSetDep,
		DesignationRef: "erase://tenant-wire/dataset-erasure-1",
	})
}

func (h *harness) appendPayload(t *testing.T, p depstate.Payload) eventspec.Event {
	t.Helper()
	ev, err := depstate.Encode(p)
	if err != nil {
		t.Fatalf("encode depstate payload %T: %v", p, err)
	}
	appended, err := h.log.Append(h.ctx, ev)
	if err != nil {
		t.Fatalf("append event %s: %v", ev.Type, err)
	}
	return appended
}

func (h *harness) replayEvents(t *testing.T) []eventspec.Event {
	t.Helper()
	var out []eventspec.Event
	if err := h.log.Replay(h.ctx, 1, func(ev eventspec.Event) error {
		out = append(out, ev)
		return nil
	}); err != nil {
		t.Fatalf("event replay: %v", err)
	}
	return out
}

func (h *harness) rebuildTenant(t *testing.T) []eventspec.Event {
	t.Helper()
	events := h.replayEvents(t)
	if err := h.repo.RebuildTenant(h.ctx, h.tenant, events); err != nil {
		t.Fatalf("RebuildTenant: %v", err)
	}
	return events
}

func (h *harness) fetchStateFromEvents(t *testing.T) depstate.KeyState {
	t.Helper()
	proj, err := depstate.Fold(h.replayEvents(t))
	if err != nil {
		t.Fatalf("Fold: %v", err)
	}
	state, ok := proj.Lookup(h.tenant, h.keyID)
	if !ok {
		t.Fatalf("projection missing %s/%s", h.tenant, h.keyID)
	}
	return state
}

func (h *harness) fetchState(t *testing.T) depstate.KeyState {
	t.Helper()
	state, ok, err := h.repo.FetchKeyState(h.ctx, h.tenant, h.keyID)
	if err != nil || !ok {
		t.Fatalf("FetchKeyState: found=%v err=%v", ok, err)
	}
	return state
}

func (h *harness) gateRequest(t *testing.T, handle string, events []eventspec.Event) signing.GatedDestroyRequest {
	t.Helper()
	proj, err := depstate.Fold(events)
	if err != nil {
		t.Fatalf("Fold for gate request: %v", err)
	}
	state, ok := proj.Lookup(h.tenant, h.keyID)
	if !ok {
		t.Fatalf("projection missing %s/%s", h.tenant, h.keyID)
	}
	required, err := gate.RequiredSetBytes(state)
	if err != nil {
		t.Fatalf("RequiredSetBytes: %v", err)
	}
	requiredDigest, err := gate.RequiredSetDigest(state)
	if err != nil {
		t.Fatalf("RequiredSetDigest: %v", err)
	}
	segment, err := gate.EncodeLedgerSegment(finalEpochWire, events)
	if err != nil {
		t.Fatalf("EncodeLedgerSegment: %v", err)
	}
	return signing.GatedDestroyRequest{
		TenantID:             h.tenant,
		Handle:               handle,
		SubjectRef:           h.keyID,
		AssertedFinalEpoch:   finalEpochWire,
		LedgerPosition:       lastSeq(events),
		RequiredSet:          required,
		RequiredSetDigest:    requiredDigest,
		SatisfactionEvidence: segment,
		AuditChainHead:       gate.AuditChainHead(events),
	}
}

func (h *harness) generateSubjectHandle(t *testing.T) string {
	t.Helper()
	handle := "vdec-intwire:" + h.keyID
	if _, err := h.signer.GenerateKeyHandle(h.ctx, crypto.ECDSAP256, handle); err != nil {
		t.Fatalf("GenerateKeyHandle subject: %v", err)
	}
	return handle
}

func (h *harness) signDestructionRecord(t *testing.T, gateReq signing.GatedDestroyRequest, evs []eventspec.Event, decision signing.GatedDestroyDecision, completion vdecverify.CompletionEvidence) record.SignedRecord {
	t.Helper()
	successor, err := h.signer.GenerateKeyHandle(h.ctx, crypto.ECDSAP384, "vdec-intwire:"+h.successorKeyID)
	if err != nil {
		t.Fatalf("GenerateKeyHandle successor: %v", err)
	}
	completionDigest, err := vdecverify.CompletionEventsDigest(h.tenant, h.keyID, finalEpochWire, completion)
	if err != nil {
		t.Fatalf("CompletionEventsDigest: %v", err)
	}
	proofNode, err := vdecverify.EncodeProofNode(vdecverify.ProofRight, crypto.SHA256Sum([]byte("vdec-intwire-proof-sibling")))
	if err != nil {
		t.Fatalf("EncodeProofNode: %v", err)
	}
	destroyEvidence := destructionEvidence(h.tenant, h.keyID, decision)
	mint := record.MintRequest{
		TenantID:                    h.tenant,
		StableKeyID:                 h.keyID,
		FinalEpoch:                  finalEpochWire,
		CompletionEventsDigest:      completionDigest,
		RequiredSetDigest:           gateReq.RequiredSetDigest,
		DestructionEvidence:         record.EvidenceFromDestruction(destroyEvidence),
		AuditChainHead:              fmt.Sprintf("%x", gate.AuditChainHead(evs)),
		Successors:                  []record.SuccessorKey{{ID: h.successorKeyID, Epoch: finalEpochWire + 1, Algorithm: successor.Algorithm(), PublicDER: successor.Public().DER}},
		PolicyRef:                   "policy://vdec/intwire/retire-root-ca",
		PolicyDecisionDigest:        crypto.SHA256Sum([]byte("vdec-intwire-policy-decision")),
		RevocationCompletionDigest:  crypto.SHA256Sum([]byte("vdec-intwire-revocation-completions")),
		TransparencyLogID:           "vdec-intwire-transparency",
		TransparencyInclusionProof:  [][]byte{proofNode},
		TransparencyTreeSize:        2,
		TransparencyCheckpointEpoch: lastSeq(evs),
	}
	payload, err := json.Marshal(mint)
	if err != nil {
		t.Fatalf("marshal mint request: %v", err)
	}
	before := time.Now().UTC().Unix()
	sig, err := h.signer.SignArtifact(h.ctx, signing.ArtifactSignRequest{
		Kind:        signerwiring.ArtifactKindDestructionRecord,
		TenantID:    h.tenant,
		AuthorityID: "vdec-record-minter",
		Payload:     payload,
	})
	after := time.Now().UTC().Unix()
	if err != nil {
		t.Fatalf("SignArtifact destruction record: %v", err)
	}
	rec, err := reconstructDestructionRecord(mint, sig, before, after)
	if err != nil {
		t.Fatalf("reconstruct signer-minted destruction record: %v", err)
	}
	return rec
}

func (h *harness) signAggregateRecord(t *testing.T, rec record.SignedRecord, evs []eventspec.Event) aggregate.SignedRecord {
	t.Helper()
	mint := aggregate.MintRequest{
		TenantID:                h.tenant,
		Records:                 []aggregate.LeafInput{{KeyClass: "root-ca", Record: rec}},
		AuditChainHead:          rec.Commitment.AuditChainHead,
		InventoryLedgerPosition: lastSeq(evs),
		InventoryKeyIDs:         []string{h.keyID},
	}
	payload, err := json.Marshal(mint)
	if err != nil {
		t.Fatalf("marshal aggregate request: %v", err)
	}
	before := time.Now().UTC().Unix()
	sig, err := h.signer.SignArtifact(h.ctx, signing.ArtifactSignRequest{
		Kind:        signerwiring.ArtifactKindAggregateRecord,
		TenantID:    h.tenant,
		AuthorityID: "vdec-aggregate-minter",
		Payload:     payload,
	})
	after := time.Now().UTC().Unix()
	if err != nil {
		t.Fatalf("SignArtifact aggregate record: %v", err)
	}
	agg, err := reconstructAggregateRecord(mint, sig, rec, before, after)
	if err != nil {
		t.Fatalf("reconstruct signer-minted aggregate record: %v", err)
	}
	return agg
}

func reconstructDestructionRecord(req record.MintRequest, sig signing.ArtifactSignature, before, after int64) (record.SignedRecord, error) {
	for ts := before - 1; ts <= after+1; ts++ {
		c := record.Commitment{
			TenantID:                   req.TenantID,
			StableKeyID:                req.StableKeyID,
			FinalEpoch:                 req.FinalEpoch,
			CompletionEventsDigest:     cloneBytes(req.CompletionEventsDigest),
			RequiredSetDigest:          cloneBytes(req.RequiredSetDigest),
			QuorumEvidence:             req.QuorumEvidence,
			RevocationCompletionDigest: cloneBytes(req.RevocationCompletionDigest),
			DestructionEvidence:        req.DestructionEvidence,
			AuditChainHead:             req.AuditChainHead,
			Successors:                 append([]record.SuccessorKey(nil), req.Successors...),
			PolicyRef:                  req.PolicyRef,
			PolicyDecisionDigest:       cloneBytes(req.PolicyDecisionDigest),
			MintedAtUnix:               ts,
			Transparency: record.TransparencyProof{
				LogID:           req.TransparencyLogID,
				TreeSize:        req.TransparencyTreeSize,
				CheckpointEpoch: req.TransparencyCheckpointEpoch,
				RootDigest:      cloneBytes(req.TransparencyRootDigest),
				Proof:           clone2D(req.TransparencyInclusionProof),
			},
		}
		digest, err := record.CommitmentDigest(c)
		if err != nil {
			return record.SignedRecord{}, err
		}
		c.Transparency.LeafDigest = digest
		rec := record.SignedRecord{
			Version:                 record.SchemaV1,
			Type:                    record.TypeDestructionRecord,
			Commitment:              c,
			CommitmentDigest:        digest,
			SignerID:                "trstctl-signer",
			AttestationAlgorithm:    sig.Algorithm,
			AttestationPublicKeyDER: cloneBytes(sig.PublicKeyDER),
			Signature:               cloneBytes(sig.Signature),
		}
		if err := record.VerifyRecord(rec, publicKey(sig.Algorithm, sig.PublicKeyDER)); err == nil {
			return rec, nil
		}
	}
	return record.SignedRecord{}, errors.New("no timestamp in signer window verified against artifact signature")
}

func reconstructAggregateRecord(req aggregate.MintRequest, sig signing.ArtifactSignature, rec record.SignedRecord, before, after int64) (aggregate.SignedRecord, error) {
	vector, err := record.Vector(rec.Commitment.StableKeyID, rec)
	if err != nil {
		return aggregate.SignedRecord{}, err
	}
	leaf := aggregate.Leaf{
		TenantID:         rec.Commitment.TenantID,
		StableKeyID:      rec.Commitment.StableKeyID,
		FinalEpoch:       rec.Commitment.FinalEpoch,
		KeyClass:         "root-ca",
		RecordDigest:     cloneBytes(vector.EncodedRecordDigest),
		CommitmentDigest: cloneBytes(rec.CommitmentDigest),
	}
	root, err := aggregate.LeafRoot([]aggregate.Leaf{leaf})
	if err != nil {
		return aggregate.SignedRecord{}, err
	}
	inventoryDigest, err := aggregate.InventoryDigest(req.TenantID, req.InventoryLedgerPosition, req.InventoryKeyIDs)
	if err != nil {
		return aggregate.SignedRecord{}, err
	}
	for ts := before - 1; ts <= after+1; ts++ {
		c := aggregate.Commitment{
			TenantID:       req.TenantID,
			Leaves:         []aggregate.Leaf{leaf},
			LeafRoot:       root,
			KeyClassCounts: []aggregate.KeyClassCount{{KeyClass: "root-ca", Count: 1}},
			AuditChainHead: req.AuditChainHead,
			Inventory: aggregate.InventoryCompleteness{
				LedgerPosition: req.InventoryLedgerPosition,
				KeyCount:       1,
				Digest:         inventoryDigest,
				Exhausted:      true,
			},
			Campaign:               req.Campaign,
			SanitizationClaims:     append([]aggregate.SanitizationClaim(nil), req.SanitizationClaims...),
			GovernanceEvidenceRefs: append([]string(nil), req.GovernanceEvidenceRefs...),
			MintedAtUnix:           ts,
		}
		digest, err := aggregate.CommitmentDigest(c)
		if err != nil {
			return aggregate.SignedRecord{}, err
		}
		agg := aggregate.SignedRecord{
			Version:                 aggregate.SchemaV1,
			Type:                    aggregate.TypeAggregateRecord,
			Commitment:              c,
			CommitmentDigest:        digest,
			SignerID:                "trstctl-signer",
			AttestationAlgorithm:    sig.Algorithm,
			AttestationPublicKeyDER: cloneBytes(sig.PublicKeyDER),
			Signature:               cloneBytes(sig.Signature),
		}
		if err := aggregate.VerifyRecord(agg, publicKey(sig.Algorithm, sig.PublicKeyDER)); err == nil {
			return agg, nil
		}
	}
	return aggregate.SignedRecord{}, errors.New("no timestamp in signer window verified aggregate signature")
}

func destructionEvidence(tenantID, keyID string, decision signing.GatedDestroyDecision) gate.DestructionEvidence {
	body := struct {
		Kind                string `json:"kind"`
		TenantID            string `json:"tenant_id"`
		StableKeyID         string `json:"stable_key_id"`
		FinalEpoch          uint64 `json:"final_epoch"`
		GateEvidenceDigest  []byte `json:"gate_evidence_digest"`
		GateDecisionDigest  []byte `json:"gate_decision_digest"`
		SignerDestroyMethod string `json:"signer_destroy_method"`
	}{
		Kind:                gate.TypeCustodyZeroized,
		TenantID:            tenantID,
		StableKeyID:         keyID,
		FinalEpoch:          finalEpochWire,
		GateEvidenceDigest:  crypto.SHA256Sum(decision.Evidence),
		GateDecisionDigest:  crypto.SHA256Sum(decision.Authorization),
		SignerDestroyMethod: "signing.GatedDestroy over real trstctl-signer UDS",
	}
	raw, _ := json.Marshal(body)
	return gate.DestructionEvidence{
		Kind:               gate.TypeCustodyZeroized,
		TenantID:           tenantID,
		StableKeyID:        keyID,
		FinalEpoch:         finalEpochWire,
		AttestationClass:   gate.ClassSoftwareZeroize,
		AttestationClassID: gate.ClassSoftwareZeroize.ID(),
		Record:             raw,
		Digest:             crypto.SHA256Sum(raw),
	}
}

func (h *harness) completionEvidence() vdecverify.CompletionEvidence {
	return vdecverify.CompletionEvidence{
		Registered: []depstate.Dependent{ciphertextDep, credentialDep, dataSetDep},
		Completed:  []depstate.Dependent{ciphertextDep},
		Released:   []depstate.Dependent{credentialDep},
		Erased:     []depstate.Dependent{dataSetDep},
	}
}

func assertOfflineVerdict(t *testing.T, flow retireFlow) {
	t.Helper()
	head, err := vdecverify.HeadForRecord(flow.record)
	if err != nil {
		t.Fatalf("HeadForRecord: %v", err)
	}
	verdict, err := vdecverify.Verify(vdecverify.Request{
		Record:          flow.record,
		VerificationKey: publicKey(flow.record.AttestationAlgorithm, flow.record.AttestationPublicKeyDER),
		LogHead:         head,
		Retained:        vdecverify.RetainedEpoch{StableKeyID: flow.record.Commitment.StableKeyID, Epoch: finalEpochWire},
		Completion:      &flow.completion,
	})
	if err != nil {
		t.Fatalf("offline Verify: %v", err)
	}
	if verdict.Determination != vdecverify.DeterminationDestroyedAfterReprotection || !verdict.CompletionChecked {
		t.Fatalf("verdict = %+v, want destroyed-after-reprotection with completion accounting", verdict)
	}
}

func (h *harness) openEventLog(t *testing.T) {
	t.Helper()
	log, err := events.Open(h.ctx, config.NATS{
		Mode:       config.NATSEmbedded,
		StoreDir:   h.natsDir,
		SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open embedded NATS: %v", err)
	}
	h.log = log
}

func (h *harness) restartEventLog(t *testing.T) {
	t.Helper()
	if h.log != nil {
		if err := h.log.Close(); err != nil {
			t.Fatalf("close event log: %v", err)
		}
		h.log = nil
	}
	h.openEventLog(t)
}

func (h *harness) startSigner(t *testing.T) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "vdec-intwire-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	args := []string{"--keystore", h.keyDir, "--kek", h.kekFile}
	if runtime.GOOS != "linux" {
		args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
	}
	client, stop, err := signing.StartChild(h.ctx, h.bin, filepath.Join(socketDir, "s.sock"), args...)
	if err != nil {
		t.Fatalf("StartChild signer: %v", err)
	}
	h.signer = client
	h.stopSign = stop
}

func (h *harness) restartSigner(t *testing.T) {
	t.Helper()
	if h.signer != nil {
		_ = h.signer.Close()
	}
	if h.stopSign != nil {
		h.stopSign()
	}
	h.startSigner(t)
}

func buildSignerBinary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer")
	cmd.Dir = root
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func startPostgres(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	inst := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(filepath.Join(dir, "rt")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := inst.Start(); err != nil {
		t.Fatalf("embedded PostgreSQL unavailable, but this is a real-infra WIRE GATE that must FAIL (not skip) when its substrate is absent (TEST-NOSKIP-001): %v", err)
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port), func() {
		_ = inst.Stop()
	}
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func jobFor(t *testing.T, jobs []jobmodel.Job, dep depstate.Dependent) jobmodel.Job {
	t.Helper()
	for _, job := range jobs {
		if job.Dependent == dep {
			return job
		}
	}
	t.Fatalf("no job for dependent %+v in %+v", dep, jobs)
	return jobmodel.Job{}
}

func lastSeq(events []eventspec.Event) uint64 {
	var last uint64
	for i, ev := range events {
		seq := ev.Sequence
		if seq == 0 {
			seq = uint64(i + 1)
		}
		if seq > last {
			last = seq
		}
	}
	return last
}

func publicKey(alg crypto.Algorithm, der []byte) crypto.PublicKey {
	return crypto.PublicKey{Algorithm: alg, DER: cloneBytes(der)}
}

func hasDependent(deps []depstate.Dependent, want depstate.Dependent) bool {
	for _, dep := range deps {
		if dep == want {
			return true
		}
	}
	return false
}

func cloneBytes(in []byte) []byte {
	return append([]byte(nil), in...)
}

func clone2D(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}
