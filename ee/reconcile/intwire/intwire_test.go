// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package intwire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	xrecplan "trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/ee/reconcile/plan/remediation"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	xrecverify "trstctl.com/trstctl/ee/reconcile/verify"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantWire        = "66666666-6666-6666-6666-666666666666"
	leftAuthority     = "vault-prod"
	rightAuthority    = "cloudkms-prod"
	planAuthority     = "operator-plan-authority"
	planKeyID         = "xrec-intwire-plan-key"
	remediationOp     = "revoke"
	specVersion       = canon.SpecVersionV1
	initialRoundID    = "xrec-wire-round-1"
	completionRoundID = "xrec-wire-round-2"
)

func TestXREC_Wire_ReconcileWitnessOffline_RealInfra(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.reconcile(t)

	if flow.recorded.WitnessID != flow.evidence.Body.WitnessID {
		t.Fatalf("recorded witness = %q, want %q", flow.recorded.WitnessID, flow.evidence.Body.WitnessID)
	}
	if !hasDetermination(flow.result, witness.ClassPresence) {
		t.Fatalf("determinations = %+v, want a presence divergence", flow.result.Determinations)
	}
	if !hasDetermination(flow.result, witness.ClassPolicyViolation) {
		t.Fatalf("determinations = %+v, want a policy violation for quarantine", flow.result.Determinations)
	}
	if flow.result.AuthorityContacted {
		t.Fatal("offline verifier reported an authority contact")
	}
	if len(flow.completion.Released) != 1 {
		t.Fatalf("released records = %d, want one quarantined authority release", len(flow.completion.Released))
	}
	var completed quarantine.Completed
	decodeEvent(t, flow.completion.Event, &completed)
	if err := quarantine.VerifyCompletionChain(flow.evidence, flow.plan, completed); err != nil {
		t.Fatalf("VerifyCompletionChain: %v", err)
	}
}

func TestXREC_Wire_SystemDetectsDivergence_RealInfra(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.recordDivergence(t)

	if !hasWitnessEntry(flow.evidence, witness.ClassPresence) {
		t.Fatalf("witness entries = %+v, want a presence divergence", flow.evidence.Body.Entries)
	}
	if !hasWitnessEntry(flow.evidence, witness.ClassPolicyViolation) {
		t.Fatalf("witness entries = %+v, want a policy violation", flow.evidence.Body.Entries)
	}
	events := h.replayEvents(t)
	if countEvents(events, witness.EventTypeWitnessRecorded) != 1 {
		t.Fatalf("witness recorded events = %d, want 1", countEvents(events, witness.EventTypeWitnessRecorded))
	}
	if countEvents(events, quarantine.EventTypeEntered) != 1 {
		t.Fatalf("quarantine entered events = %d, want 1", countEvents(events, quarantine.EventTypeEntered))
	}
	rec, ok := h.quarantineState.Lookup(h.tenant, leftAuthority)
	if !ok || !rec.Open || rec.WitnessID != flow.evidence.Body.WitnessID {
		t.Fatalf("quarantine state = (%+v,%v), want open witness %q", rec, ok, flow.evidence.Body.WitnessID)
	}
}

func TestXREC_Wire_VerifierAcceptsWitnessOffline(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.recordDivergence(t)

	got, err := xrecverify.Verify(h.ctx, xrecverify.Request{
		Evidence:           flow.evidence,
		Digests:            flow.initialDigests,
		TrustedDigestKeys:  flow.digestTrust,
		TrustedWitnessKeys: flow.witnessTrust,
		Policy: xrecverify.Policy{
			VerifierAuthority: rightAuthority,
			Now:               time.Unix(flow.generatedAt+1, 0).UTC(),
			FreshnessBound:    time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.AuthorityContacted {
		t.Fatal("verifier contacted an authority")
	}
	if got.WitnessID != flow.evidence.Body.WitnessID || len(got.DigestWatermarks) != 2 {
		t.Fatalf("verify result = %+v", got)
	}
}

func TestXREC_Wire_PlanVerifiedInRealSigner(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.reconcile(t)

	if !flow.decision.Approved || len(flow.decision.Authorization) == 0 {
		t.Fatalf("signer decision = %+v, want approved with authorization", flow.decision)
	}
	if flow.authorization.AuthorityID != leftAuthority || flow.authorization.Operation != remediationOp {
		t.Fatalf("authorization = %+v, want %s/%s", flow.authorization, leftAuthority, remediationOp)
	}
	if !flow.authorization.Inserted || !flow.authorization.OutboxInserted {
		t.Fatalf("authorization insert flags = (%v,%v), want both true", flow.authorization.Inserted, flow.authorization.OutboxInserted)
	}
	if got := h.connector.Count(); got != 1 {
		t.Fatalf("connector executions = %d, want 1", got)
	}
	if got := h.countRows(t, `SELECT count(*) FROM xrec_remediation_receipts WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND status = 'delivered'`); got != 1 {
		t.Fatalf("delivered receipts = %d, want 1", got)
	}
}

func TestXREC_Restart_WatermarkSurvives(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.recordDivergence(t)

	h.restartEventLog(t)
	var replayed witness.WitnessRecorded
	for _, ev := range h.replayEvents(t) {
		if ev.Type == witness.EventTypeWitnessRecorded {
			decodeEvent(t, ev, &replayed)
		}
	}
	if replayed.WitnessID == "" {
		t.Fatal("replayed event log did not include the recorded witness")
	}
	watermarks := map[string]digest.Watermark{}
	for _, ref := range replayed.Evidence.Body.DigestRefs {
		watermarks[ref.AuthorityID] = ref.Watermark
	}
	for _, sd := range flow.initialDigests {
		got, ok := watermarks[sd.Body.AuthorityID]
		if !ok || got.Position != sd.Body.Watermark.Position || got.ObservedAt != sd.Body.Watermark.ObservedAt {
			t.Fatalf("replayed watermark for %s = %+v (ok=%v), want %+v", sd.Body.AuthorityID, got, ok, sd.Body.Watermark)
		}
	}
}

func TestXREC_Restart_OutboxNoDoubleExecute(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.authorizePlan(t)

	h.restartControlPlane(t)
	h.drain(t)
	if got := h.connector.Count(); got != 1 {
		t.Fatalf("executions after first restart drain = %d, want 1", got)
	}
	h.restartControlPlane(t)
	h.drain(t)
	if got := h.connector.Count(); got != 1 {
		t.Fatalf("executions after second restart drain = %d, want 1", got)
	}
	if got := h.countRows(t, `SELECT count(*) FROM xrec_remediation_authorizations WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND idempotency_key = $1`, flow.authorization.IdempotencyKey); got != 1 {
		t.Fatalf("authorization rows = %d, want 1", got)
	}
}

func TestXREC_Restart_OpenWitnessResumes(t *testing.T) {
	h := newHarness(t, tenantWire)
	flow := h.authorizePlan(t)

	h.restartEventLog(t)
	before := h.replayDrift(t)
	if before.OpenWitnesses != 1 {
		t.Fatalf("open witnesses after restart replay = %d, want 1", before.OpenWitnesses)
	}
	flow = h.completeReconciliation(t, flow)
	after := h.replayDrift(t)
	if after.OpenWitnesses != 0 {
		t.Fatalf("open witnesses after completion replay = %d, want 0", after.OpenWitnesses)
	}
	if len(after.CompletionDurations) != 1 || after.CompletionDurations[0].WitnessID != flow.evidence.Body.WitnessID {
		t.Fatalf("completion durations = %+v, want completed witness %q", after.CompletionDurations, flow.evidence.Body.WitnessID)
	}
}

type harness struct {
	ctx context.Context

	tenant string
	store  *corestore.Store
	log    *events.Log

	natsDir  string
	outbox   *orchestrator.Outbox
	recorder *witness.Recorder

	quarantineState *quarantine.MemoryState
	quarantineMgr   *quarantine.Manager
	remediationMgr  *remediation.Manager

	client   *signing.Client
	stopSign func()
	bin      string
	keystore string
	kekFile  string

	planKey   *crypto.LockedSigner
	connector *recordingConnector
}

type flowState struct {
	generatedAt int64

	initialPlanes    []planeState
	initialDigests   []digest.SignedDigest
	completedPlanes  []planeState
	completedDigests []digest.SignedDigest

	digestTrust  map[string]crypto.PublicKey
	witnessTrust map[string]crypto.PublicKey

	evidence witness.Evidence
	recorded witness.WitnessRecorded
	result   xrecverify.Result

	action        xrecplan.Action
	plan          xrecplan.SignedPlan
	decision      signing.OperationDecision
	authorization remediation.AuthorizationRecord
	completion    quarantine.CompletionDecision
}

type planeState struct {
	authorityID string
	set         canon.Set
	tree        *digest.Tree
	signed      digest.SignedDigest
}

func newHarness(t *testing.T, tenant string) *harness {
	t.Helper()
	ctx := context.Background()
	dsn, stopPG := startPostgres(t)
	t.Cleanup(stopPG)

	dbName := fmt.Sprintf("xrec_intwire_%d", time.Now().UTC().UnixNano())
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	_ = admin.Close(ctx)

	dbDSN := strings.TrimSuffix(dsn, "/postgres") + "/" + dbName
	st, err := corestore.Open(ctx, dbDSN)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	t.Cleanup(st.Close)
	st.WithExtraMigrations(remediation.MigrationsFS())
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	planKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey(plan): %v", err)
	}
	t.Cleanup(planKey.Destroy)

	h := &harness{
		ctx:       ctx,
		tenant:    tenant,
		store:     st,
		natsDir:   filepath.Join(t.TempDir(), "nats"),
		bin:       buildSignerBinary(t),
		keystore:  filepath.Join(t.TempDir(), "keystore"),
		kekFile:   filepath.Join(t.TempDir(), "signer.kek"),
		planKey:   planKey,
		connector: newRecordingConnector(leftAuthority),
	}
	if err := xrecplan.WriteTrustBundle(h.keystore, xrecplan.TrustBundle{
		PlanKeys: []xrecplan.TrustedKey{{
			KeyID:        planKeyID,
			Algorithm:    planKey.Public().Algorithm,
			PublicKeyDER: planKey.Public().DER,
		}},
	}); err != nil {
		t.Fatalf("WriteTrustBundle: %v", err)
	}
	h.openEventLog(t)
	h.startSigner(t)
	h.restartControlPlane(t)
	t.Cleanup(func() {
		if h.stopSign != nil {
			h.stopSign()
		}
		if h.log != nil {
			_ = h.log.Close()
			h.log = nil
		}
	})
	return h
}

func (h *harness) recordDivergence(t *testing.T) flowState {
	t.Helper()
	generatedAt := time.Now().UTC().Unix()
	left := h.buildPlane(t, leftAuthority, initialObserved(h.tenant, leftAuthority), "vault-wm-1", generatedAt)
	right := h.buildPlane(t, rightAuthority, initialObserved(h.tenant, rightAuthority), "kms-wm-1", generatedAt)
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     initialRoundID,
		TenantID:    h.tenant,
		SpecVersion: specVersion,
		Left:        witnessPlane(left),
		Right:       witnessPlane(right),
		GeneratedAt: generatedAt,
		PolicyViolations: []witness.PolicyViolation{{
			AuthorityID:   leftAuthority,
			RecordKey:     betaRecordKey(h.tenant),
			RuleID:        "xrec-wire-policy-active",
			PolicySetHash: crypto.SHA256Sum([]byte("xrec-wire-policy")),
		}},
	})
	if err != nil {
		t.Fatalf("witness.Build: %v", err)
	}
	signed, err := witness.Sign(h.ctx, h.client, body, "")
	if err != nil {
		t.Fatalf("witness.Sign(real signer): %v", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(signed)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	initialDigests := []digest.SignedDigest{left.signed, right.signed}
	flow := flowState{
		generatedAt:    generatedAt,
		initialPlanes:  []planeState{left, right},
		initialDigests: initialDigests,
		digestTrust:    digestTrust(initialDigests),
		witnessTrust: map[string]crypto.PublicKey{
			signed.KeyID: {Algorithm: signed.Algorithm, DER: append([]byte(nil), signed.PublicKeyDER...)},
		},
		evidence: evidence,
	}
	result, err := xrecverify.Verify(h.ctx, xrecverify.Request{
		Evidence:           evidence,
		Digests:            initialDigests,
		TrustedDigestKeys:  flow.digestTrust,
		TrustedWitnessKeys: flow.witnessTrust,
		Policy: xrecverify.Policy{
			VerifierAuthority: rightAuthority,
			Now:               time.Unix(generatedAt+1, 0).UTC(),
			FreshnessBound:    time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("offline Verify: %v", err)
	}
	flow.result = result
	ev, err := h.recorder.RecordWitness(h.ctx, "record:"+evidence.Body.WitnessID, evidence)
	if err != nil {
		t.Fatalf("RecordWitness: %v", err)
	}
	decodeEvent(t, ev, &flow.recorded)
	if _, err := h.quarantineMgr.ObserveWitness(h.ctx, "quarantine:"+evidence.Body.WitnessID, evidence); err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}
	return flow
}

func (h *harness) authorizePlan(t *testing.T) flowState {
	t.Helper()
	flow := h.recordDivergence(t)
	action := xrecplan.Action{
		AuthorityID: leftAuthority,
		RecordKey:   betaRecordKey(h.tenant),
		Operation:   remediationOp,
		Parameters:  map[string]string{"source": rightAuthority},
	}
	p := xrecplan.Plan{
		PlanID:      "plan-" + flow.evidence.Body.WitnessID,
		TenantID:    h.tenant,
		WitnessID:   flow.evidence.Body.WitnessID,
		WitnessHash: flow.evidence.ContentHash(),
		Actions:     []xrecplan.Action{action},
		GeneratedAt: time.Now().UTC().Unix(),
	}
	signedPlan, err := xrecplan.Sign(h.ctx, h.planKey, p, planAuthority, planKeyID, p.GeneratedAt)
	if err != nil {
		t.Fatalf("plan.Sign: %v", err)
	}
	preconditions, err := xrecplan.EncodeSignedPlan(signedPlan)
	if err != nil {
		t.Fatalf("EncodeSignedPlan: %v", err)
	}
	evidence, err := xrecplan.EncodeVerificationEnvelope(xrecplan.VerificationEnvelope{Recorded: flow.recorded})
	if err != nil {
		t.Fatalf("EncodeVerificationEnvelope: %v", err)
	}
	decision, err := h.client.VerifyOperation(h.ctx, signing.OperationRequest{
		TenantID:       h.tenant,
		Operation:      remediationOp,
		SubjectRef:     xrecplan.RecordKeyRef(action.RecordKey),
		IdempotencyKey: "xrec-plan:" + flow.evidence.Body.WitnessID,
		Preconditions:  preconditions,
		Evidence:       evidence,
	})
	if err != nil {
		t.Fatalf("VerifyOperation(real signer): %v", err)
	}
	if !decision.Approved {
		t.Fatalf("VerifyOperation refused: %s", string(decision.RefusalRecord))
	}
	auth, err := h.remediationMgr.Authorize(h.ctx, remediation.AuthorizationRequest{
		TenantID:   h.tenant,
		SignedPlan: signedPlan,
		Action:     action,
		Decision:   decision,
	})
	if err != nil {
		t.Fatalf("remediation.Authorize: %v", err)
	}
	flow.action = action
	flow.plan = signedPlan
	flow.decision = decision
	flow.authorization = auth
	return flow
}

func (h *harness) reconcile(t *testing.T) flowState {
	t.Helper()
	flow := h.authorizePlan(t)
	return h.completeReconciliation(t, flow)
}

func (h *harness) completeReconciliation(t *testing.T, flow flowState) flowState {
	t.Helper()
	h.drain(t)

	generatedAt := time.Now().UTC().Unix()
	left := h.buildPlane(t, leftAuthority, completedObserved(h.tenant, leftAuthority), "vault-wm-2", generatedAt)
	right := h.buildPlane(t, rightAuthority, completedObserved(h.tenant, rightAuthority), "kms-wm-2", generatedAt)
	records := h.completionRecords(t, []planeState{left, right})
	decision, err := h.quarantineMgr.Complete(h.ctx, quarantine.CompletionRequest{
		IdempotencyKey:    "completion:" + flow.evidence.Body.WitnessID,
		Witness:           flow.evidence,
		Plan:              flow.plan,
		CompletingRoundID: completionRoundID,
		CompletingDigests: []digest.SignedDigest{left.signed, right.signed},
		Records:           records,
	})
	if err != nil {
		t.Fatalf("quarantine.Complete: %v", err)
	}
	flow.completedPlanes = []planeState{left, right}
	flow.completedDigests = []digest.SignedDigest{left.signed, right.signed}
	flow.completion = decision
	return flow
}

func (h *harness) buildPlane(t *testing.T, authorityID string, observed []canon.ObservedRecord, watermark string, generatedAt int64) planeState {
	t.Helper()
	set, err := canon.ReduceTenant(specVersion, h.tenant, observed)
	if err != nil {
		t.Fatalf("ReduceTenant(%s): %v", authorityID, err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Watermark: digest.Watermark{
			Position:   watermark,
			ObservedAt: generatedAt,
		},
		GeneratedAt: generatedAt,
	})
	if err != nil {
		t.Fatalf("digest.Build(%s): %v", authorityID, err)
	}
	signed, err := digest.Sign(h.ctx, h.client, built.Body, "")
	if err != nil {
		t.Fatalf("digest.Sign(%s real signer): %v", authorityID, err)
	}
	return planeState{authorityID: authorityID, set: set, tree: built.Tree, signed: signed}
}

func (h *harness) completionRecords(t *testing.T, planes []planeState) []quarantine.CompletedRecordProof {
	t.Helper()
	key := betaRecordKey(h.tenant)
	keyBytes, err := digest.RecordKeyBytes(key)
	if err != nil {
		t.Fatalf("RecordKeyBytes: %v", err)
	}
	out := quarantine.CompletedRecordProof{RecordKey: key}
	for _, plane := range planes {
		proof, ok := plane.tree.InclusionProof(keyBytes)
		if !ok {
			t.Fatalf("%s missing completion inclusion proof for beta record", plane.authorityID)
		}
		out.Proofs = append(out.Proofs, quarantine.CompletedProof{
			AuthorityID: plane.authorityID,
			Proof:       witnessProof(proof),
		})
	}
	return []quarantine.CompletedRecordProof{out}
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
	h.restartControlPlane(t)
}

func (h *harness) restartControlPlane(t *testing.T) {
	t.Helper()
	h.outbox = newTestOutbox(h.store)
	h.recorder = witness.NewRecorder(h.log, orchestrator.NewIdempotency(h.store))
	h.quarantineState = quarantine.NewMemoryState()
	h.quarantineMgr = quarantine.NewManager(quarantine.Options{
		Log:         h.log,
		Idempotency: orchestrator.NewIdempotency(h.store),
		State:       h.quarantineState,
	})
	mgr, err := remediation.NewManager(h.store, h.outbox)
	if err != nil {
		t.Fatalf("remediation.NewManager: %v", err)
	}
	h.remediationMgr = mgr
}

func (h *harness) startSigner(t *testing.T) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "xrec-intwire-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	args := []string{"--keystore", h.keystore, "--kek", h.kekFile}
	if runtime.GOOS != "linux" {
		args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
	}
	client, stop, err := signing.StartChild(h.ctx, h.bin, filepath.Join(socketDir, "s.sock"), args...)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	h.client = client
	h.stopSign = stop
}

func (h *harness) drain(t *testing.T) {
	t.Helper()
	registry := remediation.NewRegistry(remediation.NewStoreReceiptRecorder(h.store))
	registry.Register(h.connector)
	handler := remediation.NewHandler(registry)
	for i := 0; i < 10; i++ {
		n, err := h.outbox.Dispatch(h.ctx, handler)
		if err != nil {
			t.Fatalf("outbox Dispatch: %v", err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("outbox did not drain within 10 passes")
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

func (h *harness) replayDrift(t *testing.T) rounds.DriftSnapshot {
	t.Helper()
	projection := rounds.NewDriftProjection(time.Hour)
	if err := h.log.Replay(h.ctx, 1, func(ev eventspec.Event) error {
		return projection.Apply(ev)
	}); err != nil {
		t.Fatalf("drift replay: %v", err)
	}
	return projection.Snapshot()
}

func (h *harness) countRows(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	err := h.store.WithTenant(h.ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("countRows: %v", err)
	}
	return n
}

type recordingConnector struct {
	name  string
	grant remediation.OperationGrant

	mu    sync.Mutex
	count int
	keys  map[string]bool
}

func newRecordingConnector(name string) *recordingConnector {
	return &recordingConnector{
		name:  name,
		grant: remediation.NewOperationGrant(remediationOp),
		keys:  map[string]bool{},
	}
}

func (c *recordingConnector) Name() string { return c.name }

func (c *recordingConnector) OperationGrant() remediation.OperationGrant { return c.grant }

func (c *recordingConnector) ExecuteRemediationAction(_ context.Context, req remediation.RemediationRequest) (string, error) {
	if len(req.Authorization) == 0 || req.IdempotencyKey == "" {
		return "", errors.New("missing signer authorization")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.keys[req.IdempotencyKey] {
		c.keys[req.IdempotencyKey] = true
		c.count++
	}
	return "recorded corrective sync", nil
}

func (c *recordingConnector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func initialObserved(tenantID, authorityID string) []canon.ObservedRecord {
	records := []canon.ObservedRecord{
		keyRecord(tenantID, authorityID, "key-alpha", "alpha-native"),
		keyRecord(tenantID, authorityID, "key-common", "common-native"),
	}
	if authorityID == leftAuthority {
		records = append(records, keyRecord(tenantID, authorityID, "key-beta", "beta-native"))
	}
	return records
}

func completedObserved(tenantID, authorityID string) []canon.ObservedRecord {
	return []canon.ObservedRecord{
		keyRecord(tenantID, authorityID, "key-alpha", "alpha-native"),
		keyRecord(tenantID, authorityID, "key-beta", "beta-native"),
		keyRecord(tenantID, authorityID, "key-common", "common-native"),
	}
}

func keyRecord(tenantID, authorityID, stableID, nativeID string) canon.ObservedRecord {
	created := time.Unix(1_700_000_000, 0).UTC()
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeKey,
		StableID:   stableID,
		Key:        &canon.KeyIdentity{LogicalID: stableID},
		Algorithm:  "ed25519",
		Status:     canon.StatusActive,
		Validity:   canon.ValidityInput{CreatedAt: &created},
		Provenance: canon.Provenance{
			AuthorityID: authorityID,
			NativeID:    nativeID,
		},
		Attributes: map[string]canon.Value{
			"rotation_window": canon.String("30d"),
			"managed":         canon.Bool(true),
		},
	}
}

func betaRecordKey(tenantID string) canon.RecordKey {
	return canon.RecordKey{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeKey,
		StableID:   "key-beta",
	}
}

func witnessPlane(p planeState) witness.PlaneState {
	return witness.PlaneState{
		AuthorityID: p.authorityID,
		Set:         p.set,
		Tree:        p.tree,
		Digest:      p.signed,
	}
}

func digestTrust(signed []digest.SignedDigest) map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, sd := range signed {
		out[sd.KeyID] = crypto.PublicKey{Algorithm: sd.Algorithm, DER: append([]byte(nil), sd.PublicKeyDER...)}
	}
	return out
}

func witnessProof(p digest.InclusionProof) witness.InclusionProof {
	nodes := make([]witness.ProofNode, len(p.Siblings))
	for i, n := range p.Siblings {
		nodes[i] = witness.ProofNode{Hash: append([]byte(nil), n.Hash...), Left: n.Left}
	}
	return witness.InclusionProof{
		RecordKeyBytes:       append([]byte(nil), p.RecordKeyBytes...),
		CanonicalRecordBytes: append([]byte(nil), p.CanonicalRecordBytes...),
		Siblings:             nodes,
	}
}

func decodeEvent(t *testing.T, ev eventspec.Event, out any) {
	t.Helper()
	if err := json.Unmarshal(ev.Data, out); err != nil {
		t.Fatalf("decode event %s: %v", ev.Type, err)
	}
}

func countEvents(events []eventspec.Event, typ string) int {
	n := 0
	for _, ev := range events {
		if ev.Type == typ {
			n++
		}
	}
	return n
}

func hasDetermination(result xrecverify.Result, class string) bool {
	for _, det := range result.Determinations {
		if det.Class == class {
			return true
		}
	}
	return false
}

func hasWitnessEntry(evidence witness.Evidence, class string) bool {
	for _, entry := range evidence.Body.Entries {
		if entry.Class == class {
			return true
		}
	}
	return false
}

func newTestOutbox(st *corestore.Store) *orchestrator.Outbox {
	return orchestrator.NewOutbox(st,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithMaxAttempts(3),
		orchestrator.WithWorkerID("xrec-intwire"),
	)
}

func buildSignerBinary(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer")
	cmd.Dir = root
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
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
