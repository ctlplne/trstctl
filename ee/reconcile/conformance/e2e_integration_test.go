// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package conformance

import (
	"context"
	"encoding/json"
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

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	xrecplan "trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/ee/reconcile/plan/remediation"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
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
	e2eTenant         = "77777777-7777-7777-7777-777777777777"
	e2eVault          = "vault-prod"
	e2eKMS            = "cloudkms-prod"
	e2eSelf           = "trstctl-self"
	e2ePlanAuthority  = "operator-plan-authority"
	e2ePlanKeyID      = "xrec-release-plan-key"
	e2eOperation      = "revoke"
	e2eRecordStableID = "cert-revoked"
)

func TestE2E_ReconcileOfflineChain(t *testing.T) {
	h := newE2EHarness(t)
	generatedAt := time.Now().UTC().Unix()
	vault := h.buildX509Plane(t, e2eVault, canon.StatusActive, "vault-wm-1", generatedAt)
	kms := h.buildX509Plane(t, e2eKMS, canon.StatusRevoked, "kms-wm-1", generatedAt)
	self := h.buildX509Plane(t, e2eSelf, canon.StatusRevoked, "self-wm-1", generatedAt)

	majority, err := witness.ClassifyMajority(witness.MajorityRequest{
		TenantID:    h.tenant,
		SpecVersion: canon.SpecVersionV1,
		Planes: []witness.PlaneState{
			e2eWitnessPlane(vault),
			e2eWitnessPlane(kms),
			e2eWitnessPlane(self),
		},
	})
	if err != nil {
		t.Fatalf("ClassifyMajority: %v", err)
	}
	if len(majority.Entries) != 1 || len(majority.Entries[0].MinorityAuthorityIDs) != 1 || majority.Entries[0].MinorityAuthorityIDs[0] != e2eVault {
		t.Fatalf("majority = %+v, want vault minority against two revoked planes", majority)
	}

	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "xrec-release-round-1",
		TenantID:    h.tenant,
		SpecVersion: canon.SpecVersionV1,
		Left:        e2eWitnessPlane(vault),
		Right:       e2eWitnessPlane(self),
		GeneratedAt: generatedAt,
	})
	if err != nil {
		t.Fatalf("witness.Build: %v", err)
	}
	signedWitness, err := witness.Sign(h.ctx, h.client, body, "")
	if err != nil {
		t.Fatalf("witness.Sign(real signer): %v", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(signedWitness)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	initialDigests := []digest.SignedDigest{vault.signed, self.signed}
	digestTrust := e2eDigestTrust(initialDigests)
	witnessTrust := map[string]crypto.PublicKey{
		signedWitness.KeyID: {Algorithm: signedWitness.Algorithm, DER: append([]byte(nil), signedWitness.PublicKeyDER...)},
	}
	verified, err := xrecverify.Verify(h.ctx, xrecverify.Request{
		Evidence:           evidence,
		Digests:            initialDigests,
		TrustedDigestKeys:  digestTrust,
		TrustedWitnessKeys: witnessTrust,
		Policy: xrecverify.Policy{
			VerifierAuthority: e2eSelf,
			Now:               time.Unix(generatedAt+1, 0).UTC(),
			FreshnessBound:    time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("offline Verify: %v", err)
	}
	if len(verified.Determinations) != 1 || verified.Determinations[0].Class != witness.ClassAttributeConflict {
		t.Fatalf("offline verifier determinations = %+v, want one attribute conflict", verified.Determinations)
	}

	ev, err := h.recorder.RecordWitness(h.ctx, "release-record:"+evidence.Body.WitnessID, evidence)
	if err != nil {
		t.Fatalf("RecordWitness: %v", err)
	}
	var recorded witness.WitnessRecorded
	decodeConformanceEvent(t, ev, &recorded)
	q, err := h.quarantineMgr.ObserveWitness(h.ctx, "release-quarantine:"+evidence.Body.WitnessID, evidence)
	if err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}
	if !q.Entered || q.AuthorityID != e2eVault {
		t.Fatalf("quarantine = %+v, want vault quarantined", q)
	}

	action := xrecplan.Action{AuthorityID: e2eVault, RecordKey: e2eRecordKey(h.tenant), Operation: e2eOperation}
	plan := xrecplan.Plan{
		PlanID:      "plan-" + evidence.Body.WitnessID,
		TenantID:    h.tenant,
		WitnessID:   evidence.Body.WitnessID,
		WitnessHash: evidence.ContentHash(),
		Actions:     []xrecplan.Action{action},
		GeneratedAt: time.Now().UTC().Unix(),
	}
	signedPlan, err := xrecplan.Sign(h.ctx, h.planKey, plan, e2ePlanAuthority, e2ePlanKeyID, plan.GeneratedAt)
	if err != nil {
		t.Fatalf("plan.Sign: %v", err)
	}
	preconditions, err := xrecplan.EncodeSignedPlan(signedPlan)
	if err != nil {
		t.Fatalf("EncodeSignedPlan: %v", err)
	}
	envelope, err := xrecplan.EncodeVerificationEnvelope(xrecplan.VerificationEnvelope{Recorded: recorded})
	if err != nil {
		t.Fatalf("EncodeVerificationEnvelope: %v", err)
	}
	decision, err := h.client.VerifyOperation(h.ctx, signing.OperationRequest{
		TenantID:       h.tenant,
		Operation:      e2eOperation,
		SubjectRef:     xrecplan.RecordKeyRef(action.RecordKey),
		IdempotencyKey: "release-plan:" + evidence.Body.WitnessID,
		Preconditions:  preconditions,
		Evidence:       envelope,
	})
	if err != nil {
		t.Fatalf("VerifyOperation(real signer): %v", err)
	}
	if !decision.Approved {
		t.Fatalf("plan refused by real signer: %s", string(decision.RefusalRecord))
	}
	if _, err := h.remediationMgr.Authorize(h.ctx, remediation.AuthorizationRequest{
		TenantID:   h.tenant,
		SignedPlan: signedPlan,
		Action:     action,
		Decision:   decision,
	}); err != nil {
		t.Fatalf("remediation.Authorize: %v", err)
	}
	h.drain(t)
	if got := h.connector.Count(); got != 1 {
		t.Fatalf("remediation connector executions = %d, want 1", got)
	}

	completedAt := time.Now().UTC().Unix()
	doneVault := h.buildX509Plane(t, e2eVault, canon.StatusRevoked, "vault-wm-2", completedAt)
	doneKMS := h.buildX509Plane(t, e2eKMS, canon.StatusRevoked, "kms-wm-2", completedAt)
	doneSelf := h.buildX509Plane(t, e2eSelf, canon.StatusRevoked, "self-wm-2", completedAt)
	completion, err := h.quarantineMgr.Complete(h.ctx, quarantine.CompletionRequest{
		IdempotencyKey:    "release-complete:" + evidence.Body.WitnessID,
		Witness:           evidence,
		Plan:              signedPlan,
		CompletingRoundID: "xrec-release-round-2",
		CompletingDigests: []digest.SignedDigest{doneVault.signed, doneKMS.signed, doneSelf.signed},
		Records:           h.completionRecords(t, []e2ePlaneState{doneVault, doneKMS, doneSelf}),
	})
	if err != nil {
		t.Fatalf("quarantine.Complete: %v", err)
	}
	if len(completion.Released) != 1 {
		t.Fatalf("completion released = %+v, want one vault release", completion.Released)
	}
	var completed quarantine.Completed
	decodeConformanceEvent(t, completion.Event, &completed)
	if err := quarantine.VerifyCompletionChain(evidence, signedPlan, completed); err != nil {
		t.Fatalf("VerifyCompletionChain: %v", err)
	}
	if count := countEventsOfType(t, h.log, quarantine.EventTypeCompleted); count != 1 {
		t.Fatalf("completion events = %d, want 1", count)
	}
}

type e2eHarness struct {
	ctx context.Context

	tenant string
	store  *corestore.Store
	log    *events.Log
	outbox *orchestrator.Outbox

	recorder       *witness.Recorder
	quarantineMgr  *quarantine.Manager
	remediationMgr *remediation.Manager

	client    *signing.Client
	stopSign  func()
	planKey   *crypto.LockedSigner
	connector *e2eConnector
}

type e2ePlaneState struct {
	authorityID string
	set         canon.Set
	tree        *digest.Tree
	signed      digest.SignedDigest
}

func newE2EHarness(t *testing.T) *e2eHarness {
	t.Helper()
	ctx := context.Background()
	dsn, stopPG := startConformancePostgres(t)
	t.Cleanup(stopPG)

	dbName := fmt.Sprintf("xrec_conformance_%d", time.Now().UTC().UnixNano())
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	_ = admin.Close(ctx)

	st, err := corestore.Open(ctx, strings.TrimSuffix(dsn, "/postgres")+"/"+dbName)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	t.Cleanup(st.Close)
	st.WithExtraMigrations(remediation.MigrationsFS())
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{
		Mode:       config.NATSEmbedded,
		StoreDir:   filepath.Join(t.TempDir(), "nats"),
		SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	planKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey(plan): %v", err)
	}
	t.Cleanup(planKey.Destroy)
	keystore := filepath.Join(t.TempDir(), "keystore")
	if err := xrecplan.WriteTrustBundle(keystore, xrecplan.TrustBundle{
		PlanKeys: []xrecplan.TrustedKey{{
			KeyID:        e2ePlanKeyID,
			Algorithm:    planKey.Public().Algorithm,
			PublicKeyDER: planKey.Public().DER,
		}},
	}); err != nil {
		t.Fatalf("WriteTrustBundle: %v", err)
	}
	client, stop := startConformanceSigner(t, keystore)

	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithWorkerID("xrec-conformance"),
	)
	mgr, err := remediation.NewManager(st, outbox)
	if err != nil {
		t.Fatalf("remediation.NewManager: %v", err)
	}
	return &e2eHarness{
		ctx:            ctx,
		tenant:         e2eTenant,
		store:          st,
		log:            log,
		outbox:         outbox,
		recorder:       witness.NewRecorder(log, orchestrator.NewIdempotency(st)),
		quarantineMgr:  quarantine.NewManager(quarantine.Options{Log: log, Idempotency: orchestrator.NewIdempotency(st)}),
		remediationMgr: mgr,
		client:         client,
		stopSign:       stop,
		planKey:        planKey,
		connector:      newE2EConnector(e2eVault),
	}
}

func (h *e2eHarness) buildX509Plane(t *testing.T, authorityID, status, watermark string, generatedAt int64) e2ePlaneState {
	t.Helper()
	set, err := canon.ReduceTenant(canon.SpecVersionV1, h.tenant, []canon.ObservedRecord{{
		TenantID:   h.tenant,
		RecordType: canon.RecordTypeX509Certificate,
		StableID:   e2eRecordStableID,
		Algorithm:  "RSA_2048",
		Status:     status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: e2eRecordStableID},
		Attributes: map[string]canon.Value{
			"subject_dn":       canon.DN("CN=" + e2eRecordStableID),
			"revocation_state": canon.String(status),
		},
	}})
	if err != nil {
		t.Fatalf("ReduceTenant(%s): %v", authorityID, err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Watermark:   digest.Watermark{Position: watermark, ObservedAt: generatedAt},
		GeneratedAt: generatedAt,
	})
	if err != nil {
		t.Fatalf("digest.Build(%s): %v", authorityID, err)
	}
	signed, err := digest.Sign(h.ctx, h.client, built.Body, "")
	if err != nil {
		t.Fatalf("digest.Sign(%s real signer): %v", authorityID, err)
	}
	return e2ePlaneState{authorityID: authorityID, set: set, tree: built.Tree, signed: signed}
}

func (h *e2eHarness) completionRecords(t *testing.T, planes []e2ePlaneState) []quarantine.CompletedRecordProof {
	t.Helper()
	key := e2eRecordKey(h.tenant)
	keyBytes, err := digest.RecordKeyBytes(key)
	if err != nil {
		t.Fatalf("RecordKeyBytes: %v", err)
	}
	out := quarantine.CompletedRecordProof{RecordKey: key}
	for _, plane := range planes {
		proof, ok := plane.tree.InclusionProof(keyBytes)
		if !ok {
			t.Fatalf("%s missing completion proof", plane.authorityID)
		}
		out.Proofs = append(out.Proofs, quarantine.CompletedProof{
			AuthorityID: plane.authorityID,
			Proof:       e2eWitnessProof(proof),
		})
	}
	return []quarantine.CompletedRecordProof{out}
}

func (h *e2eHarness) drain(t *testing.T) {
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

type e2eConnector struct {
	name  string
	grant remediation.OperationGrant
	mu    sync.Mutex
	count int
}

func newE2EConnector(name string) *e2eConnector {
	return &e2eConnector{name: name, grant: remediation.NewOperationGrant(e2eOperation)}
}

func (c *e2eConnector) Name() string { return c.name }

func (c *e2eConnector) OperationGrant() remediation.OperationGrant { return c.grant }

func (c *e2eConnector) ExecuteRemediationAction(_ context.Context, req remediation.RemediationRequest) (string, error) {
	if len(req.Authorization) == 0 || req.Operation != e2eOperation {
		return "", fmt.Errorf("missing signer authorization for %s", req.Operation)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	return "revocation conformed to majority", nil
}

func (c *e2eConnector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func e2eWitnessPlane(p e2ePlaneState) witness.PlaneState {
	return witness.PlaneState{AuthorityID: p.authorityID, Set: p.set, Tree: p.tree, Digest: p.signed}
}

func e2eDigestTrust(signed []digest.SignedDigest) map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, sd := range signed {
		out[sd.KeyID] = crypto.PublicKey{Algorithm: sd.Algorithm, DER: append([]byte(nil), sd.PublicKeyDER...)}
	}
	return out
}

func e2eRecordKey(tenantID string) canon.RecordKey {
	return canon.RecordKey{TenantID: tenantID, RecordType: canon.RecordTypeX509Certificate, StableID: e2eRecordStableID}
}

func e2eWitnessProof(p digest.InclusionProof) witness.InclusionProof {
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

func decodeConformanceEvent(t *testing.T, ev eventspec.Event, out any) {
	t.Helper()
	if err := json.Unmarshal(ev.Data, out); err != nil {
		t.Fatalf("decode event %s: %v", ev.Type, err)
	}
}

func countEventsOfType(t *testing.T, log *events.Log, typ string) int {
	t.Helper()
	count := 0
	if err := log.Replay(context.Background(), 1, func(ev eventspec.Event) error {
		if ev.Type == typ {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return count
}

func startConformanceSigner(t *testing.T, keystore string) (*signing.Client, func()) {
	t.Helper()
	bin := buildConformanceSignerBinary(t)
	socketDir, err := os.MkdirTemp("", "xrec-conformance-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	args := []string{"--keystore", keystore, "--kek", filepath.Join(t.TempDir(), "signer.kek")}
	if runtime.GOOS != "linux" {
		args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
	}
	client, stop, err := signing.StartChild(context.Background(), bin, filepath.Join(socketDir, "s.sock"), args...)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	t.Cleanup(stop)
	return client, stop
}

func buildConformanceSignerBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer")
	cmd.Dir = repoRoot(t)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}

func startConformancePostgres(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	port, err := freeConformancePort()
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
		t.Skipf("embedded PostgreSQL unavailable: %v", err)
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port), func() {
		_ = inst.Stop()
	}
}

func freeConformancePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
