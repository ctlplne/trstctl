// SPDX-License-Identifier: LicenseRef-trstctl-EE

package store_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"

	corestore "trstctl.com/trstctl/internal/store"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL for the AGID store integration tests
// (no external service, no mocks) so RLS is exercised against the same FORCE-d
// row-level security the product runs under. Mirrors the succession store harness.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-agid-store-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// newRepoOn opens a core store against a fresh database, registers the AGID DDL
// through the feature-neutral WithExtraMigrations seam, migrates, and returns the
// repo. Each test uses its own database so tables start empty and tests don't
// interfere.
func newRepoOn(t *testing.T, dbName string) *agidstore.Repo {
	t.Helper()
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create db %s: %v", dbName, err)
	}
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/" + dbName

	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(agidstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return agidstore.New(cs)
}

// digest is a helper making a 32-byte digest from a label so tests read clearly.
func digest(label string) []byte {
	return crypto.SHA256Sum([]byte(label))
}

// linkedRecord builds a parent-linked delegation record row.
func linkedRecord(label, parent, delegator, delegate string, seq uint64) agidstore.DelegationRecord {
	return agidstore.DelegationRecord{
		RecordDigest: digest(label), ParentDigest: digest(parent), RootAnchor: false,
		DelegatorID: delegator, DelegateID: delegate, DepthRemaining: 3,
		Encoded: []byte("enc:" + label), Seq: seq,
	}
}

// rootRecord builds a root-anchored delegation record row.
func rootRecord(label, delegator, delegate string, seq uint64) agidstore.DelegationRecord {
	return agidstore.DelegationRecord{
		RecordDigest: digest(label), ParentDigest: nil, RootAnchor: true,
		DelegatorID: delegator, DelegateID: delegate, DepthRemaining: 5,
		Encoded: []byte("enc:" + label), Seq: seq,
	}
}

// TestRLS_DelegationTreeCrossTenantDenied: with tenant A's delegation-tree row
// present, a read/write under tenant B is denied by row-level security — B sees zero
// rows and B's insert lands only in B's tenant, never A's (AN-1; substrate for claim
// 24). This is the canonical RLS negative test.
func TestRLS_DelegationTreeCrossTenantDenied(t *testing.T) {
	repo := newRepoOn(t, "agid_rls")
	ctx := context.Background()

	root := rootRecord("root/A", "spiffe://a/root", "spiffe://a/agent", 1)
	if err := repo.InsertDelegationRecord(ctx, tenantA, root); err != nil {
		t.Fatalf("insert (tenantA): %v", err)
	}

	// tenantA sees its record.
	gotA, foundA, err := repo.FetchDelegationRecord(ctx, tenantA, root.RecordDigest)
	if err != nil || !foundA {
		t.Fatalf("fetch (tenantA): found=%v err=%v", foundA, err)
	}
	if gotA.DelegatorID != root.DelegatorID {
		t.Fatalf("tenantA record delegator = %q, want %q", gotA.DelegatorID, root.DelegatorID)
	}

	// tenantB must NOT see tenantA's record: RLS denies the cross-tenant read.
	_, foundB, err := repo.FetchDelegationRecord(ctx, tenantB, root.RecordDigest)
	if err != nil {
		t.Fatalf("fetch (tenantB): %v", err)
	}
	if foundB {
		t.Fatal("cross-tenant read leaked tenantA's delegation record to tenantB (RLS breach)")
	}

	// tenantB writes its OWN record with the same digest value; the WITH CHECK binds
	// it to tenantB, so it does not collide with or overwrite tenantA's row.
	rootB := rootRecord("root/A", "spiffe://b/root", "spiffe://b/agent", 1)
	if err := repo.InsertDelegationRecord(ctx, tenantB, rootB); err != nil {
		t.Fatalf("insert (tenantB, same digest): %v", err)
	}
	// tenantA's row is unchanged (still A's delegator), proving the two rows are
	// isolated by tenant even sharing a digest.
	gotA2, _, err := repo.FetchDelegationRecord(ctx, tenantA, root.RecordDigest)
	if err != nil {
		t.Fatalf("re-fetch (tenantA): %v", err)
	}
	if gotA2.DelegatorID != "spiffe://a/root" {
		t.Fatalf("tenantB write leaked into tenantA row: delegator now %q", gotA2.DelegatorID)
	}
	gotB, foundB2, err := repo.FetchDelegationRecord(ctx, tenantB, rootB.RecordDigest)
	if err != nil || !foundB2 {
		t.Fatalf("fetch (tenantB own): found=%v err=%v", foundB2, err)
	}
	if gotB.DelegatorID != "spiffe://b/root" {
		t.Fatalf("tenantB own record delegator = %q, want spiffe://b/root", gotB.DelegatorID)
	}
}

func TestRootAnchor_RegisterAndList_RLS(t *testing.T) {
	repo := newRepoOn(t, "agid_root_anchor_rls")
	ctx := context.Background()

	aAnchor := agidstore.RootAnchor{
		KeyID:     "root-key",
		PublicDER: []byte{0x30, 0x01, 0xa1},
		AuthRef:   "webauthn:tenant-a:root",
	}
	if err := repo.RegisterRootAnchor(ctx, tenantA, aAnchor); err != nil {
		t.Fatalf("register tenantA anchor: %v", err)
	}
	gotA, err := repo.ListRootAnchors(ctx, tenantA)
	if err != nil {
		t.Fatalf("list tenantA anchors: %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("tenantA anchors = %d, want 1", len(gotA))
	}
	if gotA[0].KeyID != aAnchor.KeyID || string(gotA[0].PublicDER) != string(aAnchor.PublicDER) || gotA[0].AuthRef != aAnchor.AuthRef {
		t.Fatalf("tenantA anchor = %+v, want %+v", gotA[0], aAnchor)
	}

	gotB, err := repo.ListRootAnchors(ctx, tenantB)
	if err != nil {
		t.Fatalf("list tenantB anchors: %v", err)
	}
	if len(gotB) != 0 {
		t.Fatalf("tenantB saw tenantA anchors: %+v", gotB)
	}

	bAnchor := agidstore.RootAnchor{
		KeyID:     "root-key",
		PublicDER: []byte{0x30, 0x01, 0xb2},
		AuthRef:   "webauthn:tenant-b:root",
	}
	if err := repo.RegisterRootAnchor(ctx, tenantB, bAnchor); err != nil {
		t.Fatalf("register tenantB anchor with same key id: %v", err)
	}
	gotA, err = repo.ListRootAnchors(ctx, tenantA)
	if err != nil {
		t.Fatalf("re-list tenantA anchors: %v", err)
	}
	if len(gotA) != 1 || gotA[0].AuthRef != aAnchor.AuthRef {
		t.Fatalf("tenantB write changed tenantA root anchor: %+v", gotA)
	}
	gotB, err = repo.ListRootAnchors(ctx, tenantB)
	if err != nil {
		t.Fatalf("re-list tenantB anchors: %v", err)
	}
	if len(gotB) != 1 || gotB[0].AuthRef != bAnchor.AuthRef || string(gotB[0].PublicDER) != string(bAnchor.PublicDER) {
		t.Fatalf("tenantB anchor = %+v, want %+v", gotB, bAnchor)
	}
}

// TestChain_OrderedAndGapless: FetchChain returns the delegation records for a
// credential ordered ROOT-TO-LEAF and complete, even when the records were inserted
// out of order; a chain with a missing parent is ErrChainBroken (never a silent
// partial). (Acceptance criterion 4 — ordered and complete.)
func TestChain_OrderedAndGapless(t *testing.T) {
	repo := newRepoOn(t, "agid_chain")
	ctx := context.Background()

	// Chain: root("r") <- mid("m") <- leaf("l"). Insert out of order.
	root := rootRecord("r", "root", "mid", 1)
	mid := linkedRecord("m", "r", "mid", "leaf", 2)
	leaf := linkedRecord("l", "m", "leaf", "worker", 3)
	for _, rec := range []agidstore.DelegationRecord{leaf, root, mid} {
		if err := repo.InsertDelegationRecord(ctx, tenantA, rec); err != nil {
			t.Fatalf("insert %x: %v", rec.RecordDigest[:4], err)
		}
	}
	// The credential is issued over the leaf (chain head = leaf digest).
	iss := agidstore.Issuance{
		CredentialID: "cred-1", SubjectID: "worker",
		ChainHeadDigest: leaf.RecordDigest, ChainDigest: digest("chain-l"),
		AgentStackDigest: digest("stack"), Seq: 4,
	}
	if err := repo.InsertIssuance(ctx, tenantA, iss); err != nil {
		t.Fatalf("insert issuance: %v", err)
	}

	chain, found, err := repo.FetchChain(ctx, tenantA, "cred-1")
	if err != nil || !found {
		t.Fatalf("fetch chain: found=%v err=%v", found, err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain len = %d, want 3", len(chain))
	}
	// Ordered root-to-leaf.
	wantOrder := [][]byte{root.RecordDigest, mid.RecordDigest, leaf.RecordDigest}
	for i, want := range wantOrder {
		if !reflect.DeepEqual(chain[i].RecordDigest, want) {
			t.Fatalf("chain[%d] out of root-to-leaf order", i)
		}
	}
	if !chain[0].RootAnchor {
		t.Fatal("chain[0] is not the root anchor")
	}

	// A credential whose chain has a missing parent is ErrChainBroken.
	orphanLeaf := linkedRecord("orphan", "missing-parent", "x", "y", 5)
	if err := repo.InsertDelegationRecord(ctx, tenantA, orphanLeaf); err != nil {
		t.Fatalf("insert orphan: %v", err)
	}
	issOrphan := agidstore.Issuance{
		CredentialID: "cred-broken", SubjectID: "y",
		ChainHeadDigest: orphanLeaf.RecordDigest, ChainDigest: digest("chain-orphan"),
		AgentStackDigest: digest("stack"), Seq: 6,
	}
	if err := repo.InsertIssuance(ctx, tenantA, issOrphan); err != nil {
		t.Fatalf("insert orphan issuance: %v", err)
	}
	if _, _, err := repo.FetchChain(ctx, tenantA, "cred-broken"); !errors.Is(err, agidstore.ErrChainBroken) {
		t.Fatalf("broken chain: got %v, want ErrChainBroken", err)
	}
}

// TestDescendantSet_AsOfWatermark: the descendant-set query returns every credential
// whose chain includes the subject, and only up to the recorded watermark — a
// credential recorded after the watermark is excluded (acceptance criterion 4).
func TestDescendantSet_AsOfWatermark(t *testing.T) {
	repo := newRepoOn(t, "agid_descendants")
	ctx := context.Background()

	// root(delegator=alice, delegate=bob) <- leaf(delegator=bob, delegate=carol).
	root := rootRecord("d-root", "alice", "bob", 1)
	leaf := linkedRecord("d-leaf", "d-root", "bob", "carol", 2)
	if err := repo.InsertDelegationRecord(ctx, tenantA, root); err != nil {
		t.Fatalf("insert root: %v", err)
	}
	if err := repo.InsertDelegationRecord(ctx, tenantA, leaf); err != nil {
		t.Fatalf("insert leaf: %v", err)
	}
	// Credential over the leaf, at seq 3 (<= watermark 5).
	if err := repo.InsertIssuance(ctx, tenantA, agidstore.Issuance{
		CredentialID: "cred-early", SubjectID: "carol",
		ChainHeadDigest: leaf.RecordDigest, ChainDigest: digest("c-early"),
		AgentStackDigest: digest("s"), Seq: 3,
	}); err != nil {
		t.Fatalf("insert early issuance: %v", err)
	}
	// A later credential (seq 9 > watermark 5) over the same leaf.
	if err := repo.InsertIssuance(ctx, tenantA, agidstore.Issuance{
		CredentialID: "cred-late", SubjectID: "carol",
		ChainHeadDigest: leaf.RecordDigest, ChainDigest: digest("c-late"),
		AgentStackDigest: digest("s"), Seq: 9,
	}); err != nil {
		t.Fatalf("insert late issuance: %v", err)
	}

	// alice is on the chain of cred-early (as root delegator); as of watermark 5 the
	// late credential is excluded.
	got, err := repo.FetchDescendantSet(ctx, tenantA, "alice", 5)
	if err != nil {
		t.Fatalf("descendant set: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"cred-early"}) {
		t.Fatalf("descendant set as-of watermark 5 = %v, want [cred-early]", got)
	}
	// As of a later watermark, both appear.
	gotAll, err := repo.FetchDescendantSet(ctx, tenantA, "alice", 100)
	if err != nil {
		t.Fatalf("descendant set (wm 100): %v", err)
	}
	if !reflect.DeepEqual(gotAll, []string{"cred-early", "cred-late"}) {
		t.Fatalf("descendant set as-of 100 = %v, want [cred-early cred-late]", gotAll)
	}
	// A subject on no chain has an empty descendant set.
	none, err := repo.FetchDescendantSet(ctx, tenantA, "nobody", 100)
	if err != nil {
		t.Fatalf("descendant set (nobody): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("descendant set for non-participant = %v, want empty", none)
	}
}

// TestInsertReadRoundTrip_AllTables exercises the issuance / attestation binding /
// refusal / revocation directive+jobs repositories against real RLS, and confirms
// the attestation-evidence uniqueness (INV-A6 substrate) and the single-transaction
// directive+jobs insert (INV-A8 substrate) behave.
func TestInsertReadRoundTrip_AllTables(t *testing.T) {
	repo := newRepoOn(t, "agid_roundtrip")
	ctx := context.Background()

	iss := agidstore.Issuance{
		CredentialID: "c1", SubjectID: "agent-1",
		ChainHeadDigest: digest("head"), ChainDigest: digest("chain"),
		AgentStackDigest: digest("stack"), TaskEnvelopeDigest: digest("task"),
		AttestationRef: digest("att"), Seq: 1,
	}
	if err := repo.InsertIssuance(ctx, tenantA, iss); err != nil {
		t.Fatalf("insert issuance: %v", err)
	}

	// Attestation binding; a duplicate evidence digest must be rejected (replay).
	ab := agidstore.AttestationBinding{
		BindingID: "b1", CredentialID: "c1", EvidenceDigest: digest("evidence"),
		AttestationClass: "tpm2", VerifiedAt: 100, Seq: 2,
	}
	if err := repo.InsertAttestationBinding(ctx, tenantA, ab); err != nil {
		t.Fatalf("insert attestation binding: %v", err)
	}
	dup := ab
	dup.BindingID = "b2"
	if err := repo.InsertAttestationBinding(ctx, tenantA, dup); err == nil {
		t.Fatal("duplicate attestation evidence was accepted; replay uniqueness not enforced")
	}

	// Refusal record.
	if err := repo.InsertRefusalRecord(ctx, tenantA, agidstore.RefusalRecord{
		RefusalID: "r1", SubjectID: "agent-1", FailedCheck: "attestation.min_class",
		RequestDigest: digest("req"), Signature: []byte("sig"), Seq: 3,
	}); err != nil {
		t.Fatalf("insert refusal: %v", err)
	}

	// Revocation directive + two jobs in one transaction.
	dir := agidstore.RevocationDirective{
		DirectiveID: "dir-1", SubjectID: "agent-1", Reason: "compromise", Watermark: 42, Seq: 4,
	}
	jobs := []agidstore.RevocationJob{
		{DirectiveID: "dir-1", IdempotencyKey: "job-1", CredentialID: "c1", Seq: 5},
		{DirectiveID: "dir-1", IdempotencyKey: "job-2", CredentialID: "c2", FollowOn: true, Seq: 6},
	}
	if err := repo.InsertRevocationDirectiveWithJobs(ctx, tenantA, dir, jobs); err != nil {
		t.Fatalf("insert directive+jobs: %v", err)
	}

	// tenantB sees none of it (RLS).
	if _, foundB, err := repo.FetchDelegationRecord(ctx, tenantB, digest("head")); err != nil || foundB {
		t.Fatalf("cross-tenant delegation record leak: found=%v err=%v", foundB, err)
	}
	setB, err := repo.FetchDescendantSet(ctx, tenantB, "agent-1", 100)
	if err != nil {
		t.Fatalf("descendant set (tenantB): %v", err)
	}
	if len(setB) != 0 {
		t.Fatalf("cross-tenant descendant set leaked %v", setB)
	}
}

// TestProjection_DescendantSetDeterministicReplay: replaying the same AGID-01 event
// sequence — including DUPLICATE delivery of every event — yields the identical
// descendant set AND the identical watermark, and that pure-projection answer equals
// what the durable RLS store returns for the same events (AGID-claim-16 projection /
// AGID-claim-24 replay). This is the canonical replay/determinism test.
func TestProjection_DescendantSetDeterministicReplay(t *testing.T) {
	// Build a delegation forest as AN-2 events (AGID-01 types), with explicit
	// sequences so the watermark is meaningful.
	rootDig := digest("p-root")
	leafDig := digest("p-leaf")
	credDig := digest("p-cred")

	seq := []eventFixture{
		{delegation.DelegationRecordedV1{RecordDigest: rootDig, RootAnchor: true, DelegatorID: "alice", DelegateID: "bob"}, 1},
		{delegation.DelegationRecordedV1{RecordDigest: leafDig, ParentDigest: rootDig, DelegatorID: "bob", DelegateID: "carol"}, 2},
		{delegation.IssuanceRecordedV1{CredentialDigest: credDig, SubjectID: "carol", ChainDigest: leafDig}, 3},
	}
	clean := encodeFixtures(t, seq)

	// Duplicate delivery: every event again, plus an extra copy of the issuance.
	dup := append([]evt{}, clean...)
	dup = append(dup, clean...)
	dup = append(dup, clean[2])

	dsClean, err := delegation.DescendantSetOf(toEvents(clean), "alice", delegation.UnboundedWatermark)
	if err != nil {
		t.Fatalf("DescendantSetOf(clean): %v", err)
	}
	dsDup, err := delegation.DescendantSetOf(toEvents(dup), "alice", delegation.UnboundedWatermark)
	if err != nil {
		t.Fatalf("DescendantSetOf(dup): %v", err)
	}
	if !reflect.DeepEqual(dsClean, dsDup) {
		t.Fatalf("duplicate delivery changed the descendant set/watermark:\n clean %#v\n   dup %#v", dsClean, dsDup)
	}
	if dsClean.Watermark != 3 {
		t.Fatalf("watermark = %d, want 3 (highest folded sequence)", dsClean.Watermark)
	}
	wantCred := []string{hexOf(credDig)}
	if !reflect.DeepEqual(dsClean.Credentials, wantCred) {
		t.Fatalf("descendant set = %v, want %v", dsClean.Credentials, wantCred)
	}

	// The pure projection agrees with the durable RLS store: load the same forest and
	// ask the store for alice's descendants as of the same watermark.
	repo := newRepoOn(t, "agid_replay")
	ctx := context.Background()
	if err := repo.InsertDelegationRecord(ctx, tenantA, agidstore.DelegationRecord{
		RecordDigest: rootDig, RootAnchor: true, DelegatorID: "alice", DelegateID: "bob", Encoded: []byte("r"), Seq: 1,
	}); err != nil {
		t.Fatalf("store root: %v", err)
	}
	if err := repo.InsertDelegationRecord(ctx, tenantA, agidstore.DelegationRecord{
		RecordDigest: leafDig, ParentDigest: rootDig, DelegatorID: "bob", DelegateID: "carol", Encoded: []byte("l"), Seq: 2,
	}); err != nil {
		t.Fatalf("store leaf: %v", err)
	}
	if err := repo.InsertIssuance(ctx, tenantA, agidstore.Issuance{
		CredentialID: hexOf(credDig), SubjectID: "carol",
		ChainHeadDigest: leafDig, ChainDigest: digest("whole-chain"),
		AgentStackDigest: digest("s"), Seq: 3,
	}); err != nil {
		t.Fatalf("store issuance: %v", err)
	}
	storeSet, err := repo.FetchDescendantSet(ctx, tenantA, "alice", 3)
	if err != nil {
		t.Fatalf("store descendant set: %v", err)
	}
	if !reflect.DeepEqual(storeSet, dsClean.Credentials) {
		t.Fatalf("store descendant set %v != pure projection %v", storeSet, dsClean.Credentials)
	}
}
