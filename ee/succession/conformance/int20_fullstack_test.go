// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	succapi "trstctl.com/trstctl/ee/succession/api"
	"trstctl.com/trstctl/ee/succession/background"
	pcaskem "trstctl.com/trstctl/ee/succession/kem"
	"trstctl.com/trstctl/ee/succession/minter"
	pcasmonitor "trstctl.com/trstctl/ee/succession/monitor"
	pcasorch "trstctl.com/trstctl/ee/succession/orchestrator"
	"trstctl.com/trstctl/ee/succession/recovery"
	"trstctl.com/trstctl/ee/succession/retirement"
	"trstctl.com/trstctl/ee/succession/staple"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const int20Tenant = "11111111-1111-1111-1111-111111111111"

type int20Stack struct {
	ctx       context.Context
	store     *corestore.Store
	repo      *pcasstore.Repo
	log       *events.Log
	outbox    *coreorch.Outbox
	handler   editionseam.LicensedOutboxHandler
	svc       succapi.Service
	signer    *signing.Client
	keyDir    string
	tenantID  string
	features  *featureRecorder
	closeSign func()
}

type staticSignerProvider struct{ c *signing.Client }

func (p staticSignerProvider) Client() *signing.Client { return p.c }

// TestINT20_FullStackPCASUserJourneys is the PCAS release-gate spine from
// PCAS-WIRING-DESIGN §7: user-facing API requests write tenant-scoped Postgres
// state, the licensed outbox factory drains real outbox rows, signing/KEM custody
// crosses the actual trstctl-signer subprocess over UDS, and scheduled PCAS
// workers consume embedded JetStream ledger state. Unit tests still cover the deep
// edge cases; this test proves the mechanisms are wired together as a product path.
func TestINT20_FullStackPCASUserJourneys(t *testing.T) {
	st := startINT20Stack(t)
	defer st.close()

	coreID, genesis, trustRoot := st.requestSuccessionChain(t)
	st.delegationIsEnforcedBySigner(t)
	kemID := st.kemRewrapAndRetirement(t)
	st.issuerAndStapledLeaves(t, coreID)
	st.recoveryMint(t)
	st.federationImportAndQuarantine(t)
	st.misissuanceProofPersists(t)
	st.checkpointAndPostureVerify(t, coreID)

	if kemID == "" || len(genesis.TrustRootAtt) == 0 || len(trustRoot.Public().DER) == 0 {
		t.Fatal("full-stack e2e did not retain core journey evidence")
	}
}

func startINT20Stack(t *testing.T) *int20Stack {
	t.Helper()
	ctx := context.Background()
	dsn, stopPG := startEmbeddedPostgres(t)

	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open core store: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate core+PCAS: %v", err)
	}
	if err := cs.UpsertTenant(ctx, corestore.Tenant{TenantID: int20Tenant, Name: "INT-20 Tenant", EventSeq: 1}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open embedded JetStream: %v", err)
	}

	signer, stopSign, keyDir := startLicensedSignerSubprocess(t)
	features := &featureRecorder{}
	outbox := coreorch.NewOutbox(cs,
		coreorch.WithWorkerID("pcas-int20"),
		coreorch.WithBackoff(func(int) time.Duration { return time.Millisecond }),
		coreorch.WithRetryJitter(func(d time.Duration) time.Duration { return d }),
		coreorch.WithDeliveryTimeout(10*time.Second),
		coreorch.WithMaxAttempts(2),
	)
	handler, err := pcasorch.NewLicensedOutboxFactory()(editionseam.LicensedOutboxDeps{
		Store: cs, Log: log, Minter: signer, KEMCustody: signer, FeatureObserver: features.Observe,
	})
	if err != nil {
		t.Fatalf("licensed outbox factory: %v", err)
	}
	svc := succapi.NewService(cs, log, outbox, succapi.WithSignerStoreDir(keyDir), succapi.WithKEMCustody(signer))

	st := &int20Stack{
		ctx: ctx, store: cs, repo: pcasstore.New(cs), log: log, outbox: outbox,
		handler: handler, svc: svc, signer: signer, keyDir: keyDir, tenantID: int20Tenant,
		features: features, closeSign: stopSign,
	}
	t.Cleanup(func() {
		st.close()
		_ = log.Close()
		stopPG()
	})
	return st
}

func (st *int20Stack) close() {
	if st.closeSign != nil {
		st.closeSign()
		st.closeSign = nil
	}
}

func (st *int20Stack) requestSuccessionChain(t *testing.T) (string, succession.GenesisRecord, *signing.RemoteSigner) {
	t.Helper()
	const id = "spiffe://int20.example/workload/core"
	genesisKey, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0))
	if err != nil {
		t.Fatalf("onboard genesis key: %v", err)
	}
	trustRoot, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, "int20-trust-root")
	if err != nil {
		t.Fatalf("provision trust root: %v", err)
	}
	genesis := succession.GenesisRecord{
		DeploymentScope: "spiffe://int20.example", IdentityID: id, TenantID: st.tenantID,
		Algorithm: genesisKey.Algorithm(), PublicKey: genesisKey.Public().DER, Epoch: 0,
	}
	gd, err := succession.GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	genesis.TrustRootAtt, err = crypto.SignerFromDigestSigner(trustRoot).Sign(gd, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}

	if _, err := st.svc.RequestSuccession(st.ctx, st.tenantID, succapi.RequestSuccessionRequest{
		IdentityID: id, CredentialType: "x509", TargetAlgorithm: string(crypto.ECDSAP384),
		PolicyRef: "policy:int20-core", DeploymentScope: "spiffe://int20.example",
	}); err != nil {
		t.Fatalf("request succession: %v", err)
	}
	st.dispatchAll(t)

	chainResp, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil {
		t.Fatalf("fetch chain: %v", err)
	}
	if chainResp.Count != 1 {
		t.Fatalf("chain count = %d, want 1", chainResp.Count)
	}
	chain := decodeChain(t, chainResp.Records)
	res, err := rpverify.Verify(rpverify.Input{
		TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: chain,
	}, &memEpochStore{m: map[string]uint64{}}, rpverify.Options{ExpectedTenant: st.tenantID})
	if err != nil {
		t.Fatalf("offline RP verify of served chain: %v", err)
	}
	if res.Epoch != 1 || res.Algorithm != crypto.ECDSAP384 {
		t.Fatalf("verified posture = %s@%d, want ECDSA-P384@1", res.Algorithm, res.Epoch)
	}
	return id, genesis, trustRoot
}

func (st *int20Stack) delegationIsEnforcedBySigner(t *testing.T) {
	t.Helper()
	if _, err := st.svc.ConfigureDelegationScope(st.ctx, st.tenantID, succapi.DelegationScopeRequest{ScopeID: "root", EpochFloor: 2}); err != nil {
		t.Fatalf("configure root delegation scope: %v", err)
	}
	if _, err := st.svc.ConfigureDelegationScope(st.ctx, st.tenantID, succapi.DelegationScopeRequest{ScopeID: "app", ParentScopeID: "root"}); err != nil {
		t.Fatalf("configure app delegation scope: %v", err)
	}
	const id = "spiffe://int20.example/workload/delegated"
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0)); err != nil {
		t.Fatalf("delegation genesis: %v", err)
	}
	_, err := st.signer.MintSuccessor(st.ctx, signing.MintRequest{
		IdentityID: id, TenantID: st.tenantID, DeploymentScope: "spiffe://int20.example",
		PredecessorHandle: succession.KeyHandle(id, 0), AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:int20-delegation",
		DelegationScope: "app",
	})
	if err == nil || !strings.Contains(err.Error(), "delegated-authority") {
		t.Fatalf("delegation violation err = %v, want signer refusal", err)
	}
}

func (st *int20Stack) kemRewrapAndRetirement(t *testing.T) string {
	t.Helper()
	const id = "spiffe://int20.example/workload/kem"
	predHandle := succession.KeyHandle(id, 0)
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, predHandle); err != nil {
		t.Fatalf("KEM predecessor: %v", err)
	}
	resp, err := st.svc.RequestKEMRewrap(st.ctx, st.tenantID, succapi.KEMRewrapRequest{
		IdentityID: id, PredecessorHandle: predHandle, PredecessorEpoch: 0,
		SuccessorSignHandle: succession.KeyHandle(id, 1), SuccessorKEMHandle: "kem:" + id + ":1",
		SigningAlgorithm: string(crypto.ECDSAP384), KEMAlgorithm: string(eepqc.MLKEM768),
		Stages: []string{"stage-a", "stage-b"},
	})
	if err != nil {
		t.Fatalf("request KEM rewrap: %v", err)
	}
	st.dispatchAll(t)

	status, err := st.svc.RewrapStatus(st.ctx, st.tenantID, id, 0)
	if err != nil {
		t.Fatalf("rewrap status: %v", err)
	}
	if !status.Complete || len(status.Jobs) != 2 {
		t.Fatalf("rewrap status = %+v, want complete two-stage job", status)
	}
	rows, err := st.repo.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("KEM chain rows len=%d err=%v, want 1", len(rows), err)
	}
	var paired pcaskem.PairedRecord
	if err := json.Unmarshal(rows[0].Encoded, &paired); err != nil {
		t.Fatalf("decode paired KEM record: %v", err)
	}
	if err := pcaskem.VerifyPaired(paired); err != nil {
		t.Fatalf("paired KEM record verify: %v", err)
	}

	rp, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, _ := json.Marshal([]map[string]any{{"relying_party": "rp1", "public_der": rp.Public().DER}})
	if _, err := st.svc.ConfigureRetirementPolicy(st.ctx, st.tenantID, succapi.RetirementPolicyRequest{
		IdentityID: id, PredecessorEpoch: 0, Threshold: 1, Roster: roster,
		ValidityWindowSeconds: 3600, PredecessorHandle: predHandle,
	}); err != nil {
		t.Fatalf("configure retirement: %v", err)
	}
	ackSig, err := retirement.SignAck(rp, st.tenantID, id, 0, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.svc.RecordAck(st.ctx, st.tenantID, succapi.AckRequest{IdentityID: id, Epoch: 0, RelyingParty: "rp1", Signature: ackSig}); err != nil {
		t.Fatalf("record RP ack: %v", err)
	}
	st.runWorkersOnce(t, config.PCAS{Retirement: config.PCASRetirement{Enabled: true, Interval: "1h", ValidityWindow: "1h"}})
	retired, found, err := st.svc.RetirementStatus(st.ctx, st.tenantID, id, 0)
	if err != nil || !found || retired.Status != "retired" {
		t.Fatalf("retirement status = %+v found=%v err=%v, want retired", retired, found, err)
	}
	if _, err := st.signer.SignerForHandle(st.ctx, predHandle); err == nil {
		t.Fatal("predecessor signer handle still resolves after retirement zeroize")
	}
	_ = resp
	return id
}

func (st *int20Stack) issuerAndStapledLeaves(t *testing.T, checkpointIdentity string) {
	t.Helper()
	caHandle := "int20-issuer-ca"
	ca, err := st.signer.GenerateConstrainedKeyHandle(st.ctx, crypto.ECDSAP256, caHandle, []signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("generate issuer CA: %v", err)
	}
	caDER, err := crypto.SelfSignedCACert(ca, "trstctl INT20 PCAS CA", time.Hour)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-ca", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: caHandle, CACertDER: caDER,
	}); err != nil {
		t.Fatalf("register issuer: %v", err)
	}
	leaf, err := st.svc.IssueIssuerLeaf(st.ctx, st.tenantID, succapi.IssueLeafRequest{
		IssuerID: "int20-ca", CSRDER: leafCSR(t), RotationVersion: 7, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue issuer leaf: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(leaf.CertDER, caDER); err != nil {
		t.Fatalf("issuer leaf signature: %v", err)
	}
	if err := rpverify.AcceptLeafTuple("int20-ca", rpverify.LeafTuple{IssuerEpoch: leaf.Epoch, RotationVersion: leaf.RotationVersion}, &memEpochStore{m: map[string]uint64{}}); err != nil {
		t.Fatalf("RP rejected fresh issuer tuple: %v", err)
	}

	st.runWorkersOnce(t, config.PCAS{Checkpoints: config.PCASCheckpoints{
		Enabled: true, Interval: "1h", SigningKeyHandle: "int20-checkpoint", SigningAlgorithm: string(crypto.ECDSAP256),
	}})
	stapled, err := st.svc.IssueStapledLeaf(st.ctx, st.tenantID, succapi.IssueStapledLeafRequest{
		IssuerID: "int20-ca", CSRDER: leafCSR(t), CheckpointIdentityID: checkpointIdentity, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue stapled leaf: %v", err)
	}
	cpSigner, err := st.signer.SignerForHandleWithPurpose(st.ctx, "int20-checkpoint", signing.PurposeGeneric)
	if err != nil {
		t.Fatalf("checkpoint signer: %v", err)
	}
	res, err := staple.VerifyStapledCertificate(stapled.CertDER, staple.Policy{
		ExpectedTenant: st.tenantID, RequireAttachment: true, LastAccepted: 0, CheckpointKeyDER: cpSigner.Public().DER,
	})
	if err != nil {
		t.Fatalf("verify stapled leaf: %v", err)
	}
	if res.Epoch != 1 {
		t.Fatalf("stapled posture epoch = %d, want 1", res.Epoch)
	}
}

func (st *int20Stack) recoveryMint(t *testing.T) {
	t.Helper()
	const id = "spiffe://int20.example/workload/recovery"
	trustRoot, auth, successor := recoveryAuthForSigner(t, st.ctx, st.signer, id, st.tenantID, "int20-recovery-successor", 2)
	if _, err := st.svc.ConfigureRecoveryPolicy(st.ctx, st.tenantID, succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 2, Roster: mustJSON(t, auth.Roster), TrustRootDER: trustRoot.Public().DER,
	}); err != nil {
		t.Fatalf("configure recovery policy: %v", err)
	}
	rawAuth := mustJSON(t, auth)
	if _, err := st.svc.RequestRecovery(st.ctx, st.tenantID, succapi.RecoveryRequest{
		IdentityID: id, DeploymentScope: "spiffe://int20.example", TargetAlgorithm: string(successor.Algorithm()),
		SuccessorHandle: "int20-recovery-successor", PredecessorEpoch: 1, Epoch: 2,
		PredecessorAlgorithm: string(crypto.ECDSAP256), PredecessorPublicDER: []byte("lost-predecessor-public-key"),
		TrustRootDER: trustRoot.Public().DER, Authorization: rawAuth,
	}); err != nil {
		t.Fatalf("request recovery: %v", err)
	}
	st.dispatchAll(t)
	rows, err := st.repo.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("recovery rows len=%d err=%v, want 1", len(rows), err)
	}
	var rec recovery.RecoveryRecord
	if err := json.Unmarshal(rows[0].Encoded, &rec); err != nil {
		t.Fatalf("decode recovery record: %v", err)
	}
	if err := recovery.VerifyRecord(rec, trustRoot.Public().DER); err != nil {
		t.Fatalf("verify recovery record: %v", err)
	}
}

func (st *int20Stack) federationImportAndQuarantine(t *testing.T) {
	t.Helper()
	localHandle := "int20-federation-local-authority"
	localAuthority, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, localHandle)
	if err != nil {
		t.Fatalf("local federation authority: %v", err)
	}
	_ = localAuthority
	foreign, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://foreign.example", "spiffe://foreign.example/workload", "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("foreign sample chain: %v", err)
	}
	foreignGenesis := mustJSON(t, foreign.Genesis)
	foreignChain := make([]json.RawMessage, 0, len(foreign.Records))
	for _, rec := range foreign.Records {
		foreignChain = append(foreignChain, mustJSON(t, rec))
	}
	if _, err := st.svc.RequestFederationImport(st.ctx, st.tenantID, succapi.FederationImportRequest{
		ForeignDeploymentID: "foreign-valid", LocalDeploymentID: "spiffe://int20.example",
		LocalAuthorityHandle: localHandle, IdentityID: "foreign-valid/id",
		ForeignTrustRootDER: foreign.TrustRootPubDER, LocalBaseEpoch: 100,
		ForeignGenesis: foreignGenesis, ForeignChain: foreignChain,
	}); err != nil {
		t.Fatalf("request federation import: %v", err)
	}
	st.dispatchAll(t)
	var bridgeCount int
	if err := st.store.WithTenant(st.ctx, st.tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(st.ctx,
			`SELECT count(*) FROM pcas_federation_bridge
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND foreign_deployment_id = $1`,
			"foreign-valid").Scan(&bridgeCount)
	}); err != nil {
		t.Fatalf("count federation bridges: %v", err)
	}
	if bridgeCount != 1 {
		t.Fatalf("federation bridge count = %d, want 1", bridgeCount)
	}

	badRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.svc.RequestFederationImport(st.ctx, st.tenantID, succapi.FederationImportRequest{
		ForeignDeploymentID: "foreign-bad", LocalDeploymentID: "spiffe://int20.example",
		LocalAuthorityHandle: localHandle, IdentityID: "foreign-bad/id",
		ForeignTrustRootDER: badRoot.Public().DER, LocalBaseEpoch: 100,
		ForeignGenesis: foreignGenesis, ForeignChain: foreignChain,
	}); err != nil {
		t.Fatalf("request bad federation import: %v", err)
	}
	st.dispatchAll(t)
	qs, err := st.repo.ListFederationQuarantine(st.ctx, st.tenantID)
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	found := false
	for _, q := range qs {
		found = found || q.ForeignDeploymentID == "foreign-bad"
	}
	if !found {
		t.Fatal("tampered federation import did not persist quarantine")
	}
}

func (st *int20Stack) misissuanceProofPersists(t *testing.T) {
	t.Helper()
	a, b := equivocationRecords(t, "spiffe://int20.example/workload/equivocation", st.tenantID)
	det, ok, err := pcasmonitor.New(map[string][]byte{}, st.log).Scan(st.ctx, []succession.SuccessionRecord{a, b})
	if err != nil || !ok {
		t.Fatalf("monitor scan ok=%v err=%v, want detection", ok, err)
	}
	if err := translog.VerifyMisissuanceProof(det.Proof); err != nil {
		t.Fatalf("misissuance proof verify: %v", err)
	}
	proofJSON := mustJSON(t, det.Proof)
	da, _ := succession.Commit(a.Fields)
	db, _ := succession.Commit(b.Fields)
	if err := st.repo.SaveMisissuance(st.ctx, st.tenantID, pcasstore.Misissuance{
		IdentityID: a.Fields.IdentityID, Epoch: a.Fields.Epoch,
		RecordADigest: da, RecordBDigest: db, SignerA: det.SignerA, SignerB: det.SignerB,
		ProofJSON: proofJSON,
	}); err != nil {
		t.Fatalf("persist misissuance: %v", err)
	}
	resp, err := st.svc.ListMisissuance(st.ctx, st.tenantID)
	if err != nil {
		t.Fatalf("list misissuance: %v", err)
	}
	if resp.Count == 0 {
		t.Fatal("durable misissuance proof was not served")
	}
}

func (st *int20Stack) checkpointAndPostureVerify(t *testing.T, identityID string) {
	t.Helper()
	cp, found, err := st.svc.LatestCheckpoint(st.ctx, st.tenantID, identityID)
	if err != nil || !found {
		t.Fatalf("latest checkpoint found=%v err=%v", found, err)
	}
	var signed succession.SignedEpochCheckpoint
	if err := json.Unmarshal(cp.CheckpointJSON, &signed); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	cpSigner, err := st.signer.SignerForHandleWithPurpose(st.ctx, "int20-checkpoint", signing.PurposeGeneric)
	if err != nil {
		t.Fatalf("checkpoint signer: %v", err)
	}
	if err := succession.VerifyEpochCheckpoint(cpSigner.Public().DER, signed); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	posture, found, err := st.svc.PostureReport(st.ctx, st.tenantID, identityID)
	if err != nil || !found {
		t.Fatalf("posture report found=%v err=%v", found, err)
	}
	report := succession.PostureReport{
		IdentityID: posture.IdentityID, TenantID: posture.TenantID, Algorithm: crypto.Algorithm(posture.Algorithm),
		Epoch: posture.Epoch, IntroducingRecordDigest: posture.IntroducingRecordDigest, Signature: posture.Signature,
	}
	if err := succession.VerifyPostureReport(posture.ReporterPublicDER, report); err != nil {
		t.Fatalf("verify posture report: %v", err)
	}
}

func (st *int20Stack) dispatchAll(t *testing.T) {
	t.Helper()
	h := coreorch.HandlerFunc(func(ctx context.Context, m coreorch.Message) error {
		handled, err := st.handler.DeliverLicensed(ctx, m)
		if err != nil {
			return err
		}
		if !handled {
			return fmt.Errorf("unhandled PCAS outbox destination %q", m.Destination)
		}
		return nil
	})
	for i := 0; i < 20; i++ {
		n, err := st.outbox.Dispatch(st.ctx, h)
		if err != nil {
			t.Fatalf("dispatch outbox: %v", err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("outbox did not drain")
}

func (st *int20Stack) runWorkersOnce(t *testing.T, pcas config.PCAS) {
	t.Helper()
	workers := background.NewWorkers(background.Options{
		Store: st.store, Log: st.log, Signer: staticSignerProvider{c: st.signer}, PCAS: pcas,
	})
	if len(workers) == 0 {
		t.Fatal("no background workers configured")
	}
	for _, w := range workers {
		runWorkerUntilIdle(t, w)
	}
}

func runWorkerUntilIdle(t *testing.T, w server.BackgroundWorker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx) }()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s run: %v", w.Name(), err)
		}
	case <-timer.C:
		cancel()
		err := <-errc
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s stop: %v", w.Name(), err)
		}
	}
}

func startEmbeddedPostgres(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	port := freeTCPPort(t)
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(port).
		RuntimePath(filepath.Join(dir, "rt")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	return dsn, func() { _ = pg.Stop() }
}

func startLicensedSignerSubprocess(t *testing.T) (*signing.Client, func(), string) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("license keypair: %v", err)
	}
	now := time.Now().UTC()
	rawLic, err := license.Sign(license.Claims{
		V: 1, ID: "pcas-int20", Customer: "PCAS INT20", Tier: license.TierEnterprise,
		Features: []license.Feature{license.FeaturePCAS}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("sign PCAS license: %v", err)
	}
	dir, err := os.MkdirTemp("", "pcas-int20-signer")
	if err != nil {
		t.Fatal(err)
	}
	licFile := filepath.Join(dir, "license.json")
	if err := os.WriteFile(licFile, rawLic, 0o600); err != nil {
		t.Fatalf("write license: %v", err)
	}
	bin := filepath.Join(dir, "trstctl-signer")
	ldflags := "-X trstctl.com/trstctl/internal/license.builtinPubKeysB64=" + base64.StdEncoding.EncodeToString(pub)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, "./cmd/trstctl-signer") // #nosec G204 -- executable/argv are fixed and ldflags contain only this test's base64 public key (CWE-78).
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("build licensed trstctl-signer: %v\n%s", err, out)
	}
	socketDir, err := os.MkdirTemp("", "pcas-int20-sock")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "s.sock")
	keyDir := filepath.Join(dir, "keys")
	kekFile := filepath.Join(dir, "kek.bin")
	args := []string{"--license", licFile, "--keystore", keyDir, "--kek", kekFile}
	if runtime.GOOS != "linux" {
		args = append(args, "--allow-insecure-dev-nonlinux")
	}
	client, stop, err := signing.StartChild(context.Background(), bin, socket, args...)
	if err != nil {
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(socketDir)
		t.Fatalf("start licensed signer subprocess: %v", err)
	}
	return client, func() {
		_ = client.Close()
		stop()
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(socketDir)
	}, keyDir
}

// freeTCPPort returns an unused loopback port as a uint32 — the type
// embedded-postgres' Port option takes — so the port is carried end-to-end
// without a narrowing conversion at the call site. The kernel-assigned port is
// range-checked here (a TCP port is a 16-bit number) and the test fails closed
// if it is ever outside that range.
func freeTCPPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p > 0 && p <= math.MaxUint16 {
		return uint32(p)
	}
	t.Fatalf("free port: listener reported out-of-range TCP port %d", p)
	return 0
}

func leafCSR(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "svc.int20.example", DNSNames: []string{"svc.int20.example"},
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

type int20Approver struct {
	ap     recovery.Approver
	signer crypto.Signer
}

func recoveryAuthForSigner(t *testing.T, ctx context.Context, signer *signing.Client, id, tenant, successorHandle string, epoch uint64) (crypto.Signer, recovery.RecoveryAuthorization, *signing.RemoteSigner) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	trustRoot, _ := be.GenerateKey(crypto.ECDSAP256)
	a1 := int20ApproverFromKey(t, "a1")
	a2 := int20ApproverFromKey(t, "a2")
	successor, err := signer.GenerateKeyHandle(ctx, crypto.ECDSAP384, successorHandle)
	if err != nil {
		t.Fatalf("pre-provision recovery successor: %v", err)
	}
	stmt := recovery.RecoveryStatement{
		DeploymentScope: "spiffe://int20.example", IdentityID: id, TenantID: tenant,
		Epoch: epoch, SuccessorAlg: string(successor.Algorithm()), SuccessorPub: successor.Public().DER, Nonce: "int20-recovery",
	}
	roster := []recovery.Approver{a1.ap, a2.ap}
	rosterSig, err := recovery.SignRoster(trustRoot, 2, roster)
	if err != nil {
		t.Fatal(err)
	}
	sig1, _ := recovery.SignApproval(a1.signer, stmt)
	sig2, _ := recovery.SignApproval(a2.signer, stmt)
	auth := recovery.RecoveryAuthorization{
		Statement: stmt, Threshold: 2, Roster: roster, RosterSig: rosterSig,
		Approvals: []recovery.Approval{{ApproverID: "a1", Signature: sig1}, {ApproverID: "a2", Signature: sig2}},
	}
	return trustRoot, auth, successor
}

func int20ApproverFromKey(t *testing.T, id string) int20Approver {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return int20Approver{ap: recovery.Approver{ID: id, PubDER: s.Public().DER}, signer: s}
}

func equivocationRecords(t *testing.T, identity, tenant string) (succession.SuccessionRecord, succession.SuccessionRecord) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	build := func(policy string) succession.SuccessionRecord {
		pred, _ := be.GenerateKey(crypto.ECDSAP256)
		succ, _ := be.GenerateKey(crypto.ECDSAP384)
		fields := succession.CommitmentFields{
			DeploymentScope: "spiffe://int20.example", IdentityID: identity, TenantID: tenant,
			PredecessorEpoch: 0, Epoch: 1,
			PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
			SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
			PolicyRef: policy, HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
		}
		c, _ := succession.Commit(fields)
		predSig, _ := pred.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
		succSig, _ := succ.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
		return succession.SuccessionRecord{
			Fields: fields, PredecessorAtt: predSig,
			Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
		}
	}
	return build("policy:a"), build("policy:b")
}

func decodeChain(t *testing.T, raw [][]byte) []succession.SuccessionRecord {
	t.Helper()
	out := make([]succession.SuccessionRecord, 0, len(raw))
	for _, b := range raw {
		rec, err := minter.DecodeRecord(b)
		if err != nil {
			t.Fatalf("decode chain record: %v", err)
		}
		out = append(out, rec)
	}
	return out
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "../../.."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repo root from %s: %v", wd, err)
	}
	return root
}

// TestINT20_PCASWASMParity_NoSkip keeps the WASM relying-party verifier in the
// same no-skip gate package as the full-stack e2e. Missing node/wasm support is a
// hard gate failure here; CI must provision it instead of silently degrading.
func TestINT20_PCASWASMParity_NoSkip(t *testing.T) {
	wasmExecDir := filepath.Join(goRoot(t), "lib", "wasm")
	if _, err := os.Stat(filepath.Join(wasmExecDir, "go_js_wasm_exec")); err != nil {
		t.Fatalf("wasm exec shim missing: %v", err)
	}
	cmd := exec.Command("go", "run", "./ee/rpverify/wasm")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "PATH="+wasmExecDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PCAS wasm verifier failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "epoch=2 ok=true") {
		t.Fatalf("unexpected PCAS wasm verifier output:\n%s", out)
	}
}
