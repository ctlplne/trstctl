// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"bytes"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	eepqc "trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
	"trstctl.com/trstctl/internal/succession/background"
	pcasissuer "trstctl.com/trstctl/internal/succession/issuer"
	pcaskem "trstctl.com/trstctl/internal/succession/kem"
	"trstctl.com/trstctl/internal/succession/minter"
	pcasmonitor "trstctl.com/trstctl/internal/succession/monitor"
	pcasorch "trstctl.com/trstctl/internal/succession/orchestrator"
	"trstctl.com/trstctl/internal/succession/recovery"
	"trstctl.com/trstctl/internal/succession/retirement"
	"trstctl.com/trstctl/internal/succession/staple"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
	"trstctl.com/trstctl/internal/translog"
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
	signAuthz *crypto.SignAuthorizer
	keyDir    string
	tenantID  string
	features  *featureRecorder
	closeSign func()
}

type staticSignerProvider struct{ c *signing.Client }

func (p staticSignerProvider) Client() *signing.Client { return p.c }

type int20PCASLeafIssuer func(context.Context, string, string, []byte, []byte, time.Duration, crypto.CertificateExtension) ([]byte, error)

func (f int20PCASLeafIssuer) IssuePCASLeaf(ctx context.Context, tenantID, handle string,
	expectedCACertDER, csrDER []byte, ttl time.Duration, extension crypto.CertificateExtension) ([]byte, error) {
	return f(ctx, tenantID, handle, expectedCACertDER, csrDER, ttl, extension)
}

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

	if kemID == "" || len(genesis.TrustRootAtt) == 0 || len(trustRoot) == 0 {
		t.Fatal("full-stack e2e did not retain core journey evidence")
	}
}

// The deployed control plane cannot write into the signer's nested key-store
// volume. A configured delegation must still be usable by the isolated signer.
func TestINT20_DelegationScopeCrossesIsolatedSignerBoundary(t *testing.T) {
	st := startINT20Stack(t)
	defer st.close()
	const scopeID = "int20-isolated-scope"
	svc := succapi.NewService(st.store, st.log, st.outbox,
		succapi.WithKEMCustody(st.signer))
	accepted, err := svc.ConfigureDelegationScope(st.ctx, st.tenantID,
		succapi.DelegationScopeRequest{ScopeID: scopeID, EpochFloor: 1})
	if err != nil {
		t.Fatalf("configure isolated delegation scope: %v", err)
	}
	if accepted.Status != "queued" || accepted.RequestID == "" {
		t.Fatalf("unconfirmed signer state was reported as ready: %+v", accepted)
	}
	st.dispatchAll(t)
	status, found, err := svc.GetRequestStatus(st.ctx, st.tenantID, accepted.RequestID)
	if err != nil || !found || status.Status != "delivered" || status.Kind != "delegation_scope" {
		t.Fatalf("signer-confirmed request status: %+v found=%v err=%v", status, found, err)
	}
	var queuedPayload []byte
	if err := st.store.WithTenant(st.ctx, st.tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(st.ctx, `SELECT payload FROM outbox
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  AND destination = $1 AND idempotency_key = $2`, pcasorch.DelegationScopeDestination, accepted.RequestID).
			Scan(&queuedPayload)
	}); err != nil {
		t.Fatalf("read queued command for lost-response replay: %v", err)
	}
	if err := pcasorch.NewDelegationWorker(st.store, st.log, st.signer).Deliver(st.ctx, coreorch.Message{
		TenantID: st.tenantID, Destination: pcasorch.DelegationScopeDestination, Payload: queuedPayload,
	}); err != nil {
		t.Fatalf("exact lost-response replay: %v", err)
	}
	projected, err := st.repo.ListDelegationScopes(st.ctx, st.tenantID)
	if err != nil || len(projected) != 1 || projected[0].ScopeID != scopeID || projected[0].EpochFloor != 1 {
		t.Fatalf("signer-confirmed serving projection: %+v err=%v", projected, err)
	}
	view, err := svc.ListDelegationScopes(st.ctx, st.tenantID)
	if err != nil || view.Count != 1 || !view.Scopes[0].SignerConfirmed || len(view.Scopes[0].SignerReceipt) == 0 {
		t.Fatalf("operator signer-confirmed readback: %+v err=%v", view, err)
	}
	projection := pcasstore.NewDelegationProjection(st.store)
	if err := projection.Reset(st.ctx); err != nil {
		t.Fatalf("reset projection before cold replay: %v", err)
	}
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error { return projection.Apply(st.ctx, ev) }); err != nil {
		t.Fatalf("replay signed delegation receipt: %v", err)
	}
	projected, err = st.repo.ListDelegationScopes(st.ctx, st.tenantID)
	if err != nil || len(projected) != 1 || projected[0].EpochFloor != 1 {
		t.Fatalf("cold projection readback: %+v err=%v", projected, err)
	}
	const identity = "spiffe://int20.example/workload/isolated-delegation"
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(identity, 0)); err != nil {
		t.Fatalf("generate predecessor key: %v", err)
	}
	if _, err := st.signer.MintSuccessor(st.ctx, signing.MintRequest{
		IdentityID: identity, TenantID: st.tenantID, DeploymentScope: "spiffe://int20.example",
		PredecessorHandle: succession.KeyHandle(identity, 0), AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:int20-isolated-delegation",
		DelegationScope: scopeID,
	}); err != nil {
		t.Fatalf("isolated signer did not enforce configured delegation: %v", err)
	}
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	if err := st.store.UpsertTenant(st.ctx, corestore.Tenant{TenantID: otherTenant, Name: "INT20 Other Tenant", EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	otherView, err := svc.ListDelegationScopes(st.ctx, otherTenant)
	if err != nil || otherView.Count != 0 {
		t.Fatalf("other tenant saw delegation scope: %+v err=%v", otherView, err)
	}
	const otherIdentity = "spiffe://int20.example/workload/other-tenant"
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(otherIdentity, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.signer.MintSuccessor(st.ctx, signing.MintRequest{
		IdentityID: otherIdentity, TenantID: otherTenant, DeploymentScope: "spiffe://int20.example",
		PredecessorHandle: succession.KeyHandle(otherIdentity, 0), AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:int20-cross-tenant",
		DelegationScope: scopeID,
	}); err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("cross-tenant scope reuse was accepted: %v", err)
	}
	if _, err := svc.ConfigureDelegationScope(st.ctx, otherTenant,
		succapi.DelegationScopeRequest{ScopeID: scopeID, EpochFloor: 0}); err != nil {
		t.Fatalf("configure same scope for distinct tenant: %v", err)
	}
	st.dispatchAll(t)
	if _, err := st.signer.MintSuccessor(st.ctx, signing.MintRequest{
		IdentityID: otherIdentity, TenantID: otherTenant, DeploymentScope: "spiffe://int20.example",
		PredecessorHandle: succession.KeyHandle(otherIdentity, 0), AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:int20-other-tenant",
		DelegationScope: scopeID,
	}); err != nil {
		t.Fatalf("other tenant scope did not enforce its independent floor: %v", err)
	}
	raised, err := svc.RaiseDelegationFloor(st.ctx, st.tenantID, succapi.DelegationFloorRequest{ScopeID: scopeID, EpochFloor: 3})
	if err != nil {
		t.Fatal(err)
	}
	st.dispatchAll(t)
	status, found, err = svc.GetRequestStatus(st.ctx, st.tenantID, raised.RequestID)
	if err != nil || !found || status.Status != "delivered" || status.Kind != "delegation_floor" {
		t.Fatalf("raised floor status: %+v found=%v err=%v", status, found, err)
	}
	var firstScopeEvent events.Event
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error {
		if ev.Type == succession.TypeDelegationApplied && firstScopeEvent.ID == "" {
			firstScopeEvent = ev
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if firstScopeEvent.ID == "" {
		t.Fatal("signed delegation event absent")
	}
	if err := projection.Apply(st.ctx, firstScopeEvent); err != nil {
		t.Fatalf("old tail event after newer floor: %v", err)
	}
	projected, err = st.repo.ListDelegationScopes(st.ctx, st.tenantID)
	if err != nil || len(projected) != 1 || projected[0].EpochFloor != 3 {
		t.Fatalf("old tail event regressed signer floor: %+v err=%v", projected, err)
	}
	const blockedIdentity = "spiffe://int20.example/workload/below-floor"
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(blockedIdentity, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.signer.MintSuccessor(st.ctx, signing.MintRequest{
		IdentityID: blockedIdentity, TenantID: st.tenantID, DeploymentScope: "spiffe://int20.example",
		PredecessorHandle: succession.KeyHandle(blockedIdentity, 0), AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:int20-below-floor", DelegationScope: scopeID,
	}); err == nil || !strings.Contains(err.Error(), "delegated-authority") {
		t.Fatalf("signer ignored raised floor: %v", err)
	}
}

func startINT20Stack(t *testing.T, logOptions ...events.OpenOption) *int20Stack {
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

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}, logOptions...)
	if err != nil {
		t.Fatalf("open embedded JetStream: %v", err)
	}

	signer, stopSign, keyDir, signAuthz := startLicensedSignerSubprocess(t)
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
	// Test-only bridge exercises the API's extension routing over the real
	// isolated signer. The served hierarchy test separately proves profile,
	// source event and inventory behavior of the production bridge.
	bridge := int20PCASLeafIssuer(func(ctx context.Context, _ string, handle string,
		expectedCACertDER, csrDER []byte, ttl time.Duration, extension crypto.CertificateExtension) ([]byte, error) {
		ca, err := signer.SignerForDualControlHandle(ctx, handle, signing.PurposeCASign, signAuthz)
		if err != nil {
			return nil, err
		}
		if err := crypto.VerifyCertificateSigner(expectedCACertDER, ca.Public()); err != nil {
			return nil, err
		}
		return crypto.SignLeafFromCSRWithProfile(expectedCACertDER, ca, csrDER, ttl,
			crypto.LeafProfile{ExtraExtensions: []crypto.CertificateExtension{extension}})
	})
	svc := succapi.NewService(cs, log, outbox, succapi.WithKEMCustody(signer), succapi.WithManagedLeafIssuer(bridge))

	st := &int20Stack{
		ctx: ctx, store: cs, repo: pcasstore.New(cs), log: log, outbox: outbox,
		handler: handler, svc: svc, signer: signer, signAuthz: signAuthz, keyDir: keyDir, tenantID: int20Tenant,
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

func (st *int20Stack) requestSuccessionChain(t *testing.T) (string, succession.GenesisRecord, []byte) {
	t.Helper()
	const id = "spiffe://int20.example/workload/core"
	if _, err := st.svc.RegisterGenesis(st.ctx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: id, Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://int20.example",
	}); err != nil {
		t.Fatalf("register genesis: %v", err)
	}
	st.dispatchAll(t)
	initial, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || initial.Genesis == nil || len(initial.TrustRootPublicDER) == 0 {
		t.Fatalf("registered genesis readback: %+v, %v", initial, err)
	}
	genesis := *initial.Genesis
	trustRoot := initial.TrustRootPublicDER

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
		TrustRootPubDER: trustRoot, Genesis: genesis, Chain: chain,
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
	st.dispatchAll(t)
	if _, err := st.svc.ConfigureDelegationScope(st.ctx, st.tenantID, succapi.DelegationScopeRequest{ScopeID: "app", ParentScopeID: "root"}); err != nil {
		t.Fatalf("configure app delegation scope: %v", err)
	}
	st.dispatchAll(t)
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
	predHandle := succession.TenantKeyHandle(st.tenantID, id, 0)
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, predHandle); err != nil {
		t.Fatalf("KEM predecessor: %v", err)
	}
	resp, err := st.svc.RequestKEMRewrap(st.ctx, st.tenantID, succapi.KEMRewrapRequest{
		IdentityID: id, PredecessorHandle: predHandle, PredecessorEpoch: 0,
		SuccessorSignHandle: succession.TenantKeyHandle(st.tenantID, id, 1), SuccessorKEMHandle: "kem:" + id + ":1",
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
	st.runWorkersUntil(t, config.PCAS{Retirement: config.PCASRetirement{Enabled: true, Interval: "1h", ValidityWindow: "1h"}}, func() (bool, error) {
		retired, found, err := st.svc.RetirementStatus(st.ctx, st.tenantID, id, 0)
		return found && retired.Status == "retired", err
	})
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
	// An offline/dual-control CA can be valid and tenant-owned, but a PCAS API
	// instance without the managed-CA bridge cannot obtain its per-sign approval.
	// Refuse registration before claiming an issuer is ready; the signer also
	// enforces the rule independently.
	protectedHandle := "int20-protected-issuer-ca"
	protected, err := st.signer.GenerateDualControlKeyHandle(st.ctx, crypto.ECDSAP256,
		protectedHandle, []signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, st.signAuthz)
	if err != nil {
		t.Fatalf("generate protected issuer CA: %v", err)
	}
	protectedDER, err := crypto.SelfSignedCACert(protected, "trstctl INT20 protected PCAS CA", time.Hour)
	if err != nil {
		t.Fatalf("self-sign protected CA: %v", err)
	}
	if _, err := st.store.InsertCAAuthority(st.ctx, corestore.CAAuthority{
		TenantID: st.tenantID, CommonName: "trstctl INT20 protected PCAS CA", Kind: "root", Serial: "int20-protected-issuer-ca-serial",
		CertificatePEM: string(crypto.EncodeCertificatePEM(protectedDER)), SignerHandle: protectedHandle,
	}); err != nil {
		t.Fatalf("seed protected CA authority: %v", err)
	}
	noBridge := succapi.NewService(st.store, st.log, st.outbox, succapi.WithKEMCustody(st.signer))
	if _, err := noBridge.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-protected-ca", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: protectedHandle, CACertDER: protectedDER,
	}); err == nil || !strings.Contains(err.Error(), "dual-control") {
		t.Fatalf("direct issuer registration accepted a dual-control key without an approval path: %v", err)
	}
	caHandle := "int20-issuer-ca"
	ca, err := st.signer.GenerateConstrainedKeyHandle(st.ctx, crypto.ECDSAP256, caHandle, []signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("generate issuer CA: %v", err)
	}
	caDER, err := crypto.SelfSignedCACert(ca, "trstctl INT20 PCAS CA", time.Hour)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	if _, err := st.store.InsertCAAuthority(st.ctx, corestore.CAAuthority{
		TenantID: st.tenantID, CommonName: "trstctl INT20 PCAS CA", Kind: "root", Serial: "int20-issuer-ca-serial",
		// A managed authority can retain a public PEM chain. Registration must
		// bind its first certificate to signer custody without treating the
		// remaining public certificate blocks as a private or ambiguous root.
		CertificatePEM: string(append(crypto.EncodeCertificatePEM(caDER), crypto.EncodeCertificatePEM(caDER)...)), SignerHandle: caHandle,
	}); err != nil {
		t.Fatalf("seed tenant-bound CA authority: %v", err)
	}
	if _, err := noBridge.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-no-managed-path", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: caHandle, CACertDER: caDER,
	}); err == nil || !strings.Contains(err.Error(), "managed CA issuance path is unavailable") {
		t.Fatalf("issuer registration promised leaf issuance without a managed-CA path: %v", err)
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-unobserved-epoch", IdentityID: checkpointIdentity, CurrentEpoch: 99,
		CAKeyHandle: caHandle, CACertDER: caDER,
	}); err == nil {
		t.Fatal("issuer registration accepted an epoch absent from the PCAS chain")
	}
	otherCert, err := crypto.SelfSignedCACert(ca, "different certificate for same key", time.Hour)
	if err != nil {
		t.Fatalf("make mismatched CA certificate: %v", err)
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-wrong-ca-certificate", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: caHandle, CACertDER: otherCert,
	}); err == nil {
		t.Fatal("issuer registration accepted a CA certificate outside its tenant authority row")
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, "22222222-2222-4222-8222-222222222222", succapi.IssuerAuthorityRequest{
		IssuerID: "int20-other-tenant", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: caHandle, CACertDER: caDER,
	}); err == nil {
		t.Fatal("issuer registration accepted another tenant's identity and CA handle")
	}
	issuerCommand := succapi.IssuerAuthorityRequest{
		IssuerID: "int20-ca", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: caHandle, CACertDER: caDER, OperationID: "int20-issuer-registration",
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, issuerCommand); err != nil {
		t.Fatalf("register issuer: %v", err)
	}
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, issuerCommand); err != nil {
		t.Fatalf("retry issuer after uncertain response: %v", err)
	}
	conflictingCommand := issuerCommand
	conflictingCommand.IssuerID = "int20-reused-command-id"
	if _, err := st.svc.RegisterIssuerAuthority(st.ctx, st.tenantID, conflictingCommand); err == nil {
		t.Fatal("issuer command idempotency key accepted a different issuer")
	}
	var sourceEvent bool
	var sourceEvents int
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error {
		if ev.Type == "nhi.issuer.authority.registered" && ev.TenantID == st.tenantID {
			sourceEvents++
			var payload struct {
				IssuerID string `json:"issuer_id"`
			}
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return err
			}
			sourceEvent = payload.IssuerID == "int20-ca"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !sourceEvent {
		t.Fatal("issuer authority was served without an immutable source event")
	}
	if sourceEvents != 1 {
		t.Fatalf("issuer retry appended %d source events, want one", sourceEvents)
	}
	proj := pcasstore.NewIssuerAuthorityProjection(st.store)
	if err := proj.Reset(st.ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, err := st.repo.GetIssuerAuthority(st.ctx, st.tenantID, "int20-ca"); err != nil || found {
		t.Fatalf("issuer after projection reset: found=%t err=%v", found, err)
	}
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error { return proj.Apply(st.ctx, ev) }); err != nil {
		t.Fatal(err)
	}
	if _, found, err := st.repo.GetIssuerAuthority(st.ctx, st.tenantID, "int20-ca"); err != nil || !found {
		t.Fatalf("issuer after source replay: found=%t err=%v", found, err)
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

	records, err := st.repo.ListRecords(st.ctx, st.tenantID)
	if err != nil {
		t.Fatalf("list checkpoint inputs: %v", err)
	}
	wanted := make(map[string]uint64)
	for _, record := range records {
		if record.Epoch > wanted[record.IdentityID] {
			wanted[record.IdentityID] = record.Epoch
		}
	}
	if len(wanted) == 0 {
		t.Fatal("checkpoint worker has no recorded identities")
	}
	st.runWorkersUntil(t, config.PCAS{Checkpoints: config.PCASCheckpoints{
		Enabled: true, Interval: "1h", SigningKeyHandle: "int20-checkpoint", SigningAlgorithm: string(crypto.ECDSAP256),
	}}, func() (bool, error) {
		for identity, epoch := range wanted {
			checkpoint, found, err := st.svc.LatestCheckpoint(st.ctx, st.tenantID, identity)
			if err != nil || !found || checkpoint.Epoch < epoch {
				return false, err
			}
		}
		return true, nil
	})
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
	// A source event from an older build may already name a protected CA. Cold
	// replay must not make either direct leaf path bypass its signer policy.
	legacy, err := succession.Encode(succession.IssuerAuthorityRegisteredV1{
		TenantID: st.tenantID, IssuerID: "int20-legacy-protected-ca", IdentityID: checkpointIdentity,
		CurrentEpoch: 1, CAKeyHandle: protectedHandle, CACertDER: protectedDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := st.log.Append(st.ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.repo.ApplyIssuerAuthorityEvent(st.ctx, recorded); err != nil {
		t.Fatal(err)
	}
	if _, err := noBridge.IssueIssuerLeaf(st.ctx, st.tenantID, succapi.IssueLeafRequest{
		IssuerID: "int20-legacy-protected-ca", CSRDER: leafCSR(t),
	}); err == nil || !strings.Contains(err.Error(), "managed CA issuance path is unavailable") {
		t.Fatalf("legacy protected issuer direct leaf was not refused: %v", err)
	}
	if _, err := noBridge.IssueStapledLeaf(st.ctx, st.tenantID, succapi.IssueStapledLeafRequest{
		IssuerID: "int20-legacy-protected-ca", CSRDER: leafCSR(t), CheckpointIdentityID: checkpointIdentity,
	}); err == nil || !strings.Contains(err.Error(), "managed CA issuance path is unavailable") {
		t.Fatalf("legacy protected issuer stapled leaf was not refused: %v", err)
	}
	var bridgedCalls int
	bridge := int20PCASLeafIssuer(func(_ context.Context, tenantID, handle string,
		expectedCACertDER, csrDER []byte, ttl time.Duration, extension crypto.CertificateExtension) ([]byte, error) {
		if tenantID != st.tenantID || handle != protectedHandle || !bytes.Equal(expectedCACertDER, protectedDER) {
			return nil, errors.New("PCAS bridge received an unbound CA")
		}
		bridgedCalls++
		return crypto.SignLeafFromCSRWithProfile(protectedDER, protected, csrDER, ttl,
			crypto.LeafProfile{ExtraExtensions: []crypto.CertificateExtension{extension}})
	})
	bridged := succapi.NewService(st.store, st.log, st.outbox,
		succapi.WithKEMCustody(st.signer), succapi.WithManagedLeafIssuer(bridge))
	if _, err := bridged.RegisterIssuerAuthority(st.ctx, st.tenantID, succapi.IssuerAuthorityRequest{
		IssuerID: "int20-protected-with-bridge", IdentityID: checkpointIdentity, CurrentEpoch: 1,
		CAKeyHandle: protectedHandle, CACertDER: protectedDER,
	}); err != nil {
		t.Fatalf("managed-CA bridge did not permit the protected issuer: %v", err)
	}
	bridgedLeaf, err := bridged.IssueIssuerLeaf(st.ctx, st.tenantID, succapi.IssueLeafRequest{
		IssuerID: "int20-protected-with-bridge", CSRDER: leafCSR(t), RotationVersion: 7, TTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("protected issuer leaf through managed-CA bridge: %v", err)
	}
	issuerID, epoch, rotation, err := pcasissuer.ParseAuthorityEpoch(bridgedLeaf.CertDER)
	if err != nil || issuerID != "int20-protected-with-bridge" || epoch != 1 || rotation != 7 {
		t.Fatalf("bridged issuer tuple = %q/%d/%d, err=%v", issuerID, epoch, rotation, err)
	}
	bridgedStapled, err := bridged.IssueStapledLeaf(st.ctx, st.tenantID, succapi.IssueStapledLeafRequest{
		IssuerID: "int20-protected-with-bridge", CSRDER: leafCSR(t), CheckpointIdentityID: checkpointIdentity,
	})
	if err != nil {
		t.Fatalf("protected stapled leaf through managed-CA bridge: %v", err)
	}
	if _, found, err := staple.AttachmentFromCertificate(bridgedStapled.CertDER); err != nil || !found {
		t.Fatalf("bridged stapled leaf lacks inline attachment: found=%t err=%v", found, err)
	}
	if bridgedCalls != 2 {
		t.Fatalf("managed-CA bridge calls = %d, want issuer and stapled leaves", bridgedCalls)
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
	const localDeploymentID = "spiffe://int20.example/federation-authority"
	if _, err := st.svc.RegisterGenesis(st.ctx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: localDeploymentID, DeploymentScope: "spiffe://int20.example",
		Algorithm: string(crypto.ECDSAP256),
	}); err != nil {
		t.Fatalf("register tenant federation authority genesis: %v", err)
	}
	st.dispatchAll(t)
	const otherTenant = "22222222-2222-4222-8222-222222222222"
	foreignHandle := succession.TenantKeyHandle(otherTenant, "spiffe://other.example/federation-authority", 0)
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, foreignHandle); err != nil {
		t.Fatalf("provision another tenant's local authority key: %v", err)
	}
	localHandle := succession.TenantKeyHandle(st.tenantID, localDeploymentID, 0)
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
		ForeignDeploymentID: foreign.Genesis.DeploymentScope, LocalDeploymentID: localDeploymentID,
		LocalAuthorityHandle: foreignHandle, IdentityID: foreign.Genesis.IdentityID,
		ForeignTrustRootDER: foreign.TrustRootPubDER, LocalBaseEpoch: 100,
		ForeignGenesis: foreignGenesis, ForeignChain: foreignChain,
	}); err == nil {
		t.Fatal("federation import accepted another tenant's signer-held authority handle")
	}
	if _, err := st.svc.RequestFederationImport(st.ctx, st.tenantID, succapi.FederationImportRequest{
		ForeignDeploymentID: foreign.Genesis.DeploymentScope, LocalDeploymentID: localDeploymentID,
		LocalAuthorityHandle: localHandle, IdentityID: foreign.Genesis.IdentityID,
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
			foreign.Genesis.DeploymentScope).Scan(&bridgeCount)
	}); err != nil {
		t.Fatalf("count federation bridges: %v", err)
	}
	if bridgeCount != 1 {
		t.Fatalf("federation bridge count = %d, want 1", bridgeCount)
	}
	var bridgeEvents int
	var bridgeEvent events.Event
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error {
		if ev.Type == "nhi.federation.bridge.imported" && ev.TenantID == st.tenantID {
			bridgeEvents++
			bridgeEvent = ev
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bridgeEvents != 1 {
		t.Fatalf("verified bridge has %d immutable source events, want 1", bridgeEvents)
	}
	projection := pcasstore.NewFederationBridgeProjection(st.store)
	if err := projection.Reset(st.ctx); err != nil {
		t.Fatalf("reset federation serving projection: %v", err)
	}
	if bridges, err := st.repo.ListFederationBridges(st.ctx, st.tenantID); err != nil || len(bridges) != 0 {
		t.Fatalf("bridge remained after read-model reset: count=%d err=%v", len(bridges), err)
	}
	if err := projection.Apply(st.ctx, bridgeEvent); err != nil {
		t.Fatalf("replay verified bridge event: %v", err)
	}
	if bridges, err := st.repo.ListFederationBridges(st.ctx, st.tenantID); err != nil || len(bridges) != 1 {
		t.Fatalf("verified bridge not restored by replay: count=%d err=%v", len(bridges), err)
	}

	badRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.svc.RequestFederationImport(st.ctx, st.tenantID, succapi.FederationImportRequest{
		ForeignDeploymentID: "foreign-bad", LocalDeploymentID: localDeploymentID,
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
	if len(cp.SignerPublicDER) == 0 || !bytes.Equal(cp.SignerPublicDER, signed.SignerPublicDER) {
		t.Fatal("checkpoint readback lost the persisted signer public key")
	}
	cpSigner, err := st.signer.SignerForHandleWithPurpose(st.ctx, "int20-checkpoint", signing.PurposeGeneric)
	if err != nil {
		t.Fatalf("checkpoint signer: %v", err)
	}
	if err := succession.VerifyEpochCheckpoint(cp.SignerPublicDER, signed); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	if !bytes.Equal(cp.SignerPublicDER, cpSigner.Public().DER) {
		t.Fatal("served signer key differs from the independently inspected signer key")
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

func (st *int20Stack) runWorkersUntil(t *testing.T, pcas config.PCAS, durableResult func() (bool, error)) {
	t.Helper()
	workers := background.NewWorkers(background.Options{
		Store: st.store, Log: st.log, Signer: staticSignerProvider{c: st.signer}, PCAS: pcas,
	})
	if len(workers) != 1 {
		t.Fatalf("one background worker expected, got %d", len(workers))
	}
	runWorkerUntilDurableResult(t, workers[0], durableResult)
}

func runWorkerUntilDurableResult(t *testing.T, w server.BackgroundWorker, durableResult func() (bool, error)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx) }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	for {
		select {
		case err := <-errc:
			t.Fatalf("%s stopped before its durable result: %v", w.Name(), err)
		case <-ticker.C:
			ready, err := durableResult()
			if err != nil {
				cancel()
				<-errc
				t.Fatalf("%s durable readback: %v", w.Name(), err)
			}
			if ready {
				cancel()
				err := <-errc
				if err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
					t.Fatalf("%s stop after durable result: %v", w.Name(), err)
				}
				return
			}
		case <-deadline.C:
			cancel()
			<-errc
			t.Fatalf("%s did not produce its durable result within two minutes", w.Name())
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

func startLicensedSignerSubprocess(t *testing.T) (*signing.Client, func(), string, *crypto.SignAuthorizer) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("license keypair: %v", err)
	}
	now := time.Now().UTC()
	rawLic, err := license.Sign(license.Claims{
		V: 1, ID: "pcas-int20", Customer: "PCAS INT20", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
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
	authFile := filepath.Join(dir, "sign-auth.bin")
	authz, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("create test-only dual-control authorizer: %v", err)
	}
	args := []string{"--license", licFile, "--keystore", keyDir, "--kek", kekFile, "--auth-secret", authFile}
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
		authz.Destroy()
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(socketDir)
	}, keyDir, authz
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
	cmd := exec.Command("go", "run", "./internal/rpverify/wasm")
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
