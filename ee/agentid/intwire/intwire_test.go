// SPDX-License-Identifier: LicenseRef-trstctl-EE
//go:build integration

package intwire

import (
	"bytes"
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
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/agentid/agentstack"
	agidapi "trstctl.com/trstctl/ee/agentid/api"
	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	agidorch "trstctl.com/trstctl/ee/agentid/orchestrator"
	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/ee/agentid/verify"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantIssue   = "11111111-1111-1111-1111-111111111111"
	tenantCascade = "22222222-2222-2222-2222-222222222222"
	tenantSystem  = "33333333-3333-3333-3333-333333333333"
	tenantHard    = "44444444-4444-4444-4444-444444444444"
	tenantRestart = "55555555-5555-5555-5555-555555555555"
)

func TestAGID_Wire_IssueBindsChainAndAgentStack_RealInfra(t *testing.T) {
	h := newHarness(t, tenantIssue)
	issued := h.issueAgent(t, "agent-issue", "nonce-issue")

	if len(issued.credential.CredentialDER) == 0 {
		t.Fatal("issued credential has no public DER")
	}
	if issued.chain.Count != 2 {
		t.Fatalf("chain records = %d, want 2", issued.chain.Count)
	}

	bm, err := delegation.ExtractBindingMaterial(issued.credential.CredentialDER)
	if err != nil {
		t.Fatalf("ExtractBindingMaterial: %v", err)
	}
	if !bytes.Equal(bm.AgentStackDigest, delegation.AgentStackDigestOf(issued.reprBytes)) {
		t.Fatal("credential did not bind the issued agent-stack digest")
	}
	if !bytes.Equal(bm.ChainHeadDigest, issued.headDigest) {
		t.Fatal("credential did not bind the verified chain head")
	}
	if bm.DesignatedClass != "agent-worker" {
		t.Fatalf("bound class = %q, want agent-worker", bm.DesignatedClass)
	}
	if bm.RootAnchorAuthRef != "fido2:root-auth" {
		t.Fatalf("root auth ref = %q, want fido2:root-auth", bm.RootAnchorAuthRef)
	}
	verifyOfflineToken(t, bm, issued.notBefore, issued.notAfter)
}

func TestAGID_Wire_CascadeRevokeWithEvidence_RealInfra(t *testing.T) {
	h := newHarness(t, tenantCascade)
	issued := h.issueAgent(t, "agent-cascade", "nonce-cascade")

	resp, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{
		Subject:           "manager",
		Reason:            "compromise",
		PublishDownstream: true,
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	h.drain(t, 20)

	ev, err := h.api.RevocationEvidence(h.ctx, h.tenant, resp.DirectiveID)
	if err != nil {
		t.Fatalf("RevocationEvidence: %v", err)
	}
	if !ev.Terminal {
		t.Fatalf("revocation directive is not terminal; missing=%v", ev.Missing)
	}
	if ev.JobCount != 1 || len(ev.EvidenceDigests) != 1 || len(ev.Artifact) == 0 {
		t.Fatalf("revocation proof incomplete: jobs=%d digests=%d artifact=%d", ev.JobCount, len(ev.EvidenceDigests), len(ev.Artifact))
	}
	artifact, err := revoke.DecodeAggregate(ev.Artifact)
	if err != nil {
		t.Fatalf("DecodeAggregate: %v", err)
	}
	if err := revoke.VerifyAggregateOffline(artifact, ev.EvidenceDigests); err != nil {
		t.Fatalf("VerifyAggregateOffline: %v", err)
	}
	if artifact.SubjectID != "manager" || artifact.JobCount != 1 {
		t.Fatalf("aggregate artifact = %+v, want manager/one job", artifact)
	}
	if got := h.countRows(t, `SELECT count(*) FROM agent_revocation_effects WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1`, issued.credentialID); got != 1 {
		t.Fatalf("recorded effects for credential = %d, want 1", got)
	}
}

func TestAGID_Wire_SystemE2EOfflineVerify_RealInfra(t *testing.T) {
	h := newHarness(t, tenantSystem)
	issued := h.issueAgent(t, "agent-system", "nonce-system")

	bm, err := delegation.ExtractBindingMaterial(issued.credential.CredentialDER)
	if err != nil {
		t.Fatalf("ExtractBindingMaterial: %v", err)
	}
	got := verifyOfflineToken(t, bm, issued.notBefore, issued.notAfter)
	if got.AuthorityClass != "agent-worker" || got.Operation != "read" || got.Tool != "search" {
		t.Fatalf("offline verifier result = %+v", got)
	}
}

func TestAGID_Wire_RPVerifierOffline(t *testing.T) {
	rep := agentStackRepr(t)
	bm, err := delegation.NewBindingMaterial([]byte("chain-head-digest-32-byte-value"), rep, "agent-worker", []byte("attestation"), "fido2:root-auth", nil)
	if err != nil {
		t.Fatalf("NewBindingMaterial: %v", err)
	}
	got := verifyOfflineToken(t, bm, time.Now().Add(-time.Minute).Unix(), time.Now().Add(10*time.Minute).Unix())
	if got.Operation != "read" || got.Tool != "search" {
		t.Fatalf("offline verifier result = %+v", got)
	}
}

func TestAGID_Wire_Hardening_31_32_33_RealInfra(t *testing.T) {
	h := newHarness(t, tenantHard)

	chain := signedChain(t, h.tenant, "agent-chain-only", false)
	pre := h.preconditionsWithReach(t, chain, "agent-worker")
	chainOnly := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:       h.tenant,
		TrustAnchorRef: "agent-chain-only",
		NotBefore:      time.Now().Add(-time.Minute).Unix(),
		NotAfter:       time.Now().Add(20 * time.Minute).Unix(),
		Preconditions:  pre,
	}, crypto.ECDSAP256)
	if !chainOnly.Approved {
		t.Fatalf("chain-only fallback refused: %s", string(chainOnly.RefusalRecord))
	}
	bm, err := delegation.DecodeBindingMaterial(chainOnly.BindingMaterial)
	if err != nil {
		t.Fatalf("DecodeBindingMaterial(chain-only): %v", err)
	}
	if len(bm.AgentStackDigest) != 0 || len(bm.ChainHeadDigest) == 0 {
		t.Fatalf("chain-only binding = %+v, want chain head and no stack", bm)
	}

	attPayload := h.signedAttestation(t, "agent-stack-only", "nonce-stack-only")
	attBody := attestationBody(t, "software", attPayload)
	stackOnly := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:          h.tenant,
		TrustAnchorRef:    "agent-stack-only",
		NotBefore:         time.Now().Add(-time.Minute).Unix(),
		NotAfter:          time.Now().Add(20 * time.Minute).Unix(),
		SubjectRepr:       agentStackRepr(t),
		Attestation:       attBody,
		AttestationMethod: "software",
	}, crypto.ECDSAP256)
	if !stackOnly.Approved {
		t.Fatalf("agent-stack-only fallback refused: %s", string(stackOnly.RefusalRecord))
	}
	bm, err = delegation.DecodeBindingMaterial(stackOnly.BindingMaterial)
	if err != nil {
		t.Fatalf("DecodeBindingMaterial(stack-only): %v", err)
	}
	if len(bm.ChainHeadDigest) != 0 || len(bm.AgentStackDigest) == 0 || len(bm.AttestationDigest) == 0 {
		t.Fatalf("stack-only binding = %+v, want stack+attestation and no chain", bm)
	}

	h.restartControlPlane(t)
	issued := h.issueAgent(t, "agent-hardening", "nonce-hardening")
	rev, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{Subject: "manager", Reason: "compromise"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	h.drain(t, 20)
	ev, err := h.api.RevocationEvidence(h.ctx, h.tenant, rev.DirectiveID)
	if err != nil {
		t.Fatalf("RevocationEvidence: %v", err)
	}
	artifact, err := revoke.DecodeAggregate(ev.Artifact)
	if err != nil {
		t.Fatalf("DecodeAggregate: %v", err)
	}
	if err := revoke.VerifyAggregateOffline(artifact, ev.EvidenceDigests); err != nil {
		t.Fatalf("AGID-claim-33 aggregate proof did not verify: %v", err)
	}
	if got := h.countRows(t, `SELECT count(*) FROM agent_revocation_effects WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1`, issued.credentialID); got != 1 {
		t.Fatalf("AGID-claim-33 effect rows = %d, want 1", got)
	}
}

func TestAGID_Wire_VerifyChainInRealSignerBeforeKeygen(t *testing.T) {
	h := newHarness(t, tenantHard)

	valid := signedChain(t, h.tenant, "agent-valid", false)
	okDecision := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:       h.tenant,
		TrustAnchorRef: "agent-valid",
		NotBefore:      time.Now().Add(-time.Minute).Unix(),
		NotAfter:       time.Now().Add(20 * time.Minute).Unix(),
		Preconditions:  h.preconditionsWithReach(t, valid, "agent-worker"),
	}, crypto.ECDSAP256)
	if !okDecision.Approved || len(okDecision.EncodedRecord) == 0 {
		t.Fatalf("valid signer-gated issue refused: approved=%v refusal=%s", okDecision.Approved, string(okDecision.RefusalRecord))
	}

	widened := signedChain(t, h.tenant, "agent-widened", true)
	pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{Chain: widened, DesignatedClass: "agent-worker"})
	if err != nil {
		t.Fatalf("EncodePreconditionsBody: %v", err)
	}
	badDecision := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:       h.tenant,
		TrustAnchorRef: "agent-widened",
		NotBefore:      time.Now().Add(-time.Minute).Unix(),
		NotAfter:       time.Now().Add(20 * time.Minute).Unix(),
		Preconditions:  pre,
	}, crypto.ECDSAP256)
	if badDecision.Approved {
		t.Fatal("widened delegation chain was approved by the real signer")
	}
	if len(badDecision.EncodedRecord) != 0 || len(badDecision.CredentialPublicDER) != 0 {
		t.Fatal("refused widened chain returned public credential material")
	}
}

func TestAGID_Restart_CascadeResumesNoDouble(t *testing.T) {
	h := newHarness(t, tenantRestart)
	h.issueAgent(t, "agent-resume", "nonce-resume")
	rev, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{Subject: "manager", Reason: "compromise"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	h.dispatchDirectiveOnly(t)
	jobsBefore := h.countRows(t, `SELECT count(*) FROM agent_revocation_jobs WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND directive_id = $1`, rev.DirectiveID)
	if jobsBefore != 1 {
		t.Fatalf("jobs before restart = %d, want 1", jobsBefore)
	}
	h.restartControlPlane(t)
	h.drain(t, 20)
	effects := h.countRows(t, `SELECT count(*) FROM agent_revocation_effects WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND directive_id = $1`, rev.DirectiveID)
	if effects != jobsBefore {
		t.Fatalf("effects after resume = %d, want %d", effects, jobsBefore)
	}
	h.drain(t, 20)
	effectsAgain := h.countRows(t, `SELECT count(*) FROM agent_revocation_effects WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND directive_id = $1`, rev.DirectiveID)
	if effectsAgain != effects {
		t.Fatalf("effects after repeat drain = %d, want %d", effectsAgain, effects)
	}
}

func TestAGID_Restart_DirectiveAndJobsSurvive(t *testing.T) {
	h := newHarness(t, tenantRestart)
	h.issueAgent(t, "agent-survive", "nonce-survive")
	rev, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{Subject: "manager", Reason: "compromise"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	h.dispatchDirectiveOnly(t)
	h.restartControlPlane(t)

	jobs := h.countRows(t, `SELECT count(*) FROM agent_revocation_jobs WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND directive_id = $1`, rev.DirectiveID)
	if jobs != 1 {
		t.Fatalf("persisted jobs after restart = %d, want 1", jobs)
	}
	inc, err := h.api.IncompleteJobs(h.ctx, h.tenant, rev.DirectiveID)
	if err != nil {
		t.Fatalf("IncompleteJobs: %v", err)
	}
	if inc.Count != 1 {
		t.Fatalf("incomplete jobs after restart = %d, want 1", inc.Count)
	}
}

func TestAGID_Restart_SpentNonceHoldsAcrossRestart(t *testing.T) {
	h := newHarness(t, tenantRestart)
	chain := signedChain(t, h.tenant, "agent-nonce", false)
	pre := h.preconditionsWithReach(t, chain, "agent-worker")
	repr := agentStackRepr(t)
	payload := h.signedAttestation(t, "agent-nonce", "nonce-restart-spent")
	attBody := attestationBody(t, "software", payload)

	first := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:          h.tenant,
		TrustAnchorRef:    "agent-nonce",
		NotBefore:         time.Now().Add(-time.Minute).Unix(),
		NotAfter:          time.Now().Add(20 * time.Minute).Unix(),
		Preconditions:     pre,
		SubjectRepr:       repr,
		Attestation:       attBody,
		AttestationMethod: "software",
	}, crypto.ECDSAP256)
	if !first.Approved {
		t.Fatalf("first nonce use refused: %s", string(first.RefusalRecord))
	}
	h.restartSigner(t)
	second := h.gatedIssue(t, signing.IssuancePreconditions{
		TenantID:          h.tenant,
		TrustAnchorRef:    "agent-nonce",
		NotBefore:         time.Now().Add(-time.Minute).Unix(),
		NotAfter:          time.Now().Add(20 * time.Minute).Unix(),
		Preconditions:     pre,
		SubjectRepr:       repr,
		Attestation:       attBody,
		AttestationMethod: "software",
	}, crypto.ECDSAP256)
	if second.Approved {
		t.Fatal("spent attestation nonce was accepted after signer restart")
	}
	if len(second.EncodedRecord) != 0 || len(second.CredentialPublicDER) != 0 {
		t.Fatal("spent nonce refusal returned public credential material")
	}
}

type harness struct {
	ctx      context.Context
	tenant   string
	store    *corestore.Store
	log      *events.Log
	outbox   *coreorch.Outbox
	api      agidapi.Service
	handler  editionseam.LicensedOutboxHandler
	client   *signing.Client
	stopSign func()

	bin      string
	keystore string
	kekFile  string
	attestor crypto.Signer
}

type issuedAgent struct {
	credentialID string
	credential   agidapi.CredentialResponse
	chain        agidapi.ChainResponse
	reprBytes    []byte
	headDigest   []byte
	notBefore    int64
	notAfter     int64
}

func newHarness(t *testing.T, tenant string) *harness {
	t.Helper()
	ctx := context.Background()
	dsn, stopPG := startPostgres(t)
	t.Cleanup(stopPG)

	dbName := fmt.Sprintf("agid_intwire_%d", time.Now().UnixNano())
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
	st.WithExtraMigrations(agidstore.MigrationsFS())
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{
		Mode:       config.NATSEmbedded,
		StoreDir:   filepath.Join(t.TempDir(), "nats"),
		SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open embedded NATS: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	h := &harness{
		ctx:      ctx,
		tenant:   tenant,
		store:    st,
		log:      log,
		outbox:   newTestOutbox(st),
		bin:      buildSignerBinary(t),
		keystore: filepath.Join(t.TempDir(), "keystore"),
		kekFile:  filepath.Join(t.TempDir(), "signer.kek"),
	}
	rootKey := generateSigner(t)
	h.api = agidapi.NewServiceWithRootAnchorProvisioner(st, log, h.outbox, delegation.NewDurableAnchorStore(h.keystore))
	if _, err := h.api.RegisterRootAnchor(ctx, tenant, agidapi.RootAnchorRequest{
		KeyID:     "root-key",
		PublicDER: rootKey.Public().DER,
		AuthRef:   "fido2:root-auth",
	}); err != nil {
		t.Fatalf("RegisterRootAnchor: %v", err)
	}
	chainKeys[t.Name()+tenant] = rootKey

	h.attestor = generateSigner(t)
	if err := delegation.NewDurableAttestationTrustStore(h.keystore).PutVerifier(ctx, "attestor-1", h.attestor.Public().DER); err != nil {
		t.Fatalf("PutVerifier: %v", err)
	}
	h.startSigner(t)
	h.restartControlPlane(t)
	return h
}

func (h *harness) issueAgent(t *testing.T, agentID, nonce string) issuedAgent {
	t.Helper()
	chain := signedChain(t, h.tenant, agentID, false)
	pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{Chain: chain, DesignatedClass: "agent-worker"})
	if err != nil {
		t.Fatalf("EncodePreconditionsBody: %v", err)
	}
	repr := agentStackRepr(t)
	payload := h.signedAttestation(t, agentID, nonce)
	attBody := attestationBody(t, "software", payload)
	resp, err := h.api.IssueChainBound(h.ctx, h.tenant, agidapi.IssueChainBoundRequest{
		AgentID:           agentID,
		TrustAnchorRef:    agentID,
		DesignatedClass:   "agent-worker",
		Chain:             pre,
		AgentStackRepr:    repr,
		Attestation:       attBody,
		AttestationMethod: "software",
		TTLSeconds:        1200,
	})
	if err != nil {
		t.Fatalf("IssueChainBound: %v", err)
	}
	h.drain(t, 20)
	credentialID := h.latestCredentialID(t, agentID)
	if credentialID == "" {
		t.Fatalf("queued issuance %q did not record an issued credential", resp.IssuanceID)
	}
	cred, err := h.api.FetchCredential(h.ctx, h.tenant, credentialID)
	if err != nil {
		t.Fatalf("FetchCredential: %v", err)
	}
	if !cred.Found {
		t.Fatalf("credential %q not found after outbox drain", credentialID)
	}
	ch, err := h.api.FetchChain(h.ctx, h.tenant, credentialID)
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	head, err := chain[len(chain)-1].Record.Digest(nil)
	if err != nil {
		t.Fatalf("chain head digest: %v", err)
	}
	return issuedAgent{
		credentialID: credentialID,
		credential:   cred,
		chain:        ch,
		reprBytes:    repr,
		headDigest:   head,
		notBefore:    cred.NotBefore,
		notAfter:     cred.NotAfter,
	}
}

func (h *harness) drain(t *testing.T, max int) {
	t.Helper()
	handler := coreorch.HandlerFunc(func(ctx context.Context, m coreorch.Message) error {
		// The REAL licensed handler owns every AGID destination now, including
		// agid.attestation.bound (AUD-5) — this drain no longer stands in for a
		// missing worker. An unowned destination is a wiring bug worth failing on.
		handled, err := h.handler.DeliverLicensed(ctx, m)
		if err != nil {
			return err
		}
		if !handled {
			return fmt.Errorf("licensed handler did not own destination %q", m.Destination)
		}
		return nil
	})
	for i := 0; i < max; i++ {
		n, err := h.outbox.Dispatch(h.ctx, handler)
		if err != nil {
			t.Fatalf("outbox dispatch: %v", err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatalf("outbox did not drain within %d passes", max)
}

func (h *harness) dispatchDirectiveOnly(t *testing.T) {
	t.Helper()
	handler := coreorch.HandlerFunc(func(ctx context.Context, m coreorch.Message) error {
		if m.Destination == agidorch.RevocationDirectiveDestination {
			_, err := h.handler.DeliverLicensed(ctx, m)
			return err
		}
		if m.Destination == agidorch.RevocationJobDestination {
			return fmt.Errorf("test pause before revocation job execution")
		}
		return nil
	})
	if _, err := h.outbox.Dispatch(h.ctx, handler); err != nil {
		t.Fatalf("dispatch directive only: %v", err)
	}
}

func (h *harness) restartControlPlane(t *testing.T) {
	t.Helper()
	h.outbox = newTestOutbox(h.store)
	h.api = agidapi.NewServiceWithRootAnchorProvisioner(h.store, h.log, h.outbox, delegation.NewDurableAnchorStore(h.keystore))
	licensed, err := agidorch.NewLicensedOutboxFactory()(editionseam.LicensedOutboxDeps{
		Store:             h.store,
		Log:               h.log,
		SignerKeyStoreDir: h.keystore,
		IssuanceGate:      h.client,
	})
	if err != nil {
		t.Fatalf("NewLicensedOutboxFactory: %v", err)
	}
	h.handler = licensed
}

func (h *harness) startSigner(t *testing.T) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "agid-intwire-sock")
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
	t.Cleanup(func() {
		if h.stopSign != nil {
			h.stopSign()
		}
	})
}

func (h *harness) restartSigner(t *testing.T) {
	t.Helper()
	if h.stopSign != nil {
		h.stopSign()
	}
	h.startSigner(t)
	h.restartControlPlane(t)
}

func (h *harness) gatedIssue(t *testing.T, req signing.IssuancePreconditions, alg crypto.Algorithm) signing.IssuanceDecision {
	t.Helper()
	decision, err := h.client.GatedIssue(h.ctx, req, alg)
	if err != nil {
		t.Fatalf("GatedIssue: %v", err)
	}
	return decision
}

func (h *harness) preconditionsWithReach(t *testing.T, chain []delegation.RecordEnvelope, class string) []byte {
	t.Helper()
	verdictSigner := generateSigner(t)
	key := reach.VerdictKeyRef{ID: "agentid-reach-verdict", Algorithm: string(verdictSigner.Algorithm())}
	if err := delegation.NewDurableReachabilityTrustStore(h.keystore).PutVerdictSigner(h.ctx, key.ID, verdictSigner.Public().DER); err != nil {
		t.Fatalf("PutVerdictSigner: %v", err)
	}
	subjectDigest, err := delegation.CanonicalDigest(chain[len(chain)-1].Record.Authority, nil)
	if err != nil {
		t.Fatalf("authority digest: %v", err)
	}
	reachable := reach.ReachableSet{TenantID: h.tenant}
	verdict, err := reach.NewVerdict(
		reachable,
		reach.DetermineOrFailClosed(reachable, class, reach.NewCeilingPolicy(map[string]reach.Ceiling{class: {MaxTenantSpan: 1}})),
		"wm-intwire",
		subjectDigest,
		time.Now().UTC().Unix(),
		key,
	).Sign(verdictSigner)
	if err != nil {
		t.Fatalf("sign reach verdict: %v", err)
	}
	encoded, err := reach.EncodeVerdict(verdict)
	if err != nil {
		t.Fatalf("EncodeVerdict: %v", err)
	}
	pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{Chain: chain, DesignatedClass: class, ReachabilityVerdict: encoded})
	if err != nil {
		t.Fatalf("EncodePreconditionsBody: %v", err)
	}
	return pre
}

func (h *harness) signedAttestation(t *testing.T, subject, nonce string) []byte {
	t.Helper()
	payload, err := delegation.SignAttestation(h.attestor, "attestor-1", "software", subject, map[string]string{"attestation_class": "software"}, []byte(nonce))
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	return payload
}

func (h *harness) latestCredentialID(t *testing.T, agentID string) string {
	t.Helper()
	var id string
	err := h.store.WithTenant(h.ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(h.ctx,
			`SELECT credential_id
			   FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND subject_id = $1
			  ORDER BY seq DESC, credential_id DESC
			  LIMIT 1`, agentID).Scan(&id)
	})
	if err == pgx.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("latest credential: %v", err)
	}
	return id
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

func newTestOutbox(st *corestore.Store) *coreorch.Outbox {
	return coreorch.NewOutbox(st,
		coreorch.WithBackoff(func(int) time.Duration { return 0 }),
		coreorch.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		coreorch.WithMaxAttempts(3),
		coreorch.WithWorkerID("agid-intwire"),
	)
}

var chainKeys = map[string]crypto.Signer{}

func signedChain(t *testing.T, tenant, agentID string, widened bool) []delegation.RecordEnvelope {
	t.Helper()
	root := chainKeys[t.Name()+tenant]
	if root == nil {
		root = generateSigner(t)
	}
	manager := generateSigner(t)
	now := time.Now().Add(-time.Minute).Unix()
	later := time.Now().Add(45 * time.Minute).Unix()
	parentAuth := delegation.Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  delegation.Budget{Amount: 100, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 100, Per: "minute"},
		Depth:  2,
		Validity: delegation.Window{
			NotBefore: now,
			NotAfter:  later,
		},
	}
	childAuth := delegation.Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  delegation.Budget{Amount: 50, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 50, Per: "minute"},
		Depth:  1,
		Validity: delegation.Window{
			NotBefore: now,
			NotAfter:  later,
		},
	}
	if widened {
		childAuth.Tools = []string{"search", "shell.exec"}
	}
	rootRec, err := (delegation.Record{
		TenantID:       tenant,
		DelegatorID:    "root",
		DelegatorKey:   delegation.KeyRef{ID: "root-key", Algorithm: string(root.Algorithm())},
		DelegateID:     "manager",
		Authority:      parentAuth,
		DepthRemaining: 2,
		Validity:       delegation.Window{NotBefore: now, NotAfter: later},
		RootAnchor:     true,
	}).Sign(root, nil)
	if err != nil {
		t.Fatalf("sign root record: %v", err)
	}
	rootDigest, err := rootRec.Digest(nil)
	if err != nil {
		t.Fatalf("root digest: %v", err)
	}
	childRec, err := (delegation.Record{
		TenantID:       tenant,
		DelegatorID:    "manager",
		DelegatorKey:   delegation.KeyRef{ID: "manager-key", Algorithm: string(manager.Algorithm())},
		DelegateID:     agentID,
		Authority:      childAuth,
		DepthRemaining: 1,
		Validity:       delegation.Window{NotBefore: now, NotAfter: later},
		ParentDigest:   rootDigest,
	}).Sign(manager, nil)
	if err != nil {
		t.Fatalf("sign child record: %v", err)
	}
	return []delegation.RecordEnvelope{
		{Record: rootRec, DelegatorPublicDER: root.Public().DER},
		{Record: childRec, DelegatorPublicDER: manager.Public().DER},
	}
}

func agentStackRepr(t *testing.T) []byte {
	t.Helper()
	rep, err := agentstack.New(
		[]byte("system prompt: answer with constrained tools"),
		agentstack.NewToolManifest("search"),
		agentstack.Model{Form: agentstack.ModelFormProviderID, ProviderModelID: "openai/gpt-5", ModelVersion: "2026-07-07"},
	)
	if err != nil {
		t.Fatalf("agentstack.New: %v", err)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("agent stack JSON: %v", err)
	}
	return b
}

func attestationBody(t *testing.T, method string, payload []byte) []byte {
	t.Helper()
	b, err := json.Marshal(delegation.AttestationBody{Method: method, Payload: payload})
	if err != nil {
		t.Fatalf("marshal attestation body: %v", err)
	}
	return b
}

func verifyOfflineToken(t *testing.T, bm delegation.BindingMaterial, notBefore, notAfter int64) verify.Result {
	t.Helper()
	issuer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer issuer.Destroy()
	jwk, err := crypto.PublicJWK(issuer.Public(), "rp-kid")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	bv := carriage.BoundValues{
		ChainHeadDigest:    bm.ChainHeadDigest,
		AgentStackDigest:   bm.AgentStackDigest,
		AgentStackRepr:     bm.AgentStackRepr,
		DesignatedClass:    bm.DesignatedClass,
		AttestationDigest:  bm.AttestationDigest,
		ComparatorVersion:  bm.ComparatorVersion,
		RootAnchorAuthRef:  bm.RootAnchorAuthRef,
		TaskEnvelopeDigest: bm.TaskEnvelopeDigest,
	}
	tok, err := carriage.EncodeSignedToken(issuer, "rp-kid", bv, "spiffe://agent", "rp", "trstctl")
	if err != nil {
		t.Fatalf("EncodeSignedToken: %v", err)
	}
	policy := verify.NewLocalPolicy().
		ApproveAgentStack(bm.AgentStackDigest).
		PermitClass("agent-worker").
		GrantOperations("agent-worker", "read").
		WithToolManifest("search")
	got, err := verify.Verify(
		verify.Credential{
			Form:  verify.FormSignedToken,
			Bytes: []byte(tok),
			ValidityWindow: &verify.Window{
				NotBefore: notBefore,
				NotAfter:  notAfter,
			},
		},
		verify.TrustRoot{JWKSJSON: jwks},
		policy,
		verify.Action{Operation: "read", Tool: "search"},
		verify.FixedClock(time.Unix(notBefore+1, 0).UTC()),
	)
	if err != nil {
		t.Fatalf("offline Verify: %v", err)
	}
	return got
}

func generateSigner(t *testing.T) crypto.Signer {
	t.Helper()
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return signer
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
