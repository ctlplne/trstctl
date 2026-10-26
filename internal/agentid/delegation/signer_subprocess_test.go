// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestSignerBinaryAGIDRootAnchorsSurviveRestart launches the shipped trstctl-signer
// binary, not an in-process signing.Server. It provisions an AGID root anchor into the
// signer's keystore/floor directory, drives GatedIssue over the real UDS transport, stops
// the signer, launches a fresh signer process over the same directory, and drives
// GatedIssue again. This is the AGID-INT-WIRE process-boundary/restart proof for the
// root-anchor provisioning path: the signer reads public trust anchors from durable local
// state while linking no SQL, NATS, or HTTP.
//
// It is also the executed-medium proof for AGID-claim-30 (the non-transitory
// computer-readable-medium form of AGID-claim-1): the test compiles the shipped
// trstctl-signer program image, executes it as a separate OS process, and drives
// GatedIssue over the real transport, so the stored instructions are shown to cause the
// control plane to perform the method rather than an in-process test harness standing in
// for it. The construction seam those instructions are built from is signerwiring.go.
func TestSignerBinaryAGIDRootAnchorsSurviveRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and launches the real trstctl-signer binary")
	}
	const tenantID = "tenant-subprocess"
	fx := newSignerSubprocessFixture(t, tenantID)
	verdictSigner, verdictKey, anchors := fx.verdictSigner, fx.verdictKey, fx.anchors
	start, issue := fx.start, func(t *testing.T, client *signing.Client, ref string) signing.IssuanceDecision {
		t.Helper()
		decision := fx.gatedIssue(t, client, ref, nil, "")
		if !decision.Approved {
			t.Fatalf("GatedIssue(%s) refused; refusal=%s", ref, string(decision.RefusalRecord))
		}
		return decision
	}

	client1, stop1 := start(t)
	if err := client1.ProvisionAgentReachabilityKey(context.Background(), verdictKey.ID, verdictSigner.Public().DER); err != nil {
		t.Fatalf("provision verdict key over authenticated transport: %v", err)
	}
	if err := client1.ProvisionAgentReachabilityKey(context.Background(), verdictKey.ID, verdictSigner.Public().DER); err != nil {
		t.Fatalf("exact verdict key retry: %v", err)
	}
	otherVerdict, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := client1.ProvisionAgentReachabilityKey(context.Background(), verdictKey.ID, otherVerdict.Public().DER); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed verdict key binding = %v, want AlreadyExists", err)
	}
	verdictReadback, err := client1.ReadAgentReachabilityKey(context.Background(), verdictKey.ID)
	if err != nil || string(verdictReadback) != string(verdictSigner.Public().DER) {
		t.Fatalf("signer verdict key readback differs: %v", err)
	}
	wantAnchor := anchors["root-key"]
	if err := client1.ProvisionAgentRootAnchor(context.Background(), tenantID, "root-key", wantAnchor.PublicDER, wantAnchor.AuthRef); err != nil {
		t.Fatalf("provision signer root over authenticated transport: %v", err)
	}
	if err := client1.ProvisionAgentRootAnchor(context.Background(), tenantID, "root-key", wantAnchor.PublicDER, wantAnchor.AuthRef); err != nil {
		t.Fatalf("exact signer retry: %v", err)
	}
	if err := client1.ProvisionAgentRootAnchor(context.Background(), tenantID, "root-key", wantAnchor.PublicDER, "other-authenticator"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed signer binding = %v, want AlreadyExists", err)
	}
	gotDER, gotAuthRef, err := client1.ReadAgentRootAnchor(context.Background(), tenantID, "root-key")
	if err != nil || string(gotDER) != string(wantAnchor.PublicDER) || gotAuthRef != wantAnchor.AuthRef {
		t.Fatalf("signer root readback differs: der=%x auth_ref=%q err=%v", gotDER, gotAuthRef, err)
	}
	first := issue(t, client1, "leaf-first")
	stop1()

	client2, stop2 := start(t)
	defer stop2()
	verdictReadback, err = client2.ReadAgentReachabilityKey(context.Background(), verdictKey.ID)
	if err != nil || string(verdictReadback) != string(verdictSigner.Public().DER) {
		t.Fatalf("cold signer verdict readback differs: %v", err)
	}
	second := issue(t, client2, "leaf-second")

	if string(first.EncodedRecord) == string(second.EncodedRecord) {
		t.Fatal("restart issuance returned byte-identical credential records; expected a fresh public credential")
	}
}

// A150: a tenant attestor provisioned over the signer's authenticated transport is
// held by the shipped signer binary, keeps its first writer, survives a restart, and
// the binary's gate verifies attested issuance against it; evidence from a key the
// tenant never registered is refused before keygen.
func TestSignerBinaryAGIDTenantAttestorsSurviveRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and launches the real trstctl-signer binary")
	}
	const tenantID = "tenant-attestor"
	fx := newSignerSubprocessFixture(t, tenantID)
	attestorKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	evidence := func(signer crypto.Signer, nonce string) []byte {
		t.Helper()
		payload, err := SignAttestation(signer, "tpm-verifier", "tpm", "instance-1", nil, []byte(nonce))
		if err != nil {
			t.Fatal(err)
		}
		return attBody(t, "tpm", payload)
	}

	client1, stop1 := fx.start(t)
	fx.provisionFloors(t, client1)
	ctx := context.Background()
	if err := client1.ProvisionAgentAttestor(ctx, tenantID, "tpm-verifier", attestorKey.Public().DER, "tpm"); err != nil {
		t.Fatalf("provision attestor over the signer transport: %v", err)
	}
	if err := client1.ProvisionAgentAttestor(ctx, tenantID, "tpm-verifier", attestorKey.Public().DER, "tpm"); err != nil {
		t.Fatalf("exact attestor retry: %v", err)
	}
	if err := client1.ProvisionAgentAttestor(ctx, tenantID, "tpm-verifier", stranger.Public().DER, "tpm"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed attestor key = %v, want AlreadyExists", err)
	}
	if err := client1.ProvisionAgentAttestor(ctx, tenantID, "tpm-verifier", attestorKey.Public().DER, "hsm"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed attestor method = %v, want AlreadyExists", err)
	}
	if err := client1.ProvisionAgentAttestor(ctx, tenantID, "other-verifier", attestorKey.Public().DER, "made-up"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown attestation method = %v, want InvalidArgument", err)
	}
	if _, _, err := client1.ReadAgentAttestor(ctx, "another-tenant", "tpm-verifier"); status.Code(err) != codes.NotFound {
		t.Fatalf("another tenant's attestor readback = %v, want NotFound", err)
	}
	if decision := fx.gatedIssue(t, client1, "leaf-attested", evidence(attestorKey, "n1"), "tpm"); !decision.Approved {
		t.Fatalf("attested issuance refused: %s", decision.RefusalRecord)
	}
	if decision := fx.gatedIssue(t, client1, "leaf-stranger", evidence(stranger, "n2"), "tpm"); decision.Approved || len(decision.CredentialPublicDER) != 0 {
		t.Fatal("evidence from a key the tenant never registered was approved")
	}
	stop1()

	client2, stop2 := fx.start(t)
	defer stop2()
	gotDER, gotMethod, err := client2.ReadAgentAttestor(ctx, tenantID, "tpm-verifier")
	if err != nil || string(gotDER) != string(attestorKey.Public().DER) || gotMethod != "tpm" {
		t.Fatalf("restarted signer attestor readback: method=%q err=%v", gotMethod, err)
	}
	if decision := fx.gatedIssue(t, client2, "leaf-after-restart", evidence(attestorKey, "n3"), "tpm"); !decision.Approved {
		t.Fatalf("attested issuance after restart refused: %s", decision.RefusalRecord)
	}
}

// signerSubprocessFixture is one tenant's chain, root anchor and reachability verdict
// for driving GatedIssue on the shipped signer binary over its real transport.
type signerSubprocessFixture struct {
	tenantID      string
	bin, keystore string
	kekFile       string
	anchors       map[string]RootAnchor
	verdictSigner crypto.Signer
	verdictKey    reach.VerdictKeyRef
	pre           []byte
}

func newSignerSubprocessFixture(t *testing.T, tenantID string) *signerSubprocessFixture {
	t.Helper()
	dir := t.TempDir()
	fx := &signerSubprocessFixture{
		tenantID: tenantID, bin: buildSignerBinaryForAGID(t),
		keystore: filepath.Join(dir, "keystore"), kekFile: filepath.Join(dir, "signer.kek"),
	}
	envs, anchors, _ := singleAnchorChain(t, nil, tenantID, "fido2:root-authenticator")
	fx.anchors = anchors
	verdictSigner, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("verdict signer: %v", err)
	}
	fx.verdictSigner = verdictSigner
	fx.verdictKey = reach.VerdictKeyRef{ID: "agentid-reach-verdict", Algorithm: string(verdictSigner.Algorithm())}
	subjectDigest, err := CanonicalDigest(envs[len(envs)-1].Record.Authority, nil)
	if err != nil {
		t.Fatalf("authority digest: %v", err)
	}
	verdict, err := reach.NewVerdict(
		reach.ReachableSet{TenantID: tenantID},
		reach.DetermineOrFailClosed(reach.ReachableSet{TenantID: tenantID}, "agent-worker", reach.NewCeilingPolicy(map[string]reach.Ceiling{
			"agent-worker": {MaxTenantSpan: 1},
		})),
		"wm-signer-subprocess",
		subjectDigest,
		time.Now().UTC().Unix(),
		fx.verdictKey,
	).Sign(verdictSigner)
	if err != nil {
		t.Fatalf("sign verdict: %v", err)
	}
	verdictBytes, err := reach.EncodeVerdict(verdict)
	if err != nil {
		t.Fatalf("encode verdict: %v", err)
	}
	fx.pre, err = encodePreconditionsForTest(PreconditionsBody{Chain: envs, DesignatedClass: "agent-worker", ReachabilityVerdict: verdictBytes})
	if err != nil {
		t.Fatalf("encode preconditions: %v", err)
	}
	return fx
}

// start launches the shipped signer binary over the fixture's durable key store.
func (fx *signerSubprocessFixture) start(t *testing.T) (*signing.Client, func()) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	args := []string{"--keystore", fx.keystore, "--kek", fx.kekFile}
	if runtime.GOOS != "linux" {
		args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
	}
	client, stop, err := signing.StartChild(context.Background(), fx.bin, socket, args...)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	return client, stop
}

// provisionFloors sends the fixture's verdict key and root anchor over the transport.
func (fx *signerSubprocessFixture) provisionFloors(t *testing.T, client *signing.Client) {
	t.Helper()
	if err := client.ProvisionAgentReachabilityKey(context.Background(), fx.verdictKey.ID, fx.verdictSigner.Public().DER); err != nil {
		t.Fatalf("provision verdict key: %v", err)
	}
	anchor := fx.anchors["root-key"]
	if err := client.ProvisionAgentRootAnchor(context.Background(), fx.tenantID, "root-key", anchor.PublicDER, anchor.AuthRef); err != nil {
		t.Fatalf("provision root anchor: %v", err)
	}
}

// gatedIssue drives one GatedIssue for the fixture's chain, optionally attested.
func (fx *signerSubprocessFixture) gatedIssue(t *testing.T, client *signing.Client, ref string, attestation []byte, method string) signing.IssuanceDecision {
	t.Helper()
	now := time.Now().UTC()
	decision, err := client.GatedIssue(context.Background(), signing.IssuancePreconditions{
		TenantID:          fx.tenantID,
		TrustAnchorRef:    ref,
		NotBefore:         now.Unix(),
		NotAfter:          now.Add(20 * time.Minute).Unix(),
		Preconditions:     fx.pre,
		Attestation:       attestation,
		AttestationMethod: method,
	}, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GatedIssue(%s): %v", ref, err)
	}
	if decision.Approved && (len(decision.CredentialPublicDER) == 0 || len(decision.EncodedRecord) == 0) {
		t.Fatalf("GatedIssue(%s) returned no public credential material", ref)
	}
	return decision
}

func buildSignerBinaryForAGID(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer") // #nosec G204 -- executable and argv are fixed; output is confined to TempDir (CWE-78).
	cmd.Dir = root
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}
