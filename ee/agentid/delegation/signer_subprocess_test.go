// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/reach"
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
	bin := buildSignerBinaryForAGID(t)
	dir := t.TempDir()
	keystore := filepath.Join(dir, "keystore")
	kekFile := filepath.Join(dir, "signer.kek")

	envs, anchors, _ := singleAnchorChain(t, nil, tenantID, "fido2:root-authenticator")
	anchorStore := NewDurableAnchorStore(keystore)
	if err := anchorStore.PutRootAnchor(context.Background(), tenantID, "root-key", anchors["root-key"]); err != nil {
		t.Fatalf("PutRootAnchor: %v", err)
	}
	verdictSigner, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("verdict signer: %v", err)
	}
	verdictKey := reach.VerdictKeyRef{ID: "agentid-reach-verdict", Algorithm: string(verdictSigner.Algorithm())}
	reachTrust := NewDurableReachabilityTrustStore(keystore)
	if err := reachTrust.PutVerdictSigner(context.Background(), verdictKey.ID, verdictSigner.Public().DER); err != nil {
		t.Fatalf("PutVerdictSigner: %v", err)
	}
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
		verdictKey,
	).Sign(verdictSigner)
	if err != nil {
		t.Fatalf("sign verdict: %v", err)
	}
	verdictBytes, err := reach.EncodeVerdict(verdict)
	if err != nil {
		t.Fatalf("encode verdict: %v", err)
	}
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: envs, DesignatedClass: "agent-worker", ReachabilityVerdict: verdictBytes})
	if err != nil {
		t.Fatalf("encode preconditions: %v", err)
	}

	start := func(t *testing.T) (*signing.Client, func()) {
		t.Helper()
		socketDir, err := os.MkdirTemp("", "as")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
		socket := filepath.Join(socketDir, "s.sock")
		args := []string{"--keystore", keystore, "--kek", kekFile}
		if runtime.GOOS != "linux" {
			args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
		}
		client, stop, err := signing.StartChild(context.Background(), bin, socket, args...)
		if err != nil {
			t.Fatalf("StartChild: %v", err)
		}
		return client, stop
	}
	issue := func(t *testing.T, client *signing.Client, ref string) signing.IssuanceDecision {
		t.Helper()
		now := time.Now().UTC()
		decision, err := client.GatedIssue(context.Background(), signing.IssuancePreconditions{
			TenantID:       tenantID,
			TrustAnchorRef: ref,
			NotBefore:      now.Unix(),
			NotAfter:       now.Add(20 * time.Minute).Unix(),
			Preconditions:  pre,
		}, crypto.ECDSAP256)
		if err != nil {
			t.Fatalf("GatedIssue(%s): %v", ref, err)
		}
		if !decision.Approved {
			t.Fatalf("GatedIssue(%s) refused; refusal=%s", ref, string(decision.RefusalRecord))
		}
		if len(decision.CredentialPublicDER) == 0 || len(decision.EncodedRecord) == 0 {
			t.Fatalf("GatedIssue(%s) returned no public credential material", ref)
		}
		return decision
	}

	client1, stop1 := start(t)
	first := issue(t, client1, "leaf-first")
	stop1()

	client2, stop2 := start(t)
	defer stop2()
	second := issue(t, client2, "leaf-second")

	if string(first.EncodedRecord) == string(second.EncodedRecord) {
		t.Fatal("restart issuance returned byte-identical credential records; expected a fresh public credential")
	}
}

func buildSignerBinaryForAGID(t *testing.T) string {
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
