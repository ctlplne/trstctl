// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

const proofCleanupModeEnv = "TRSTCTL_PROOF_CLEANUP_MODE"
const proofCleanupMarkerEnv = "TRSTCTL_PROOF_CLEANUP_MARKER"
const proofMissingExpectationModeEnv = "TRSTCTL_PROOF_MISSING_EXPECTATION_MODE"

func TestBrokerDynamicEnvironmentNamesAreExact(t *testing.T) {
	tests := []struct {
		expected expectation
		want     string
	}{
		{expectation{ID: "external_ca.entrust"}, "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE,TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE,TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"},
		{expectation{ID: "code_signing.default"}, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"},
		{expectation{ID: "hsm_kms.tpm2", SubstrateID: "managed_key_custody"}, "TRSTCTL_HSM_PROOF_IMAGE,TRSTCTL_HSM_PROOF_NETWORK"},
		{expectation{ID: "connector.nginx"}, ""},
	}
	for _, test := range tests {
		if got := strings.Join(brokerDynamicEnvironmentNames(test.expected), ","); got != test.want {
			t.Errorf("broker dynamic environment for %s = %q, want %q", test.expected.ID, got, test.want)
		}
	}
}

func TestStartCompleteWritesUnsignedEvidenceForParentGate(t *testing.T) {
	dir := t.TempDir()
	receiptFile := filepath.Join(dir, "receipt.json")
	evidenceFile := filepath.Join(dir, "evidence.json")
	expected := expectation{
		SchemaVersion: 1, Nonce: strings.Repeat("a", 64), ID: "connector.example",
		BuildProfile: "static", Method: http.MethodPost, Path: "/api/v1/connectors/example", RuntimeMode: "assembled-handler",
		SubstrateID: "vendor_example", SubstrateKind: "vendor-emulator",
		SubstrateIdentity: "vendor/example@sha256:" + strings.Repeat("b", 64),
		ContractDigest:    "sha256:" + internalcrypto.SHA256Hex([]byte("contract")),
		Verifier:          "external-write", ReceiptFile: receiptFile, EvidenceFile: evidenceFile,
		RuntimeRunnerIdentity: "runner@sha256:" + strings.Repeat("c", 64),
		RuntimeRunnerImage:    "sha256:" + strings.Repeat("d", 64),
		BrokerEndpoint:        "http://127.0.0.1:1", BrokerToken: "parent-broker-token",
	}
	payload, err := json.Marshal([]expectation{expected})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_DOD_EXPECTATIONS", string(payload))
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != expected.Path {
			t.Fatalf("handler path = %q", request.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"delivered"}`))
	})
	request, err := http.NewRequest(expected.Method, expected.Path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	session := Start(t, expected.ID, handler, request)
	written := []byte("high-fidelity external payload")
	execution, err := json.Marshal(substrateExecutionReceipt{
		SchemaVersion: 1, Challenge: expected.Nonce, EntryID: expected.ID, Identity: expected.SubstrateIdentity,
		ContractDigest: expected.ContractDigest, PID: os.Getpid() + 1000, Passed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.Complete(ExternalWrite(ExternalWriteProbe{
		Destination: []byte("external-system/item/42"), Written: written, ReadBack: append([]byte(nil), written...),
		ExecutionReceipt: execution,
	}))
	data, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	var got receipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Passed || got.Skipped || got.Nonce != expected.Nonce || got.ID != expected.ID || got.SubstrateIdentity != expected.SubstrateIdentity || got.MAC != "" || len(got.ExecutionReceipt) == 0 {
		t.Fatalf("unsigned evidence lost parent-bound identity: %+v", got)
	}
	if _, err := os.Stat(receiptFile); !os.IsNotExist(err) {
		t.Fatal("proof child created the final parent-only receipt")
	}
	if got.Observations["write_digest"] != got.Observations["readback_digest"] {
		t.Fatalf("external write/readback were not bound: %+v", got.Observations)
	}
}

func TestManagedKeyExecutionReceiptRequiresContentAddressedRuntimeIdentity(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if !runtimeIdentityMatches("managed_key_custody", valid) {
		t.Fatal("content-addressed managed-key runtime identity was rejected")
	}
	for _, invalid := range []string{"", "trstctl-managed-key-runtime:dod", "sha256:abc", "sha256:" + strings.Repeat("A", 64)} {
		if runtimeIdentityMatches("managed_key_custody", invalid) {
			t.Errorf("mutable/invalid managed-key runtime identity %q was accepted", invalid)
		}
	}
	if runtimeIdentityMatches("connector_universal", valid) {
		t.Fatal("unrequested runtime identity was accepted for an ordinary command substrate")
	}
}

func TestResponseValidationRejectsStatusAndSentinels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusNotImplemented, `{}`},
		{http.StatusServiceUnavailable, `{}`},
		{http.StatusOK, `{"status":"unrouted"}`},
		{http.StatusOK, `{"detail":"not configured"}`},
	} {
		if err := responseIsServed(tc.status, []byte(tc.body)); err == nil {
			t.Errorf("accepted sentinel status/body %d %q", tc.status, tc.body)
		}
	}
}

func TestFixedProbesRejectMissingLifecycleObservationsAndLiteralBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		evidence Evidence
	}{
		{"external missing readback", ExternalWrite(ExternalWriteProbe{Destination: []byte("destination long enough"), Written: []byte("written bytes long enough")})},
		{"external literal x", ExternalWrite(ExternalWriteProbe{Destination: []byte("x"), Written: []byte("x"), ReadBack: []byte("x")})},
		{"lifecycle missing revoke", CredentialLifecycle(CredentialLifecycleProbe{Issued: []byte("issued credential bytes"), Rotated: []byte("rotated credential bytes"), Exported: []byte("exported public bytes")})},
		{"lifecycle missing export", CredentialLifecycle(CredentialLifecycleProbe{Issued: []byte("issued credential bytes"), Rotated: []byte("rotated credential bytes"), RevocationReceipt: []byte("revocation receipt bytes")})},
		{"TLS missing readback", TLSDeploy(TLSDeployProbe{Deployed: []byte("deployed certificate bytes"), Config: []byte("configuration bytes"), ReloadReceipt: []byte("reload receipt bytes")})},
		{"HSM literal x", HSMSign(HSMSignProbe{Signature: []byte("x"), PublicKey: []byte("x"), ExportDenial: []byte("x")})},
	}
	for _, tc := range tests {
		if payload := tc.evidence.dodEvidence(); payload.err == nil {
			t.Errorf("%s produced valid sealed evidence: %+v", tc.name, payload)
		}
	}
}

// TestStartFailsClosedWithoutGateExpectations uses a nested test process because
// the expected behavior is testing.T.Fatal. This protects the isolation tag from
// accidentally turning direct, ordinary invocations into self-authorizing proof.
func TestStartFailsClosedWithoutGateExpectations(t *testing.T) {
	if os.Getenv(proofMissingExpectationModeEnv) == "driver" {
		_ = os.Unsetenv("TRSTCTL_DOD_EXPECTATIONS")
		request, err := http.NewRequest(http.MethodGet, "/api/v1/missing-proof", nil)
		if err != nil {
			t.Fatal(err)
		}
		Start(t, "missing.expectation", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), request)
		t.Fatal("proof.Start returned without gate-issued expectations")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartFailsClosedWithoutGateExpectations$")
	cmd.Env = proofMissingExpectationEnvironment(os.Environ())
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("missing-expectation driver timed out: %v output=%s", ctx.Err(), output)
	}
	if err == nil {
		t.Fatalf("proof.Start accepted missing gate expectations: %s", output)
	}
	if !strings.Contains(string(output), "gate-issued TRSTCTL_DOD_EXPECTATIONS is missing") {
		t.Fatalf("missing expectations failed for the wrong reason: %s", output)
	}
}

func proofMissingExpectationEnvironment(base []string) []string {
	out := make([]string, 0, len(base)+1)
	for _, item := range base {
		if strings.HasPrefix(item, proofMissingExpectationModeEnv+"=") || strings.HasPrefix(item, "TRSTCTL_DOD_EXPECTATIONS=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, proofMissingExpectationModeEnv+"=driver")
}

// TestExternalSubstrateCleanupAfterFatal uses a nested test process so the
// middle process can intentionally call t.Fatal without making this outer test
// fail. The registered cleanup must interrupt and reap its READY substrate even
// though StopAndReceipt was never reached.
func TestExternalSubstrateCleanupAfterFatal(t *testing.T) {
	switch os.Getenv(proofCleanupModeEnv) {
	case "substrate":
		runProofCleanupSubstrate(t)
		return
	case "fatal-driver":
		runProofCleanupFatalDriver(t)
		return
	}

	marker := filepath.Join(t.TempDir(), "interrupted.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExternalSubstrateCleanupAfterFatal$")
	cmd.Env = proofCleanupEnvironment(os.Environ(), "fatal-driver", marker)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("fatal-driver cleanup timed out: %v output=%s", ctx.Err(), output)
	}
	if err == nil {
		t.Fatalf("fatal-driver unexpectedly passed; intentional t.Fatal did not run: %s", output)
	}
	rawPID, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("substrate cleanup marker is missing after t.Fatal: %v; output=%s", err, output)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid cleaned substrate pid %q: %v", rawPID, err)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("substrate process %d survived fatal-driver cleanup", pid)
	} else if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("probe cleaned substrate pid %d: %v", pid, err)
	}
}

func runProofCleanupFatalDriver(t *testing.T) {
	marker := os.Getenv(proofCleanupMarkerEnv)
	expected := expectation{
		SchemaVersion: 1, Nonce: strings.Repeat("c", 64), ID: "cleanup.substrate",
		SubstrateID: "cleanup_substrate", SubstrateKind: "vendor-emulator",
		SubstrateIdentity: "cleanup/substrate@sha256:" + strings.Repeat("d", 64),
		ContractDigest:    "sha256:" + strings.Repeat("e", 64), Verifier: "external-write",
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExternalSubstrateCleanupAfterFatal$")
	cmd.Env = proofCleanupEnvironment(substrateEnvironment(expected), "substrate", marker)
	_ = startExternal(t, expected, cmd, true)
	t.Fatal("intentional fatal after READY before StopAndReceipt")
}

func runProofCleanupSubstrate(t *testing.T) {
	ready := substrateReady{
		SchemaVersion:  1,
		Challenge:      os.Getenv("TRSTCTL_DOD_CHALLENGE"),
		EntryID:        os.Getenv("TRSTCTL_DOD_ENTRY_ID"),
		Identity:       os.Getenv("TRSTCTL_DOD_SUBSTRATE_IDENTITY"),
		ContractDigest: os.Getenv("TRSTCTL_DOD_CONTRACT_DIGEST"),
		PID:            os.Getpid(), Ready: true, Endpoint: "http://127.0.0.1:1",
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		t.Fatal(err)
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	select {
	case <-interrupt:
	case <-time.After(20 * time.Second):
		t.Fatal("cleanup substrate was never interrupted")
	}
	if err := os.WriteFile(os.Getenv(proofCleanupMarkerEnv), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
}

func proofCleanupEnvironment(base []string, mode, marker string) []string {
	out := make([]string, 0, len(base)+2)
	for _, item := range base {
		if strings.HasPrefix(item, proofCleanupModeEnv+"=") || strings.HasPrefix(item, proofCleanupMarkerEnv+"=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, proofCleanupModeEnv+"="+mode, proofCleanupMarkerEnv+"="+marker)
}
