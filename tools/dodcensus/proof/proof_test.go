// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

func TestStartCompleteWritesExactNonceBoundJSONReceipt(t *testing.T) {
	receiptFile := filepath.Join(t.TempDir(), "receipt.json")
	expected := expectation{
		SchemaVersion: 1, Nonce: strings.Repeat("a", 64), ID: "connector.example",
		BuildProfile: "static", Method: http.MethodPost, Path: "/api/v1/connectors/example",
		SubstrateID: "vendor_example", SubstrateKind: "vendor-emulator",
		SubstrateIdentity: "vendor/example@sha256:" + strings.Repeat("b", 64),
		ContractDigest:    "sha256:" + internalcrypto.SHA256Hex([]byte("contract")),
		Verifier:          "external-write", ReceiptFile: receiptFile,
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
		SchemaVersion: 1, Challenge: expected.Nonce, Identity: expected.SubstrateIdentity,
		ContractDigest: expected.ContractDigest, PID: os.Getpid() + 1000, Passed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.Complete(ExternalWrite(ExternalWriteProbe{
		Destination: []byte("external-system/item/42"), Written: written, ReadBack: append([]byte(nil), written...),
		ExecutionReceipt: execution,
	}))
	data, err := os.ReadFile(receiptFile)
	if err != nil {
		t.Fatal(err)
	}
	var got receipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Passed || got.Skipped || got.Nonce != expected.Nonce || got.ID != expected.ID || got.SubstrateIdentity != expected.SubstrateIdentity {
		t.Fatalf("receipt lost gate identity: %+v", got)
	}
	if got.Observations["write_digest"] != got.Observations["readback_digest"] {
		t.Fatalf("external write/readback were not bound: %+v", got.Observations)
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
