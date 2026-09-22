// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
)

// The public API must observe the actual served ML-DSA leaf. This is discovery
// evidence only: not managed deployment, trusted-chain validation, application
// availability, migration completion, or revocation enforcement.
func TestServedCBOMNativeScanObservesMLDSALeaves(t *testing.T) {
	executable, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("stock OpenSSL is required for native discovery: ", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "CBOM native discovery fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []boundarycrypto.Algorithm{pqc.MLDSA44, pqc.MLDSA65, pqc.MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.CBOMTLSProbeOpenSSL = executable })
			token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
			key, err := pqc.GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "scan.example.test", DNSNames: []string{"scan.example.test"}}, algorithm)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			preparation, err := boundarycrypto.NewLeafPreparation()
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := pqc.SignPQCLeafFromCSRWithPreparation(caDER, ca, key.CSRDER, 10*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, preparation)
			if err != nil {
				t.Fatal(err)
			}
			private, err := key.PrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			keyPath, certPath := filepath.Join(dir, "subject.pem"), filepath.Join(dir, "leaf.pem")
			writeErr := os.WriteFile(keyPath, private, 0600)
			secret.Wipe(private)
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER}), 0600); err != nil {
				t.Fatal(err)
			}
			address := startCBOMNativeFixture(t, executable, certPath, keyPath)
			before, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			// A request cannot override the operator's executable. Unknown JSON fields
			// follow the API's normal compatibility behavior and must have no effect.
			request := map[string]any{"tls_endpoints": []string{address}, "tls_probe_openssl": "/tenant-must-not-select-executable"}
			status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans/preview", token, request)
			if status != http.StatusOK {
				t.Fatalf("preview status=%d body=%s", status, body)
			}
			var preview struct {
				Ready       bool `json:"ready"`
				EffectFree  bool `json:"effect_free"`
				Connections int  `json:"tls_connection_limit"`
			}
			if err := json.Unmarshal(body, &preview); err != nil {
				t.Fatal(err)
			}
			if !preview.Ready || !preview.EffectFree || preview.Connections != 2 {
				t.Fatalf("native preview=%+v", preview)
			}
			if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
				t.Fatalf("preview changed event head: %d => %d (%v)", before, after, err)
			}
			status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", token, "native-cbom-"+string(algorithm), request)
			if status != http.StatusCreated {
				t.Fatalf("scan status=%d body=%s", status, body)
			}
			var scan struct {
				Report struct {
					Findings int `json:"findings"`
					Failed   int `json:"failed"`
				} `json:"report"`
			}
			if err := json.Unmarshal(body, &scan); err != nil {
				t.Fatal(err)
			}
			if scan.Report.Findings != 2 || scan.Report.Failed != 0 {
				t.Fatalf("native TLS scan did not observe protocol and key: %s", body)
			}
			status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
			if status != http.StatusOK {
				t.Fatalf("inventory status=%d body=%s", status, body)
			}
			var inventory struct {
				Items []struct {
					Kind        string `json:"kind"`
					Location    string `json:"location"`
					Algorithm   string `json:"algorithm"`
					Bits        int    `json:"key_bits"`
					Fingerprint string `json:"certificate_fingerprint"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &inventory); err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, item := range inventory.Items {
				if item.Location != address || item.Kind != "certificate-key" {
					continue
				}
				found++
				if item.Algorithm != string(algorithm) || item.Bits != 0 || item.Fingerprint != boundarycrypto.SHA256Hex(leaf.DER) {
					t.Fatalf("inventory does not identify actual served leaf: %+v", item)
				}
			}
			if found != 1 {
				t.Fatalf("observed %d certificate records, want one", found)
			}
			if !h.hasEvent(t, "cbom.asset.observed") {
				t.Fatal("native discovery bypassed immutable observation log")
			}
		})
	}
}

func startCBOMNativeFixture(t *testing.T, executable, certPath, keyPath string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, executable, "s_server", "-accept", address, "-cert", certPath, "-key", keyPath, "-quiet", "-tls1_3", "-groups", "X25519") // #nosec G204 -- resolved stock OpenSSL, fixed arguments and owned loopback fixture paths (CWE-78).
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return address
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("owned native TLS discovery fixture did not start; OpenSSL must support ML-DSA")
	return ""
}
