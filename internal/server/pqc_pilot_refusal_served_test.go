// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/pqc/compatlab"
)

// endsHandshakeListener is an endpoint that reads the client's first flight
// and answers with a fatal handshake_failure alert, as OpenSSL does when the
// client offers no signature algorithm its leaf can sign with (it logs "no
// suitable signature algorithm").
func endsHandshakeListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			// TLS record: alert, legacy version 3.3, length 2, fatal (2), handshake_failure (40).
			_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

// ingestPilotLeaf records a public leaf in the inventory and returns its
// fingerprint and the key algorithm the inventory holds for it.
func ingestPilotLeaf(t *testing.T, h *roleHarness, token, key string, pemBytes []byte) (string, string) {
	t.Helper()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/certificates", token, key,
		map[string]any{"pem": string(pemBytes), "deployment_location": "pilot canary", "source": "import"})
	var cert struct {
		Fingerprint  string `json:"fingerprint"`
		KeyAlgorithm string `json:"key_algorithm"`
	}
	if (code != http.StatusCreated && code != http.StatusOK) || json.Unmarshal(body, &cert) != nil || cert.Fingerprint == "" {
		t.Fatalf("ingest the pilot leaf = %d %s", code, body)
	}
	return strings.ToLower(cert.Fingerprint), cert.KeyAlgorithm
}

// pilotDetail runs a one-target pilot against address and returns the
// target's outcome and detail.
func pilotDetail(t *testing.T, ctx context.Context, h *roleHarness, token, key, address, fingerprint string) (string, string) {
	t.Helper()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, key, map[string]any{
		"name": "pq canary " + key, "authority_id": "pq-issuing-ca", "waves": []map[string]any{
			{"name": "canary", "targets": []map[string]any{{"target_id": "pq-canary", "address": address, "server_name": "pq.test", "fingerprint": fingerprint}}},
		},
	})
	var started struct {
		ID string `json:"id"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start pilot = %d %s", code, body)
	}
	probeWaveAsRelay(t, ctx, h, started.ID, 1)
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/pilots/"+started.ID, token, nil)
	var pilot struct {
		Waves []struct {
			Results []struct {
				TargetID string `json:"target_id"`
				Outcome  string `json:"outcome"`
				Detail   string `json:"detail"`
			} `json:"results"`
		} `json:"waves"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &pilot) != nil || len(pilot.Waves) == 0 || len(pilot.Waves[0].Results) != 1 {
		t.Fatalf("read pilot = %d %s", code, body)
	}
	r := pilot.Waves[0].Results[0]
	return r.Outcome, r.Detail
}

// TestServedPQCPilotRefusalNamesTheLeafAlgorithmAndCauseB7L1 is B7-L1's
// Done-when (served): a pilot whose expected leaf is an ML-DSA-65 certificate
// in the inventory, at an endpoint that ends the handshake with a
// handshake_failure alert (as a stock OpenSSL server does for a client that
// offers no ML-DSA signature algorithm), reads rejected with a verdict that
// names ML-DSA-65 and the cause — the client does not offer it — not only
// "the client refused the handshake". A leaf the inventory does not hold is
// named as the post-quantum leaf.
func TestServedPQCPilotRefusalNamesTheLeafAlgorithmAndCauseB7L1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read", "certs:write", "certs:read")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	leafPEM, err := os.ReadFile(filepath.Join("testdata", "b7l1-ml-dsa-65-leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fp, algorithm := ingestPilotLeaf(t, h, token, "b7l1-leaf", leafPEM)
	if algorithm != "ML-DSA-65" {
		t.Fatalf("the inventory records the leaf as %q, want ML-DSA-65", algorithm)
	}
	outcome, detail := pilotDetail(t, ctx, h, token, "b7l1-ends", endsHandshakeListener(t), fp)
	if outcome != string(compatlab.OutcomeRejected) || !strings.Contains(detail, "the client does not offer ML-DSA-65 among its signature algorithms") ||
		!strings.Contains(detail, "the ML-DSA-65 leaf") || !strings.Contains(detail, "handshake failure") {
		t.Fatalf("the refusal reads %s: %q; want it to name ML-DSA-65 and that the client does not offer it", outcome, detail)
	}
	unknown := strings.Repeat("ab", 32)
	if outcome, detail := pilotDetail(t, ctx, h, token, "b7l1-unknown", endsHandshakeListener(t), unknown); outcome != string(compatlab.OutcomeRejected) ||
		!strings.Contains(detail, "the post-quantum leaf") || !strings.Contains(detail, "the leaf's algorithm") {
		t.Fatalf("a leaf the inventory does not hold reads %s: %q", outcome, detail)
	}
	t.Logf("B7L1_OK %s", detail)
}

// TestServedPQCPilotAgainstAStockOpenSSLMLDSAServerB7L1 is B7-L1's lab proof:
// a stock OpenSSL server (TRSTCTL_B7L1_OPENSSL names its binary, 3.5 or later)
// serves an ML-DSA-65 leaf it generated; the relay's probe, which offers no
// ML-DSA signature algorithm, is refused, OpenSSL logs "no suitable signature
// algorithm", and the pilot's verdict names ML-DSA-65 and that the client
// does not offer it.
func TestServedPQCPilotAgainstAStockOpenSSLMLDSAServerB7L1(t *testing.T) {
	openssl := os.Getenv("TRSTCTL_B7L1_OPENSSL")
	if openssl == "" {
		t.Skip("stock OpenSSL ML-DSA lab not requested (TRSTCTL_B7L1_OPENSSL)")
	}
	ctx := context.Background()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, openssl, args...).CombinedOutput(); err != nil { // #nosec G204 G702 -- the lab's own OpenSSL binary and test-owned arguments (CWE-78)
			t.Fatalf("openssl %v: %v %s", args, err, out)
		}
	}
	key, leaf := filepath.Join(dir, "leaf.key"), filepath.Join(dir, "leaf.pem")
	run("genpkey", "-algorithm", "ML-DSA-65", "-out", key)
	run("req", "-x509", "-new", "-key", key, "-subj", "/CN=pq.test", "-addext", "subjectAltName=DNS:pq.test", "-days", "1", "-out", leaf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()
	var serverLog bytes.Buffer
	server := exec.CommandContext(ctx, openssl, "s_server", "-cert", leaf, "-key", key, "-accept", address, "-quiet") // #nosec G204 G702 -- the lab's own OpenSSL binary and test-owned arguments (CWE-78)
	server.Stdout, server.Stderr = io.Discard, &serverLog
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read", "certs:write", "certs:read")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	leafPEM, err := os.ReadFile(leaf) // #nosec G304 -- the lab's own temporary certificate (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(caCertDER(t, leafPEM))
	if err != nil || info.KeyAlgorithm != "ML-DSA-65" {
		t.Fatalf("the stock leaf inspects as %q: %v", info.KeyAlgorithm, err)
	}
	fp, _ := ingestPilotLeaf(t, h, token, "b7l1-stk", leafPEM)
	outcome, detail := pilotDetail(t, ctx, h, token, "b7l1-stock", address, fp)
	if outcome != string(compatlab.OutcomeRejected) || !strings.Contains(detail, "the client does not offer ML-DSA-65 among its signature algorithms") {
		t.Fatalf("against stock OpenSSL the pilot reads %s: %q", outcome, detail)
	}
	_ = server.Process.Kill()
	_ = server.Wait()
	if !strings.Contains(serverLog.String(), "no suitable signature algorithm") {
		t.Fatalf("OpenSSL did not refuse for lack of a signature algorithm:\n%s", serverLog.String())
	}
	version, _ := exec.CommandContext(ctx, openssl, "version").Output() // #nosec G204 G702 -- the lab's own OpenSSL binary (CWE-78)
	t.Logf("B7L1_LAB_OK %s | %s", strings.TrimSpace(string(version)), detail)
}
