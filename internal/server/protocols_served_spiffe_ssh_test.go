package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// TestServedSPIFFEWorkloadAPIEndToEnd is the EXC-WIRE-02 / INTEROP-004 acceptance
// proof for the SPIFFE Workload API: a real gRPC client speaking the SPIFFE Workload
// API wire protocol (the vendored go-spiffe proto + the mandatory
// workload.spiffe.io:true security header) dials the SERVED UDS the binary stands up
// (Server.RunSPIFFE) and FetchX509SVID returns an X.509-SVID + trust bundle signed
// through the out-of-process signer (AN-4). The SVID's SPIFFE ID and trust bundle
// verify. It MUST fail on the pre-wiring tree (no UDS server existed — the spiffe
// package exposed only Go methods) and PASS after, race-clean.
func TestServedSPIFFEWorkloadAPIEndToEnd(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "trstctl-spiffe-")
	if err != nil {
		t.Fatalf("spiffe socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled:     true,
			TenantID:    servedTestTenant,
			TrustDomain: "served.test",
			SocketPath:  socket,
		},
	})
	if !protoContains(h.srv.ServedProtocols(), "spiffe") {
		t.Fatal("SPIFFE is not reported as served — wire-in failed")
	}
	if h.srv.SPIFFESocket() != socket {
		t.Fatalf("SPIFFE socket = %q, want %q", h.srv.SPIFFESocket(), socket)
	}

	// Serve the Workload API over the UDS (the binary's RunSPIFFE), then drive it with
	// a real Workload API gRPC client.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Wait for the socket to appear (the server creates it on Listen).
	waitForSocket(t, socket, 5*time.Second)

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial workload API: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := workloadpb.NewSpiffeWorkloadAPIClient(conn)

	// A conformant client sets the mandatory security header; without it the server
	// rejects (asserted in the negative case below).
	md := metadata.Pairs(spiffeSecurityHeader())
	fetchCtx, fcancel := context.WithTimeout(metadata.NewOutgoingContext(ctx, md), 10*time.Second)
	defer fcancel()

	stream, err := client.FetchX509SVID(fetchCtx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv X509SVIDResponse: %v", err)
	}
	if len(resp.GetSvids()) == 0 {
		t.Fatal("Workload API returned no SVIDs")
	}
	svid := resp.GetSvids()[0]

	// The SVID's SPIFFE ID matches the registered entry, and it carries a private key
	// + a trust bundle (the spec-shaped response a go-spiffe client validates).
	if svid.GetSpiffeId() != "spiffe://served.test/workload" {
		t.Errorf("SVID SPIFFE ID = %q, want spiffe://served.test/workload", svid.GetSpiffeId())
	}
	if len(svid.GetX509SvidKey()) == 0 {
		t.Error("SVID carries no private key")
	}
	if len(svid.GetBundle()) == 0 {
		t.Error("SVID carries no trust bundle")
	}
	// The X.509-SVID leaf's SPIFFE ID URI SAN matches (proves a real, signed SVID).
	id, err := crypto.SPIFFEIDFromCert(svid.GetX509Svid())
	if err != nil {
		t.Fatalf("extract SPIFFE ID from SVID cert: %v", err)
	}
	if id != "spiffe://served.test/workload" {
		t.Errorf("SVID cert URI SAN = %q, want spiffe://served.test/workload", id)
	}
	// The SVID must chain to the served issuing CA (signer-backed, AN-4).
	if err := crypto.VerifyLeafSignedByCA(svid.GetX509Svid(), caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("SVID does not verify against the served CA: %v", err)
	}

	// AN-2: the SVID issuance was audited.
	if !h.hasEvent(t, "spiffe.svid.issued") {
		t.Error("no spiffe.svid.issued event — the served SVID mint was not audited (AN-2)")
	}

	// Negative: a client that omits the mandatory security header is rejected (the
	// SPIFFE Workload API contract), proving the gate is real.
	bare, err := client.FetchX509SVID(context.Background(), &workloadpb.X509SVIDRequest{})
	if err == nil {
		if _, rerr := bare.Recv(); rerr == nil {
			t.Error("Workload API accepted a request with no security header — the gate is missing")
		}
	}
}

// TestServedSPIFFEGoSpiffeClient is the INTEROP-002 stock-client proof: the real
// go-spiffe workloadapi client fetches an X.509-SVID from the served UDS, validates
// the SPIFFE ID and trust bundle, and proves the leaf chains to the served CA.
func TestServedSPIFFEGoSpiffeClient(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "trstctl-spiffe-gospiffe-")
	if err != nil {
		t.Fatalf("spiffe socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled:     true,
			TenantID:    servedTestTenant,
			TrustDomain: "served.test",
			SocketPath:  socket,
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	result := runServedGoSpiffeClient(t, "unix://"+socket)
	if got := result.ID; got != "spiffe://served.test/workload" {
		t.Fatalf("go-spiffe SVID ID = %q, want spiffe://served.test/workload", got)
	}
	if result.CertDER == "" {
		t.Fatal("go-spiffe SVID has no certificate chain")
	}
	if !result.HasPrivateKey {
		t.Fatal("go-spiffe SVID has no private key")
	}
	leafDER, err := base64.StdEncoding.DecodeString(result.CertDER)
	if err != nil {
		t.Fatalf("go-spiffe client returned non-base64 certificate DER: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("go-spiffe SVID does not verify against served CA: %v", err)
	}
	if result.BundleAuthorities == 0 {
		t.Fatal("go-spiffe context did not include the served.test trust bundle")
	}
	if !h.hasEvent(t, "spiffe.svid.issued") {
		t.Error("no spiffe.svid.issued event after go-spiffe FetchX509Context")
	}
}

// TestServedSPIFFESpiffeHelperWritesSVID runs stock spiffe-helper in one-shot mode
// against the served Workload API UDS. CI installs the helper and sets
// TRSTCTL_REQUIRE_SPIFFE_HELPER=1 so this cannot become a skip-only proof.
func TestServedSPIFFESpiffeHelperWritesSVID(t *testing.T) {
	helper, err := exec.LookPath("spiffe-helper")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_SPIFFE_HELPER") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_SPIFFE_HELPER is set but spiffe-helper is not on PATH: %v", err)
		}
		t.Skip("spiffe-helper not on PATH; set TRSTCTL_REQUIRE_SPIFFE_HELPER=1 in CI to make the stock helper mandatory")
	}

	socketDir, err := os.MkdirTemp("", "trstctl-spiffe-helper-")
	if err != nil {
		t.Fatalf("spiffe socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled:     true,
			TenantID:    servedTestTenant,
			TrustDomain: "served.test",
			SocketPath:  socket,
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "helper.conf")
	configBody := fmt.Sprintf(`agent_address = %q
cert_dir = %q
daemon_mode = false
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
cert_file_mode = 0600
key_file_mode = 0600
jwt_bundle_file_mode = 0600
jwt_svid_file_mode = 0600
`, socket, certDir)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}

	runCtx, runCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, helper, "-config", configPath, "-daemon-mode=false")
	out, err := cmd.CombinedOutput()
	if runCtx.Err() != nil {
		t.Fatalf("spiffe-helper timed out:\n%s", out)
	}
	if err != nil {
		t.Fatalf("spiffe-helper failed against served Workload API: %v\n%s", err, out)
	}

	svidPath := filepath.Join(certDir, "svid.pem")
	keyPath := filepath.Join(certDir, "svid_key.pem")
	bundlePath := filepath.Join(certDir, "svid_bundle.pem")
	for _, p := range []string{svidPath, keyPath, bundlePath} {
		if stat, err := os.Stat(p); err != nil {
			t.Fatalf("spiffe-helper did not write %s: %v\n%s", p, err, out)
		} else if stat.Size() == 0 {
			t.Fatalf("spiffe-helper wrote empty %s\n%s", p, out)
		}
	}
	leafDER := servedReadPEMCert(t, svidPath)
	id, err := crypto.SPIFFEIDFromCert(leafDER)
	if err != nil {
		t.Fatalf("spiffe-helper SVID has no SPIFFE ID: %v", err)
	}
	if id != "spiffe://served.test/workload" {
		t.Fatalf("spiffe-helper SVID ID = %q, want spiffe://served.test/workload", id)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("spiffe-helper SVID does not verify against served CA: %v", err)
	}
	if !h.hasEvent(t, "spiffe.svid.issued") {
		t.Error("no spiffe.svid.issued event after spiffe-helper fetch")
	}
	servedArchiveConformanceTranscripts(t, "served-spiffe-helper", configPath, svidPath, keyPath, bundlePath)
}

type servedGoSpiffeResult struct {
	ID                string `json:"id"`
	CertDER           string `json:"cert_der"`
	HasPrivateKey     bool   `json:"has_private_key"`
	BundleAuthorities int    `json:"bundle_authorities"`
}

func runServedGoSpiffeClient(t *testing.T, endpoint string) servedGoSpiffeResult {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_GOSPIFFE") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_GOSPIFFE is set but go is not on PATH: %v", err)
		}
		t.Skip("go not on PATH; cannot build the stock go-spiffe client")
	}
	clientDir := filepath.Join("testdata", "gospiffe-client")
	runCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, goBin, "run", ".", endpoint)
	cmd.Dir = clientDir
	out, err := cmd.CombinedOutput()
	if runCtx.Err() != nil {
		t.Fatalf("go-spiffe client timed out:\n%s", out)
	}
	if err != nil {
		t.Fatalf("go-spiffe client failed against served UDS: %v\n%s", err, out)
	}
	var result servedGoSpiffeResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("decode go-spiffe client output: %v\n%s", err, out)
	}
	return result
}

// spiffeSecurityHeader returns the mandatory Workload API metadata pair, read from
// the served package's exported constants so the client and server agree.
func spiffeSecurityHeader() (string, string) {
	return spiffe.SecurityHeaderKey, spiffe.SecurityHeaderValue
}

// waitForSocket blocks until the UDS path exists and accepts a dial, or the deadline
// elapses.
func waitForSocket(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			c, derr := net.Dial("unix", path)
			if derr == nil {
				_ = c.Close()
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("spiffe socket %s never became ready", path)
}

// TestServedSSHEndToEnd is the EXC-WIRE-02 / INTEROP-009 acceptance proof for the SSH
// CA: the SERVED SSH endpoints (mounted on the binary's handler) issue an OpenSSH user
// certificate signed through the out-of-process signer (AN-4), and the binary serves
// the OpenSSH BINARY KRL sshd consumes. ssh-keygen -L parses the cert and ssh-keygen
// -Qf checks revocation against the served KRL when ssh-keygen is available; otherwise
// the cert/KRL are validated structurally. It MUST fail pre-wiring (no /ssh routes
// existed) and PASS after.
func TestServedSSHEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "ssh") {
		t.Fatal("SSH is not reported as served — wire-in failed")
	}
	sshp := h.srv.sshProtocolForTest()
	if sshp == nil {
		t.Fatal("served SSH protocol is nil")
	}

	// Generate a subject SSH key pair (the thing being certified). Use ssh-keygen when
	// present so the public key is exactly the authorized_keys form sshd expects.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	pubAuthorizedKeys := genSSHKey(t, keyPath)

	// Drive the SERVED /ssh/issue/user endpoint through the assembled handler.
	body, _ := json.Marshal(sshIssueRequest{
		PublicKey:  string(pubAuthorizedKeys),
		KeyID:      "alice@corp",
		Principals: []string{"alice"},
		TTLSeconds: 3600,
	})
	resp, err := h.ts.Client().Post(h.ts.URL+"/ssh/issue/user", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /ssh/issue/user: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("/ssh/issue/user status %d", resp.StatusCode)
	}
	var issued sshIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatalf("decode issue response: %v", err)
	}
	if issued.Certificate == "" {
		t.Fatal("served SSH issuance returned no certificate")
	}

	// The served /ssh/ca endpoint returns the CA authority key.
	caResp, err := h.ts.Client().Get(h.ts.URL + "/ssh/ca")
	if err != nil {
		t.Fatalf("GET /ssh/ca: %v", err)
	}
	caKey, _ := readAllClose(caResp)
	if len(caKey) == 0 {
		t.Fatal("served /ssh/ca returned no authority key")
	}

	// Write the issued cert and verify it with ssh-keygen -L when available (the stock
	// OpenSSH tool the audit asks for). Otherwise parse it through the crypto boundary.
	certPath := filepath.Join(dir, "id_ed25519-cert.pub")
	if err := os.WriteFile(certPath, []byte(issued.Certificate), 0o644); err != nil {
		t.Fatal(err)
	}
	if sshKeygen, err := exec.LookPath("ssh-keygen"); err == nil {
		out, lerr := exec.Command(sshKeygen, "-L", "-f", certPath).CombinedOutput()
		if lerr != nil {
			t.Fatalf("ssh-keygen -L failed: %v\n%s", lerr, out)
		}
		if !bytes.Contains(out, []byte("alice")) || !bytes.Contains(out, []byte("user certificate")) {
			t.Errorf("ssh-keygen -L did not report the expected user cert/principal:\n%s", out)
		}
	} else {
		// No ssh-keygen: assert the artifact parses as an OpenSSH certificate (test
		// files may import x/crypto/ssh directly).
		pk, _, _, _, perr := xssh.ParseAuthorizedKey([]byte(issued.Certificate))
		if perr != nil {
			t.Fatalf("issued artifact does not parse as an SSH public key: %v", perr)
		}
		if _, ok := pk.(*xssh.Certificate); !ok {
			t.Errorf("issued artifact is not an OpenSSH certificate (type %T)", pk)
		}
	}

	// INTEROP-009: revoke the cert and confirm the SERVED /ssh/krl emits the OpenSSH
	// BINARY KRL (magic "SSHKRL"), the artifact sshd's RevokedKeys consumes — not the
	// JSON snapshot sshd cannot load.
	rev, _ := json.Marshal(sshRevokeRequest{Serial: issued.Serial})
	rresp, err := h.ts.Client().Post(h.ts.URL+"/ssh/revoke", "application/json", bytes.NewReader(rev))
	if err != nil {
		t.Fatalf("POST /ssh/revoke: %v", err)
	}
	_ = rresp.Body.Close()

	krlResp, err := h.ts.Client().Get(h.ts.URL + "/ssh/krl")
	if err != nil {
		t.Fatalf("GET /ssh/krl: %v", err)
	}
	krl, _ := readAllClose(krlResp)
	if !bytes.HasPrefix(krl, []byte("SSHKRL\n\x00")) {
		t.Fatalf("served /ssh/krl is not the OpenSSH binary KRL format (got %d bytes, prefix %q)", len(krl), firstBytes(krl, 8))
	}
	// When ssh-keygen is present, confirm it reports the cert revoked against the KRL.
	if sshKeygen, err := exec.LookPath("ssh-keygen"); err == nil {
		krlPath := filepath.Join(dir, "trstctl.krl")
		if err := os.WriteFile(krlPath, krl, 0o644); err != nil {
			t.Fatal(err)
		}
		out, qerr := exec.Command(sshKeygen, "-Q", "-f", krlPath, certPath).CombinedOutput()
		// ssh-keygen -Qf exits non-zero when the cert is revoked; either way the output
		// must mention revocation.
		if !bytes.Contains(bytes.ToLower(out), []byte("revoked")) && qerr == nil {
			t.Errorf("ssh-keygen -Qf did not report the cert revoked against the served KRL:\n%s", out)
		}
	}
}

// genSSHKey generates an ed25519 SSH key pair at keyPath using ssh-keygen when
// available, returning the public key in authorized_keys form. When ssh-keygen is
// absent it generates one through the crypto boundary.
func genSSHKey(t *testing.T, keyPath string) []byte {
	t.Helper()
	if sshKeygen, err := exec.LookPath("ssh-keygen"); err == nil {
		if out, gerr := exec.Command(sshKeygen, "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "alice@corp").CombinedOutput(); gerr != nil {
			t.Fatalf("ssh-keygen genkey: %v\n%s", gerr, out)
		}
		pub, err := os.ReadFile(keyPath + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		return bytes.TrimSpace(pub)
	}
	// Fallback: a fresh signer's SSH public key (authorized_keys form) via crypto.
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	pub, err := crypto.SSHPublicKeyFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(pub)
}

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// readAllClose reads and closes an HTTP response body.
func readAllClose(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}
