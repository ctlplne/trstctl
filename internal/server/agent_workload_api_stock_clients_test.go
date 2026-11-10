// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/workloadapi"
	"trstctl.com/trstctl/internal/agent/workloadchannel"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// B8-L2: the stock SPIFFE clients against a HOST AGENT's Workload API socket,
// where workload identity is delivered since A85, through the whole real path:
// the stock client dials the host socket; the host Workload API attests it
// from the kernel's peer credentials, generates its key and sends the public
// half and the observed selectors up the agent channel through the agent's
// own adapter (internal/agent/workloadchannel), on the enrolled agent's mTLS
// connection; the served control plane issues for the entry
// protocols.spiffe.entries scopes to that agent. CI's spiffe workload api
// conformance job runs these beside the control-plane socket's own proofs
// with TRSTCTL_REQUIRE_GOSPIFFE=1 and TRSTCTL_REQUIRE_SPIFFE_HELPER=1.

const hostAgentWorkloadID = "spiffe://served.test/b8l2-payments"

// startHostAgentWorkloadAPI serves the host Workload API for the enrolled
// agent of an agent-channel harness whose trust domain scopes one entry to
// that agent, matching any process running as this test's user.
func startHostAgentWorkloadAPI(t *testing.T) (*agentChannelHarness, string) {
	t.Helper()
	h := newAgentChannelHarnessWithProtocols(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
		SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		Entries: []config.SPIFFEEntry{{
			SPIFFEID: hostAgentWorkloadID, Selectors: []string{"unix:uid:" + strconv.Itoa(os.Getuid())}, Agent: "job-agent-1",
		}},
	}})
	if h.srv.protocols == nil || h.srv.protocols.spiffe == nil {
		t.Skip("this build serves no SPIFFE trust domain")
	}
	// A short directory: a Unix socket path has a small length limit.
	socketDir, err := os.MkdirTemp("", "trstctl-b8l2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "w.sock")
	srv := workloadapi.New(workloadchannel.New(h.client), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, socket) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)
	return h, socket
}

// The stock go-spiffe client receives the entry's X.509-SVID, with its private
// key and the trust bundle, from the host agent's socket; the certificate chains
// to the served CA and the issuance went up the agent channel.
func TestServedGoSpiffeClientFetchesFromAHostAgentSocketB8L2(t *testing.T) {
	h, socket := startHostAgentWorkloadAPI(t)
	result := runServedGoSpiffeClient(t, "unix://"+socket)
	if result.ID != hostAgentWorkloadID {
		t.Fatalf("the stock go-spiffe client got %q from the host agent's socket, want %q", result.ID, hostAgentWorkloadID)
	}
	if !result.HasPrivateKey || result.BundleAuthorities == 0 {
		t.Fatalf("the stock client got no private key or no trust bundle: %+v", result)
	}
	leafDER, err := base64.StdEncoding.DecodeString(result.CertDER)
	if err != nil {
		t.Fatalf("the client returned non-base64 certificate DER: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("the SVID from the host agent's socket does not chain to the served CA: %v", err)
	}
	if !h.hasEvent(t, "spiffe.workload.svid_issued_via_agent") {
		t.Error("no spiffe.workload.svid_issued_via_agent event: the SVID did not come up the agent channel")
	}
}

// Stock spiffe-helper, in one-shot mode, writes the entry's SVID, key and
// bundle from the host agent's socket.
func TestServedSpiffeHelperWritesAnSVIDFromAHostAgentSocketB8L2(t *testing.T) {
	helper, err := exec.LookPath("spiffe-helper")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_SPIFFE_HELPER") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_SPIFFE_HELPER is set but spiffe-helper is not on PATH: %v", err)
		}
		t.Skip("spiffe-helper not on PATH; set TRSTCTL_REQUIRE_SPIFFE_HELPER=1 in CI to make the stock helper mandatory")
	}
	h, socket := startHostAgentWorkloadAPI(t)
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "helper.conf")
	if err := os.WriteFile(configPath, fmt.Appendf(nil, `agent_address = %q
cert_dir = %q
daemon_mode = false
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
cert_file_mode = 0600
key_file_mode = 0600
`, socket, certDir), 0o600); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, helper, "-config", configPath, "-daemon-mode=false").CombinedOutput() // #nosec G204 -- the stock helper on PATH with a config this test wrote (CWE-78)
	if runCtx.Err() != nil {
		t.Fatalf("spiffe-helper timed out:\n%s", out)
	}
	if err != nil {
		t.Fatalf("spiffe-helper failed against the host agent's socket: %v\n%s", err, out)
	}
	for _, name := range []string{"svid.pem", "svid_key.pem", "svid_bundle.pem"} {
		if stat, err := os.Stat(filepath.Join(certDir, name)); err != nil || stat.Size() == 0 {
			t.Fatalf("spiffe-helper did not write %s: %v\n%s", name, err, out)
		}
	}
	leafDER := servedReadPEMCert(t, filepath.Join(certDir, "svid.pem"))
	if id, err := crypto.SPIFFEIDFromCert(leafDER); err != nil || id != hostAgentWorkloadID {
		t.Fatalf("spiffe-helper's SVID names %q (%v), want %q", id, err, hostAgentWorkloadID)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("spiffe-helper's SVID does not chain to the served CA: %v", err)
	}
	if !h.hasEvent(t, "spiffe.workload.svid_issued_via_agent") {
		t.Error("no spiffe.workload.svid_issued_via_agent event: the SVID did not come up the agent channel")
	}
}
