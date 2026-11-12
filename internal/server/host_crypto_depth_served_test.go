// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type x2Finding struct {
	Kind     string            `json:"kind"`
	Ref      string            `json:"ref"`
	Metadata map[string]string `json:"metadata"`
}

// X2: an agent inventories a JKS and a PKCS#12 keystore on its host, and both
// appear with key type and size while nothing the agent sends or the API
// serves carries key material; its OpenSSL 3.5 library reads as able to
// negotiate X25519MLKEM768 and its OpenSSL 3.0 library as not; and a CBOM scan
// of a HAProxy file that allows TLS 1.0 raises one weak finding, still one
// after a rescan.
func TestServedHostCryptoDiscoveryDepthX2(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a := enrollAgent(t, h, "edge-agent-host-crypto", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	registerInventoryAgent(t, client)
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "risk:read")
	findingsOf := func(runID string) []x2Finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runID, reader, nil)
		var page struct {
			Items []x2Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("discovery findings: HTTP %d %s", status, body)
		}
		if strings.Contains(string(body), "PRIVATE KEY") {
			t.Fatalf("served discovery findings expose private-key bytes: %s", body)
		}
		return page.Items
	}

	// Two keystores holding the same ECDSA P-256 key and its two-certificate chain.
	root := t.TempDir()
	hostKey, err := crypto.GenerateHostSubjectKey("app.example.test", []string{"app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer hostKey.Destroy()
	keyPEM, err := hostKey.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(keyPEM)
	ca, err := mtls.NewCA("x2-host-ca")
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := ca.SignClientCSR(hostKey.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jksData, err := jks.EncodeDeterministic(keyPEM, chainPEM, "storepass", "tomcat")
	if err != nil {
		t.Fatal(err)
	}
	p12Data, err := pfx.EncodeDeterministic(keyPEM, chainPEM, "p12pass")
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "opt", "app", "conf")
	mustWriteFileMode(t, filepath.Join(conf, "server.jks"), jksData, 0o600)
	mustWriteFileMode(t, filepath.Join(conf, "client.p12"), p12Data, 0o600)
	found, err := agentdiscovery.NewKeystoreSource([][]byte{[]byte("storepass"), []byte("p12pass")}, conf).Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sent := privateKeyInventoryFindings(found)
	wire, err := json.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := strings.Join(strings.Split(string(keyPEM), "\n")[1:3], "")
	if strings.Contains(string(wire), "PRIVATE KEY") || strings.Contains(string(wire), keyBody) {
		t.Fatal("the agent's keystore report carries key material")
	}
	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: agentdiscovery.SourceKeystore, Findings: sent})
	if err != nil || inv.Recorded != 2 || inv.Rejected != 0 {
		t.Fatalf("keystore inventory: %+v, %v", inv, err)
	}
	formats := map[string]x2Finding{}
	for _, f := range findingsOf(inv.RunID) {
		formats[f.Metadata["keystore_format"]] = f
	}
	for format, ref := range map[string]string{"JKS": filepath.Join(conf, "server.jks") + "#tomcat", "PKCS12": filepath.Join(conf, "client.p12")} {
		f := formats[format]
		if f.Kind != "private_key" || f.Ref != ref || f.Metadata["key_algorithm"] != "ECDSA-P256" || f.Metadata["key_type"] != "ECDSA" ||
			f.Metadata["key_size_bits"] != "256" || f.Metadata["key_bytes_present"] != "false" || f.Metadata["integrity_verified"] != "true" {
			t.Fatalf("%s keystore finding = %+v", format, f)
		}
	}

	// TLS libraries: OpenSSL 3.5 can negotiate X25519MLKEM768, OpenSSL 3.0 cannot.
	libs := filepath.Join(root, "usr", "lib")
	mustWriteFileMode(t, filepath.Join(libs, "libcrypto.so.3"), []byte("\x7fELF\x00OpenSSL 3.5.1 1 Jul 2025\x00"), 0o644)
	mustWriteFileMode(t, filepath.Join(libs, "legacy", "libcrypto.so.3"), []byte("\x7fELF\x00OpenSSL 3.0.13 30 Jan 2024\x00"), 0o644)
	// X2-L6: the system crypto policy leaves the ML-KEM groups out of
	// OpenSSL's defaults, so OpenSSL 3.5 does not offer X25519MLKEM768 by
	// default on this host.
	policy := filepath.Join(root, "etc", "crypto-policies")
	mustWriteFileMode(t, filepath.Join(policy, "config"), []byte("DEFAULT\n"), 0o644)
	mustWriteFileMode(t, filepath.Join(policy, "back-ends", "opensslcnf.config"), []byte("[ssl_default]\nGroups = X25519:secp256r1:x448\n"), 0o644)
	libraries, err := agentdiscovery.NewCryptoLibrarySource([]string{libs}, nil).WithCryptoPolicy(policy).Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var libraryFindings []transport.InventoryFinding
	for _, l := range libraries {
		libraryFindings = append(libraryFindings, transport.InventoryFinding{
			Kind: "crypto_library", Ref: l.Location, Provenance: agentdiscovery.SourceCryptoLibrary + ":" + l.Location, RiskScore: 30,
			Metadata: map[string]string{"library": l.Library, "library_version": l.Version, "pq_hybrid_x25519mlkem768": l.PQHybrid, "pq_basis": l.Basis},
		})
	}
	inv, err = client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: agentdiscovery.SourceCryptoLibrary, Findings: libraryFindings})
	if err != nil || inv.Recorded != 3 {
		t.Fatalf("crypto library inventory: %+v, %v", inv, err)
	}
	answers, bases := map[string]string{}, map[string]string{}
	for _, f := range findingsOf(inv.RunID) {
		key := f.Metadata["library"] + " " + f.Metadata["library_version"]
		answers[key], bases[key] = f.Metadata["pq_hybrid_x25519mlkem768"], f.Metadata["pq_basis"]
	}
	if answers["openssl 3.5.1"] != "yes" || answers["openssl 3.0.13"] != "no" || answers["crypto-policies DEFAULT"] != "no" ||
		!strings.Contains(bases["crypto-policies DEFAULT"], "leaves the ML-KEM hybrid groups out") {
		t.Fatalf("library answers = %v (%v)", answers, bases)
	}

	// A HAProxy file that allows TLS 1.0 raises one weak finding.
	haproxy := filepath.Join(root, "etc", "haproxy", "haproxy.cfg")
	mustWriteFileMode(t, haproxy, []byte("global\n  ssl-default-bind-options ssl-min-ver TLSv1.0\nfrontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n"), 0o600)
	weak := func() int {
		t.Helper()
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans", reader, map[string]any{"host_configs": []string{haproxy}}); status != http.StatusCreated {
			t.Fatalf("CBOM scan: HTTP %d %s", status, body)
		}
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", reader, nil)
		var inventory struct {
			Items []struct {
				Location    string `json:"location"`
				Protocol    string `json:"protocol"`
				OutOfPolicy bool   `json:"out_of_policy"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &inventory) != nil {
			t.Fatalf("CBOM assets: HTTP %d %s", status, body)
		}
		n := 0
		for _, item := range inventory.Items {
			if item.Location == haproxy && item.OutOfPolicy {
				if item.Protocol != "TLSv1.0" {
					t.Fatalf("unexpected weak HAProxy fact %+v", item)
				}
				n++
			}
		}
		return n
	}
	if n := weak(); n != 1 {
		t.Fatalf("HAProxy TLS 1.0 findings = %d, want 1", n)
	}
	if n := weak(); n != 1 {
		t.Fatalf("after a rescan the HAProxy TLS 1.0 findings = %d, want 1", n)
	}
}
