// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// X2-L5R: a host agent's libraries, keystore keys and key files reach the
// CBOM inventory itself. Two agents report over the served agent channel; GET
// /api/v1/cbom/assets then lists each library at "<agent>:<path>", rated by
// its X25519MLKEM768 answer (OpenSSL 3.5.9 strong, OpenSSL 3.0.13
// quantum-vulnerable, a Java installation strong) with its version, each
// keystore key by its type and size (RSA-2048 quantum-vulnerable, RSA-1024
// weak and out of policy) and each key file by its algorithm (ECDSA-P256,
// Ed25519); a locked store that names no key, and a finding that names no
// library, are no asset. The agent's next library report, with OpenSSL
// upgraded in place and the old library gone, updates the first asset and
// retires the second, while the other agent's library at the same path and
// the agent's keys stay; a keystore report retires keystore keys only. The
// CycloneDX export still carries each library once.
func TestServedHostAgentLibrariesAndKeystoreKeysAreCBOMAssetsX2L5R(t *testing.T) {
	signingKey, err := jose.GenerateRSASigningKey("x2l5r-cbom")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) { d.AuditSigningKey = signingKey })
	tok := seedScopedToken(t, h.store, h.tenant, "risk:read", "discovery:read", "audit:read")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	agentClient := func(cn string) *transport.AgentClient {
		a := enrollAgentWithRoles(t, h, cn, "agent.trstctl.local", []string{"host"})
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
		registerInventoryAgent(t, client)
		return client
	}
	library := func(ref, name, version, pq, basis string) transport.InventoryFinding {
		return transport.InventoryFinding{Kind: "crypto_library", Ref: ref, Provenance: agentdiscovery.SourceCryptoLibrary + ":" + ref, RiskScore: 30,
			Metadata: map[string]string{"library": name, "library_version": version, "pq_hybrid_x25519mlkem768": pq, "pq_basis": basis}}
	}
	report := func(client *transport.AgentClient, source string, findings ...transport.InventoryFinding) {
		t.Helper()
		inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: source, Findings: findings})
		if err != nil || inv.Recorded != len(findings) {
			t.Fatalf("%s inventory: %+v, %v", source, inv, err)
		}
	}
	type asset struct {
		ID                string   `json:"id"`
		Kind              string   `json:"kind"`
		Location          string   `json:"location"`
		Algorithm         string   `json:"algorithm"`
		KeyBits           int      `json:"key_bits"`
		Library           string   `json:"library"`
		ProductVersion    string   `json:"product_version"`
		Strength          string   `json:"strength"`
		QuantumVulnerable bool     `json:"quantum_vulnerable"`
		OutOfPolicy       bool     `json:"out_of_policy"`
		Reasons           []string `json:"reasons"`
		MigrationTarget   string   `json:"migration_target"`
	}
	inventory := func() map[string]asset {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
		var inv struct {
			Items []asset `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &inv) != nil {
			t.Fatalf("CBOM inventory = %d %s", status, body)
		}
		out := map[string]asset{}
		for _, a := range inv.Items {
			if a.Kind == "crypto-library" || a.Kind == "keystore-key" || a.Kind == "key-file" {
				out[a.Location] = a
			}
		}
		return out
	}

	web, edge := agentClient("web-x2l5r"), agentClient("edge-x2l5r")
	report(web, agentdiscovery.SourceCryptoLibrary,
		library("/usr/lib/libcrypto.so.3", "openssl", "3.5.9", "yes", "OpenSSL 3.5 and later include ML-KEM"),
		library("/opt/old/libcrypto.so.3", "openssl", "3.0.13", "no", "OpenSSL before 3.5 has no built-in ML-KEM"),
		library("/usr/lib/jvm/java-25-openjdk", "java", "25.0.5.0.3", "yes", "this Java installation's modules name the X25519MLKEM768 group"),
		transport.InventoryFinding{Kind: "crypto_library", Ref: "/usr/lib/unnamed.so", Provenance: "crypto-library:/usr/lib/unnamed.so", Metadata: map[string]string{"library_version": "1"}})
	report(edge, agentdiscovery.SourceCryptoLibrary, library("/usr/lib/libcrypto.so.3", "openssl", "3.0.13", "no", "OpenSSL before 3.5"))
	key := func(ref, keyType, bits string, extra ...string) transport.InventoryFinding {
		meta := map[string]string{"material_class": "private-key", "key_format": "PKCS12", "key_algorithm": keyType, "key_bytes_present": "false"}
		if keyType != "" {
			meta["key_type"], meta["key_size_bits"] = keyType, bits
		}
		for i := 0; i+1 < len(extra); i += 2 {
			meta[extra[i]] = extra[i+1]
		}
		return transport.InventoryFinding{Kind: "private_key", Ref: ref, Provenance: agentdiscovery.SourceKeystore + ":" + ref,
			Fingerprint: strings.Repeat("cd", 32), RiskScore: 85, Metadata: meta}
	}
	report(web, agentdiscovery.SourceKeystore,
		key("/opt/app/keystore.p12#tomcat", "RSA", "2048"),
		key("/opt/app/legacy.jks#old", "RSA", "1024", "key_strength", "weak", "key_weak_reason", "RSA modulus is 1024 bits"),
		key("/opt/app/locked.p12", "", "", "keystore_state", "locked"))
	keyFile := func(ref, algorithm string) transport.InventoryFinding {
		return transport.InventoryFinding{Kind: "private_key", Ref: ref, Provenance: agentdiscovery.SourcePrivateKey + ":" + ref,
			Fingerprint: strings.Repeat("ef", 32), RiskScore: 85, Metadata: map[string]string{"material_class": "private-key",
				"key_format": "PKCS8", "key_algorithm": algorithm, "key_bytes_present": "false"}}
	}
	report(web, agentdiscovery.SourcePrivateKey, keyFile("/etc/ssl/private/web.key", "ECDSA-P256"), keyFile("/etc/ssh/ssh_host_ed25519_key", "Ed25519"))

	got := inventory()
	for location, want := range map[string]struct {
		kind, product, strength string
		qv, oop                 bool
		bits                    int
	}{
		"web-x2l5r:/usr/lib/libcrypto.so.3":       {"crypto-library", "openssl 3.5.9", "strong", false, false, 0},
		"web-x2l5r:/opt/old/libcrypto.so.3":       {"crypto-library", "openssl 3.0.13", "acceptable", true, false, 0},
		"web-x2l5r:/usr/lib/jvm/java-25-openjdk":  {"crypto-library", "java 25.0.5.0.3", "strong", false, false, 0},
		"edge-x2l5r:/usr/lib/libcrypto.so.3":      {"crypto-library", "openssl 3.0.13", "acceptable", true, false, 0},
		"web-x2l5r:/opt/app/keystore.p12#tomcat":  {"keystore-key", "", "acceptable", true, false, 2048},
		"web-x2l5r:/opt/app/legacy.jks#old":       {"keystore-key", "", "weak", true, true, 1024},
		"web-x2l5r:/etc/ssl/private/web.key":      {"key-file", "", "acceptable", true, false, 256},
		"web-x2l5r:/etc/ssh/ssh_host_ed25519_key": {"key-file", "", "acceptable", true, false, 256},
	} {
		a, ok := got[location]
		if !ok || a.Kind != want.kind || a.ProductVersion != want.product || a.Strength != want.strength || a.QuantumVulnerable != want.qv ||
			a.OutOfPolicy != want.oop || a.KeyBits != want.bits || len(a.Reasons) == 0 || a.MigrationTarget == "" {
			t.Errorf("%s = %+v; want %+v", location, a, want)
		}
	}
	if len(got) != 8 {
		t.Errorf("%d host agent assets, want 8 (a finding naming no library and a locked store are no asset): %+v", len(got), got)
	}
	if a := got["web-x2l5r:/opt/old/libcrypto.so.3"]; !strings.Contains(strings.Join(a.Reasons, " "), "cannot negotiate X25519MLKEM768") {
		t.Errorf("the old OpenSSL's reasons: %v", a.Reasons)
	}
	firstID := got["web-x2l5r:/usr/lib/libcrypto.so.3"].ID

	// The next report: OpenSSL upgraded in place, the old library gone.
	report(web, agentdiscovery.SourceCryptoLibrary,
		library("/usr/lib/libcrypto.so.3", "openssl", "3.5.10", "yes", "OpenSSL 3.5 and later include ML-KEM"),
		library("/usr/lib/jvm/java-25-openjdk", "java", "25.0.5.0.3", "yes", "this Java installation's modules name the X25519MLKEM768 group"))
	got = inventory()
	if a := got["web-x2l5r:/usr/lib/libcrypto.so.3"]; a.ID != firstID || a.ProductVersion != "openssl 3.5.10" {
		t.Errorf("the upgraded library = %+v; want the same asset (%s) at openssl 3.5.10", a, firstID)
	}
	if _, ok := got["web-x2l5r:/opt/old/libcrypto.so.3"]; ok {
		t.Error("the library the agent no longer reports is still listed")
	}
	if _, ok := got["edge-x2l5r:/usr/lib/libcrypto.so.3"]; !ok {
		t.Error("one agent's report retired another's library")
	}
	if _, ok := got["web-x2l5r:/opt/app/keystore.p12#tomcat"]; !ok {
		t.Error("a library report retired a keystore key")
	}
	// A keystore report retires keystore keys only, not key files.
	report(web, agentdiscovery.SourceKeystore, key("/opt/app/keystore.p12#tomcat", "RSA", "2048"))
	got = inventory()
	if _, ok := got["web-x2l5r:/opt/app/legacy.jks#old"]; ok {
		t.Error("the keystore key the agent no longer reports is still listed")
	}
	if _, ok := got["web-x2l5r:/etc/ssl/private/web.key"]; !ok {
		t.Error("a keystore report retired a key file")
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/export/cyclonedx", tok, nil)
	var export struct {
		BOM struct {
			Components []struct {
				Type       string `json:"type"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"components"`
		} `json:"bom"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &export) != nil {
		t.Fatalf("export = %d %s", status, body)
	}
	libraries := 0
	for _, c := range export.BOM.Components {
		for _, p := range c.Properties {
			if p.Name == "trstctl:asset_kind" && (p.Value == "crypto-library" || p.Value == "keystore-key" || p.Value == "key-file") && c.Type == "cryptographic-asset" {
				t.Errorf("the export writes a host agent's %s from the inventory too", p.Value)
			}
		}
		if c.Type == "library" {
			libraries++
		}
	}
	if libraries == 0 {
		t.Error("the export carries no library")
	}
}
