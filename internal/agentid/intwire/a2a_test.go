// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package intwire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
)

const tenantA2A = "99999999-9999-4999-8999-999999999999"

// TestAGID_ReferenceA2A_TwoAgentsExchangeTaskWithVerifiedIdentities_RealInfra runs
// the reference A2A pair (official A2A Go SDK) against the real signer and the
// served agent-delegation API. agent-b serves skills behind its signed Agent Card;
// agent-a reaches it with its trstctl identity and delegated credential. The task
// within agent-a's delegated scope completes; an out-of-scope skill, the same
// credential presented by another agent, an agent from an untrusted CA, and a
// caller that reached a different agent than it meant to are all refused.
func TestAGID_ReferenceA2A_TwoAgentsExchangeTaskWithVerifiedIdentities_RealInfra(t *testing.T) {
	h := newHarness(t, tenantA2A)
	issued := h.issueAgent(t, "agent-a", "nonce-a2a")
	toolserverBin, a2aBin := buildReferenceA2A(t)
	apiURL, apiCA, token := h.serveRelyingPartyAPI(t)
	ids := newLabIdentities(t, h)
	outsiders := newLabIdentitiesUnder(t, h, "lab-outsider-identity-ca") // a CA agent-b does not trust
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	agentCA := write("agent-ca.pem", crypto.EncodeCertificatePEM(ids.caDER))
	bCert, bKey := ids.agentIdentity(t, dir, "agent-b")
	aCert, aKey := ids.agentIdentity(t, dir, "agent-a")
	intruderCert, intruderKey := ids.agentIdentity(t, dir, "agent-intruder")
	outsiderCert, outsiderKey := outsiders.agentIdentity(t, dir, "agent-outsider")
	credential := write("agent-a.der", issued.credential.CredentialDER)
	port := freeLabPort(t)
	publicURL := "https://127.0.0.1:" + port
	pinsFile := filepath.Join(dir, "pins.json")
	config, err := json.Marshal(map[string]any{
		"listen": "127.0.0.1:" + port, "public_url": publicURL, "agent_id": "agent-b",
		"tls_cert_file": bCert, "tls_key_file": bKey, "agent_ca_file": agentCA,
		"agent_id_prefix": labSPIFFEPrefix, "tenant_id": h.tenant, "pins_file": pinsFile,
		"trstctl_url": apiURL, "trstctl_ca_file": write("trstctl-ca.pem", apiCA),
		"trstctl_token_file": write("trstctl-token", []byte(token)),
		"status_ttl_seconds": int(labStatusTTL / time.Second), "audit_file": filepath.Join(dir, "audit.jsonl"),
		"policy": map[string]any{
			"approved_agent_stacks": []string{hex.EncodeToString(delegation.AgentStackDigestOf(issued.reprBytes))},
			"tool_manifest":         []string{"search"},
			"operations":            map[string][]string{"agent-worker": {"read"}},
			"tool_operations":       map[string]string{"search": "read", "purge": "delete"},
		},
		"skills": map[string]string{"research": "search", "purge": "purge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	configFile := write("agent-b.json", config)
	runReference(t, toolserverBin, "pin", "--config", configFile)
	if listening := startToolServer(t, a2aBin, configFile); listening != publicURL {
		t.Fatalf("agent-b serves %s, want %s", listening, publicURL)
	}

	call := func(cert, key, expect, skill string) map[string]any {
		t.Helper()
		out := runReference(t, a2aBin, "call", "--card", publicURL, "--expect-agent", expect,
			"--agent-id-prefix", labSPIFFEPrefix, "--tls-cert", cert, "--tls-key", key, "--agent-ca", agentCA,
			"--credential", credential, "--credential-id", issued.credentialID, "--skill", skill, "--text", "open invoices")
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("a2aagent output %q: %v", out, err)
		}
		return got
	}
	errorOf := func(r map[string]any) string { s, _ := r["error"].(string); return s }

	if r := call(aCert, aKey, "agent-b", "research"); errorOf(r) != "" || r["reply"] != "research result for open invoices" || r["card"] != "agent-b" {
		t.Fatalf("agent-a's in-scope task: %v", r)
	}
	if msg := errorOf(call(aCert, aKey, "agent-b", "purge")); !strings.Contains(strings.ToLower(msg), "permission denied") || !strings.Contains(msg, "manifest") {
		t.Fatalf("agent-a's out-of-scope task was not refused by agent-b: %q", msg)
	}
	if msg := errorOf(call(intruderCert, intruderKey, "agent-b", "research")); !strings.Contains(msg, "not to the connected agent agent-intruder") {
		t.Fatalf("another agent presenting agent-a's credential was not refused: %q", msg)
	}
	if msg := errorOf(call(outsiderCert, outsiderKey, "agent-b", "research")); !strings.Contains(msg, "card was not accepted") {
		t.Fatalf("an agent from an untrusted CA reached agent-b: %q", msg)
	}
	if msg := errorOf(call(aCert, aKey, "agent-c", "research")); !strings.Contains(msg, "not agent-c") {
		t.Fatalf("a caller reached a different agent than it meant to: %q", msg)
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !bytes.Contains(audit, []byte(`"allowed":true`)) || !bytes.Contains(audit, []byte(`"chain":["root","manager","agent-a"]`)) {
		t.Fatalf("agent-b's audit does not show the delegation chain behind the task: %s %v", audit, err)
	}
}

func buildReferenceA2A(t *testing.T) (toolserver, a2aagent string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "test", "interop", "agentframeworks"))
	out := t.TempDir()
	for _, name := range []string{"toolserver", "a2aagent"} {
		cmd := exec.Command("go", "build", "-mod=readonly", "-o", filepath.Join(out, name), "./cmd/"+name)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off",
			"GOPRIVATE=trstctl.com/*,github.com/ctlplne/*", "GONOPROXY=trstctl.com/*,github.com/ctlplne/*", "GONOSUMDB=trstctl.com/*,github.com/ctlplne/*")
		if built, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build reference %s: %v\n%s", name, err, built)
		}
	}
	return filepath.Join(out, "toolserver"), filepath.Join(out, "a2aagent")
}

// freeLabPort reserves a loopback port for a reference server.
func freeLabPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}
