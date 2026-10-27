// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type mcpFinding struct {
	FindingID   string            `json:"finding_id"`
	Kind        string            `json:"kind"`
	Summary     string            `json:"summary"`
	EvidenceIDs []string          `json:"evidence_ids"`
	Source      string            `json:"source"`
	ObservedAt  *time.Time        `json:"observed_at"`
	Confidence  string            `json:"confidence"`
	Attributes  map[string]string `json:"attributes"`
}

type mcpToolResult struct {
	Schema     string       `json:"schema"`
	Tool       string       `json:"tool"`
	Text       string       `json:"text"`
	Sufficient *bool        `json:"sufficient"`
	Findings   []mcpFinding `json:"findings"`
}

// TestServedMCPToolsAnswerWithSchemaValidFindingsA184 proves every kind of MCP
// tool (investigation, evidence, REST-backed and write) answers with structured
// findings that validate against the result schema the tool listing publishes,
// and that distrust_exposure names the certificates and host trust stores a
// distrust-list entry affects, each with evidence IDs.
func TestServedMCPToolsAnswerWithSchemaValidFindingsA184(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel, withMCPWriteToolsEnabled(), func(d *Deps) {
		d.AuditSigningKey = auditKey
		d.AIRateMax = 20
	})
	ctx := t.Context()

	// A host trust store holding the distrusted emSign ECC Root CA - G3 and a weak
	// RSA-1024 anchor, reported by an enrolled agent over its mTLS channel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a := enrollAgent(t, h, "edge-agent-mcp", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	registerInventoryAgent(t, client)
	reportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	inv, err := client.ReportInventory(reportCtx, &transport.InventoryRequest{
		SourceKind: "trust-store",
		Findings: []transport.InventoryFinding{
			{
				Kind: "trust-store", Ref: "trust-store:os:/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem",
				Provenance:  "trust-store:/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem",
				Fingerprint: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b", RiskScore: 20,
				Metadata: map[string]string{"subject": "CN=emSign ECC Root CA - G3", "spki_sha256": "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"},
			},
			{
				Kind: "trust-store", Ref: "trust-store:os:/etc/ssl/certs/legacy-1024.pem", Provenance: "trust-store:/etc/ssl/certs/legacy-1024.pem",
				Fingerprint: "3333333333333333333333333333333333333333333333333333333333333333", RiskScore: 20,
				Metadata: map[string]string{"subject": "CN=Legacy 1024 Root", "spki_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
					"key_strength": "weak", "key_weak_reason": "RSA-1024 is below the 2048-bit minimum"},
			},
		},
	})
	if err != nil || inv.Recorded != 2 {
		t.Fatalf("report trust-store inventory: %+v %v", inv, err)
	}

	// Inventory: a certificate issued under the distrusted root (known by its
	// issuer name), one with a weak key, and a crypto asset.
	expiry := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	record := func(serial, issuer, alg string) store.Certificate {
		t.Helper()
		cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
			Subject: "CN=" + serial + ".mcp-evidence.example.test", Serial: serial, Issuer: issuer, KeyAlgorithm: alg,
			Fingerprint: strings.Repeat(serial[:1], 64), Source: "discovered", NotAfter: &expiry,
		})
		if err != nil {
			t.Fatalf("record %s: %v", serial, err)
		}
		return cert
	}
	distrusted := record("a1emsign", "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN", "ECDSA")
	weak := record("b2weak", "CN=Acme Issuing CA", "RSA-1024")
	if _, err := h.store.UpsertCryptoAsset(ctx, store.CryptoAsset{TenantID: h.tenant, Kind: "tls", Location: "pay.mcp-evidence.example.test:443",
		Algorithm: "RSA", KeyBits: 1024, QuantumVulnerable: true, Library: "openssl", Strength: "weak"}); err != nil {
		t.Fatal(err)
	}
	requested := mcpGateIdentity(t, h, "evidence-issue", orchestrator.StateRequested)

	token := seedScopedToken(t, h.store, h.tenant, "graph:read", "certs:read", "certs:issue", "identities:read", "identities:write",
		"discovery:read", "nhi:read", "risk:read", "audit:read", "owners:read")
	status, body := aiReq(t, h, http.MethodGet, "/api/v1/mcp/tools", token, nil)
	var listed struct {
		Tools        []string          `json:"tools"`
		Descriptions map[string]string `json:"descriptions"`
		ResultSchema json.RawMessage   `json:"result_schema"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.ResultSchema) == 0 {
		t.Fatalf("MCP tools: %d %s", status, body)
	}
	evidenceTools := []string{"posture_findings", "weak_key_exposure", "distrust_exposure", "assurance_record", "revocation_status", "crypto_inventory"}
	for _, tool := range evidenceTools {
		if !slices.Contains(listed.Tools, tool) || listed.Descriptions[tool] == "" {
			t.Fatalf("MCP tools miss %s or its description: %s", tool, body)
		}
	}

	call := func(token, tool string, args map[string]any) (int, mcpToolResult, []byte) {
		t.Helper()
		status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/mcp/tools/"+tool, token, "mcp-evidence-"+tool+"-"+time.Now().Format("150405.000000"), args)
		var got mcpToolResult
		_ = json.Unmarshal(body, &got)
		return status, got, body
	}
	valid := func(tool string, body []byte) {
		t.Helper()
		if problems := mcpSchemaProblems(t, listed.ResultSchema, body); len(problems) != 0 {
			t.Fatalf("%s result does not validate against the published schema: %v\n%s", tool, problems, body)
		}
	}
	// The validator is not vacuous: a result without findings, or with a finding
	// that lacks evidence or names an unknown confidence, fails it.
	for _, bad := range []string{
		`{"schema":"trstctl.mcp.tool-result/v1","tool":"x","text":"t","generated_at":"2026-10-27T00:00:00Z"}`,
		`{"schema":"trstctl.mcp.tool-result/v1","tool":"x","text":"t","generated_at":"2026-10-27T00:00:00Z","findings":[{"finding_id":"f","kind":"k","summary":"s","evidence_ids":[],"source":"s","observed_at":null,"confidence":"recorded"}]}`,
		`{"schema":"trstctl.mcp.tool-result/v1","tool":"x","text":"t","generated_at":"2026-10-27T00:00:00Z","findings":[{"finding_id":"f","kind":"k","summary":"s","evidence_ids":["e:1"],"source":"s","observed_at":null,"confidence":"certain"}]}`,
	} {
		if len(mcpSchemaProblems(t, listed.ResultSchema, []byte(bad))) == 0 {
			t.Fatalf("the published schema accepted an invalid result: %s", bad)
		}
	}
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"query_credentials", map[string]any{"subject": "mcp-evidence"}},
		{"get_blast_radius", map[string]any{"subject": "mcp-evidence"}},
		{"explain_incident", map[string]any{"subject": "mcp-evidence"}},
		{"compliance_status", map[string]any{"subject": "mcp-evidence"}},
		{"posture_findings", map[string]any{}},
		{"weak_key_exposure", map[string]any{}},
		{"distrust_exposure", map[string]any{"subject": "emSign ECC Root CA - G3"}},
		{"assurance_record", map[string]any{"subject": distrusted.ID}},
		{"revocation_status", map[string]any{"subject": weak.ID}},
		{"crypto_inventory", map[string]any{"subject": "RSA"}},
		{"rest_list_owners", map[string]any{}},
		{"issue_certificate", map[string]any{"identity_id": requested.ID, "csr_pem": mcpGateCSR(t, requested.Name), "reason": "evidence fixture"}},
	}
	results := map[string]mcpToolResult{}
	for _, c := range calls {
		status, got, body := call(token, c.tool, c.args)
		if status != http.StatusOK || got.Schema != "trstctl.mcp.tool-result/v1" || got.Findings == nil {
			t.Fatalf("%s = %d %s", c.tool, status, body)
		}
		valid(c.tool, body)
		results[c.tool] = got
	}
	for _, tool := range []string{"query_credentials", "posture_findings", "weak_key_exposure", "distrust_exposure", "assurance_record", "revocation_status", "crypto_inventory", "rest_list_owners", "issue_certificate"} {
		if tool == "posture_findings" {
			continue // a fresh tenant may have no NHI posture finding; the empty answer still validates
		}
		if len(results[tool].Findings) == 0 {
			t.Fatalf("%s returned no findings: %+v", tool, results[tool])
		}
	}

	// distrust_exposure: the affected certificate and trust store, with evidence IDs.
	exposure := results["distrust_exposure"]
	var anchor, cert *mcpFinding
	for i, f := range exposure.Findings {
		switch f.Kind {
		case "distrusted_trust_anchor":
			anchor = &exposure.Findings[i]
		case "distrusted_certificate":
			cert = &exposure.Findings[i]
		}
	}
	if anchor == nil || cert == nil {
		t.Fatalf("distrust_exposure must name the affected certificate and trust store: %+v", exposure)
	}
	if !mcpHasEvidencePrefix(anchor.EvidenceIDs, "discovery_finding:") || !mcpHasEvidencePrefix(anchor.EvidenceIDs, "graph:ts:") ||
		anchor.Attributes["host"] == "" || anchor.Confidence != "observed" || anchor.ObservedAt == nil {
		t.Fatalf("trust store finding lacks its evidence: %+v", *anchor)
	}
	if !slices.Contains(cert.EvidenceIDs, "certificate:"+distrusted.ID) || cert.Confidence != "inferred" || cert.Attributes["distrust_how"] != "issuer_name" {
		t.Fatalf("certificate finding lacks its evidence: %+v", *cert)
	}
	if !strings.Contains(exposure.Text, "It affects 1 certificate and 1 trust store across 1 host.") {
		t.Fatalf("distrust_exposure narrative: %q", exposure.Text)
	}
	if status, _, body := call(token, "distrust_exposure", map[string]any{"subject": "Made Up CA"}); status != http.StatusNotFound || !strings.Contains(string(body), "emSign ECC Root CA - G3") {
		t.Fatalf("an unknown distrust entry = %d %s, want 404 naming the list", status, body)
	}

	// weak_key_exposure covers the weak inventory certificate and the weak anchor.
	kinds := map[string]bool{}
	for _, f := range results["weak_key_exposure"].Findings {
		kinds[f.Kind] = true
		if f.Kind == "weak_key_certificate" && !slices.Contains(f.EvidenceIDs, "certificate:"+weak.ID) && f.Attributes["certificate_id"] == weak.ID {
			t.Fatalf("weak certificate finding lacks its certificate evidence: %+v", f)
		}
	}
	if !kinds["weak_key_certificate"] || !kinds["weak_key_trust_anchor"] {
		t.Fatalf("weak_key_exposure kinds = %v", kinds)
	}

	// A token that may not read discovery findings gets the inventory side only,
	// and the answer says so.
	limited := seedScopedToken(t, h.store, h.tenant, "graph:read", "certs:read")
	status, partial, body := call(limited, "distrust_exposure", map[string]any{"subject": "emSign ECC Root CA - G3"})
	if status != http.StatusOK || partial.Sufficient == nil || *partial.Sufficient || !strings.Contains(partial.Text, "could not read discovery findings") {
		t.Fatalf("distrust_exposure without discovery:read = %d %s", status, body)
	}
	valid("distrust_exposure (limited)", body)
	for _, f := range partial.Findings {
		if f.Kind == "distrusted_trust_anchor" {
			t.Fatalf("a token without discovery:read saw a trust store: %+v", f)
		}
	}
}

func mcpHasEvidencePrefix(ids []string, prefix string) bool {
	for _, id := range ids {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// mcpSchemaProblems validates body against schema with OPA's JSON Schema
// validator, independently of the code that produced either.
func mcpSchemaProblems(t *testing.T, schema json.RawMessage, body []byte) []any {
	t.Helper()
	var doc, sch any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	if err := json.Unmarshal(schema, &sch); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	rs, err := rego.New(rego.Query("result := json.match_schema(input.doc, input.schema)"),
		rego.Input(map[string]any{"doc": doc, "schema": sch})).Eval(t.Context())
	if err != nil || len(rs) != 1 {
		t.Fatalf("evaluate json.match_schema: %v %v", rs, err)
	}
	result, _ := rs[0].Bindings["result"].([]any)
	if len(result) != 2 {
		t.Fatalf("json.match_schema answered %v", rs[0].Bindings["result"])
	}
	if ok, _ := result[0].(bool); ok {
		return nil
	}
	problems, _ := result[1].([]any)
	if len(problems) == 0 {
		problems = []any{"invalid"}
	}
	return problems
}
