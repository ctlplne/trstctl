// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These are independently specified producer payloads, including both signed
// report variants. A policy registration must not turn off closed validation.
func TestAgentAuditPayloadsKeepClosedProductionSchemas(t *testing.T) {
	fixtures := map[string][]string{
		"agent.jobs.claimed":                      {`{"agent":"agent-1","count":1,"kinds":["connector.deploy"]}`},
		"agent.jobs.role_refused":                 {`{"agent":"agent-1","roles":["host"],"refused_kinds":["discovery.scan"]}`},
		"agent.jobs.envelope_refused":             {`{"agent":"agent-1","job_id":12,"kind":"connector.deploy"}`},
		"agent.jobs.csr_signed":                   {`{"agent":"agent-1","job_id":12,"names":["edge.example.test"],"fingerprint":"fp-1"}`},
		"agent.job.credential.redeemed":           {`{"agent":"agent-1","job_id":12,"attempt":2,"audit_ref":"audit-1","ref_names":["edge-password"]}`},
		"agent.job.credential.redemption_refused": {`{"agent":"agent-1","job_id":12,"attempt":2,"reason":"claim_not_held"}`},
		"agent.job.receipt.rejected":              {`{"agent":"agent-1","job_id":12,"outcome":"executed","reason":"signature_missing","agent_fingerprint":"fp-1"}`},
		"agent.job.executed": {
			`{"agent":"agent-1","job_id":12,"kind":"connector.deploy","evidence_digest":"digest-1","receipt_statement":"signed bytes","receipt_signature":"signature","receipt_signer_fingerprint":"fp-1"}`,
			`{"agent":"agent-1","job_id":12,"kind":"connector.rollback","evidence_digest":"digest-1","connector":"nginx","target":"edge listener","target_id":"target-1","predecessor_fingerprint":"old","successor_fingerprint":"new","required_agent_id":"agent-1","required_agent_role":"network","receipt_statement":"signed bytes","receipt_signature":"signature","receipt_signer_fingerprint":"fp-1"}`,
		},
		"agent.job.failed": {
			`{"agent":"agent-1","job_id":12,"detail":"failed","receipt_statement":"signed bytes","receipt_signature":"signature","receipt_signer_fingerprint":"fp-1"}`,
			`{"agent":"agent-1","job_id":12,"detail":"lifecycle_transition_refused","outcome":"executed","receipt_statement":"signed bytes","receipt_signature":"signature","receipt_signer_fingerprint":"fp-1"}`,
		},
		"spiffe.workload.svid_issued_via_agent": {`{"agent":"agent-1","node":"node-1","selectors":["unix:uid:1000"],"x509":1,"jwt":0}`},
	}
	for eventType, payloads := range fixtures {
		t.Run(eventType, func(t *testing.T) {
			for _, payload := range payloads {
				data := []byte(payload)
				if err := validateRegisteredPrivacyEventPayload(data, eventType, 1); err != nil {
					t.Fatalf("valid producer payload refused: %v", err)
				}
				if err := validateRegisteredPrivacyEventPayload(data, eventType, 2); err == nil {
					t.Error("undeclared schema version accepted")
				}
				for _, mutation := range []string{"unknown", "missing", "wrong-type"} {
					var fields map[string]any
					if err := json.Unmarshal(data, &fields); err != nil {
						t.Fatal(err)
					}
					switch mutation {
					case "unknown":
						fields["secret_material"] = "must not enter history"
					case "missing":
						delete(fields, "agent")
					case "wrong-type":
						fields["agent"] = []string{"agent-1"}
					}
					encoded, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					if err := validateRegisteredPrivacyEventPayload(encoded, eventType, 1); err == nil {
						t.Errorf("%s producer payload accepted", mutation)
					}
				}
				if eventType == "agent.job.executed" || eventType == "agent.job.failed" {
					if rewritten, changed, err := applyRegisteredPrivacyEventPolicy(data, "tenant-1", "agent-1", eventType, 1); err == nil || changed || rewritten != nil {
						t.Errorf("signed subject-bearing receipt was eligible for rewrite: changed=%v err=%v", changed, err)
					}
					if retained, changed, err := applyRegisteredPrivacyEventPolicy(data, "tenant-1", "unrelated-subject", eventType, 1); err != nil || changed || !bytes.Equal(retained, data) {
						t.Errorf("unrelated erasure altered signed receipt: changed=%v err=%v", changed, err)
					}
				}
			}
		})
	}
	// A partial rollback must not fit either the plain or complete rollback shape.
	partial := strings.Replace(fixtures["agent.job.executed"][0], `"kind":"connector.deploy"`, `"kind":"connector.rollback","target_id":"target-1"`, 1)
	if err := validateRegisteredPrivacyEventPayload([]byte(partial), "agent.job.executed", 1); err == nil {
		t.Fatal("partial rollback receipt accepted")
	}
}

// Production rejects unknown event types even when an ordinary test log accepts
// them. Bind every generic agent publisher call to a core registration so a new
// caller cannot silently lose its audit record in the shipped server.
func TestEveryAgentAuditPublisherHasProductionPrivacySchema(t *testing.T) {
	registered := map[string]bool{}
	for _, schema := range CoreProductionPrivacyEventSchemas() {
		if schema.SchemaVersion == DefaultSchemaVersion {
			registered[schema.EventType] = true
		}
	}
	files, err := filepath.Glob("../server/*.go")
	if err != nil {
		t.Fatal(err)
	}
	callers := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "recordAgentJobEvent" {
				return true
			}
			callers++
			if len(call.Args) != 4 {
				t.Errorf("%s: unexpected agent publisher signature", set.Position(call.Pos()))
				return true
			}
			literal, ok := call.Args[2].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Errorf("%s: agent publisher must declare a reviewable event type", set.Position(call.Pos()))
				return true
			}
			eventType, err := strconv.Unquote(literal.Value)
			if err != nil || !registered[eventType] {
				t.Errorf("%s: agent event %q lacks a production privacy schema", set.Position(call.Pos()), eventType)
			}
			return true
		})
	}
	if callers == 0 {
		t.Fatal("agent publisher guard examined no calls")
	}
}
