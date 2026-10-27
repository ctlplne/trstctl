// SPDX-License-Identifier: BUSL-1.1

package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/rca"
)

// The published schema is a draft-07 document a client can validate against, and
// it requires what every result carries.
func TestResultSchemaIsAPublishedDraft07Document(t *testing.T) {
	var schema struct {
		Schema     string                     `json:"$schema"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(ResultSchema(), &schema); err != nil {
		t.Fatalf("result schema is not JSON: %v", err)
	}
	if schema.Schema != "http://json-schema.org/draft-07/schema#" {
		t.Fatalf("$schema = %q", schema.Schema)
	}
	for _, want := range []string{"schema", "tool", "text", "generated_at", "findings"} {
		if !slices.Contains(schema.Required, want) {
			t.Fatalf("schema does not require %s: %v", want, schema.Required)
		}
	}
	var version struct {
		Const string `json:"const"`
	}
	if json.Unmarshal(schema.Properties["schema"], &version) != nil || version.Const != ResultSchemaID {
		t.Fatalf("schema version const = %q, want %q", version.Const, ResultSchemaID)
	}
	if &ResultSchema()[0] == &resultSchema[0] {
		t.Fatal("ResultSchema must return a copy")
	}
}

// An investigation tool answers with one finding per cited record: the record's
// citation as its evidence, its source, its recorded time, and a confidence.
func TestInvestigationToolsAnswerWithAFindingPerCitedRecord(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	q := stubQuery{byTenant: map[string][]rca.Record{"t1": {
		{Source: "log", ID: "e1", Summary: "event type=identity.renewal_failed reason=ca timeout", At: at},
		{Source: "log", ID: "e1", Summary: "the same record again"},
		{Source: "cbom", ID: "pay:443", Summary: "crypto asset algorithm=RSA"},
	}}}
	s := New("t1", rca.NewPipeline(q, nil), rca.NewSynthesizer(aimodel.New(nil, nil)), NewRateLimiter(100, time.Minute), &auditsink.Recorder{}, "spiffe://example.org/mcp")
	res, err := s.Call(context.Background(), "agent", "t1", "explain_incident", "payments")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 || !res.Sufficient {
		t.Fatalf("findings = %+v (sufficient %v), want one per distinct cited record", res.Findings, res.Sufficient)
	}
	logFinding, cbomFinding := res.Findings[0], res.Findings[1]
	if logFinding.FindingID != "record:log#e1" || logFinding.Kind != "log_record" || logFinding.Source != "log" ||
		!slices.Equal(logFinding.EvidenceIDs, []string{"log#e1"}) || logFinding.ObservedAt == nil || !logFinding.ObservedAt.Equal(at) ||
		logFinding.Confidence != ConfidenceRecorded {
		t.Fatalf("event finding = %+v", logFinding)
	}
	if cbomFinding.ObservedAt != nil || cbomFinding.Confidence != ConfidenceObserved {
		t.Fatalf("scan finding = %+v, want no time and observed", cbomFinding)
	}
	raw, err := json.Marshal(cbomFinding)
	if err != nil || !json.Valid(raw) || string(mustField(t, raw, "observed_at")) != "null" {
		t.Fatalf("a finding without a time must say null: %s", raw)
	}
}

// Evidence tools are listed and described, but answered by the API layer.
func TestEvidenceToolsAreListedAndDescribedButNotCalledHere(t *testing.T) {
	s := New("t1", rca.NewPipeline(stubQuery{}, nil), rca.NewSynthesizer(aimodel.New(nil, nil)), nil, nil, "id",
		WithEvidenceTools(map[string]string{"distrust_exposure": "which certificates and stores an entry affects"}))
	if !slices.Contains(s.Tools(), "distrust_exposure") || !s.IsEvidenceTool("distrust_exposure") || s.IsEvidenceTool("query_credentials") {
		t.Fatalf("tools = %v", s.Tools())
	}
	if s.Describe("distrust_exposure") != "which certificates and stores an entry affects" || s.Describe("query_credentials") == "" {
		t.Fatalf("descriptions: %q / %q", s.Describe("distrust_exposure"), s.Describe("query_credentials"))
	}
	if _, err := s.Call(context.Background(), "agent", "t1", "distrust_exposure", "x"); err == nil {
		t.Fatal("an evidence tool was answered by the investigation pipeline")
	}
}

func mustField(t *testing.T, raw []byte, field string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m[field]
}
