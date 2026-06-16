package secretscan

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
)

func TestParseGitleaksDropsValueAndIngests(t *testing.T) {
	// A gitleaks report carrying a real-looking secret value.
	report := []byte(`[{"RuleID":"aws-access-token","File":"config.yaml","StartLine":12,"Secret":"AKIASECRETLEAKEDVALUE","Match":"key=AKIASECRETLEAKEDVALUE"}]`)
	findings, err := ParseGitleaks(report)
	if err != nil || len(findings) != 1 {
		t.Fatalf("parse = %d (err %v)", len(findings), err)
	}
	g := graph.New()
	rec := &auditsink.Recorder{}
	triggered := ""
	ing := New("t1", g, rec, func(_ context.Context, ref string) error { triggered = ref; return nil })
	if _, err := ing.Ingest(context.Background(), findings, true); err != nil {
		t.Fatal(err)
	}
	// Finding appears in the graph with provenance.
	if _, ok := g.Node("leak:gitleaks:config.yaml:12"); !ok {
		t.Error("finding not merged into the graph")
	}
	// Drove the compromise workflow.
	if triggered != "aws-access-token@config.yaml" {
		t.Errorf("compromise trigger = %q", triggered)
	}
	// The defining safety test: the secret value never appears anywhere we persist.
	for _, r := range rec.Records() {
		if bytes.Contains(r.Data, []byte("AKIASECRETLEAKEDVALUE")) {
			t.Fatal("leaked secret value persisted into the audit log")
		}
	}
	for _, n := range g.Nodes() {
		for _, v := range n.Attrs {
			if v == "AKIASECRETLEAKEDVALUE" || bytes.Contains([]byte(v), []byte("AKIASECRETLEAKED")) {
				t.Fatal("leaked secret value persisted into the graph")
			}
		}
	}
}

func TestParseTrufflehog(t *testing.T) {
	jsonl := []byte(`{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"main.tf","line":7}}},"Raw":"AKIALEAK"}`)
	findings, err := ParseTrufflehog(jsonl)
	if err != nil || len(findings) != 1 {
		t.Fatalf("parse = %d (err %v)", len(findings), err)
	}
	if findings[0].RuleID != "AWS" || findings[0].File != "main.tf" {
		t.Errorf("finding = %+v", findings[0])
	}
}
