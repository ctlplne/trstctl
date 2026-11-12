// SPDX-License-Identifier: BUSL-1.1

package elastic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/eventspec"
)

type mapping struct {
	Type       string             `json:"type"`
	Enabled    *bool              `json:"enabled"`
	Properties map[string]mapping `json:"properties"`
}

// mapped reports how the template treats a document path: indexed under a
// type, or kept in _source under an object it does not index.
func mapped(root map[string]mapping, path []string) (string, bool) {
	props := root
	for i, part := range path {
		m, ok := props[part]
		if !ok {
			return "", false
		}
		if m.Enabled != nil && !*m.Enabled {
			return "unindexed", true
		}
		if i == len(path)-1 {
			return m.Type, m.Type != ""
		}
		props = m.Properties
	}
	return "", false
}

// leaves lists every leaf path of a JSON document.
func leaves(prefix []string, v any, out *[][]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			leaves(append(append([]string(nil), prefix...), k), child, out)
		}
	case []any:
		for _, child := range x {
			leaves(prefix, child, out)
		}
	default:
		*out = append(*out, prefix)
	}
}

// P5-L6: every field the elastic feed writes is mapped by the shipped index
// template, or kept unindexed under an event's own data; the ingest pipeline
// copies the chain trailer's proof from its data into trstctl_trailer, which
// the template maps as keywords, so trailers are searchable on their own.
func TestIndexTemplateAndPipelineMapTheFeedP5L6(t *testing.T) {
	var template struct {
		IndexPatterns []string `json:"index_patterns"`
		Template      struct {
			Settings map[string]string `json:"settings"`
			Mappings struct {
				Dynamic    bool               `json:"dynamic"`
				Properties map[string]mapping `json:"properties"`
			} `json:"mappings"`
		} `json:"template"`
	}
	raw, err := os.ReadFile("trstctl-audit-index-template.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &template); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(template.IndexPatterns, "trstctl-audit*") || template.Template.Settings["index.default_pipeline"] != "trstctl-audit" ||
		template.Template.Mappings.Dynamic {
		t.Fatalf("template patterns %v, pipeline %q, dynamic %v", template.IndexPatterns,
			template.Template.Settings["index.default_pipeline"], template.Template.Mappings.Dynamic)
	}
	props := template.Template.Mappings.Properties

	// A real batch, as the feed writes it: two audit records and the trailer.
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	batch := auditsink.FeedBatch{ // #nosec G101 -- a test batch naming an env: reference, not a credential (CWE-798)
		BatchID: "b1d2c3e4-0000-4000-8000-000000000001", DestinationID: "d1", Provider: auditsink.ProviderElastic,
		EndpointURL: "https://search.example.test/trstctl-audit/_bulk", TokenRef: "env:ES_KEY",
		StartSequence: 41, EndSequence: 42, PrevHash: "aa11", ChainHead: "bb22",
		Records: []auditchain.Record{
			{Sequence: 41, ID: "r41", Type: "owner.created", TenantID: "t1", Time: at,
				Actor: &eventspec.Actor{Subject: "ops@example.test", Roles: []string{"admin"}}, Data: json.RawMessage(`{"name":"team","nested":{"x":1}}`), Hash: "h41"},
			{Sequence: 42, ID: "r42", Type: "certificate.revoked", TenantID: "t1", Time: at.Add(time.Second),
				Data: json.RawMessage(`{"name":{"first":"object where another type had a string"}}`), Hash: "h42"},
		},
	}
	var body bytes.Buffer
	if err := auditsink.WriteCollectorBatch(&body, batch); err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	scanner := bufio.NewScanner(&body)
	for line := 0; scanner.Scan(); line++ {
		if line%2 == 0 {
			continue // the create action
		}
		var doc map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		docs = append(docs, doc)
	}
	if len(docs) != 3 {
		t.Fatalf("%d documents, want two records and the trailer", len(docs))
	}
	for _, doc := range docs {
		var paths [][]string
		leaves(nil, doc, &paths)
		for _, path := range paths {
			if kind, ok := mapped(props, path); !ok {
				t.Fatalf("the template does not map %s (document %v)", strings.Join(path, "."), doc["event"])
			} else if kind == "" {
				t.Fatalf("%s has no type", strings.Join(path, "."))
			}
		}
	}
	trailer := docs[2]["trstctl"].(map[string]any)
	if trailer["type"] != "trstctl.audit.chain_trailer" {
		t.Fatalf("the last document is %v, want the trailer", trailer["type"])
	}
	proof := trailer["data"].(map[string]any)

	// The pipeline's trailer processors read the trailer's proof and write
	// fields the template maps.
	var pipeline struct {
		Processors []map[string]struct {
			If       string `json:"if"`
			Field    string `json:"field"`
			Value    string `json:"value"`
			Override *bool  `json:"override"`
		} `json:"processors"`
	}
	raw, err = os.ReadFile("trstctl-audit-pipeline.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pipeline); err != nil {
		t.Fatal(err)
	}
	source := regexp.MustCompile(`^\{\{\{trstctl\.data\.([a-z_]+)\}\}\}$`)
	var copied []string
	for _, processor := range pipeline.Processors {
		set, ok := processor["set"]
		if !ok {
			t.Fatalf("unexpected processor %v", processor)
		}
		if kind, ok := mapped(props, strings.Split(set.Field, ".")); !ok || kind == "unindexed" {
			t.Fatalf("the pipeline writes %s, which the template does not index", set.Field)
		}
		if m := source.FindStringSubmatch(set.Value); m != nil {
			if !strings.Contains(set.If, "'trstctl.audit.chain_trailer'") {
				t.Fatalf("%s is copied for documents other than the trailer: %q", set.Field, set.If)
			}
			if _, ok := proof[m[1]]; !ok {
				t.Fatalf("the trailer's proof has no %s for %s", m[1], set.Field)
			}
			copied = append(copied, m[1])
		}
	}
	slices.Sort(copied)
	if !slices.Equal(copied, []string{"batch_id", "chain_head", "count", "prev_hash"}) {
		t.Fatalf("the pipeline copies %v of the trailer's proof", copied)
	}
}
