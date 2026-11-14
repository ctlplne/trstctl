// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
)

func p5Batch(provider string) FeedBatch {
	at := time.Date(2026, 11, 1, 9, 0, 0, 123456789, time.UTC)
	return FeedBatch{
		BatchID: "batch-p5", Provider: provider, PrevHash: "prev", ChainHead: "head-2",
		Records: []auditchain.Record{
			{Sequence: 41, ID: "rec-41", Type: "certificate.issued", TenantID: "tenant-a", Time: at, Hash: "h41", Data: json.RawMessage(`{"serial":"01"}`)},
			{Sequence: 42, ID: "rec-42", Type: "certificate.revoked", TenantID: "tenant-a", Time: at.Add(time.Second), Hash: "h42", Data: json.RawMessage(`{"serial":"01"}`)},
		},
	}
}

// P5: syslog carries one RFC 5424 message per record and the chain trailer,
// octet-counted, with the same collector record as the other feeds.
func TestSyslogBatchIsOctetCountedRFC5424InSequence(t *testing.T) {
	var out bytes.Buffer
	if err := WriteCollectorBatch(&out, p5Batch(ProviderSyslog)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(&out)
	var bodies []collectorRecord
	for {
		lenText, err := r.ReadString(' ')
		if err != nil {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenText))
		if err != nil {
			t.Fatalf("frame length %q: %v", lenText, err)
		}
		msg := make([]byte, n)
		if _, err := r.Read(msg); err != nil {
			t.Fatal(err)
		}
		head, body, ok := strings.Cut(string(msg), " trstctl-audit - ")
		if !ok || !strings.HasPrefix(head, "<110>1 2026-11-01T09:00:0") || !strings.HasSuffix(head, "Z - trstctl -") {
			t.Fatalf("not an RFC 5424 audit message: %q", msg)
		}
		var rec collectorRecord
		if err := json.Unmarshal([]byte(body), &rec); err != nil {
			t.Fatalf("message body: %v", err)
		}
		bodies = append(bodies, rec)
	}
	if len(bodies) != 3 || bodies[0].Sequence != 41 || bodies[1].Sequence != 42 || bodies[1].ChainHash != "h42" ||
		bodies[2].Type != "trstctl.audit.chain_trailer" {
		t.Fatalf("messages = %+v", bodies)
	}
}

// P5: the Elasticsearch body creates each record under its audit ID, so a
// redelivery conflicts instead of duplicating; the bulk result counts only
// real failures.
func TestElasticBatchCreatesEachRecordUnderItsID(t *testing.T) {
	var out bytes.Buffer
	if err := WriteCollectorBatch(&out, p5Batch(ProviderElastic)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("bulk body has %d lines: %s", len(lines), out.String())
	}
	for i, want := range []string{"rec-41", "rec-42", "audit-feed-trailer:batch-p5"} {
		var action elasticAction
		var doc elasticDocument
		if json.Unmarshal([]byte(lines[2*i]), &action) != nil || json.Unmarshal([]byte(lines[2*i+1]), &doc) != nil {
			t.Fatalf("pair %d is not an action and a document: %s / %s", i, lines[2*i], lines[2*i+1])
		}
		if action.Create.ID != want || doc.Event.ID != want || doc.Trstctl.ID != want || doc.Labels.BatchID != "batch-p5" {
			t.Fatalf("pair %d = %+v %+v", i, action, doc)
		}
	}
	if !strings.Contains(lines[1], `"@timestamp":"2026-11-01T09:00:00.123456789Z"`) || !strings.Contains(lines[1], `"sequence":41`) {
		t.Fatalf("first document: %s", lines[1])
	}
	for body, want := range map[string][2]int{
		`{"errors":false,"items":[{"create":{"status":201}},{"create":{"status":201}}]}`: {0, 0},
		`{"errors":true,"items":[{"create":{"status":409}},{"create":{"status":201}}]}`:  {0, 0},
		`{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":429}}]}`:  {1, 429},
		`{"errors":true,"items":[{"create":{"status":400}},{"create":{"status":503}}]}`:  {2, 400},
	} {
		failed, first, err := ElasticBulkResult([]byte(body))
		if err != nil || failed != want[0] || first != want[1] {
			t.Fatalf("%s → failed=%d first=%d err=%v", body, failed, first, err)
		}
	}
	if _, _, err := ElasticBulkResult([]byte("<html>")); err == nil {
		t.Fatal("a non-JSON bulk response was accepted")
	}
}

// P5: endpoint forms each provider takes.
func TestSyslogAndElasticEndpointForms(t *testing.T) {
	for endpoint, want := range map[string]string{
		"syslog+tls://logs.example.test":       "logs.example.test:6514",
		"syslog+tls://logs.example.test:10514": "logs.example.test:10514",
		"syslog+tls://[2001:db8::7]:6514":      "[2001:db8::7]:6514",
	} {
		if target, err := ParseSyslogEndpoint(endpoint); err != nil || target.Addr != want || target.Transport != SyslogTLS {
			t.Fatalf("%s → %+v, %v", endpoint, target, err)
		}
	}
	for _, bad := range []string{"syslog://logs.example.test", "tcp://logs.example.test:514", "syslog+tls://u:p@logs.example.test", "syslog+tls://logs.example.test/x", "syslog+tls://logs.example.test:0", "https://logs.example.test"} {
		if _, err := ParseSyslogEndpoint(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	if index, err := ElasticBulkIndex("/trstctl-audit/_bulk"); err != nil || index != "trstctl-audit" {
		t.Fatalf("index = %q, %v", index, err)
	}
	for _, bad := range []string{"/_bulk", "/a/b/_bulk", "/Audit/_bulk", "/_all/_bulk", "/trstctl-audit/_doc"} {
		if _, err := ElasticBulkIndex(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}
