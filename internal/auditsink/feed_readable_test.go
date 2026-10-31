// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestCollectorReadableFieldsStayOutsideTheSourceCommitment(t *testing.T) {
	for _, provider := range []string{ProviderSplunkHEC, ProviderSentinel} {
		for _, erased := range []bool{false, true} {
			record := auditchain.Record{Sequence: 7, ID: "source-7", Type: "authz.decision", TenantID: "tenant-a", Time: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Hash: "original-hash", Data: json.RawMessage(`{"format":"trstctl.protected-audit-source/v1","protection":{"ciphertext":"retained-proof"}}`)}
			before, _ := json.Marshal(record)
			detail := ReadableEvent{Sequence: 7, ID: record.ID, SensitiveErased: erased}
			if !erased {
				detail.Actor = &eventspec.Actor{Subject: "readable-operator"}
				detail.Data = json.RawMessage(`{"decision":"deny"}`)
			}
			var output bytes.Buffer
			err := WriteCollectorBatchWithReadable(&output, FeedBatch{Provider: provider, Records: []auditchain.Record{record}, BatchID: "batch-7"}, []ReadableEvent{detail})
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]json.RawMessage
			sourceField, scopeField, dataField, erasedField := "signed_record", "hash_scope", "data", "sensitive_erased"
			if provider == ProviderSplunkHEC {
				var envelope struct {
					Event json.RawMessage `json:"event"`
				}
				if err := json.NewDecoder(&output).Decode(&envelope); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(envelope.Event, &row); err != nil {
					t.Fatal(err)
				}
			} else {
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal(output.Bytes(), &rows); err != nil {
					t.Fatal(err)
				}
				row = rows[0]
				sourceField, scopeField, dataField, erasedField = "SignedRecord", "HashScope", "Data", "SensitiveErased"
			}
			var source auditchain.Record
			if err := json.Unmarshal(row[sourceField], &source); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(source)
			if !bytes.Equal(before, after) {
				t.Fatal("collector replaced the signed source with readable fields")
			}
			var scope string
			if err := json.Unmarshal(row[scopeField], &scope); err != nil || scope != sourceField {
				t.Fatal("collector hash does not identify its immutable source")
			}
			if erased {
				if len(row[dataField]) != 0 || string(row[erasedField]) != "true" {
					t.Fatal("erased collector fields are not explicit or retain data")
				}
			} else if !bytes.Contains(row[dataField], []byte(`"deny"`)) {
				t.Fatal("readable collector payload is missing")
			}
		}
	}
}

func TestCollectorRejectsUnboundReadableFieldsBeforeWriting(t *testing.T) {
	record := auditchain.Record{Sequence: 7, ID: "source-7", Data: json.RawMessage(`{"format":"trstctl.protected-audit-source/v1"}`)}
	valid := ReadableEvent{Sequence: 7, ID: "source-7"}
	cases := []struct {
		name    string
		records []auditchain.Record
		details []ReadableEvent
	}{
		{"missing", []auditchain.Record{record}, nil},
		{"wrong-id", []auditchain.Record{record}, []ReadableEvent{{Sequence: 7, ID: "other"}}},
		{"wrong-sequence", []auditchain.Record{record}, []ReadableEvent{{Sequence: 8, ID: record.ID}}},
		{"duplicate", []auditchain.Record{record}, []ReadableEvent{valid, valid}},
		{"extra", []auditchain.Record{record}, []ReadableEvent{valid, {Sequence: 8, ID: "other"}}},
		{"erased-with-data", []auditchain.Record{record}, []ReadableEvent{{Sequence: 7, ID: record.ID, SensitiveErased: true, Data: json.RawMessage(`{"private":"must-refuse"}`)}}},
		{"erased-with-actor", []auditchain.Record{record}, []ReadableEvent{{Sequence: 7, ID: record.ID, SensitiveErased: true, Actor: &eventspec.Actor{Subject: "must-refuse"}}}},
		{"legacy-overlay", []auditchain.Record{{Sequence: 7, ID: record.ID, Data: json.RawMessage(`{"legacy":true}`)}}, []ReadableEvent{valid}},
		{"duplicate-source", []auditchain.Record{record, record}, []ReadableEvent{valid}},
	}
	for _, provider := range []string{ProviderSplunkHEC, ProviderSentinel} {
		for _, tc := range cases {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				var output bytes.Buffer
				if err := WriteCollectorBatchWithReadable(&output, FeedBatch{Provider: provider, Records: tc.records}, tc.details); err == nil || output.Len() != 0 {
					t.Fatal("unbound collector fields were accepted or partly written")
				}
			})
		}
	}
}
