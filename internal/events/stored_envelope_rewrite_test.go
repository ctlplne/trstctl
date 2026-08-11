// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestRewriteStoredEnvelopeDataExactPreservesEveryOtherByte(t *testing.T) {
	t.Parallel()
	before := []byte(`{"error":"provider-credential"}`)
	after := []byte(`{"error":"execution_failed"}`)
	beforeToken, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	afterToken, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte("{\n" +
		"  \"unknown_future_field\" : { \"preserve\" : [1, 2, 3] },\n" +
		"  \"actor\" : null,\n" +
		"  \"data\" : " + string(beforeToken) + ",\n" +
		"  \"time\" : \"2026-08-11T12:00:00Z\",\n" +
		"  \"tenant_id\" : \"11111111-1111-1111-1111-111111111111\",\n" +
		"  \"type\" : \"secret.rotation_schedule.ran\",\n" +
		"  \"id\" : \"legacy-run-1\"\n" +
		"}\n")
	want := bytes.Replace(stored, beforeToken, afterToken, 1)

	got, err := RewriteStoredEnvelopeDataExact(stored, before, after)
	if err != nil {
		t.Fatalf("RewriteStoredEnvelopeDataExact: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stored envelope changed outside data token:\n got: %s\nwant: %s", got, want)
	}
	if bytes.Contains(got, []byte(base64.StdEncoding.EncodeToString(before))) {
		t.Fatalf("stored envelope retained old data token: %s", got)
	}
}

func TestValidateRewritePairRejectsSemanticallyEqualEnvelopeReserialization(t *testing.T) {
	t.Parallel()
	before := []byte(`{"error":"provider-credential"}`)
	after := []byte(`{"error":"execution_failed"}`)
	beforeToken, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte("{ \"unknown\" : true, \"actor\" : null, \"data\" : " + string(beforeToken) +
		", \"time\" : \"2026-08-11T12:00:00Z\", \"tenant_id\" : \"11111111-1111-1111-1111-111111111111\", \"type\" : \"secret.rotation_schedule.ran\", \"id\" : \"legacy-run-1\" }")
	var reserialized storedEvent
	if err := json.Unmarshal(stored, &reserialized); err != nil {
		t.Fatal(err)
	}
	reserialized.Data = after
	wrong, err := json.Marshal(reserialized)
	if err != nil {
		t.Fatal(err)
	}
	header := nats.Header{}
	header.Set(jetstream.MsgIDHeader, "legacy-run-1")
	source := &jetstream.RawStreamMsg{Sequence: 1, Subject: "events.secret.rotation_schedule.ran", Header: header, Data: stored}
	target := &jetstream.RawStreamMsg{Sequence: 1, Subject: source.Subject, Header: header, Data: wrong}
	validate := func(beforeEvent, afterEvent storedEvent) error {
		if !bytes.Equal(beforeEvent.Data, before) || !bytes.Equal(afterEvent.Data, after) {
			t.Fatalf("validator data = %q -> %q", beforeEvent.Data, afterEvent.Data)
		}
		return nil
	}
	if _, err := validateRewritePair(source, target, validate); err == nil {
		t.Fatal("rewrite pair accepted a target that dropped unknown/raw envelope bytes")
	}

	exact, err := RewriteStoredEnvelopeDataExact(stored, before, after)
	if err != nil {
		t.Fatal(err)
	}
	target.Data = exact
	changed, err := validateRewritePair(source, target, validate)
	if err != nil {
		t.Fatalf("exact surgical pair rejected: %v", err)
	}
	if !changed {
		t.Fatal("exact surgical pair was not reported changed")
	}
}

func TestRewriteStoredEnvelopeDataExactRejectsDuplicateDataMember(t *testing.T) {
	t.Parallel()
	old := []byte(`{"old":true}`)
	token, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte(`{"id":"event-1","data":` + string(token) + `,"data":` + string(token) + `}`)
	if _, err := RewriteStoredEnvelopeDataExact(stored, old, []byte(`{"new":true}`)); err == nil {
		t.Fatal("duplicate data member was accepted")
	}
}
