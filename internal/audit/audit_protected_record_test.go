// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

func TestProtectedAuditCoreSurvivesLogicalErasureWithoutPlaintext(t *testing.T) {
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	key, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	event := events.Event{ID: "opaque-audit-source", Type: "owner.created", TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", SchemaVersion: 1, Time: time.Now().UTC(), Sequence: 19, Data: []byte(`{"email":"person@example.invalid"}`), Actor: &events.Actor{Subject: "private-operator@example.invalid"}}
	context := eventprotect.Context{Scope: eventprotect.ScopeEvent, ID: event.ID, Type: event.Type, TenantID: event.TenantID, SchemaVersion: event.SchemaVersion, Time: event.Time}
	protected, err := eventprotect.Protect(key, context, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", strings.Repeat("a", 64), eventprotect.Payload{Data: event.Data, Actor: event.Actor})
	if err != nil {
		t.Fatal(err)
	}
	event.Protection = &protected
	before, ok, err := protectedSourceRecord(event, 7)
	if err != nil || !ok {
		t.Fatalf("protect audit core: %v", err)
	}
	if before.Actor != nil || bytes.Contains(before.Data, []byte("example.invalid")) {
		t.Fatal("protected audit core exposed readable personal fields")
	}
	for name, change := range map[string]func(*events.Event){
		"identity": func(e *events.Event) { e.ID = "changed-source" },
		"type":     func(e *events.Event) { e.Type = "owner.updated" },
		"tenant":   func(e *events.Event) { e.TenantID = "2c14fe81-1956-4e9d-a174-e27a38e8e979" },
		"schema":   func(e *events.Event) { e.SchemaVersion = 2 },
		"time":     func(e *events.Event) { e.Time = e.Time.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			change(&changed)
			// The codec authenticates source headers while the key exists.
			// The key-independent record formatter checks structure; its signed
			// chain must still bind every header after key removal.
			binding := eventprotect.Context{Scope: eventprotect.ScopeEvent, ID: changed.ID, Type: changed.Type, TenantID: changed.TenantID, SchemaVersion: changed.SchemaVersion, Time: changed.Time}
			opened, err := eventprotect.Open(key, binding, strings.Repeat("a", 64), *changed.Protection)
			defer secret.Wipe(opened.Data)
			if err == nil || len(opened.Data) != 0 || opened.Actor != nil {
				t.Fatal("transplanted source header authenticated or exposed data")
			}
			record, protected, err := protectedSourceRecord(changed, 7)
			if err != nil || !protected {
				t.Fatalf("well-formed changed header cannot exercise signed binding: %v", err)
			}
			original := []Record{before}
			auditchain.Seal(original)
			if _, err := VerifyChain(original); err != nil {
				t.Fatalf("original audit commitment did not verify: %v", err)
			}
			record.Hash = original[0].Hash
			if _, err := VerifyChain([]Record{record}); err == nil {
				t.Fatal("transplanted header verified against the original audit commitment")
			}
		})
	}
	event.Data, event.Actor, event.SensitiveErased = nil, nil, true
	after, ok, err := protectedSourceRecord(event, 7)
	if err != nil || !ok || !bytes.Equal(before.Data, after.Data) {
		t.Fatalf("erasure changed committed audit bytes: %v", err)
	}
	if auditchain.Seal([]Record{before}) != auditchain.Seal([]Record{after}) {
		t.Fatal("key removal invalidated audit verification")
	}
}
