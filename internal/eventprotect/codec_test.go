// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestProtectionRefusesLossyActorUTF8(t *testing.T) {
	for name, actor := range map[string]*eventspec.Actor{
		"subject": {Subject: "actor\xff"},
		"role":    {Subject: "actor", Roles: []string{"reader\xff"}},
	} {
		t.Run(name, func(t *testing.T) {
			frame, err := encodePayload(Payload{Data: []byte("original data"), Actor: actor})
			defer secret.Wipe(frame)
			if err == nil {
				t.Fatal("invalid UTF-8 actor was silently changed during encryption")
			}
		})
	}
}

func testEventKey(t *testing.T) *seal.LocalKEK {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	key, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func TestProtectedPayloadRefusesAmbiguousActorEncoding(t *testing.T) {
	for _, actor := range []string{
		"null", "{}", `{"subject":"first","subject":"second"}`,
		`{"subject":"a"}{"subject":"b"}`, `{"subject":"a","unknown":true}`,
	} {
		t.Run(actor, func(t *testing.T) {
			frame := append([]byte("EPF1"), make([]byte, 16)...)
			binary.BigEndian.PutUint64(frame[12:20], uint64(len(actor)))
			frame = append(frame, actor...)
			if opened, err := decodePayload(frame); err == nil || opened.Actor != nil || len(opened.Data) != 0 {
				secret.Wipe(opened.Data)
				t.Fatal("ambiguous or noncanonical actor encoding was admitted")
			}
		})
	}
}

func testProtectionContext() Context {
	return Context{Scope: ScopeEvent, ID: "a233-event-1", Type: "a233.synthetic", TenantID: "4dc555fa-a52d-4c26-b63d-1e06a3f3e651", SchemaVersion: 1, Time: time.Date(2026, 10, 29, 0, 0, 0, 123000, time.UTC)}
}

func TestProtectedEventRetainsExactPayloadAndImmutableAuditBytes(t *testing.T) {
	key, context := testEventKey(t), testProtectionContext()
	policy := crypto.SHA256Hex([]byte("declared field classes for the synthetic schema"))
	// Whitespace, field order and escape spelling must survive. Existing command
	// recovery binds exact source bytes, so a JSON re-marshal is not equivalent.
	data := []byte(" {\n \"z\":\"A233-private-field-marker\", \"a\":\"<keep>\\u0020\" } ")
	actor := &eventspec.Actor{Subject: "A233-private-actor-marker", Roles: []string{"reader", "delegate:A233-private-role-marker"}}
	envelope, err := Protect(key, context, "key-a233", policy, Payload{Data: data, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte("A233-private-field-marker"), []byte(actor.Subject), []byte(actor.Roles[1])} {
		if bytes.Contains(wire, marker) {
			t.Fatal("protected storage representation contains a sensitive marker")
		}
	}
	opened, err := Open(key, context, policy, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(opened.Data)
	if !bytes.Equal(opened.Data, data) || opened.Actor == nil || opened.Actor.Subject != actor.Subject ||
		len(opened.Actor.Roles) != 2 || opened.Actor.Roles[1] != actor.Roles[1] {
		t.Fatal("authenticated opening changed the exact payload or actor")
	}
	// An archive commits ciphertext. Key destruction never rewrites these bytes,
	// so the existing audit-chain algorithm remains independently verifiable.
	before := []auditchain.Record{{Sequence: 1, ID: context.ID, Type: context.Type, TenantID: context.TenantID, Time: context.Time, Data: wire}}
	head := auditchain.Seal(before)
	key.Destroy()
	if after, err := Open(key, context, policy, envelope); err == nil || len(after.Data) != 0 || after.Actor != nil {
		secret.Wipe(after.Data)
		t.Fatal("destroyed key still opened the protected event")
	}
	after := append([]auditchain.Record(nil), before...)
	if afterHead := auditchain.Seal(after); head == "" || afterHead != head {
		t.Fatal("key destruction changed immutable audit bytes or their chain head")
	}
}

func TestProtectedEventRejectsChangedAuthorityAndSchema(t *testing.T) {
	key, context := testEventKey(t), testProtectionContext()
	policy := crypto.SHA256Hex([]byte("synthetic schema classes"))
	envelope, err := Protect(key, context, "key-a233", policy, Payload{Data: []byte(`{"reason":"A233-private-marker"}`)})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Context){
		"tenant":       func(c *Context) { c.TenantID = "4859d864-10e0-4cb8-8eb1-a7c2cb1a70b6" },
		"event id":     func(c *Context) { c.ID += "-other" },
		"event type":   func(c *Context) { c.Type += ".other" },
		"schema":       func(c *Context) { c.SchemaVersion++ },
		"time":         func(c *Context) { c.Time = c.Time.Add(time.Nanosecond) },
		"backup scope": func(c *Context) { c.Scope = ScopePostgresRow },
	} {
		t.Run(name, func(t *testing.T) {
			changed := context
			change(&changed)
			if opened, err := Open(key, changed, policy, envelope); err == nil || len(opened.Data) != 0 || opened.Actor != nil {
				secret.Wipe(opened.Data)
				t.Fatal("changed protection context opened the original data")
			}
		})
	}
	otherPolicy := crypto.SHA256Hex([]byte("different field classes"))
	if opened, err := Open(key, context, otherPolicy, envelope); err == nil || len(opened.Data) != 0 {
		secret.Wipe(opened.Data)
		t.Fatal("different field-class declaration opened the original data")
	}
	if opened, err := Open(testEventKey(t), context, policy, envelope); err == nil || len(opened.Data) != 0 {
		secret.Wipe(opened.Data)
		t.Fatal("another tenant key opened the original data")
	}
	changedKey := envelope
	changedKey.KeyID = "key-other"
	if opened, err := Open(key, context, policy, changedKey); err == nil || len(opened.Data) != 0 {
		secret.Wipe(opened.Data)
		t.Fatal("changed key reference opened the original data")
	}
	changedWire := envelope
	changedWire.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	changedWire.Ciphertext[len(changedWire.Ciphertext)-1] ^= 1
	if opened, err := Open(key, context, policy, changedWire); err == nil || len(opened.Data) != 0 {
		secret.Wipe(opened.Data)
		t.Fatal("tampered ciphertext opened")
	}
}

func TestProtectionContextRejectsInvalidUTF8InsteadOfCreatingAliases(t *testing.T) {
	key, context := testEventKey(t), testProtectionContext()
	policy := crypto.SHA256Hex([]byte("synthetic schema classes"))
	for _, field := range []string{"id", "type", "tenant", "key"} {
		t.Run(field, func(t *testing.T) {
			changed, keyID := context, "key-a233"
			switch field {
			case "id":
				changed.ID = "event-\xff"
			case "type":
				changed.Type = "type-\xff"
			case "tenant":
				changed.TenantID = "tenant-\xff"
			case "key":
				keyID = "key-\xff"
			}
			if _, err := Protect(key, changed, keyID, policy, Payload{Data: []byte(`{}`)}); err == nil {
				t.Fatal("invalid UTF-8 protection identity was normalized into another identity")
			}
		})
	}
}
