// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
)

func TestPrivacySubjectErasureIdentityIsStableAndTenantScoped(t *testing.T) {
	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
		key     = "erase-42"
	)
	const binding = "sha256:command-a"
	first := PrivacySubjectErasureIdentityFor(tenantA, key, binding)
	if same := PrivacySubjectErasureIdentityFor(tenantA, key, binding); same != first {
		t.Fatalf("same tenant/key identity changed: %+v != %+v", same, first)
	}
	if other := PrivacySubjectErasureIdentityFor(tenantA, "erase-43", binding); other == first {
		t.Fatal("different raw key reused privacy erasure identity")
	}
	if other := PrivacySubjectErasureIdentityFor(tenantB, key, binding); other == first {
		t.Fatal("different tenant reused privacy erasure identity")
	}
	changedBinding := PrivacySubjectErasureIdentityFor(tenantA, key, "sha256:command-b")
	if changedBinding.EventID != first.EventID || changedBinding.OperationID == first.OperationID {
		t.Fatalf("binding change must retain raw-key event anchor but change operation: first=%+v changed=%+v",
			first, changedBinding)
	}
	if first.OperationID == "" || first.EventID == "" || first.OperationID == first.EventID {
		t.Fatalf("privacy erasure identities are incomplete or not domain-separated: %+v", first)
	}
}

func TestPrivacyErasureCanonicalEventFailsClosedOnBindingDrift(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
		binding  = "sha256:canonical-command"
	)
	identity := PrivacySubjectErasureIdentityFor(tenantID, "erase-42", binding)
	payload, err := json.Marshal(projections.PrivacySubjectErased{
		OperationID:    identity.OperationID,
		RequestBinding: binding,
		SubjectRef:     privacy.SubjectRef(tenantID, subject),
		Reason:         "data subject request",
		Counts:         map[string]int{"owners": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := events.Event{
		ID: identity.EventID, Type: projections.EventPrivacySubjectErased,
		TenantID: tenantID, SchemaVersion: projections.PrivacySubjectErasedEventSchemaVersion,
		Time: time.Now().UTC(), Data: payload,
	}
	got, err := privacyErasureFromEvent(canonical, tenantID, subject, identity, binding)
	if err != nil {
		t.Fatalf("canonical event: %v", err)
	}
	if got.SubjectRef != privacy.SubjectRef(tenantID, subject) || got.Counts["owners"] != 1 {
		t.Fatalf("canonical erasure = %+v", got)
	}

	for name, call := range map[string]func() error{
		"request binding": func() error {
			_, err := privacyErasureFromEvent(canonical, tenantID, subject, identity, "sha256:changed-command")
			return err
		},
		"subject": func() error {
			_, err := privacyErasureFromEvent(canonical, tenantID, "bob@example.com", identity, binding)
			return err
		},
		"event schema": func() error {
			changed := canonical
			changed.SchemaVersion = 1
			_, err := privacyErasureFromEvent(changed, tenantID, subject, identity, binding)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrIdempotencyConflict) {
			t.Errorf("%s drift error = %v, want ErrIdempotencyConflict", name, err)
		}
	}
}

func TestSanitizedPrivacyErasureActorRemovesSubjectFromSubjectAndRoles(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice+privacy@example.com"
	)
	ctx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "operator:" + subject,
		Roles:   []string{"privacy:write", "delegated:" + subject},
	})
	actor := sanitizedPrivacyErasureActor(ctx, tenantID, subject)
	if actor == nil {
		t.Fatal("sanitized actor is nil")
	}
	encoded, err := json.Marshal(actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || !json.Valid(encoded) {
		t.Fatalf("sanitized actor JSON is invalid: %s", encoded)
	}
	for _, raw := range []string{subject, "alice%2Bprivacy%40example.com"} {
		if bytes.Contains(encoded, []byte(raw)) {
			t.Fatalf("sanitized actor leaked %q: %s", raw, encoded)
		}
	}
}
