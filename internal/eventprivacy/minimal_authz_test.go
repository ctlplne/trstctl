// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
)

func minimalAuthzFixture() events.Event {
	return events.Event{Type: EventAuthorizationDecision, TenantID: controlTestTenant, SchemaVersion: MinimalAuthzSchemaVersion, Data: []byte(`{"permission":"privacy:read","decision":"deny","details_omitted":"key_preparing"}`)}
}

func TestMinimalAuthzDecisionCannotCarryCallerIdentityOrInventPermissionVocabulary(t *testing.T) {
	event := minimalAuthzFixture()
	if _, err := ParseMinimalAuthzDecision(event); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"permission":"private-person@example.invalid","decision":"deny","details_omitted":"key_preparing"}`,
		`{"permission":"*","decision":"allow","details_omitted":"key_preparing"}`,
		`{"permission":"privacy:read","decision":"maybe","details_omitted":"key_preparing"}`,
		`{"permission":"privacy:read","decision":"deny","details_omitted":"fixture-person@example.invalid"}`,
		`{"permission":"privacy:read","decision":"deny","details_omitted":"key_preparing","actor":"private-person@example.invalid"}`,
		`{"permission":"privacy:read","decision":"deny","decision":"allow","details_omitted":"key_preparing"}`,
		`null`,
	} {
		changed := event
		changed.Data = []byte(data)
		if _, err := ParseMinimalAuthzDecision(changed); err == nil {
			t.Fatalf("personal/ambiguous decision accepted: %s", data)
		}
	}
	for name, mutate := range map[string]func(*events.Event){
		"schema":   func(e *events.Event) { e.SchemaVersion = 1 },
		"actor":    func(e *events.Event) { e.Actor = &events.Actor{Subject: "private-person@example.invalid"} },
		"envelope": func(e *events.Event) { e.Protection = &eventspec.ProtectedPayload{Version: 1} },
		"erased":   func(e *events.Event) { e.SensitiveErased = true },
		"tenant":   func(e *events.Event) { e.TenantID = "not-a-tenant" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			mutate(&changed)
			if _, err := ParseMinimalAuthzDecision(changed); err == nil {
				t.Fatal("altered public decision frame accepted")
			}
		})
	}
}

func FuzzMinimalAuthzDecision(f *testing.F) {
	f.Add(minimalAuthzFixture().Data)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"permission":"privacy:read","decision":"deny","actor":"person@example.invalid"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		event := minimalAuthzFixture()
		event.Data = data
		body, err := ParseMinimalAuthzDecision(event)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(body)
		if err != nil || !bytes.Equal(canonical, data) || !minimalAuthzPermissions[body.Permission] {
			t.Fatal("unbounded or noncanonical public authorization data accepted")
		}
	})
}

// Default-off deployments retain their existing detailed audit representation,
// including the audit-only writer's behavior after ordinary tenant offboarding.
func TestMinimalAuthzStateDoesNotChangeLegacyOffboardedTenants(t *testing.T) {
	life := Lifetime{Offboard: &events.EnvelopeMetadata{ID: "legacy-offboard"}}
	if minimalAuthzState(life) != "" {
		t.Fatal("feature-disabled lifetime selected the new minimal schema")
	}
}

// The closed public protocol must keep pace with actual route permissions while
// rejecting arbitrary caller strings. This uses the authorization engine's live
// vocabulary, rather than generating both sides from the minimal-audit map.
func TestMinimalAuthzCoversCompiledPermissionVocabulary(t *testing.T) {
	permissions := append(authz.CustomRoleVocabulary(), authz.AgentsHeartbeat, authz.AgentsJobPoll, authz.AgentsJobComplete, authz.AgentsJobReport, authz.ApprovalsReview)
	for _, permission := range permissions {
		event := minimalAuthzFixture()
		wire, err := json.Marshal(MinimalAuthzDecision{Permission: string(permission), Decision: "deny", DetailsOmitted: "key_preparing"})
		if err != nil {
			t.Fatal(err)
		}
		event.Data = wire
		if _, err := ParseMinimalAuthzDecision(event); err != nil {
			t.Fatalf("compiled permission has no closed audit representation: %s", permission)
		}
	}
}
