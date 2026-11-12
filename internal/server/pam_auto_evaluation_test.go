// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

const a261ReviewTTL = 5 * time.Minute

func a261CanonicalEvaluation() (events.Event, pamAutoApprovalRequest, error) {
	rule, req := a261MatchingRule()
	rule.ID = "11111111-1111-4111-8111-111111111111"
	rule.Name = "Routine read"
	rule.Revision = 1
	matched, ok := pamAutoApprovalMatches(rule, req)
	if !ok {
		return events.Event{}, req, errors.New("fixture rule does not match")
	}
	value := projections.PAMAutoApprovalEvaluated{RequestID: "request", Kind: req.Kind, Requester: "user", BaseDigest: "digest", TargetType: req.TargetType, TargetID: req.TargetID, Folder: req.Folder, Rule: &rule, Facts: &projections.PAMAutoApprovalFacts{Target: matched.Target, Folder: matched.Folder, Roles: matched.Roles, Window: matched.Window, Ticket: matched.Ticket}, At: req.At, ExpiresAt: req.At.Add(a261ReviewTTL)}
	raw, err := json.Marshal(value)
	if err != nil {
		return events.Event{}, req, err
	}
	return events.Event{ID: "event", TenantID: "tenant", Type: projections.EventPAMAutoApprovalEvaluated, Time: req.At, Actor: &events.Actor{Subject: "user", Roles: req.Roles}, Data: raw}, req, nil
}

func TestCanonicalAutoEvaluationRejectsChangedAuthorityA261(t *testing.T) {
	cases := []struct {
		name   string
		change func(*events.Event)
	}{
		{"wrong tenant", func(e *events.Event) { e.TenantID = "neighbor" }},
		{"wrong event", func(e *events.Event) { e.ID = "other" }},
		{"wrong type", func(e *events.Event) { e.Type = "pam.session.opened" }},
		{"missing actor", func(e *events.Event) { e.Actor = nil }},
		{"changed requester", func(e *events.Event) { e.Actor.Subject = "other" }},
		{"changed actor roles", func(e *events.Event) { e.Actor.Roles = []string{"other"} }},
		{"changed source time", func(e *events.Event) { e.Time = e.Time.Add(time.Second) }},
		{"unknown field", func(e *events.Event) {
			e.Data = append(append([]byte(nil), e.Data[:len(e.Data)-1]...), []byte(`,"unknown":true}`)...)
		}},
		{"trailing value", func(e *events.Event) { e.Data = append(e.Data, []byte(` {}`)...) }},
		{"truncated", func(e *events.Event) { e.Data = e.Data[:len(e.Data)-1] }},
		{"oversized", func(e *events.Event) { e.Data = bytes.Repeat([]byte(" "), (256<<10)+1) }},
		{"changed deadline", func(e *events.Event) {
			var v projections.PAMAutoApprovalEvaluated
			_ = json.Unmarshal(e.Data, &v)
			v.ExpiresAt = v.ExpiresAt.Add(time.Second)
			e.Data, _ = json.Marshal(v)
		}},
		{"changed witness", func(e *events.Event) {
			var v projections.PAMAutoApprovalEvaluated
			_ = json.Unmarshal(e.Data, &v)
			v.Facts.Target = "postgres/other"
			e.Data, _ = json.Marshal(v)
		}},
	}
	source, req, err := a261CanonicalEvaluation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pamCanonicalAutoEvaluation(source, "tenant", "event", "request", req, "user", "digest", a261ReviewTTL); err != nil {
		t.Fatal(err)
	}
	if _, err := pamCanonicalAutoEvaluation(source, "tenant", "event", "request", req, "user", "digest", time.Duration(req.TTLSeconds)*time.Second); err == nil {
		t.Fatal("session lifetime substituted for review deadline")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, req, err := a261CanonicalEvaluation()
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&source)
			if _, err := pamCanonicalAutoEvaluation(source, "tenant", "event", "request", req, "user", "digest", a261ReviewTTL); err == nil {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

func FuzzPAMCanonicalAutoEvaluation(f *testing.F) {
	source, req, err := a261CanonicalEvaluation()
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add(source.Data)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add(append(append([]byte(nil), source.Data...), []byte(` {}`)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		candidate := source
		candidate.Data = raw
		got, err := pamCanonicalAutoEvaluation(candidate, "tenant", "event", "request", req, "user", "digest", a261ReviewTTL)
		if err != nil {
			return
		}
		if got.RequestID != "request" || got.Requester != "user" || got.BaseDigest != "digest" || !got.At.Equal(source.Time) || !got.ExpiresAt.Equal(got.At.Add(a261ReviewTTL)) {
			t.Fatal("accepted evaluation lost command/time binding")
		}
		if got.Rule != nil {
			frozen := req
			frozen.At, frozen.Folder = got.At, got.Folder
			if _, ok := pamAutoApprovalMatches(*got.Rule, frozen); !ok {
				t.Fatal("accepted nonmatching rule")
			}
		}
	})
}

// OD-9: a frozen evaluation a bundle's standing approval decided is canonical
// only for the run and role it was decided for, never beside a rule, never
// for a check-out, and only while the session ends before the approval does.
func TestCanonicalAutoEvaluationBindsTheStandingApprovalOD9(t *testing.T) {
	at := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	req := pamAutoApprovalRequest{Kind: "session", TargetType: "postgres", TargetID: "orders-db", Role: "readonly", RunID: "run-a", TTLSeconds: 600, At: at}
	requester := "bundle-run:agent-9"
	build := func(change func(*projections.PAMAutoApprovalEvaluated)) events.Event {
		v := projections.PAMAutoApprovalEvaluated{RequestID: "request", Kind: "session", Requester: requester, BaseDigest: "digest",
			TargetType: "postgres", TargetID: "orders-db", At: at, ExpiresAt: at.Add(a261ReviewTTL),
			Standing: &projections.PAMStandingApprovalMatch{ApprovalID: "22222222-2222-4222-8222-222222222222",
				BundleID: "33333333-3333-4333-8333-333333333333", RunID: "run-a", Principal: "agent-9", Role: "readonly", ExpiresAt: at.Add(time.Hour)}}
		if change != nil {
			change(&v)
		}
		raw, _ := json.Marshal(v)
		return events.Event{ID: "event", TenantID: "tenant", Type: projections.EventPAMAutoApprovalEvaluated, Time: at, Actor: &events.Actor{Subject: requester}, Data: raw}
	}
	if _, err := pamCanonicalAutoEvaluation(build(nil), "tenant", "event", "request", req, requester, "digest", a261ReviewTTL); err != nil {
		t.Fatalf("the evaluation it froze: %v", err)
	}
	other := req
	other.RunID = "run-b"
	if _, err := pamCanonicalAutoEvaluation(build(nil), "tenant", "event", "request", other, requester, "digest", a261ReviewTTL); err == nil {
		t.Fatal("another run's retry kept the standing approval")
	}
	otherRole := req
	otherRole.Role = "readwrite"
	if _, err := pamCanonicalAutoEvaluation(build(nil), "tenant", "event", "request", otherRole, requester, "digest", a261ReviewTTL); err == nil {
		t.Fatal("another role's retry kept the standing approval")
	}
	longer := req
	longer.TTLSeconds = 2 * 3600
	if _, err := pamCanonicalAutoEvaluation(build(nil), "tenant", "event", "request", longer, requester, "digest", a261ReviewTTL); err == nil {
		t.Fatal("a session outliving the approval kept it")
	}
	for name, change := range map[string]func(*projections.PAMAutoApprovalEvaluated){
		"not a UUID approval": func(v *projections.PAMAutoApprovalEvaluated) { v.Standing.ApprovalID = "approval" },
		"the requester itself": func(v *projections.PAMAutoApprovalEvaluated) {
			v.Standing.ApprovalID = "44444444-4444-4444-8444-444444444444"
		},
		"beside a rule": func(v *projections.PAMAutoApprovalEvaluated) {
			rule, _ := a261MatchingRule()
			v.Rule, v.Facts = &rule, &projections.PAMAutoApprovalFacts{Target: "postgres/orders-db"}
		},
	} {
		requesterFor := requester
		if name == "the requester itself" {
			requesterFor = "standing-approval:44444444-4444-4444-8444-444444444444"
		}
		event := build(change)
		event.Actor = &events.Actor{Subject: requesterFor}
		if _, err := pamCanonicalAutoEvaluation(event, "tenant", "event", "request", req, requesterFor, "digest", a261ReviewTTL); err == nil {
			t.Errorf("%s: the frozen standing approval was accepted", name)
		}
	}
	checkout := req
	checkout.Kind = "checkout"
	event := build(func(v *projections.PAMAutoApprovalEvaluated) { v.Kind = "checkout" })
	if _, err := pamCanonicalAutoEvaluation(event, "tenant", "event", "request", checkout, requester, "digest", a261ReviewTTL); err == nil {
		t.Fatal("a check-out's evaluation kept a standing approval")
	}
}
