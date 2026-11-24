// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
)

func TestCR832ABACDecisionAuditsEvaluatedResourceScope(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithFixtureAppendAdmission())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	engine, err := policy.NewABAC(policy.ABACConfig{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.EvaluateDeny(t.Context(), policy.ABACInput{
		TenantID:   "11111111-1111-1111-1111-111111111111",
		Permission: "certs:issue", Actor: "fixture-issuer",
		Resource: map[string]string{"profile": "tls-prod", "issuer": "ca-one", "project": "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	err = log.Replay(t.Context(), 1, func(e events.Event) error {
		if e.Type != "policy.abac.decision" {
			return nil
		}
		seen = true
		var payload struct {
			Profile string `json:"profile"`
			Issuer  string `json:"issuer"`
			Project string `json:"project"`
		}
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return err
		}
		if payload.Profile != "tls-prod" || payload.Issuer != "ca-one" || payload.Project != "prod" {
			t.Errorf("ABAC decision audit scope = %+v, want evaluated profile, issuer and project", payload)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("policy.abac.decision event missing")
	}
}
