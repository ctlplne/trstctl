// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/rehearsal"
	"trstctl.com/trstctl/internal/store"
)

// Rehearsals of failure scenarios (A247): a saved scenario, and each run's
// start (what it replays, with which versions, against what expectations) and
// completion (what was observed, the verdict and the mode's label).
const (
	EventRehearsalScenarioSaved = "rehearsal.scenario.saved"
	EventRehearsalRunStarted    = "rehearsal.run.started"
	EventRehearsalRunCompleted  = "rehearsal.run.completed"
)

// RehearsalScenarioSaved is the payload of rehearsal.scenario.saved.
type RehearsalScenarioSaved struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Kind      string              `json:"kind"`
	Revision  int64               `json:"revision"`
	Candidate rehearsal.Candidate `json:"candidate"`
	DataSet   rehearsal.DataSet   `json:"data_set"`
	Steps     []rehearsal.Step    `json:"steps"`
	SavedBy   string              `json:"saved_by"`
}

// RehearsalRunStarted is the payload of rehearsal.run.started.
type RehearsalRunStarted struct {
	ID                string              `json:"id"`
	ScenarioID        string              `json:"scenario_id"`
	ScenarioRevision  int64               `json:"scenario_revision"`
	Mode              string              `json:"mode"`
	ToolVersion       string              `json:"tool_version"`
	ConnectorVersions map[string]string   `json:"connector_versions"`
	Candidate         rehearsal.Candidate `json:"candidate"`
	DataSetDigest     string              `json:"data_set_digest"`
	Expected          []rehearsal.Step    `json:"expected"`
	StartedBy         string              `json:"started_by"`
}

// RehearsalRunCompleted is the payload of rehearsal.run.completed.
type RehearsalRunCompleted struct {
	ID           string                  `json:"id"`
	Verdict      string                  `json:"verdict"`
	Label        string                  `json:"label"`
	Observations []rehearsal.Observation `json:"observations"`
	Detail       string                  `json:"detail"`
}

func init() {
	for _, typ := range []string{EventRehearsalScenarioSaved, EventRehearsalRunStarted, EventRehearsalRunCompleted} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyRehearsalTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventRehearsalScenarioSaved:
		var d RehearsalScenarioSaved
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		candidate, dataSet, steps, err := rehearsalJSON(d.Candidate, d.DataSet, d.Steps)
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyRehearsalScenarioSavedTx(ctx, tx, e.TenantID, store.RehearsalScenario{
			ID: d.ID, Name: d.Name, Kind: d.Kind, Revision: d.Revision, Candidate: candidate, DataSet: dataSet,
			Steps: steps, CreatedBy: d.SavedBy, CreatedAt: e.Time,
		}, e.Sequence)
	case EventRehearsalRunStarted:
		var d RehearsalRunStarted
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		candidate, versions, expected, err := rehearsalJSON(d.Candidate, d.ConnectorVersions, d.Expected)
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyRehearsalRunStartedTx(ctx, tx, e.TenantID, store.RehearsalRun{
			ID: d.ID, ScenarioID: d.ScenarioID, ScenarioRevision: d.ScenarioRevision, Mode: d.Mode,
			ToolVersion: d.ToolVersion, ConnectorVersions: versions, Candidate: candidate,
			DataSetDigest: d.DataSetDigest, Expected: expected, StartedBy: d.StartedBy, StartedAt: e.Time,
		}, e.Sequence)
	case EventRehearsalRunCompleted:
		var d RehearsalRunCompleted
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		observations, err := json.Marshal(d.Observations)
		if err != nil {
			return true, err
		}
		at := e.Time
		return true, p.store.ApplyRehearsalRunCompletedTx(ctx, tx, e.TenantID, store.RehearsalRun{
			ID: d.ID, Verdict: d.Verdict, Label: d.Label, Observations: observations, Detail: d.Detail, CompletedAt: &at,
		}, e.Sequence)
	}
	return false, nil
}

// rehearsalJSON marshals the three structured parts a rehearsal row keeps.
func rehearsalJSON(a, b, c any) (json.RawMessage, json.RawMessage, json.RawMessage, error) {
	out := make([]json.RawMessage, 0, 3)
	for _, v := range []any{a, b, c} {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, nil, nil, err
		}
		out = append(out, raw)
	}
	return out[0], out[1], out[2], nil
}

func addRehearsalPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	candidate := func(prefix string) []events.PrivacyFieldRule {
		return []events.PrivacyFieldRule{privacyRule(prefix+"/kind", opaque), privacyRule(prefix+"/ref", opaque), privacyRule(prefix+"/revision", opaque)}
	}
	step := func(prefix string) []events.PrivacyFieldRule {
		return []events.PrivacyFieldRule{privacyRule(prefix+"/action", opaque), privacyRule(prefix+"/target", opaque),
			privacyRule(prefix+"/expect", opaque)}
	}
	saved := []events.PrivacyFieldRule{
		privacyRule("/id", opaque), privacyRule("/name", opaque), privacyRule("/kind", opaque), privacyRule("/revision", opaque),
		privacyRule("/data_set/kind", opaque), privacyRule("/data_set/identity_ids/*", opaque),
		privacyRule("/data_set/failure/source", opaque), privacyRule("/data_set/failure/ref", opaque),
		privacyRule("/data_set/failure/step", opaque), privacyRule("/data_set/failure/code", opaque),
		privacyRule("/data_set/secret_refs/*", opaque), privacyRule("/saved_by", exact),
	}
	saved = append(append(saved, candidate("/candidate")...), step("/steps/*")...)
	policies[privacyEventPolicyKey{EventRehearsalScenarioSaved, 1}] = privacyRules(saved...)
	started := []events.PrivacyFieldRule{
		privacyRule("/id", opaque), privacyRule("/scenario_id", opaque), privacyRule("/scenario_revision", opaque),
		privacyRule("/mode", opaque), privacyRule("/tool_version", opaque), privacyRule("/connector_versions/*", opaque),
		privacyRule("/data_set_digest", opaque), privacyRule("/started_by", exact),
	}
	started = append(append(started, candidate("/candidate")...), step("/expected/*")...)
	policies[privacyEventPolicyKey{EventRehearsalRunStarted, 1}] = privacyRules(started...)
	policies[privacyEventPolicyKey{EventRehearsalRunCompleted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/verdict", opaque), privacyRule("/label", opaque),
		privacyRule("/observations/*/step", opaque), privacyRule("/observations/*/effect", opaque),
		privacyRule("/observations/*/source", opaque), privacyRule("/observations/*/receipt", opaque),
		privacyRule("/detail", opaque))
}

func addRehearsalPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventRehearsalScenarioSaved, 1}] = privacyPayloadShape[RehearsalScenarioSaved]()
	shapes[privacyEventPolicyKey{EventRehearsalRunStarted, 1}] = privacyPayloadShape[RehearsalRunStarted]()
	shapes[privacyEventPolicyKey{EventRehearsalRunCompleted, 1}] = privacyPayloadShape[RehearsalRunCompleted]()
}
