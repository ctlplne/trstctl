// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rehearsal"
	"trstctl.com/trstctl/internal/store"
)

// Rehearsals of failure scenarios (A247). A scenario is saved once and
// revised; a run replays it in one mode and records the tool and connector
// versions, the candidate, the data set's digest, the expected effects and
// what was observed. Its label is its mode's (rehearsal.Label), so a mocked
// success never reads as live. Saving a scenario needs incidents:write; a run
// is a game day and needs incidents:game-day.

const (
	rehearsalListLimit = 100
	rehearsalStepLimit = 32
)

// rehearsalCandidateKinds are what a scenario can test.
var rehearsalCandidateKinds = map[string]bool{"identity": true, "issuer": true, "profile": true, "target": true, "binary": true}

type rehearsalScenarioRequest struct {
	Name      string              `json:"name"`
	Kind      string              `json:"kind"`
	Candidate rehearsal.Candidate `json:"candidate"`
	DataSet   rehearsal.DataSet   `json:"data_set"`
	Steps     []rehearsal.Step    `json:"steps,omitempty"`
}

type rehearsalScenarioResponse struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Kind      string              `json:"kind"`
	Revision  int64               `json:"revision"`
	Candidate rehearsal.Candidate `json:"candidate"`
	DataSet   rehearsal.DataSet   `json:"data_set"`
	Steps     []rehearsal.Step    `json:"steps"`
	CreatedBy string              `json:"created_by,omitempty"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

type rehearsalRunRequest struct {
	Mode string `json:"mode"`
}

type rehearsalRunResponse struct {
	ID                string                  `json:"id"`
	ScenarioID        string                  `json:"scenario_id"`
	ScenarioRevision  int64                   `json:"scenario_revision"`
	Mode              string                  `json:"mode"`
	Status            string                  `json:"status"`
	Verdict           string                  `json:"verdict,omitempty"`
	Label             string                  `json:"label,omitempty"`
	ToolVersion       string                  `json:"tool_version"`
	ConnectorVersions map[string]string       `json:"connector_versions"`
	Candidate         rehearsal.Candidate     `json:"candidate"`
	DataSetDigest     string                  `json:"data_set_digest"`
	Expected          []rehearsal.Step        `json:"expected"`
	Observations      []rehearsal.Observation `json:"observations"`
	Detail            string                  `json:"detail,omitempty"`
	StartedBy         string                  `json:"started_by,omitempty"`
	StartedAt         time.Time               `json:"started_at"`
	CompletedAt       *time.Time              `json:"completed_at,omitempty"`
}

func (req *rehearsalScenarioRequest) validate() error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 {
		return errors.New("name is required and at most 200 characters")
	}
	steps, ok := rehearsal.Template(rehearsal.Kind(req.Kind))
	if !ok {
		return fmt.Errorf("kind must be one of %v", rehearsal.Kinds())
	}
	if len(req.Steps) == 0 {
		req.Steps = steps
	}
	if len(req.Steps) > rehearsalStepLimit {
		return fmt.Errorf("a scenario has at most %d steps", rehearsalStepLimit)
	}
	for i, s := range req.Steps {
		if strings.TrimSpace(s.Action) == "" || strings.TrimSpace(s.Expect) == "" {
			return fmt.Errorf("step %d needs an action and an expected effect", i+1)
		}
	}
	if !rehearsalCandidateKinds[req.Candidate.Kind] || strings.TrimSpace(req.Candidate.Ref) == "" {
		return errors.New("candidate needs a kind (identity, issuer, profile, target or binary) and a ref")
	}
	switch req.DataSet.Kind {
	case "identities":
		if req.DataSet.Failure != nil {
			return errors.New("an identities data set carries no failure")
		}
	case "scrubbed_failure":
		if req.DataSet.Failure == nil || req.DataSet.Failure.Source == "" || req.DataSet.Failure.Ref == "" {
			return errors.New("a scrubbed_failure data set needs the failure's source and ref")
		}
	default:
		return errors.New("data_set.kind must be identities or scrubbed_failure")
	}
	return nil
}

func rehearsalScenarioView(sc store.RehearsalScenario) (rehearsalScenarioResponse, error) {
	out := rehearsalScenarioResponse{ID: sc.ID, Name: sc.Name, Kind: sc.Kind, Revision: sc.Revision,
		CreatedBy: sc.CreatedBy, CreatedAt: sc.CreatedAt, UpdatedAt: sc.UpdatedAt}
	for _, part := range []struct {
		raw json.RawMessage
		v   any
	}{{sc.Candidate, &out.Candidate}, {sc.DataSet, &out.DataSet}, {sc.Steps, &out.Steps}} {
		if err := json.Unmarshal(part.raw, part.v); err != nil {
			return out, err
		}
	}
	return out, nil
}

func rehearsalRunView(r store.RehearsalRun) (rehearsalRunResponse, error) {
	out := rehearsalRunResponse{ID: r.ID, ScenarioID: r.ScenarioID, ScenarioRevision: r.ScenarioRevision, Mode: r.Mode,
		Status: r.Status, Verdict: r.Verdict, Label: r.Label, ToolVersion: r.ToolVersion, DataSetDigest: r.DataSetDigest,
		Detail: r.Detail, StartedBy: r.StartedBy, StartedAt: r.StartedAt, CompletedAt: r.CompletedAt,
		ConnectorVersions: map[string]string{}, Observations: []rehearsal.Observation{}}
	for _, part := range []struct {
		raw json.RawMessage
		v   any
	}{{r.ConnectorVersions, &out.ConnectorVersions}, {r.Candidate, &out.Candidate}, {r.Expected, &out.Expected}, {r.Observations, &out.Observations}} {
		if len(part.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(part.raw, part.v); err != nil {
			return out, err
		}
	}
	return out, nil
}

//trstctl:mutation
func (a *API) saveRehearsalScenario(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req rehearsalScenarioRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := req.validate(); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		id, revision, status := googleuuid.NewString(), int64(1), http.StatusCreated
		if existing := r.PathValue("id"); existing != "" {
			current, err := a.store.GetRehearsalScenario(ctx, tenantID, existing)
			if errors.Is(err, store.ErrRehearsalNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such scenario")
			} else if err != nil {
				return 0, nil, err
			}
			id, revision, status = current.ID, current.Revision+1, http.StatusOK
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.SaveRehearsalScenario(ctx, tenantID, projections.RehearsalScenarioSaved{
			ID: id, Name: req.Name, Kind: req.Kind, Revision: revision, Candidate: req.Candidate,
			DataSet: req.DataSet, Steps: req.Steps, SavedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		saved, err := a.store.GetRehearsalScenario(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		view, err := rehearsalScenarioView(saved)
		return status, view, err
	})
}

func (a *API) listRehearsalScenarios(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListRehearsalScenarios(r.Context(), tenantID, rehearsalListLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := make([]rehearsalScenarioResponse, 0, len(rows))
	for _, row := range rows {
		view, err := rehearsalScenarioView(row)
		if err != nil {
			a.writeError(w, err)
			return
		}
		out = append(out, view)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"scenarios": out})
}

func (a *API) getRehearsalScenario(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	sc, err := a.store.GetRehearsalScenario(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrRehearsalNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "no such scenario"))
		return
	} else if err != nil {
		a.writeError(w, err)
		return
	}
	view, err := rehearsalScenarioView(sc)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// rehearsalModesServed are the modes a run can use today; sandbox execution
// and live observation come with A247 part 2.
var rehearsalModesServed = map[rehearsal.Mode]bool{rehearsal.ModeStaticPreview: true, rehearsal.ModeMockedRehearsal: true}

//trstctl:mutation
func (a *API) startRehearsalRun(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req rehearsalRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		mode := rehearsal.Mode(req.Mode)
		if !rehearsalModesServed[mode] {
			return 0, nil, errStatus(http.StatusBadRequest, "mode must be static_preview or mocked_rehearsal")
		}
		row, err := a.store.GetRehearsalScenario(ctx, tenantID, r.PathValue("id"))
		if errors.Is(err, store.ErrRehearsalNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no such scenario")
		} else if err != nil {
			return 0, nil, err
		}
		sc, err := rehearsalScenarioView(row)
		if err != nil {
			return 0, nil, err
		}
		if err := rehearsal.Guard(mode, sc.Steps, sc.DataSet, a.rehearsalEnvironments(ctx, tenantID)); err != nil {
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
		}
		digest, err := rehearsal.DataSetDigest(sc.DataSet)
		if err != nil {
			return 0, nil, err
		}
		versions, err := a.rehearsalConnectorVersions(ctx, tenantID, sc.Steps)
		if err != nil {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		runID := googleuuid.NewString()
		if err := a.orch.StartRehearsalRun(ctx, tenantID, projections.RehearsalRunStarted{
			ID: runID, ScenarioID: sc.ID, ScenarioRevision: sc.Revision, Mode: string(mode),
			ToolVersion: buildinfo.Version(), ConnectorVersions: versions, Candidate: sc.Candidate,
			DataSetDigest: digest, Expected: sc.Steps, StartedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		var observations []rehearsal.Observation
		switch mode {
		case rehearsal.ModeStaticPreview:
			observations = rehearsal.Preview(sc.Steps, a.rehearsalResolver(ctx, tenantID, sc))
		case rehearsal.ModeMockedRehearsal:
			observations = rehearsal.Mock(sc.Steps)
		}
		verdict, detail := rehearsal.Compare(mode, sc.Steps, observations)
		if err := a.orch.CompleteRehearsalRun(ctx, tenantID, projections.RehearsalRunCompleted{
			ID: runID, Verdict: string(verdict), Label: rehearsal.Label(mode, verdict, observations),
			Observations: observations, Detail: detail,
		}); err != nil {
			return 0, nil, err
		}
		run, err := a.store.GetRehearsalRun(ctx, tenantID, runID)
		if err != nil {
			return 0, nil, err
		}
		view, err := rehearsalRunView(run)
		return http.StatusCreated, view, err
	})
}

func (a *API) getRehearsalRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetRehearsalRun(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrRehearsalNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "no such run"))
		return
	} else if err != nil {
		a.writeError(w, err)
		return
	}
	view, err := rehearsalRunView(run)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

func (a *API) listRehearsalRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListRehearsalRuns(r.Context(), tenantID, r.PathValue("id"), rehearsalListLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := make([]rehearsalRunResponse, 0, len(rows))
	for _, row := range rows {
		view, err := rehearsalRunView(row)
		if err != nil {
			a.writeError(w, err)
			return
		}
		out = append(out, view)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

// rehearsalEnvironments reads environments from the product's records, as a
// game day does: a target's from its configuration, an identity's from its
// owner (a conflict between the two is not resolved for it).
func (a *API) rehearsalEnvironments(ctx context.Context, tenantID string) rehearsal.Environments {
	return rehearsal.Environments{
		Target: func(id string) (string, error) {
			target, err := a.store.GetDeploymentTarget(ctx, tenantID, id)
			if err != nil {
				return "", err
			}
			return incidentTargetEnvironment(target.Config), nil
		},
		Identity: func(id string) (string, error) {
			identity, err := a.store.GetIdentity(ctx, tenantID, id)
			if err != nil {
				return "", err
			}
			owner, err := a.store.GetOwner(ctx, tenantID, identity.OwnerID)
			if err != nil {
				return "", err
			}
			return strings.ToLower(strings.TrimSpace(owner.Environment)), nil
		},
	}
}

// rehearsalConnectorVersions names the connector behind each target a step
// acts on, at the version that runs it: a first-party connector is this
// binary's.
func (a *API) rehearsalConnectorVersions(ctx context.Context, tenantID string, steps []rehearsal.Step) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range steps {
		if s.Target == "" {
			continue
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, s.Target)
		if err != nil {
			if store.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out[target.Type] = buildinfo.Version()
	}
	return out, nil
}

// rehearsalResolver resolves a step's references for a static preview: the
// candidate, the data set's identities and the step's target must exist.
func (a *API) rehearsalResolver(ctx context.Context, tenantID string, sc rehearsalScenarioResponse) func(rehearsal.Step) error {
	candidateErr := a.resolveRehearsalCandidate(ctx, tenantID, sc.Candidate)
	var identityErr error
	for _, id := range sc.DataSet.IdentityIDs {
		if _, err := a.store.GetIdentity(ctx, tenantID, id); err != nil {
			identityErr = fmt.Errorf("identity %s is not inventoried", id)
			break
		}
	}
	return func(s rehearsal.Step) error {
		if candidateErr != nil {
			return candidateErr
		}
		if identityErr != nil {
			return identityErr
		}
		if s.Target != "" {
			if _, err := a.store.GetDeploymentTarget(ctx, tenantID, s.Target); err != nil {
				return fmt.Errorf("target %s does not exist", s.Target)
			}
		}
		return nil
	}
}

func (a *API) resolveRehearsalCandidate(ctx context.Context, tenantID string, c rehearsal.Candidate) error {
	var err error
	switch c.Kind {
	case "identity":
		_, err = a.store.GetIdentity(ctx, tenantID, c.Ref)
	case "issuer":
		_, err = a.store.GetIssuer(ctx, tenantID, c.Ref)
	case "profile":
		_, err = a.store.GetActiveProfile(ctx, tenantID, c.Ref)
	case "target":
		_, err = a.store.GetDeploymentTarget(ctx, tenantID, c.Ref)
	case "binary":
		if c.Ref != buildinfo.Version() {
			return fmt.Errorf("candidate binary %s is not the running %s", c.Ref, buildinfo.Version())
		}
	}
	if err != nil {
		return fmt.Errorf("candidate %s %s does not exist", c.Kind, c.Ref)
	}
	return nil
}

func rehearsalRoutes(a *API) []route {
	return []route{
		{method: "POST", path: "/api/v1/rehearsals/scenarios", opID: "saveRehearsalScenario",
			summary: "Save a failure scenario to rehearse: its kind, candidate, data set and the effect each step should have",
			handler: a.saveRehearsalScenario, reqSchema: "RehearsalScenarioRequest", resSchema: "RehearsalScenario", successCode: "201", mutation: true, perm: authz.IncidentsWrite},
		{method: "GET", path: "/api/v1/rehearsals/scenarios", opID: "listRehearsalScenarios",
			summary: "List the saved failure scenarios",
			handler: a.listRehearsalScenarios, resSchema: "RehearsalScenarioList", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/rehearsals/scenarios/{id}", opID: "getRehearsalScenario",
			summary: "Show one saved failure scenario", pathParams: []param{pathUUID("id")},
			handler: a.getRehearsalScenario, resSchema: "RehearsalScenario", successCode: "200", perm: authz.IncidentsRead},
		{method: "PUT", path: "/api/v1/rehearsals/scenarios/{id}", opID: "reviseRehearsalScenario",
			summary: "Revise a saved failure scenario; its runs keep the revision they replayed", pathParams: []param{pathUUID("id")},
			handler: a.saveRehearsalScenario, reqSchema: "RehearsalScenarioRequest", resSchema: "RehearsalScenario", successCode: "200", mutation: true, perm: authz.IncidentsWrite},
		{method: "POST", path: "/api/v1/rehearsals/scenarios/{id}/runs", opID: "startRehearsalRun",
			summary:    "Replay a scenario in one mode and record the versions, candidate, data set, expected effects and observations; a mocked success is never labeled live",
			pathParams: []param{pathUUID("id")},
			handler:    a.startRehearsalRun, reqSchema: "RehearsalRunRequest", resSchema: "RehearsalRun", successCode: "201", mutation: true, perm: authz.IncidentsGameDay},
		{method: "GET", path: "/api/v1/rehearsals/scenarios/{id}/runs", opID: "listRehearsalRuns",
			summary: "List a scenario's runs, newest first", pathParams: []param{pathUUID("id")},
			handler: a.listRehearsalRuns, resSchema: "RehearsalRunList", successCode: "200", perm: authz.IncidentsRead},
		{method: "GET", path: "/api/v1/rehearsals/runs/{id}", opID: "getRehearsalRun",
			summary: "Show one rehearsal run with what it expected and what it observed", pathParams: []param{pathUUID("id")},
			handler: a.getRehearsalRun, resSchema: "RehearsalRun", successCode: "200", perm: authz.IncidentsRead},
	}
}

func rehearsalSchemas() map[string]*Schema {
	integer := func() *Schema { return &Schema{Type: "integer"} }
	enum := func(values ...string) *Schema { return &Schema{Type: "string", Enum: values} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	kinds := make([]string, 0, len(rehearsal.Kinds()))
	for _, k := range rehearsal.Kinds() {
		kinds = append(kinds, string(k))
	}
	candidate := object(map[string]*Schema{"kind": enum("identity", "issuer", "profile", "target", "binary"), "ref": str(), "revision": str()}, "kind", "ref")
	dataSet := object(map[string]*Schema{
		"kind": enum("identities", "scrubbed_failure"), "identity_ids": list(str()), "secret_refs": list(str()),
		"failure": object(map[string]*Schema{"source": str(), "ref": str(), "step": str(), "code": str()}, "source", "ref"),
	}, "kind")
	step := object(map[string]*Schema{"action": str(), "target": str(), "expect": str()}, "action", "expect")
	observation := object(map[string]*Schema{
		"step": integer(), "effect": str(), "receipt": str(),
		"source": enum(string(rehearsal.SourcePreview), string(rehearsal.SourceMock), string(rehearsal.SourceSandboxReceipt), string(rehearsal.SourceLiveReceipt)),
	}, "step", "effect", "source")
	scenario := object(map[string]*Schema{
		"id": uuid(), "name": str(), "kind": enum(kinds...), "revision": integer(), "candidate": candidate,
		"data_set": dataSet, "steps": list(step), "created_by": str(), "created_at": timestamp(), "updated_at": timestamp(),
	}, "id", "name", "kind", "revision", "candidate", "data_set", "steps", "created_at", "updated_at")
	run := object(map[string]*Schema{
		"id": uuid(), "scenario_id": uuid(), "scenario_revision": integer(),
		"mode":   enum(string(rehearsal.ModeStaticPreview), string(rehearsal.ModeMockedRehearsal), string(rehearsal.ModeSandboxExecution), string(rehearsal.ModeLiveObservation)),
		"status": enum("running", "completed"), "verdict": enum("matched", "diverged", "blocked"), "label": str(),
		"tool_version": str(), "connector_versions": {Type: "object", AdditionalProperties: str()},
		"candidate": candidate, "data_set_digest": str(), "expected": list(step), "observations": list(observation),
		"detail": str(), "started_by": str(), "started_at": timestamp(), "completed_at": timestamp(),
	}, "id", "scenario_id", "scenario_revision", "mode", "status", "tool_version", "connector_versions", "candidate", "data_set_digest", "expected", "observations", "started_at")
	return map[string]*Schema{
		"RehearsalScenarioRequest": object(map[string]*Schema{"name": str(), "kind": enum(kinds...), "candidate": candidate, "data_set": dataSet, "steps": list(step)}, "name", "kind", "candidate", "data_set"),
		"RehearsalScenario":        scenario,
		"RehearsalScenarioList":    object(map[string]*Schema{"scenarios": list(scenario)}, "scenarios"),
		"RehearsalRunRequest":      object(map[string]*Schema{"mode": enum(string(rehearsal.ModeStaticPreview), string(rehearsal.ModeMockedRehearsal))}, "mode"),
		"RehearsalRun":             run,
		"RehearsalRunList":         object(map[string]*Schema{"runs": list(run)}, "runs"),
	}
}
