// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
)

// An AI draft of a reviewed change set (A248). The model turns an operator's
// request into the same typed change set a form, an API call or a GitOps file
// produces, and the draft goes through the same plan; it is never applied here.
// The model gets the request and the tenant's names — roles, profiles, CAs,
// targets, owners — never a spec, a config, a chain, an email or a secret: a
// request that carries a secret is refused before the model is called, and
// the model adapter redacts and refuses what remains. With no model, drafting
// answers 503 and every other way of authoring a change set works as before.

// maxDraftRequest bounds the request a draft is made from.
const maxDraftRequest = 4 << 10

// maxDraftCatalog bounds each list of names the model is shown.
const maxDraftCatalog = 200

// ChangeDraftRequest is what an operator asks the model to draft.
type ChangeDraftRequest struct {
	Request string `json:"request"`
}

// ChangeDraft is a drafted change set and its plan, or why it does not plan.
type ChangeDraft struct {
	ChangeSet ChangeSet   `json:"change_set"`
	Plan      *ChangePlan `json:"plan,omitempty"`
	Refused   string      `json:"refused,omitempty"`
	Model     string      `json:"model"`
}

// errDraftUnavailable is drafting with no model configured.
var errDraftUnavailable = errStatus(http.StatusServiceUnavailable,
	"AI drafting is unavailable: no model is configured; write the change set by form, API or GitOps")

func (a *API) draftModel() (*aimodel.Adapter, error) {
	if a.ai == nil || a.ai.be.Model == nil || !a.ai.be.Model.Available() {
		return nil, errDraftUnavailable
	}
	return a.ai.be.Model, nil
}

// draftCatalog is the tenant's names a draft may use: never a spec, config,
// chain, email or member subject.
func (a *API) draftCatalog(ctx context.Context, tenantID string) (map[string][]string, error) {
	catalog := map[string][]string{}
	add := func(kind, name string) {
		if name = strings.TrimSpace(name); name != "" && len(catalog[kind]) < maxDraftCatalog {
			catalog[kind] = append(catalog[kind], name)
		}
	}
	for _, role := range a.roles.Roles() {
		add("roles", role.Name)
	}
	custom, err := a.store.ListTenantCustomRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, role := range custom {
		add("roles", role.Name)
	}
	profiles, err := a.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, p := range profiles {
		add("profiles", p.Name)
	}
	issuers, err := a.store.ListIssuers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, i := range issuers {
		add("issuers", i.Name+" ("+string(i.Kind)+")")
	}
	targets, err := a.store.ListDeploymentTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		add("deployment_targets", t.Name+" ("+t.Type+")")
	}
	owners, err := a.store.ListOwners(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, o := range owners {
		add("owners", o.Name+" ("+string(o.Kind)+")")
	}
	for kind := range catalog {
		sort.Strings(catalog[kind])
	}
	return catalog, nil
}

// draftPrompt is the instruction, the change set's shape, the catalog and the
// request.
func draftPrompt(catalog map[string][]string, request string) string {
	var b strings.Builder
	b.WriteString("You draft a trstctl configuration change set. Answer with one JSON object and nothing else, shaped:\n")
	b.WriteString(`{"name": "...", "description": "...",
 "profiles": [{"name": "...", "spec": {"allowed_key_algorithms": ["ECDSA"], "allowed_protocols": ["acme"], "max_validity": "720h"}}],
 "deployment_targets": [{"key": "...", "name": "...", "connector": "...", "config": {"address_ref": "<stored secret name>"}, "enabled": false}],
 "members": [{"subject": "...", "roles": ["..."]}],
 "owners": [{"key": "...", "kind": "team|user|service|workload|vendor", "name": "...", "application_id": "...", "service": "...", "environment": "..."}]}` + "\n")
	b.WriteString("Use only the objects the request asks for. Name each object exactly, never with a pattern. Never write a secret value: refer to a stored secret by a field ending in _ref. Use existing names from this catalog where the request refers to them:\n")
	kinds := make([]string, 0, len(catalog))
	for kind := range catalog {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		b.WriteString(kind + ": " + strings.Join(catalog[kind], ", ") + "\n")
	}
	b.WriteString("Request: " + request + "\n")
	return b.String()
}

// draftedChangeSet reads the first JSON object in the model's answer as a
// change set, strictly.
func draftedChangeSet(answer string) (ChangeSet, error) {
	start := strings.Index(answer, "{")
	end := strings.LastIndex(answer, "}")
	if start < 0 || end < start {
		return ChangeSet{}, errors.New("the model's answer holds no JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(answer[start : end+1])))
	dec.DisallowUnknownFields()
	var cs ChangeSet
	if err := dec.Decode(&cs); err != nil {
		return ChangeSet{}, fmt.Errorf("the model's answer is not a change set: %w", err)
	}
	return cs, nil
}

func (a *API) draftChangeSet(ctx context.Context, principal authz.Principal, tenantID string, req ChangeDraftRequest) (ChangeDraft, error) {
	request := strings.TrimSpace(req.Request)
	switch {
	case request == "":
		return ChangeDraft{}, errStatus(http.StatusBadRequest, "request is required: say what the change set should do")
	case len(request) > maxDraftRequest:
		return ChangeDraft{}, errStatus(http.StatusBadRequest, fmt.Sprintf("request is longer than %d bytes", maxDraftRequest))
	}
	model, err := a.draftModel()
	if err != nil {
		return ChangeDraft{}, err
	}
	if shape, found := aimodel.StructuredSecret(request); found {
		return ChangeDraft{}, errStatus(http.StatusUnprocessableEntity, "the request holds "+shape+"; describe objects by name and refer to stored secrets, never paste one")
	}
	catalog, err := a.draftCatalog(ctx, tenantID)
	if err != nil {
		return ChangeDraft{}, err
	}
	answer, err := model.Reason(ctx, draftPrompt(catalog, request))
	if err != nil {
		if errors.Is(err, aimodel.ErrResidualSecret) || errors.Is(err, aimodel.ErrPIIBlocked) {
			return ChangeDraft{}, errStatusFrom(http.StatusUnprocessableEntity, err)
		}
		return ChangeDraft{}, errStatusFrom(http.StatusBadGateway, err)
	}
	cs, err := draftedChangeSet(answer)
	if err != nil {
		return ChangeDraft{}, errStatusFrom(http.StatusUnprocessableEntity, err)
	}
	if strings.TrimSpace(cs.Name) == "" {
		cs.Name = "AI draft"
	}
	out := ChangeDraft{ChangeSet: cs, Model: model.ModelName()}
	plan, _, err := a.planChangeSet(ctx, principal, tenantID, cs)
	if err != nil {
		out.Refused = err.Error()
	} else {
		out.Plan = &plan
	}
	payload, err := json.Marshal(map[string]any{
		"model": out.Model, "request_sha256": crypto.SHA256Hex([]byte(request)),
		"change_set_digest": ChangeSetDigest(cs), "plan_digest": planDigestOf(out.Plan), "refused": out.Refused != "",
	})
	if err != nil {
		return ChangeDraft{}, err
	}
	if err := a.ai.be.Audit.Audit(ctx, "ai.change_set.drafted", tenantID, payload); err != nil {
		return ChangeDraft{}, err
	}
	return out, nil
}

func planDigestOf(p *ChangePlan) string {
	if p == nil {
		return ""
	}
	return p.PlanDigest
}

func (a *API) draftChangeSetHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	var req ChangeDraftRequest
	if err := decodeJSONWithLimitOptions(r, &req, defaultRESTJSONBodyLimit, true); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	draft, err := a.draftChangeSet(r.Context(), principal, tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, draft)
}
