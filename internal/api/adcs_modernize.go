// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/adcsmodern"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A160: "modernize this template". An inventoried AD CS template becomes a
// trstctl certificate profile with its risky properties removed: names confined
// to the template's domain (the requester no longer supplies the subject),
// domain-logon and enrollment-agent usages dropped, short validity. The preview
// is effect-free; modernize creates the profile through the normal profile
// path, under dual control when the template required manager approval.

// adcsModernizeTemplateLimit bounds the posture rows a lookup reads.
const adcsModernizeTemplateLimit = 1000

type adcsModernizeRequest struct {
	// Domain and Template name the posture row (Domain is the label the posture
	// view shows, the publishing CA for a relay observation).
	Domain   string `json:"domain"`
	Template string `json:"template"`
	// DNSSuffix is the DNS domain certificates from the profile may name;
	// empty derives it from the publishing CA's DNS name.
	DNSSuffix   string `json:"dns_suffix,omitempty"`
	ProfileName string `json:"profile_name,omitempty"`
}

type adcsModernizePlan struct {
	Capability  string              `json:"capability"`
	EffectFree  bool                `json:"effect_free"`
	Ready       bool                `json:"ready"`
	Domain      string              `json:"domain"`
	Template    string              `json:"template"`
	DNSSuffix   string              `json:"dns_suffix"`
	ProfileName string              `json:"profile_name"`
	Spec        json.RawMessage     `json:"spec"`
	Changes     []adcsmodern.Change `json:"changes"`
	Blockers    []string            `json:"blockers"`
}

type adcsModernizeResult struct {
	Profile    *profileResponse    `json:"profile,omitempty"`
	ApprovalID string              `json:"approval_id,omitempty"`
	State      string              `json:"state"`
	Changes    []adcsmodern.Change `json:"changes"`
}

func decodeADCSModernizeRequest(r *http.Request) (adcsModernizeRequest, error) {
	var req adcsModernizeRequest
	if err := decodeJSON(r, &req); err != nil {
		return adcsModernizeRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	req.Domain, req.Template, req.ProfileName = strings.TrimSpace(req.Domain), strings.TrimSpace(req.Template), strings.TrimSpace(req.ProfileName)
	req.DNSSuffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.DNSSuffix), "."))
	if req.Domain == "" || req.Template == "" {
		return adcsModernizeRequest{}, errStatus(http.StatusBadRequest, "domain and template are required")
	}
	return req, nil
}

func (a *API) previewADCSModernize(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	req, err := decodeADCSModernizeRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan, err := a.adcsModernizePlan(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

func (a *API) modernizeADCSTemplate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeADCSModernizeRequest(r)
		if err != nil {
			return 0, nil, err
		}
		plan, err := a.adcsModernizePlan(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		if !plan.Ready {
			return 0, nil, errStatus(http.StatusConflict, strings.Join(plan.Blockers, " "))
		}
		rec, err := a.orch.CreateProfile(ctx, tenantID, plan.ProfileName, plan.Spec)
		if err != nil {
			var pending *orchestrator.ProfileEditPendingError
			if errors.As(err, &pending) {
				return http.StatusAccepted, adcsModernizeResult{ApprovalID: pending.Request.ID, State: string(pending.Request.State), Changes: plan.Changes}, nil
			}
			return 0, nil, err
		}
		created := toProfileResponse(rec)
		return http.StatusCreated, adcsModernizeResult{Profile: &created, State: "created", Changes: plan.Changes}, nil
	})
}

// adcsModernizePlan reads the observed template and proposes its profile. It
// writes nothing and calls nothing outside the store.
func (a *API) adcsModernizePlan(ctx context.Context, tenantID string, req adcsModernizeRequest) (adcsModernizePlan, error) {
	plan := adcsModernizePlan{Capability: "P11", EffectFree: true, Domain: req.Domain, Template: req.Template,
		Spec: json.RawMessage(`{}`), Changes: []adcsmodern.Change{}, Blockers: []string{}}
	if a.store == nil || a.orch == nil {
		return plan, errStatus(http.StatusServiceUnavailable, "profile storage is not configured")
	}
	rows, err := a.store.ListADCSTemplatePosture(ctx, tenantID, adcsModernizeTemplateLimit)
	if err != nil {
		return plan, err
	}
	var row *store.ADCSTemplatePosture
	for i := range rows {
		if strings.EqualFold(rows[i].Domain, req.Domain) && rows[i].Template == req.Template {
			row = &rows[i]
			break
		}
	}
	plan.ProfileName = req.ProfileName
	if plan.ProfileName == "" {
		plan.ProfileName = adcsmodern.ProfileName(req.Template)
	}
	if row == nil {
		plan.Blockers = append(plan.Blockers, "No relay has observed template "+req.Template+" in "+req.Domain+"; run an AD CS census first.")
		return plan, nil
	}
	var observed adcs.Template
	if len(row.ObservedTemplate) == 0 || json.Unmarshal(row.ObservedTemplate, &observed) != nil || observed.Name == "" {
		plan.Blockers = append(plan.Blockers, "The stored observation of "+req.Template+" predates full template capture; run a fresh AD CS census.")
		return plan, nil
	}
	plan.DNSSuffix = req.DNSSuffix
	if plan.DNSSuffix == "" {
		suffix, err := a.adcsPublishingDNSSuffix(ctx, tenantID, row.Domain)
		if err != nil {
			return plan, err
		}
		plan.DNSSuffix = suffix
	}
	if plan.DNSSuffix == "" {
		plan.Blockers = append(plan.Blockers, "No DNS name was observed for the publishing CA; name the DNS suffix certificates from this profile may carry (dns_suffix).")
		return plan, nil
	}
	m, err := adcsmodern.Modernize(observed, plan.DNSSuffix)
	if err != nil {
		plan.Blockers = append(plan.Blockers, err.Error())
		return plan, nil
	}
	spec, err := json.Marshal(m.Profile)
	if err != nil {
		return plan, err
	}
	plan.Spec, plan.Changes = specWithoutIdentity(spec), m.Changes
	if _, err := a.store.GetActiveProfile(ctx, tenantID, plan.ProfileName); err == nil {
		plan.Blockers = append(plan.Blockers, "A profile named "+plan.ProfileName+" already exists; choose another name.")
	} else if !store.IsNotFound(err) {
		return plan, err
	}
	plan.Ready = len(plan.Blockers) == 0
	return plan, nil
}

// adcsPublishingDNSSuffix derives the DNS domain from the publishing CA's
// observed DNS name (ca01.corp.example → corp.example), or "" when none was
// observed.
func (a *API) adcsPublishingDNSSuffix(ctx context.Context, tenantID, domain string) (string, error) {
	services, err := a.store.ListADCSEnrollmentServicePosture(ctx, tenantID, adcsModernizeTemplateLimit)
	if err != nil {
		return "", err
	}
	for _, service := range services {
		if !strings.EqualFold(service.Domain, domain) {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(service.DNSName), "."))
		if _, suffix, ok := strings.Cut(host, "."); ok && strings.Contains(suffix, ".") {
			return suffix, nil
		}
	}
	return "", nil
}

// specWithoutIdentity drops the name and version a profile record assigns, and
// the unset fields, so the stored spec reads like one an operator wrote.
func specWithoutIdentity(spec []byte) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(spec, &fields) != nil {
		return spec
	}
	delete(fields, "name")
	delete(fields, "version")
	for key, value := range fields {
		if bytes.Equal(value, []byte("null")) {
			delete(fields, key)
		}
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return spec
	}
	return out
}
