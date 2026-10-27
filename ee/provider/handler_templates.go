// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (h *handler) recordTemplate(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	var req TemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProviderError(w, err)
		return
	}
	tmpl, err := h.svc.RecordTemplate(r.Context(), op, req)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tmpl)
}

func (h *handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	templates, err := h.svc.ListTemplates(r.Context(), op)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

func (h *handler) getTemplate(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	detail, err := h.svc.GetTemplate(r.Context(), op, strings.TrimPrefix(r.URL.Path, "/provider/v1/templates/"))
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *handler) templateRollout(w http.ResponseWriter, r *http.Request, preview bool) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	suffix := "/rollout"
	if preview {
		suffix = "/rollout/preview"
	}
	templateID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/templates/"), suffix)
	var req RolloutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProviderError(w, err)
		return
	}
	if preview {
		out, err := h.svc.PreviewTemplateRollout(r.Context(), op, templateID, req)
		if err != nil {
			writeProviderError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	out, err := h.svc.RolloutTemplate(r.Context(), op, templateID, req)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) applyTemplate(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/template")
	var req TemplateApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProviderError(w, err)
		return
	}
	app, err := h.svc.ApplyTemplate(r.Context(), op, customerID, req)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (h *handler) templateDrift(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/template-drift")
	drift, err := h.svc.TemplateDrift(r.Context(), op, customerID)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, drift)
}
