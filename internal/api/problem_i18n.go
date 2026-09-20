// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/api/problem"
)

const defaultProblemLocale = "en-US"

type problemLocaleWriter struct {
	http.ResponseWriter
	locale string
}

func localizedProblemWriter(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	return &problemLocaleWriter{
		ResponseWriter: w,
		locale:         negotiateProblemLocale(r.Header.Get("Accept-Language")),
	}
}

func (w *problemLocaleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type localizedProblem interface {
	problemLocale() string
}

func (w *problemLocaleWriter) problemLocale() string { return w.locale }

func problemLocaleFromWriter(w http.ResponseWriter) string {
	if localized, ok := w.(localizedProblem); ok && localized.problemLocale() != "" {
		return localized.problemLocale()
	}
	return defaultProblemLocale
}

func negotiateProblemLocale(acceptLanguage string) string {
	bestLocale := defaultProblemLocale
	bestQuality := -1.0
	for _, raw := range strings.Split(acceptLanguage, ",") {
		tag, quality := parseAcceptLanguageRange(raw)
		if tag == "" || quality <= 0 {
			continue
		}
		locale := problemLocaleForLanguageTag(tag)
		if locale == "" || quality <= bestQuality {
			continue
		}
		bestLocale = locale
		bestQuality = quality
	}
	return bestLocale
}

func problemLocaleForLanguageTag(tag string) string {
	switch strings.ToLower(tag) {
	case "en", "en-us":
		return "en-US"
	case "es", "es-es":
		return "es-ES"
	}
	lang, _, _ := strings.Cut(tag, "-")
	switch strings.ToLower(lang) {
	case "en":
		return "en-US"
	case "es":
		return "es-ES"
	default:
		return ""
	}
}

type problemCatalogEntry struct {
	code    string
	details map[string]string
}

var problemCatalog = map[string]problemCatalogEntry{
	"missing or invalid tenant": {
		code: "problem.auth.missing_or_invalid_tenant",
		details: map[string]string{
			"en-US": "missing or invalid tenant",
			"es-ES": "tenant faltante o no valido",
		},
	},
	"no such resource": {
		code: "problem.resource.not_found",
		details: map[string]string{
			"en-US": "no such resource",
			"es-ES": "recurso no encontrado",
		},
	},
	"resource not found": {
		code: "problem.resource.not_found",
		details: map[string]string{
			"en-US": "resource not found",
			"es-ES": "recurso no encontrado",
		},
	},
	"internal error": {
		code: "problem.internal.error",
		details: map[string]string{
			"en-US": "internal error",
			"es-ES": "error interno",
		},
	},
	"failed to encode response": {
		code: "problem.internal.encode_response",
		details: map[string]string{
			"en-US": "failed to encode response",
			"es-ES": "no se pudo codificar la respuesta",
		},
	},
	"rate limit exceeded for this tenant": {
		code: "problem.rate_limit.tenant_exceeded",
		details: map[string]string{
			"en-US": "rate limit exceeded for this tenant",
			"es-ES": "limite de tasa excedido para este tenant",
		},
	},
	"Idempotency-Key header is required for mutations": {
		code: "problem.mutation.idempotency_key_required",
		details: map[string]string{
			"en-US": "Idempotency-Key header is required for mutations",
			"es-ES": "el encabezado Idempotency-Key es obligatorio para mutaciones",
		},
	},
	"missing or invalid CSRF token": {
		code: "problem.auth.missing_or_invalid_csrf",
		details: map[string]string{
			"en-US": "missing or invalid CSRF token",
			"es-ES": "token CSRF faltante o no valido",
		},
	},
	"no tenant for this user": {
		code: "problem.auth.no_tenant_for_user",
		details: map[string]string{
			"en-US": "no tenant for this user",
			"es-ES": "sin tenant para este usuario",
		},
	},
}

func localizeProblemResponse(w http.ResponseWriter, p *problem.Problem) bool {
	if p == nil {
		return false
	}
	entry, ok := problemCatalog[p.Detail]
	if !ok {
		return false
	}
	if p.Extensions == nil {
		p.Extensions = make(map[string]any, 1)
	}
	if _, exists := p.Extensions["code"]; !exists {
		p.Extensions["code"] = entry.code
	}
	locale := problemLocaleFromWriter(w)
	if detail := entry.details[locale]; detail != "" {
		p.Detail = detail
		return true
	}
	if detail := entry.details[defaultProblemLocale]; detail != "" {
		p.Detail = detail
		return true
	}
	return false
}

func addVaryHeader(h http.Header, value string) {
	for _, existing := range h.Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), value) {
				return
			}
		}
	}
	h.Add("Vary", value)
}
