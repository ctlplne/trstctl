// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
)

// The served invoice-evidence route (epic L2).
//
// A provider pulls this to bill a customer. The route's job is to make an
// incomplete period IMPOSSIBLE TO MISREAD, not to always answer 200 with
// numbers — the document carries its own signable flag and reason, and this
// handler refuses to hide either.

// EvidenceReader is what the route needs from the metering store.
type EvidenceReader interface {
	Query(ctx context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error)
	CoverageFor(ctx context.Context, tenantID string) (Coverage, error)
}

// EvidenceDeps is everything the served evidence route consults. Reconciler
// and Signer may be nil — the document then says, in its reason, exactly which
// attestation ingredient is missing, rather than serving numbers that imply a
// check or a signature that never happened.
type EvidenceDeps struct {
	Reader     EvidenceReader
	Reconciler EvidenceReconciler
	Signer     EvidenceSigner
}

// Routes is the served evidence surface.
func Routes(deps EvidenceDeps) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method:      http.MethodGet,
			Path:        "/api/v1/provider/usage-evidence",
			OperationID: "getUsageEvidence",
			Summary:     "Per-customer usage as invoice evidence; the document states whether it may be signed",
			Handler: func(a *api.API) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) { serveEvidence(a, w, r, deps) }
			},
			ResponseSchema: "UsageEvidence",
			SuccessCode:    "200",
			// audit:read, not a billing-specific permission: this document is
			// evidence about a customer's activity, and the people who may read
			// what a tenant did are the people who may read this.
			Permission: authz.AuditRead,
		},
	}
}

// NewAPIOptionsFactory mounts the evidence route behind the Enterprise seam.
func NewAPIOptionsFactory(deps EvidenceDeps) editionseam.LicensedAPIOptionsFactory {
	return func(editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		return []api.Option{
			api.WithLicensedRoutes(Routes(deps)...),
			api.WithLicensedSchemas(evidenceSchemas()),
		}, nil
	}
}

// evidenceSchemas describes the document. `signable` and `reason` are REQUIRED
// so a generated client cannot omit the fields that say whether the numbers
// mean anything.
func evidenceSchemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"UsageEvidence": {
			Type: "object",
			Properties: map[string]*api.Schema{
				"customer_id":  {Type: "string"},
				"period_start": {Type: "string"},
				"period_end":   {Type: "string"},
				"lines": {Type: "array", Items: &api.Schema{Type: "object", Properties: map[string]*api.Schema{
					"meter": {Type: "string"}, "kind": {Type: "string"}, "value": {Type: "integer"},
				}}},
				"signable":      {Type: "boolean"},
				"reason":        {Type: "string"},
				"observed_from": {Type: "string"},
				"observed_to":   {Type: "string"},
				"reconciliation": {Type: "array", Items: &api.Schema{Type: "object", Properties: map[string]*api.Schema{
					"meter": {Type: "string"}, "metered": {Type: "integer"},
					"event_history": {Type: "integer"}, "checked": {Type: "boolean"},
					"matches": {Type: "boolean"}, "source": {Type: "string"}, "note": {Type: "string"},
				}}},
				"digest": {Type: "string"},
				"signature": {Type: "object", Properties: map[string]*api.Schema{
					"alg": {Type: "string"}, "key_id": {Type: "string"}, "jws": {Type: "string"},
				}},
				"guidance": {Type: "string"},
			},
			Required: []string{"customer_id", "period_start", "period_end", "signable", "reason", "digest"},
		},
	}
}

// serveEvidence answers for one customer and period.
//
// A period the store cannot vouch for still returns 200 with the document,
// NOT an error. An error would tell a finance team "the system is broken" when
// the truth is "your usage is incomplete and here is exactly how" — and the
// second is actionable while the first gets escalated to engineering.
func serveEvidence(a *api.API, w http.ResponseWriter, r *http.Request, deps EvidenceDeps) {
	reader := deps.Reader
	// The customer is the CALLER'S TENANT, never a name in the query string.
	//
	// An evidence document is a full record of one tenant's activity, so a
	// customer_id parameter that could name somebody else would be a
	// cross-tenant read behind a read permission the caller holds in their own
	// tenancy — AN-1 defeated by a query parameter. A provider pulling a
	// customer's invoice does it inside that customer's tenancy.
	caller, ok := a.Tenant(r)
	if !ok || strings.TrimSpace(caller) == "" {
		writeEvidenceError(w, http.StatusForbidden,
			"no tenant on this request; usage evidence is always scoped to the caller's own tenancy")
		return
	}
	customer := strings.TrimSpace(caller)
	q := r.URL.Query()
	if named := strings.TrimSpace(q.Get("customer_id")); named != "" && named != customer {
		// Fail closed and SAY WHY. Cross-customer evidence needs the provider
		// delegation set (ee/provider), which has no served or stored form yet;
		// answering here would mean inventing an authorization decision this
		// binary cannot make.
		writeEvidenceError(w, http.StatusForbidden,
			"customer_id names another tenant. Cross-customer evidence requires a provider delegation, "+
				"which is not served yet, so this route refuses rather than guessing that the caller "+
				"is entitled to another customer's usage")
		return
	}
	start, err := time.Parse(time.RFC3339, strings.TrimSpace(q.Get("period_start")))
	if err != nil {
		writeEvidenceError(w, http.StatusBadRequest, "period_start must be RFC3339")
		return
	}
	end, err := time.Parse(time.RFC3339, strings.TrimSpace(q.Get("period_end")))
	if err != nil {
		writeEvidenceError(w, http.StatusBadRequest, "period_end must be RFC3339")
		return
	}
	if !end.After(start) {
		writeEvidenceError(w, http.StatusBadRequest, "period_end must be after period_start")
		return
	}
	if reader == nil {
		// No metering store attached. Refusing beats answering zero: a document
		// reporting no usage would be indistinguishable from a customer who did
		// nothing, and would be invoiced as such.
		writeEvidenceError(w, http.StatusServiceUnavailable,
			"metering is not attached, so no usage can be vouched for. Zero usage and no metering are "+
				"different facts and this route will not conflate them")
		return
	}
	ctx := r.Context()
	coverage, err := reader.CoverageFor(ctx, customer)
	if err != nil {
		writeEvidenceError(w, http.StatusInternalServerError, "could not read metering coverage")
		return
	}
	records, err := reader.Query(ctx, start, end, customer)
	if err != nil {
		writeEvidenceError(w, http.StatusInternalServerError, "could not read usage")
		return
	}
	doc, err := BuildSignedEvidence(ctx, EvidencePeriod{CustomerID: customer, Start: start, End: end},
		coverage, records, deps.Reconciler, deps.Signer, time.Now().UTC())
	if err != nil {
		writeEvidenceError(w, http.StatusInternalServerError, "could not assemble the evidence document")
		return
	}
	if strings.EqualFold(strings.TrimSpace(q.Get("format")), "csv") {
		// The CSV is the document's TABLE, verdict on every row; the JSON
		// document remains the attestation (the JWS does not ride a
		// spreadsheet). The digest column ties each row back to it.
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition",
			`attachment; filename="usage-evidence-`+customer+`-`+start.UTC().Format("20060102")+`-`+end.UTC().Format("20060102")+`.csv"`)
		w.WriteHeader(http.StatusOK)
		_ = WriteEvidenceCSV(w, doc)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

func writeEvidenceError(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": code, "detail": detail})
}
