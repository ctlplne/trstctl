// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/store"
)

// What went wrong with an enrollment, in the operator's terms (epic I4).
//
// A refused enrollment is the moment an operator has the least information and
// the most urgency. The protocol told the client something — an RFC 8555 problem
// type, an EST status, a SCEP failInfo — and none of that reaches the person who
// has to fix it, because the client logged it on a host they are not looking at.
//
// This is that, kept and served. Each refusal is an immutable tenant-attributed
// event, while PostgreSQL projects the newest 200 exact failed operations under
// FORCE RLS. The projection survives restart and can be rebuilt from the log;
// the bound keeps a live troubleshooting surface from pretending to be an
// unbounded historical archive.

// EnrollmentDiagnostic is one recorded failure.
type EnrollmentDiagnostic struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Step     string `json:"step"`
	Cause    string `json:"cause"`
	Summary  string `json:"summary"`
	// Remediation is what to do. Empty when the cause is unknown, and that
	// emptiness is deliberate: a diagnosis that cannot name an action must not
	// invent one, because a confident wrong instruction costs more than silence.
	Remediation string `json:"remediation,omitempty"`
	// Actionable separates a diagnosis that names a fix from one that does not,
	// so a console can show the difference rather than rendering an empty
	// remediation as if the operator simply has nothing to do.
	Actionable bool   `json:"actionable"`
	ObservedAt string `json:"observed_at"`
	// Count is how many times this exact failed operation has been seen.
	//
	// Collapsed rather than listed: a broken challenge fails on every retry, and
	// a hundred identical rows would bury the second, different failure that
	// explains the first.
	Count                      int64  `json:"count"`
	OperationRef               string `json:"operation_ref,omitempty"`
	IdentityRef                string `json:"identity_ref,omitempty"`
	EndpointRef                string `json:"endpoint_ref,omitempty"`
	VerificationKind           string `json:"verification_kind,omitempty"`
	VerificationAddress        string `json:"verification_address,omitempty"`
	VerificationServerName     string `json:"verification_server_name,omitempty"`
	ExpectedFingerprint        string `json:"expected_fingerprint,omitempty"`
	VerificationEndpointID     string `json:"verification_endpoint_id,omitempty"`
	VerificationQueuedAt       string `json:"verification_queued_at,omitempty"`
	VerificationStatus         string `json:"verification_status,omitempty"`
	VerificationEvidenceDigest string `json:"verification_evidence_digest,omitempty"`
	VerificationAgent          string `json:"verification_agent,omitempty"`
	VerificationCheckedAt      string `json:"verification_checked_at,omitempty"`
	VerificationResultPath     string `json:"verification_result_path,omitempty"`
}

// EnrollmentDiagnosticVerification is the accepted prove-fixed command.
type EnrollmentDiagnosticVerification struct {
	DiagnosticID           string `json:"diagnostic_id"`
	VerificationEndpointID string `json:"verification_endpoint_id"`
	Status                 string `json:"status"`
	QueuedAt               string `json:"queued_at"`
	ResultPath             string `json:"result_path"`
}

// EnrollmentDiagnosticsSupportAddendum is the authorized, already-redacted
// shape the CLI may add to an offline support archive.
type EnrollmentDiagnosticsSupportAddendum struct {
	SchemaVersion int                                    `json:"schema_version"`
	Rows          []EnrollmentDiagnosticSupportAggregate `json:"rows"`
	UnknownCount  int64                                  `json:"unknown_count"`
}

type EnrollmentDiagnosticSupportAggregate struct {
	Protocol   string `json:"protocol"`
	Cause      string `json:"cause"`
	Actionable bool   `json:"actionable"`
	Count      int64  `json:"count"`
}

// EnrollmentDiagnosticList is the served response.
type EnrollmentDiagnosticList struct {
	Items []EnrollmentDiagnostic `json:"items"`
	// UnknownCount is how many recent failures could not be classified.
	//
	// Reported as a headline because it is a measure of THIS system rather than
	// of the estate: a rising number means the classifier is meeting failures it
	// has no vocabulary for, and that is a gap to close here rather than
	// something for the operator to act on.
	UnknownCount int64  `json:"unknown_count"`
	Guidance     string `json:"guidance"`
}

const enrollmentDiagnosticGuidance = "Each row is a refusal this control plane issued, classified " +
	"from what the protocol actually said. A row with no remediation is one the classifier could " +
	"not place: that is reported as unknown rather than guessed at, because a diagnosis that sends " +
	"you to the wrong system costs more than no diagnosis. Operation, identity, and endpoint references " +
	"name the exact failed attempt. These are durable tenant-scoped events, collapsed only when that exact " +
	"operation repeats, and bounded to the 200 most recent operations. Prove fixed queues a network relay; " +
	"only its signed result can turn the row green."

// RecordEnrollmentDiagnosis is the tenant-carrying seam protocol servers emit
// into. It returns persistence errors so the composition root can log a closed
// diagnostic without changing the protocol response already being written.
func (a *API) RecordEnrollmentDiagnosis(ctx context.Context, tenantID string, diagnostic enrollmentdiag.Diagnosis) error {
	if a == nil || a.orch == nil {
		return fmt.Errorf("api: enrollment diagnostics are not configured")
	}
	return a.orch.RecordEnrollmentDiagnosis(ctx, tenantID, diagnostic)
}

func (a *API) listEnrollmentDiagnostics(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "enrollment diagnostics are not configured"))
		return
	}
	rows, err := a.store.ListEnrollmentDiagnostics(r.Context(), tenantID, store.EnrollmentDiagnosticRetentionLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]EnrollmentDiagnostic, 0, len(rows))
	for _, row := range rows {
		items = append(items, EnrollmentDiagnostic{
			ID: row.DiagnosticID, Protocol: row.Protocol, Step: row.Step, Cause: row.Cause,
			Summary: row.Summary, Remediation: row.Remediation, Actionable: row.Actionable,
			ObservedAt: row.ObservedAt.UTC().Format(time.RFC3339), Count: row.Count,
			OperationRef: row.OperationRef, IdentityRef: row.IdentityRef, EndpointRef: row.EndpointRef,
			VerificationKind: row.VerificationKind, VerificationAddress: row.VerificationAddress,
			VerificationServerName: row.VerificationServerName, ExpectedFingerprint: row.ExpectedFingerprint,
			VerificationEndpointID:     row.VerificationEndpointID,
			VerificationStatus:         row.VerificationStatus,
			VerificationEvidenceDigest: row.VerificationEvidenceDigest,
			VerificationAgent:          row.VerificationAgent,
		})
		item := &items[len(items)-1]
		if !row.VerificationQueuedAt.IsZero() {
			item.VerificationQueuedAt = row.VerificationQueuedAt.UTC().Format(time.RFC3339)
		}
		if !row.VerificationCheckedAt.IsZero() {
			item.VerificationCheckedAt = row.VerificationCheckedAt.UTC().Format(time.RFC3339)
		}
		if row.VerificationEndpointID != "" {
			item.VerificationResultPath = "/api/v1/endpoints/verifications/" + row.VerificationEndpointID
		}
	}
	out := EnrollmentDiagnosticList{
		Items: items, Guidance: enrollmentDiagnosticGuidance,
	}
	if out.Items == nil {
		out.Items = []EnrollmentDiagnostic{}
	}
	for _, item := range items {
		if item.Cause == string(enrollmentdiag.CauseUnknown) {
			out.UnknownCount += item.Count
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) enrollmentDiagnosticsSupportAddendum(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "enrollment diagnostics are not configured"))
		return
	}
	rows, err := a.store.ListEnrollmentDiagnostics(r.Context(), tenantID, store.EnrollmentDiagnosticRetentionLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	type aggregateKey struct {
		protocol   string
		cause      string
		actionable bool
	}
	counts := map[aggregateKey]int64{}
	out := EnrollmentDiagnosticsSupportAddendum{SchemaVersion: 1, Rows: []EnrollmentDiagnosticSupportAggregate{}}
	for _, row := range rows {
		key := aggregateKey{protocol: row.Protocol, cause: row.Cause, actionable: row.Actionable}
		counts[key] += row.Count
		if row.Cause == string(enrollmentdiag.CauseUnknown) {
			out.UnknownCount += row.Count
		}
	}
	for key, count := range counts {
		out.Rows = append(out.Rows, EnrollmentDiagnosticSupportAggregate{
			Protocol: key.protocol, Cause: key.cause, Actionable: key.actionable, Count: count,
		})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Protocol != out.Rows[j].Protocol {
			return out.Rows[i].Protocol < out.Rows[j].Protocol
		}
		if out.Rows[i].Cause != out.Rows[j].Cause {
			return out.Rows[i].Cause < out.Rows[j].Cause
		}
		return !out.Rows[i].Actionable && out.Rows[j].Actionable
	})
	a.writeJSON(w, http.StatusOK, out)
}

//trstctl:mutation
func (a *API) proveEnrollmentDiagnosticFixed(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "enrollment diagnostics are not configured"))
		return
	}
	diagnosticID := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("enrollment-diagnostic.prove-fixed\x00" + principal + "\x00" + diagnosticID))
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		event, queued, _, err := a.orch.QueueEnrollmentDiagnosticVerification(ctx, tenantID, diagnosticID, idempotencyKey)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, errStatus(http.StatusNotFound, "enrollment diagnostic not found")
			}
			if errors.Is(err, store.ErrEnrollmentDiagnosticNoPostFailureCertificate) {
				return 0, nil, errStatus(http.StatusConflict, "retry the enrollment successfully before proving the repaired deployment endpoint")
			}
			if errors.Is(err, store.ErrEnrollmentDiagnosticNoVerificationRoute) {
				return 0, nil, errStatus(http.StatusConflict, "configure one enabled identity deployment target with an exact deployment target verify_address before proving the fix")
			}
			return 0, nil, err
		}
		return http.StatusAccepted, EnrollmentDiagnosticVerification{
			DiagnosticID: diagnosticID, VerificationEndpointID: queued.VerificationEndpointID,
			Status: "queued", QueuedAt: event.Time.UTC().Format(time.RFC3339),
			ResultPath: "/api/v1/endpoints/verifications/" + queued.VerificationEndpointID,
		}, nil
	})
}
