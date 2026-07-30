// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

const (
	ACMEARIPublicationServed    = "served"
	ACMEARIPublicationNotServed = "not_served"

	ACMEARISchedulerEnabled  = "enabled"
	ACMEARISchedulerDisabled = "disabled"

	ACMEARICertificatePublished             = "published"
	ACMEARICertificateNotPublished          = "not_published"
	ACMEARICertificateIdentifierUnavailable = "identifier_unavailable"

	ACMEARIRunPending       = "pending"
	ACMEARIRunRunning       = "running"
	ACMEARIRunSucceeded     = "succeeded"
	ACMEARIRunFailed        = "failed"
	ACMEARIRunNotApplicable = "not_applicable"

	ACMEARISourceARI              = "ari"
	ACMEARISourceFixedThreshold   = "fixed_threshold"
	ACMEARISourceManual           = "manual"
	ACMEARISourceNone             = "none"
	ACMEARISourceUnknownScheduler = "unknown_scheduler"
)

// ACMEARIPostureProvider is the narrow server-owned seam for the ARI operator
// view. The provider sees the authenticated tenant and reads through PostgreSQL
// RLS; the API never receives certificate bytes, fingerprints, tenant ids, or
// rotation reasons.
type ACMEARIPostureProvider func(
	ctx context.Context,
	tenantID, afterID string,
	limit int,
	at time.Time,
) (ACMEARIPosture, string, error)

// WithACMEARIPosture wires the assembled ACME publisher and lifecycle scheduler
// into the always-registered read route. The function is evaluated at request
// time because API construction intentionally precedes protocol construction.
func WithACMEARIPosture(provider ACMEARIPostureProvider) Option {
	return func(c *config) { c.acmeARIPosture = provider }
}

type ACMEARIWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ACMEARIPostureSummary struct {
	AffectedCertificates int `json:"affected_certificates"`
	Published            int `json:"published"`
	SchedulerPending     int `json:"scheduler_pending"`
	SchedulerConsumed    int `json:"scheduler_consumed"`
	SchedulerFailed      int `json:"scheduler_failed"`
}

type ACMEARICertificatePosture struct {
	CertificateID     string         `json:"certificate_id"`
	IdentityID        string         `json:"identity_id,omitempty"`
	IdentityName      string         `json:"identity_name,omitempty"`
	ARICertificateID  string         `json:"ari_certificate_id,omitempty"`
	CertificateStatus string         `json:"certificate_status"`
	PublicationStatus string         `json:"publication_status"`
	SuggestedWindow   *ACMEARIWindow `json:"suggested_window,omitempty"`
	SchedulerStatus   string         `json:"scheduler_status"`
	SchedulerConsumed bool           `json:"scheduler_consumed"`
	SchedulerSource   string         `json:"scheduler_source"`
	RotationRunID     string         `json:"rotation_run_id,omitempty"`
	ConsumedAt        *time.Time     `json:"consumed_at,omitempty"`
}

// ACMEARIPosture separates three facts that must not be conflated:
// whether the read model is assembled, whether renewalInfo is actually mounted
// for this tenant, and whether lifecycle scheduling is enabled.
type ACMEARIPosture struct {
	Served              bool                        `json:"served"`
	GeneratedAt         time.Time                   `json:"generated_at"`
	PublicationStatus   string                      `json:"publication_status"`
	PublicationEndpoint string                      `json:"publication_endpoint"`
	SchedulerStatus     string                      `json:"scheduler_status"`
	Summary             ACMEARIPostureSummary       `json:"summary"`
	Items               []ACMEARICertificatePosture `json:"items"`
	NextCursor          string                      `json:"next_cursor,omitempty"`
}

func (a *API) getACMEARIPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.acmeARIPosture == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME ARI posture is not assembled"))
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	posture, nextID, err := a.acmeARIPosture(r.Context(), tenantID, after, limit, time.Now().UTC())
	if err != nil {
		a.writeError(w, err)
		return
	}
	if posture.Items == nil {
		posture.Items = []ACMEARICertificatePosture{}
	}
	if nextID != "" {
		posture.NextCursor = encodeCursor(nextID)
	}
	a.writeJSON(w, http.StatusOK, posture)
}
