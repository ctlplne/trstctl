// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Resolution workflows for posture findings (A106). An operator investigates
// a finding (an assignee and an optional due date), records it remediated (the
// evidence of the fix), accepts its risk until a time (a reason and an expiry
// within a year, after which the sweep reopens it), or reopens it. Posture
// reads leave remediated findings and unexpired acceptances out of the open
// posture and count them; a remediated finding seen again after its fix, and
// an acceptance past its expiry, count as open.

const (
	resolutionInvestigate = "investigate"
	resolutionRemediated  = "remediated"
	resolutionAcceptRisk  = "accept_risk"
	resolutionReopen      = "reopen"
	// maxResolutionHorizon bounds a due date and an acceptance: a person
	// renews an acceptance, with a reason, at least once a year.
	maxResolutionHorizon = 365 * 24 * time.Hour
)

type discoveryFindingResolutionRequest struct {
	Action      string     `json:"action"`
	Reason      string     `json:"reason"`
	Assignee    string     `json:"assignee,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	EvidenceRef string     `json:"evidence_ref,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func resolutionText(name, value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New(name + " is required")
	}
	if len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New(name + " must be one line of at most " + strconv.Itoa(max) + " characters")
	}
	return value, nil
}

func resolutionInstant(name string, t *time.Time, now time.Time) (*time.Time, error) {
	if t == nil {
		return nil, nil
	}
	u := t.UTC()
	if !u.After(now) || u.After(now.Add(maxResolutionHorizon)) {
		return nil, errors.New(name + " must be in the future and within one year")
	}
	return &u, nil
}

// resolution validates a request against its action: each action takes its
// own fields and refuses the others.
func (req discoveryFindingResolutionRequest) resolution(now time.Time) (orchestrator.DiscoveryFindingResolution, error) {
	var out orchestrator.DiscoveryFindingResolution
	reason, err := resolutionText("reason", req.Reason, 1024)
	if err != nil {
		return out, err
	}
	out.Reason = reason
	action := strings.TrimSpace(req.Action)
	if (action != resolutionInvestigate && (req.Assignee != "" || req.DueAt != nil)) ||
		(action != resolutionRemediated && req.EvidenceRef != "") || (action != resolutionAcceptRisk && req.ExpiresAt != nil) {
		return out, errors.New("assignee and due_at belong to investigate, evidence_ref to remediated, and expires_at to accept_risk")
	}
	switch action {
	case resolutionInvestigate:
		out.Status = discovery.TriageInvestigating
		if out.Assignee, err = resolutionText("assignee", req.Assignee, 256); err != nil {
			return out, err
		}
		out.DueAt, err = resolutionInstant("due_at", req.DueAt, now)
	case resolutionRemediated:
		out.Status = discovery.TriageRemediated
		out.EvidenceRef, err = resolutionText("evidence_ref", req.EvidenceRef, 512)
	case resolutionAcceptRisk:
		out.Status = discovery.TriageAcceptedRisk
		if req.ExpiresAt == nil {
			return out, errors.New("expires_at is required: a risk is accepted until a time")
		}
		out.RiskAcceptedUntil, err = resolutionInstant("expires_at", req.ExpiresAt, now)
	case resolutionReopen:
		out.Status = discovery.TriageUnmanaged
	default:
		return out, errors.New("action must be investigate, remediated, accept_risk or reopen")
	}
	return out, err
}

//trstctl:mutation
func (a *API) resolveDiscoveryFinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingResolutionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if _, uerr := googleuuid.Parse(r.PathValue("id")); uerr != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "id must be a valid UUID")
		}
		res, err := req.resolution(time.Now().UTC())
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		f, err := a.orch.ResolveDiscoveryFinding(ctx, tenantID, r.PathValue("id"), res)
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		return http.StatusOK, toDiscoveryFindingResponse(f), nil
	})
}

// findingOverdue: under investigation past its due date.
func findingOverdue(f store.DiscoveryFinding, now time.Time) bool {
	return f.TriageStatus == string(discovery.TriageInvestigating) && f.TriageDueAt != nil && now.After(*f.TriageDueAt)
}

// findingRegressed: remediated, then seen again after the fix was recorded.
func findingRegressed(f store.DiscoveryFinding) bool {
	return f.TriageStatus == string(discovery.TriageRemediated) && f.TriagedAt != nil && f.LastSeenAt.After(*f.TriagedAt)
}

// findingResolution names the resolution that keeps a finding out of the open
// posture at now, or "" when it is open: a remediation that held, or an
// acceptance that has not expired.
func findingResolution(f store.DiscoveryFinding, now time.Time) discovery.TriageStatus {
	switch discovery.TriageStatus(f.TriageStatus) {
	case discovery.TriageRemediated:
		if !findingRegressed(f) {
			return discovery.TriageRemediated
		}
	case discovery.TriageAcceptedRisk:
		if f.RiskAcceptedUntil != nil && now.Before(*f.RiskAcceptedUntil) {
			return discovery.TriageAcceptedRisk
		}
	}
	return ""
}
