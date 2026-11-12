// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// P3-L1: a read-only planner that builds canary-first cohorts from a
// selector, instead of an operator listing every member. It reads the same
// facts a start would: deployed X.509 identities bound to a deployment
// target, and, by issuer, the trstctl CA that issued each one's current
// certificate (the CA a planned switch revokes it through).

const (
	// maxCohortPlanScan bounds the identities one plan reads.
	maxCohortPlanScan = 20000
	// maxCohortPlanSkips bounds the skipped members listed; the count is
	// always whole.
	maxCohortPlanSkips    = 100
	cohortPlanPageSize    = 500
	maxCohortSelectorRune = 256
)

type migrationCohortSelector struct {
	Profile    string `json:"profile,omitempty"`
	IssuerCAID string `json:"issuer_ca_id,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	Connector  string `json:"connector,omitempty"`
}

type migrationCohortSkip struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
	Reason     string `json:"reason"`
}

type migrationCohortPlan struct {
	Selector     migrationCohortSelector   `json:"selector"`
	CanarySize   int                       `json:"canary_size"`
	CohortSize   int                       `json:"cohort_size"`
	Members      int                       `json:"members"`
	Truncated    bool                      `json:"truncated"`
	Waves        []migration.PlannedCohort `json:"waves"`
	Skipped      []migrationCohortSkip     `json:"skipped"`
	SkippedCount int                       `json:"skipped_count"`
	Guidance     string                    `json:"guidance"`
}

const cohortPlanGuidance = "A read-only proposal: nothing was distributed, issued or recorded. The canary " +
	"comes first, so a failed live check pauses the run before the rest of the estate is touched. " +
	"Review the cohorts, add each member's trust anchor path, then assess and start the plan."

// planMigrationCohorts answers GET /api/v1/migrations/cohort-plan.
func (a *API) planMigrationCohorts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	q := r.URL.Query()
	sel, err := cohortSelectorFrom(q)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	canary, err := cohortSizeParam(q, "canary_size", migration.DefaultCanarySize, migration.MaxCanarySize)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	cohort, err := cohortSizeParam(q, "cohort_size", migration.DefaultCohortSize, migration.MaxCohortSize)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	plan, err := a.buildCohortPlan(r.Context(), tenantID, sel, canary, cohort)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

func cohortSelectorFrom(q url.Values) (migrationCohortSelector, error) {
	sel := migrationCohortSelector{
		Profile: strings.TrimSpace(q.Get("profile")), IssuerCAID: strings.TrimSpace(q.Get("issuer_ca_id")),
		OwnerID: strings.TrimSpace(q.Get("owner_id")), Connector: strings.TrimSpace(q.Get("connector")),
	}
	if sel.Profile == "" && sel.IssuerCAID == "" && sel.OwnerID == "" && sel.Connector == "" {
		return sel, errors.New("name at least one of profile, issuer_ca_id, owner_id or connector")
	}
	for _, v := range []string{sel.Profile, sel.IssuerCAID, sel.OwnerID, sel.Connector} {
		if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxCohortSelectorRune || strings.ContainsRune(v, 0) {
			return sel, errors.New("a selector is at most 256 characters of valid UTF-8 without NUL")
		}
	}
	if sel.OwnerID != "" && guuid.Validate(sel.OwnerID) != nil {
		return sel, errors.New("owner_id must be a UUID")
	}
	if sel.IssuerCAID != "" && guuid.Validate(sel.IssuerCAID) != nil {
		return sel, errors.New("issuer_ca_id must be a UUID")
	}
	return sel, nil
}

func cohortSizeParam(q url.Values, name string, def, maxSize int) (int, error) {
	raw := strings.TrimSpace(q.Get(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxSize {
		return 0, errors.New(name + " must be an integer between 1 and " + strconv.Itoa(maxSize))
	}
	return n, nil
}

func (a *API) buildCohortPlan(ctx context.Context, tenantID string, sel migrationCohortSelector, canary, cohort int) (migrationCohortPlan, error) {
	out := migrationCohortPlan{Selector: sel, CanarySize: canary, CohortSize: cohort,
		Waves: []migration.PlannedCohort{}, Skipped: []migrationCohortSkip{}, Guidance: cohortPlanGuidance}
	if a.store == nil {
		return out, nil
	}
	targets, err := a.store.ListDeploymentTargets(ctx, tenantID)
	if err != nil {
		return out, err
	}
	byID := make(map[string]store.DeploymentTarget, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}
	skip := func(ident store.Identity, reason string) {
		out.SkippedCount++
		if len(out.Skipped) < maxCohortPlanSkips {
			out.Skipped = append(out.Skipped, migrationCohortSkip{IdentityID: ident.ID, Name: ident.Name, Reason: reason})
		}
	}
	var candidates []migration.CohortCandidate
	scanned := 0
	for after := store.ZeroUUID; ; {
		page, err := a.store.ListIdentitiesPage(ctx, tenantID, after, cohortPlanPageSize)
		if err != nil {
			return out, err
		}
		for _, ident := range page {
			after = ident.ID
			if scanned++; scanned > maxCohortPlanScan {
				out.Truncated = true
				break
			}
			if ident.Kind != store.KindX509Certificate {
				continue
			}
			target, hasTarget := byID[targetIDFromIdentityAttrs(ident.Attributes)]
			if !cohortSelectorMatches(sel, ident, target, hasTarget) {
				continue
			}
			switch {
			case ident.Status != string(orchestrator.StateDeployed):
				skip(ident, "not deployed ("+ident.Status+")")
				continue
			case !hasTarget || !target.Enabled:
				skip(ident, "no enabled deployment target")
				continue
			}
			if sel.IssuerCAID != "" {
				cert, err := a.migrationPredecessorCertificate(ctx, tenantID, ident)
				if err != nil {
					skip(ident, "its current certificate could not be read: "+err.Error())
					continue
				}
				caID, err := a.switchPredecessorCA(ctx, tenantID, cert)
				if err != nil {
					skip(ident, err.Error())
					continue
				}
				if caID != sel.IssuerCAID {
					continue
				}
			}
			if len(candidates) == migration.MaxCohortPlanMembers {
				out.Truncated = true
				break
			}
			agentID, _ := connector.TargetHostAgentID(target.Config)
			candidates = append(candidates, migration.CohortCandidate{IdentityID: ident.ID, Name: ident.Name, AgentID: agentID})
		}
		if out.Truncated || len(page) < cohortPlanPageSize {
			break
		}
	}
	sort.SliceStable(out.Skipped, func(i, j int) bool { return out.Skipped[i].Name < out.Skipped[j].Name })
	waves, err := migration.PlanCohorts(candidates, canary, cohort)
	if err != nil {
		return out, errStatusFrom(http.StatusBadRequest, err)
	}
	out.Waves, out.Members = waves, len(candidates)
	return out, nil
}

// cohortSelectorMatches checks the selector's cheap fields; the issuer is
// read only for the identities these leave.
func cohortSelectorMatches(sel migrationCohortSelector, ident store.Identity, target store.DeploymentTarget, hasTarget bool) bool {
	if sel.OwnerID != "" && !strings.EqualFold(ident.OwnerID, sel.OwnerID) {
		return false
	}
	if sel.Profile != "" && identityProfileName(ident.Attributes) != sel.Profile {
		return false
	}
	if sel.Connector != "" && (!hasTarget || target.Type != sel.Connector) {
		return false
	}
	return true
}

// identityProfileName reads the profile an identity is issued under.
func identityProfileName(raw json.RawMessage) string {
	var attrs struct {
		ProfileName string `json:"profile_name"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &attrs) != nil {
		return ""
	}
	return strings.TrimSpace(attrs.ProfileName)
}
