// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
)

// buildADCSComplianceEvidence selects only complete, internally consistent v2
// observations. Historical v1 template events remain valid audit history, but
// they cannot prove IIS or CA-side restriction posture and therefore do not
// masquerade as complete F3 evidence.
func buildADCSComplianceEvidence(tenantID string, records []audit.Record, window EvidenceWindow) (api.ADCSComplianceEvidence, error) {
	latest := make(map[string]api.ADCSComplianceObservation)
	drift := make([]api.ADCSComplianceDrift, 0)
	for _, record := range records {
		if record.TenantID != tenantID || record.Time.Before(window.From) || record.Time.After(window.Through) {
			continue
		}
		switch record.Type {
		case projections.EventADCSInventoryObserved:
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(record.Data, &fields); err != nil {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: decode AD CS observation %s: %w", record.ID, err)
			}
			if _, completeV2 := fields["enrollment_services"]; !completeV2 {
				continue
			}
			var observed adcsdiscovery.InventoryObserved
			if err := json.Unmarshal(record.Data, &observed); err != nil {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: decode AD CS v2 observation %s: %w", record.ID, err)
			}
			if observed.RunID == "" || observed.SourceID == "" || observed.Domain == "" || observed.AgentID == "" || observed.AgentName == "" {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: AD CS observation %s lacks relay authority", record.ID)
			}
			want, err := json.Marshal(adcsdiscovery.Findings(adcsdiscovery.Inventory{Templates: observed.Templates, EnrollmentServices: observed.EnrollmentServices}))
			if err != nil {
				return api.ADCSComplianceEvidence{}, err
			}
			got, err := json.Marshal(observed.Findings)
			if err != nil || !bytes.Equal(got, want) {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: AD CS observation %s findings disagree with its live facts", record.ID)
			}
			candidate := api.ADCSComplianceObservation{
				Reference: auditReference(record), RunID: observed.RunID, SourceID: observed.SourceID,
				Domain: observed.Domain, AgentID: observed.AgentID, AgentName: observed.AgentName,
				DirectoryVerified: observed.DirectoryVerified,
				Inventory:         adcsdiscovery.Inventory{Templates: observed.Templates, EnrollmentServices: observed.EnrollmentServices},
				Findings:          observed.Findings,
			}
			previous, exists := latest[observed.Domain]
			if !exists || candidate.Reference.ObservedAt.After(previous.Reference.ObservedAt) ||
				(candidate.Reference.ObservedAt.Equal(previous.Reference.ObservedAt) && candidate.Reference.Sequence > previous.Reference.Sequence) {
				latest[observed.Domain] = candidate
			}
		case projections.EventADCSTemplateDriftObserved, projections.EventADCSTemplateDriftWorsened:
			var observed projections.ADCSTemplateDriftObserved
			if err := json.Unmarshal(record.Data, &observed); err != nil {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: decode AD CS drift %s: %w", record.ID, err)
			}
			if observed.RunID == "" || observed.SourceID == "" || observed.Domain == "" || observed.AgentID == "" || observed.ObservedBy == "" {
				// V1 drift had no source/run/relay authority and cannot enter a
				// compliance artifact as if it were receipt-bound.
				continue
			}
			semantic := adcsdiscovery.Drift{Changes: observed.Changes, Lifecycle: observed.Lifecycle}
			if observed.Direction != semantic.Direction() || observed.Worsened != semantic.Worsened() ||
				(record.Type == projections.EventADCSTemplateDriftWorsened) != observed.Worsened {
				return api.ADCSComplianceEvidence{}, fmt.Errorf("governance: AD CS drift %s contradicts its semantic changes", record.ID)
			}
			changes := make([]api.ADCSTemplateDriftChange, 0, len(observed.Changes))
			for _, change := range observed.Changes {
				changes = append(changes, api.ADCSTemplateDriftChange{
					Template: change.Template, Direction: string(change.Direction), Change: change.Change,
					Attribute: change.Attribute, Before: change.Before, After: change.After,
				})
			}
			lifecycle := make([]api.ADCSTemplateLifecycleChange, 0, len(observed.Lifecycle))
			for _, change := range observed.Lifecycle {
				lifecycle = append(lifecycle, api.ADCSTemplateLifecycleChange{
					Template: change.Template, Lifecycle: string(change.Lifecycle),
					WasDangerous: change.WasDangerous, NowDangerous: change.NowDangerous,
				})
			}
			drift = append(drift, api.ADCSComplianceDrift{
				Reference: auditReference(record), RunID: observed.RunID, SourceID: observed.SourceID,
				Domain: observed.Domain, AgentID: observed.AgentID, ObservedBy: observed.ObservedBy,
				Direction: string(observed.Direction), Worsened: observed.Worsened,
				Changes: changes, Lifecycle: lifecycle,
			})
		}
	}
	observations := make([]api.ADCSComplianceObservation, 0, len(latest))
	for _, observed := range latest {
		observations = append(observations, observed)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].Domain < observations[j].Domain })
	sort.Slice(drift, func(i, j int) bool { return drift[i].Reference.Sequence < drift[j].Reference.Sequence })
	if observations == nil {
		observations = []api.ADCSComplianceObservation{}
	}
	if drift == nil {
		drift = []api.ADCSComplianceDrift{}
	}
	return api.ADCSComplianceEvidence{Observations: observations, Drift: drift}, nil
}

func auditReference(record audit.Record) api.ADCSAuditReference {
	return api.ADCSAuditReference{
		EventID: record.ID, EventType: record.Type, Sequence: record.Sequence,
		Digest: record.Hash, ObservedAt: record.Time.UTC(),
	}
}
