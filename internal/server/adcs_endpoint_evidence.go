// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A new endpoint fact is served only while its source observation is retained.
// The event anchor belongs to the projector, never to a relay's report.
func (s *Server) boundADCSEndpointEvidence(ctx context.Context, tenantID string, row store.ADCSEnrollmentServicePosture, cache map[string]adcsEndpointObservation) (adcs.EnrollmentService, error) {
	var projected struct {
		adcs.EnrollmentService
		ObservationEventID string `json:"observation_event_id"`
	}
	if err := json.Unmarshal(row.ObservedService, &projected); err != nil {
		return adcs.EnrollmentService{}, err
	}
	if projected.ObservationEventID == "" {
		if projected.EndpointProbe != nil {
			return adcs.EnrollmentService{}, errors.New("AD CS endpoint coverage lacks its retained observation")
		}
		for _, endpoint := range projected.Endpoints {
			if endpoint.Source != "" || endpoint.NotCheckedReason != "" || endpoint.State == adcs.EndpointNotChecked {
				return adcs.EnrollmentService{}, errors.New("AD CS endpoint provenance lacks its retained observation")
			}
		}
		return projected.EnrollmentService, nil
	}
	if s.log == nil {
		return adcs.EnrollmentService{}, errors.New("AD CS endpoint source log is unavailable")
	}

	saved, cached := cache[projected.ObservationEventID]
	facts := saved.Facts
	if !cached {
		event, found, err := s.log.EventByID(ctx, projected.ObservationEventID)
		if err != nil {
			return adcs.EnrollmentService{}, err
		}
		if !found || event.TenantID != tenantID || event.Type != projections.EventADCSInventoryObserved || event.SchemaVersion < adcs.InventoryEndpointProbeSchemaVersion || event.SchemaVersion > adcs.InventoryEventSchemaVersion {
			return adcs.EnrollmentService{}, errors.New("AD CS endpoint source observation is unavailable")
		}
		facts, err = adcs.DecodeInventoryObservation(event.SchemaVersion, event.Data)
		if err != nil {
			return adcs.EnrollmentService{}, err
		}
		if err := facts.Validate(); err != nil {
			return adcs.EnrollmentService{}, err
		}
		if !event.Time.Truncate(1000).Equal(row.ObservedAt.UTC().Truncate(1000)) {
			return adcs.EnrollmentService{}, errors.New("AD CS endpoint timestamp differs from its source observation")
		}
		// Keep at most one full source inventory per request. Adjacent rows
		// reuse it; moving to another observation releases the previous one.
		clear(cache)
		cache[projected.ObservationEventID] = adcsEndpointObservation{Facts: facts, ObservedAt: event.Time}
		saved = cache[projected.ObservationEventID]
	}
	if facts.Domain != row.Domain || facts.AgentName != row.ObservedBy || !saved.ObservedAt.Truncate(1000).Equal(row.ObservedAt.UTC().Truncate(1000)) {
		return adcs.EnrollmentService{}, errors.New("AD CS endpoint identity differs from its source observation")
	}
	for _, service := range facts.EnrollmentServices {
		if service.Name != row.Service {
			continue
		}
		a, _ := json.Marshal(service)
		b, _ := json.Marshal(projected.EnrollmentService)
		if !bytes.Equal(a, b) || service.DNSName != row.DNSName || service.AgentRestrictions.State != adcs.EvidenceState(row.AgentRestrictionState) || service.AgentRestrictions.Source != row.AgentRestrictionSource || !adcsPublicJSONEqual(service.EnrollmentWebServices, row.EnrollmentWebServices) {
			return adcs.EnrollmentService{}, errors.New("AD CS endpoint facts differ from their source; replay the projection")
		}
		findings := []adcs.Finding{}
		worst := ""
		for _, finding := range facts.Findings {
			if finding.ResourceKind == "enrollment_service" && finding.Resource == row.Service {
				findings = append(findings, finding)
				if worst == "" {
					worst = string(finding.Severity)
				}
			}
		}
		expected, _ := json.Marshal(findings)
		var candidate []adcs.Finding
		if err := json.Unmarshal(row.Findings, &candidate); err != nil {
			return adcs.EnrollmentService{}, err
		}
		actual, _ := json.Marshal(candidate)
		if !bytes.Equal(expected, actual) || worst != row.WorstSeverity {
			return adcs.EnrollmentService{}, errors.New("AD CS endpoint findings differ from their source; replay the projection")
		}
		return service, nil
	}
	return adcs.EnrollmentService{}, errors.New("AD CS endpoint service is absent from its source observation")
}

func adcsPublicJSONEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

type adcsEndpointObservation struct {
	Facts      adcs.InventoryObserved
	ObservedAt time.Time
}
