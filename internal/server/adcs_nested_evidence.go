// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// boundADCSMembership makes each new served path depend on retained source
// facts. The row anchor is projection metadata, never relay-controlled input.
func (s *Server) boundADCSMembership(ctx context.Context, tenantID string, row store.ADCSTemplatePosture) (*adcs.EnrollmentMembership, error) {
	var projected struct {
		adcs.Template
		ObservationEventID string `json:"observation_event_id"`
	}
	if len(row.ObservedTemplate) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(row.ObservedTemplate, &projected); err != nil {
		return nil, err
	}
	if projected.EnrollmentMembership == nil {
		return nil, nil
	}
	if s.log == nil || projected.ObservationEventID == "" {
		return nil, errors.New("AD CS membership has no retained observation; restore history and replay")
	}
	event, found, err := s.log.EventByID(ctx, projected.ObservationEventID)
	if err != nil {
		return nil, err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventADCSInventoryObserved || (event.SchemaVersion < adcs.InventoryMembershipSchemaVersion || event.SchemaVersion > adcs.InventoryEventSchemaVersion) {
		return nil, errors.New("AD CS membership observation is unavailable")
	}
	observed, err := adcs.DecodeInventoryObservation(event.SchemaVersion, event.Data)
	if err != nil {
		return nil, err
	}
	if !observed.NestedGroupsEnabled || observed.Domain != row.Domain || observed.AgentName != row.ObservedBy || !event.Time.Truncate(1000).Equal(row.ObservedAt.UTC().Truncate(1000)) {
		return nil, errors.New("AD CS membership identity differs from its source observation")
	}
	if err := observed.Validate(); err != nil {
		return nil, err
	}
	for _, template := range observed.Templates {
		if template.Name == row.Template {
			source, _ := json.Marshal(template)
			candidate, _ := json.Marshal(projected.Template)
			if !bytes.Equal(source, candidate) {
				return nil, errors.New("AD CS membership differs from its immutable observation; replay the projection")
			}
			return template.EnrollmentMembership, nil
		}
	}
	return nil, errors.New("AD CS membership template is absent from its source observation")
}
