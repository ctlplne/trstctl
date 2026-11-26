// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Legacy and internally generated events can have no actor. Projection must
// preserve that absence so later credential redemption can fail closed; it must
// not crash a replay or invent an administrator.
func TestActorlessConfigurationReplayKeepsUnknownConfigurer(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Actorless replay"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)
	for _, tc := range []struct {
		name, eventType string
		payload         any
		check           func(*testing.T)
	}{
		{
			name: "notification", eventType: projections.EventNotificationChannelUpserted,
			payload: projections.NotificationChannelUpserted{
				ID: "77777777-7777-4777-8777-777777777771", ChannelType: "webhook",
				Label: "legacy observer", EndpointURL: "https://observer.example.test", Enabled: true,
			},
			check: func(t *testing.T) {
				ch, err := s.GetNotificationChannel(ctx, tenantA, "77777777-7777-4777-8777-777777777771")
				if err != nil || ch.ConfiguredBy != "" || ch.ConfiguredByRef != "" {
					t.Fatalf("actorless notification acquired an authority: %+v err=%v", ch, err)
				}
			},
		},
		{
			name: "ticket", eventType: projections.EventTicketIntakeConfigured,
			payload: projections.TicketIntakeConfigured{
				Name: "legacy", System: "servicenow", InstanceURL: "https://tickets.example.test",
				TokenRef: "secret://legacy", SNTable: "incident", SubjectField: "subject", ProfileField: "profile",
				IntervalSeconds: 60, Enabled: true,
			},
			check: func(t *testing.T) {
				schedule, found, err := s.GetTicketIntakeSchedule(ctx, tenantA, "servicenow", "legacy")
				if err != nil || !found || schedule.ConfiguredBy != "" {
					t.Fatalf("actorless ticket intake acquired an authority: %+v found=%v err=%v", schedule, found, err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("actorless %s event crashed projection: %v", tc.name, p)
				}
			}()
			data, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Apply(ctx, events.Event{
				ID: "actorless-" + tc.name, Type: tc.eventType, TenantID: tenantA,
				Time: time.Now().UTC(), SchemaVersion: 1, Data: data,
			}); err != nil {
				t.Fatal(err)
			}
			tc.check(t)
		})
	}
}
