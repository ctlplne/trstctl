// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestBrokerIssuanceFromBeforeQ4NamesItsRequesterFromTheEventActorQ4L2: an
// agent broker issuance recorded before Q4 has no requester in its payload.
// Its event's recorded actor names it, marked as derived from that actor; an
// event that recorded no actor leaves it unnamed; an issuance that recorded
// its requester keeps it, whatever actor the event names. A snapshot restore
// and an event-only rebuild reach the same facts.
func TestBrokerIssuanceFromBeforeQ4NamesItsRequesterFromTheEventActorQ4L2(t *testing.T) {
	s, log := newStore(t), openLog(t)
	p := projections.New(s)
	ctx := t.Context()
	base := brokerRecordedFixture()
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Broker requester tenant")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(*base.OwnerID, "agent owner")})
	issuance := func(n, requestedBy string) projections.CertificateRecorded {
		c := base
		c.ID = "00000000-0000-0000-0000-00000000c4" + n + "0"
		c.Fingerprint, c.Serial = "broker-q4l2-fingerprint-"+n, "4"+n
		c.IssuanceIdempotencyKey, c.IssuanceRequestBinding = "broker-issue:q4l2-"+n, strings.Repeat(n, 64)
		facts := *base.BrokerIssuance
		facts.AgentID, facts.RequestedBy = "q4l2-agent-"+n, requestedBy
		c.BrokerIssuance = &facts
		return c
	}
	withActor := func(c projections.CertificateRecorded, subject string) events.Event {
		e := brokerRecordedEvent(t, c)
		if subject != "" {
			e.Actor = &events.Actor{Subject: subject}
		}
		return e
	}
	derived, unnamed, recorded := issuance("1", ""), issuance("2", ""), issuance("3", "eli-platform")
	mustAppend(t, log, withActor(derived, "dana-ops"))
	mustAppend(t, log, withActor(unnamed, ""))
	mustAppend(t, log, withActor(recorded, "someone-else"))
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		t.Helper()
		for _, c := range []struct {
			fixture           projections.CertificateRecorded
			requestedBy, from string
		}{
			{derived, "dana-ops", store.BrokerRequesterFromEventActor},
			{unnamed, "", ""},
			{recorded, "eli-platform", ""},
		} {
			got, err := s.GetCertificate(ctx, tenantA, c.fixture.ID)
			if err != nil || got.BrokerIssuance == nil {
				t.Fatalf("%s: certificate %s: %v", stage, c.fixture.ID, err)
			}
			if got.BrokerIssuance.RequestedBy != c.requestedBy || got.BrokerIssuance.RequestedBySource != c.from {
				t.Fatalf("%s: %s names requester %q from %q, want %q from %q", stage, got.BrokerIssuance.AgentID,
					got.BrokerIssuance.RequestedBy, got.BrokerIssuance.RequestedBySource, c.requestedBy, c.from)
			}
		}
	}
	check("projection")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("event-only rebuild")
}
