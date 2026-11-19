// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestConditionalAppendFencesCompetingWritersOnOneSubject(t *testing.T) {
	log := openEmbedded(t)
	ctx := t.Context()
	const tenant = "fixture-tenant"
	const eventType = "fixture.choice"
	position, err := log.ObserveAppendSubject(ctx, tenant, eventType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: "fixture.other"}); err != nil {
		t.Fatal(err)
	}
	const otherTenant = "fixture-other-tenant"
	if _, err := log.AppendAtSubjectPosition(ctx, events.Event{TenantID: otherTenant, Type: eventType}, position); !errors.Is(err, events.ErrAppendPositionChanged) {
		t.Fatalf("another tenant reused the observed position: %v", err)
	}
	first, err := log.AppendAtSubjectPosition(ctx, events.Event{TenantID: tenant, Type: eventType}, position)
	if err != nil || first.Sequence == 0 {
		t.Fatalf("another subject invalidated the observed choice: %v", err)
	}
	if _, err := log.AppendAtSubjectPosition(ctx, events.Event{TenantID: tenant, Type: eventType}, position); !errors.Is(err, events.ErrAppendPositionChanged) {
		t.Fatalf("stale publication authority did not reject the competing event: %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != first.Sequence {
		t.Fatalf("a rejected choice advanced the durable journal: head=%d err=%v", head, err)
	}
	position, err = log.ObserveAppendSubject(ctx, tenant, eventType)
	if err != nil {
		t.Fatal(err)
	}
	// The default pooled route shares a subject for each event type.
	if _, err := log.Append(ctx, events.Event{TenantID: otherTenant, Type: eventType}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.AppendAtSubjectPosition(ctx, events.Event{TenantID: tenant, Type: eventType}, position); !errors.Is(err, events.ErrAppendPositionChanged) {
		t.Fatalf("a pooled writer did not advance the shared broker subject: %v", err)
	}
}
