// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestEventIngressChecksProjectionSchemaBeforePublish(t *testing.T) {
	published := false
	_, err := restoreEventIngressAdmissionWithCustody(nil, nil)(context.Background(), events.Event{
		ID: "candidate", Type: projections.EventOwnerCreated,
		TenantID: "00000000-0000-4000-8000-0000000000a1", SchemaVersion: 99,
		Data: []byte(`{"id":"00000000-0000-4000-8000-0000000000b1"}`),
	}, func(context.Context) (events.Event, error) {
		published = true
		return events.Event{}, nil
	})
	if !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("unsupported projection schema=%v, want version error", err)
	}
	if published {
		t.Fatal("unsupported projection schema reached publication")
	}
}
