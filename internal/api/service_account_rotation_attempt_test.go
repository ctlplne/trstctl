// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestManifestAttemptReusesOnlyExactPublicAuthorityWithinOneWorkerCallA267(t *testing.T) {
	position := servicedependents.ManifestCursor{Direction: servicedependents.Forward, Position: servicedependents.ManifestPosition{Stage: servicedependents.Preflight}}
	parent := store.ServiceDependentRotation{TenantID: "owned-tenant", ID: "owned-root", IntentDigest: "owned-digest", ManifestCursor: &position, ManifestCursorSourceID: "owned-source", ManifestCursorSequence: 1, Direction: servicedependents.Forward}
	ctx := withDependentManifestAttempt(context.Background())
	reads := 0
	reader := func() (servicedependents.RotationManifestResolver, *events.Event, error) {
		reads++
		return servicedependents.RotationManifestResolver{}, nil, nil
	}
	for i := 0; i < 3; i++ {
		if _, _, err := resolveDependentManifestAttempt(ctx, parent, reader); err != nil {
			t.Fatal(err)
		}
	}
	if reads != 1 {
		t.Fatalf("one immutable authority was reread %d times inside one attempt", reads)
	}
	for _, field := range []string{"position", "source", "sequence", "tenant", "digest", "direction"} {
		changed := parent
		copy := position
		changed.ManifestCursor = &copy
		switch field {
		case "position":
			copy.Position.EntryOrdinal++
		case "source":
			changed.ManifestCursorSourceID = "next-source"
		case "sequence":
			changed.ManifestCursorSequence++
		case "tenant":
			changed.TenantID = "another-tenant"
		case "digest":
			changed.IntentDigest = "another-digest"
		case "direction":
			changed.Direction = servicedependents.Inverse
		}
		before := reads
		if _, _, err := resolveDependentManifestAttempt(ctx, changed, reader); err != nil {
			t.Fatal(err)
		}
		if reads != before+1 {
			t.Fatal("changed authority reused a prior source proof", field)
		}
	}
	before := reads
	fresh := withDependentManifestAttempt(context.Background())
	if _, _, err := resolveDependentManifestAttempt(fresh, parent, reader); err != nil {
		t.Fatal(err)
	}
	if reads != before+1 {
		t.Fatal("a new native worker call borrowed stale authority")
	}
	// A failed read for changed authority also invalidates the earlier proof;
	// restoring an old SQL pointer inside this call must read its source again.
	changed := parent
	changed.ManifestCursorSourceID = "unavailable-new-source"
	failureBefore := reads
	if _, _, err := resolveDependentManifestAttempt(fresh, changed, func() (servicedependents.RotationManifestResolver, *events.Event, error) {
		return servicedependents.RotationManifestResolver{}, nil, errors.New("owned changed source unavailable")
	}); err == nil {
		t.Fatal("changed source unexpectedly succeeded")
	}
	if _, _, err := resolveDependentManifestAttempt(fresh, parent, reader); err != nil {
		t.Fatal(err)
	}
	if reads != failureBefore+1 {
		t.Fatal("restored old pointer resurrected a proof after a failed changed-source read")
	}
	failed := withDependentManifestAttempt(context.Background())
	failure := errors.New("owned unavailable source")
	calls := 0
	for i := 0; i < 2; i++ {
		_, _, err := resolveDependentManifestAttempt(failed, parent, func() (servicedependents.RotationManifestResolver, *events.Event, error) {
			calls++
			return servicedependents.RotationManifestResolver{}, nil, failure
		})
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("a failed source read became a cached success")
	}
}
