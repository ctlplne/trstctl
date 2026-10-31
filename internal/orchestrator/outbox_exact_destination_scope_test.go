// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "testing"

func TestOutboxExactDestinationScopeDoesNotAdmitPrefixCollisions(t *testing.T) {
	exact := DestinationScope{IncludeDestinations: []string{"eventprivacy.destroy"}}
	if err := exact.validate(); err != nil {
		t.Fatal(err)
	}
	for destination, want := range map[string]bool{"eventprivacy.destroy": true, "eventprivacy.destroy.extra": false, "eventprivacy.destroyed": false, "notification.eventprivacy.destroy": false, "": false} {
		if got := exact.matches(destination); got != want {
			t.Fatalf("exact destination %q match=%v want%v", destination, got, want)
		}
	}
	normal := DestinationScope{ExcludeDestinations: []string{"eventprivacy.destroy"}}
	for destination, want := range map[string]bool{"eventprivacy.destroy": false, "eventprivacy.destroy.extra": true, "connector.deploy": true} {
		if got := normal.matches(destination); got != want {
			t.Fatalf("normal scope %q match=%v want%v", destination, got, want)
		}
	}
	mixed := DestinationScope{IncludePrefixes: []string{"connector."}, IncludeDestinations: []string{"eventprivacy.prepare"}, ExcludeDestinations: []string{"connector.retired"}}
	for destination, want := range map[string]bool{"connector.deploy": true, "connector.retired": false, "eventprivacy.prepare": true, "eventprivacy.prepare.extra": false, "other": false} {
		if got := mixed.matches(destination); got != want {
			t.Fatalf("combined scope %q match=%v want%v", destination, got, want)
		}
	}
}

func TestOutboxExactDestinationScopeRejectsEmptyAndDuplicateCoordinates(t *testing.T) {
	for _, scope := range []DestinationScope{
		{IncludeDestinations: []string{""}},
		{ExcludeDestinations: []string{""}},
		{IncludeDestinations: []string{"eventprivacy.destroy", "eventprivacy.destroy"}},
		{IncludeDestinations: []string{"eventprivacy.destroy"}, ExcludeDestinations: []string{"eventprivacy.destroy"}},
	} {
		if err := scope.validate(); err == nil {
			t.Fatal("empty/duplicate exact scope accepted")
		}
	}
	// Existing prefix behavior stays literal and unchanged.
	literal := DestinationScope{IncludePrefixes: []string{"literal.%_"}}
	if err := literal.validate(); err != nil || !literal.matches("literal.%_suffix") || literal.matches("literal.anything") {
		t.Fatal("scope extension changed existing literal prefix semantics")
	}
}
