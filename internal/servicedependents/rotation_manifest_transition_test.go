// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"strings"
	"testing"
)

func TestManifestTransitionCannotSkipCoordinatesEvenBeforePageResolutionA267(t *testing.T) {
	intent, _, r := cursorFixture(t, 4, false)
	from, err := r.Initial(Forward)
	if err != nil {
		t.Fatal(err)
	}
	to, err := r.Advance(from)
	if err != nil {
		t.Fatal(err)
	}
	value := ManifestCursorAdvance{RotationID: intent.Plan.ID, IntentDigest: "", PreviousSourceID: intent.Plan.ID, From: from, To: to, Cause: ManifestNativeSucceeded, StepID: strings.Repeat("a", 32), ReportDigest: strings.Repeat("b", 64), At: intent.Plan.CreatedAt}
	value.IntentDigest, err = intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := value.Validate(intent); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ordinal", "index", "stage", "complete"} {
		altered := value
		switch field {
		case "ordinal":
			altered.To.Position.EntryOrdinal++
		case "index":
			altered.To.Position.EntryIndex++
		case "stage":
			altered.To.Position.Stage = Probe
		case "complete":
			altered.To.Position = ManifestPosition{Stage: ManifestComplete, EntryOrdinal: r.Seal.EntryCount, PageNumber: r.Seal.PageCount}
		}
		if altered.Validate(intent) == nil {
			t.Fatalf("nonlinear %s transition accepted without exact page resolution", field)
		}
	}
}

func TestManifestTransitionCoordinatesKeepEveryGlobalBoundaryA267(t *testing.T) {
	for _, direction := range []string{Forward, Inverse} {
		for _, empty := range []bool{false, true} {
			for width := 1; width <= 4; width++ {
				intent, _, r := cursorFixture(t, width, empty)
				cursor, err := r.Initial(direction)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := intent.Digest()
				if err != nil {
					t.Fatal(err)
				}
				for cursor.Position.Stage != ManifestComplete {
					next, err := r.Advance(cursor)
					if err != nil {
						t.Fatal(err)
					}
					value := ManifestCursorAdvance{RotationID: intent.Plan.ID, IntentDigest: digest, PreviousSourceID: intent.Plan.ID, From: cursor, To: next, Cause: ManifestNativeSucceeded, StepID: strings.Repeat("a", 32), ReportDigest: strings.Repeat("b", 64), At: intent.Plan.CreatedAt}
					if err := value.Validate(intent); err != nil {
						t.Fatalf("legitimate stage/page transition refused: %+v -> %+v: %v", cursor, next, err)
					}
					cursor = next
				}
			}
		}
	}
}
