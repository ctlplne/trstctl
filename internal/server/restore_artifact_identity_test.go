// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/store"
)

func TestRawArtifactCutMustMatchCommittedRestoreMarkerCR045(t *testing.T) {
	summary := backup.EventLogBackupSummary{ArtifactSHA256: "plain-artifact-digest", EventCutSequence: 7}
	marker := store.RestoreMarker{EventHistorySHA256: summary.ArtifactSHA256, EventCut: 8}
	if err := requireVerifiedEventArtifactIdentity(summary, &marker); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("artifact cut from another restore reached broker Open: %v", err)
	}
	marker.EventCut = summary.EventCutSequence
	if err := requireVerifiedEventArtifactIdentity(summary, &marker); err != nil {
		t.Fatalf("exact artifact marker refused: %v", err)
	}
}
