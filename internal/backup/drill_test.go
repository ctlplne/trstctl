// SPDX-License-Identifier: MPL-2.0

package backup_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
)

// A drill attests what happened, including when it failed (epic J2).
//
// The gap a drill closes is between "these bytes are intact" and "these bytes
// restore". An artifact of a format the current binary no longer reads, a
// manifest missing a table added three migrations ago, an event log whose
// restore stops on a gap — every one verifies and fails a restore, and the usual
// way to find out is during the outage.

func drillableBackup(t *testing.T, age time.Duration) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("event data"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := backup.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := backup.NewFullManifest([]backup.Artifact{{
		Name: "events.jsonl", Path: "events.jsonl", SHA256: sum, Bytes: size,
		Exists: true, Captured: true, Required: true,
	}})
	m.CreatedAt = time.Now().UTC().Add(-age)
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestASuccessfulDrillMeasuresRPOAndRTO(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, 3*time.Hour)

	att, err := backup.RunDrill(context.Background(), dir,
		func(context.Context) (int, error) { return 1200, nil }, nil)
	if err != nil {
		t.Fatalf("drill: %v", err)
	}
	if att.Outcome != backup.DrillRestored {
		t.Fatalf("outcome = %q, want restored: %s", att.Outcome, att.Detail)
	}
	// RPO is measured from the backup's OWN manifest, not from a configured
	// target. A configured RPO is an intention; this is what was achievable
	// with the artifacts actually on disk.
	if att.RPOSeconds < int64((3*time.Hour).Seconds())-60 {
		t.Errorf("RPO = %ds, want about 3 hours measured from the backup's timestamp", att.RPOSeconds)
	}
	if att.EventsRestored != 1200 {
		t.Errorf("events restored = %d, want 1200", att.EventsRestored)
	}
	if att.RTOSeconds < 0 {
		t.Error("RTO was not measured")
	}
}

// A FAILED restore still produces an attestation.
//
// The case the attestation exists for. Without one, "no attestation" is
// ambiguous between "nobody ran a drill" and "the drill failed", and those are
// the two states most worth telling apart.
func TestAFailedDrillStillProducesAnAttestation(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, time.Hour)

	att, err := backup.RunDrill(context.Background(), dir,
		func(context.Context) (int, error) { return 0, errors.New("relation does not exist") }, nil)
	if err != nil {
		t.Fatalf("a failed drill returned an error instead of attesting the failure: %v", err)
	}
	if att.Outcome != backup.DrillFailed {
		t.Fatalf("outcome = %q, want failed", att.Outcome)
	}
	if att.Detail == "" {
		t.Error("a failed drill attested nothing an operator can act on")
	}
	// The restore error can carry paths and internal detail; a signed
	// attestation may travel, so it must not echo them.
	if strings.Contains(att.Detail, "relation does not exist") {
		t.Error("the raw restore error was echoed into a signed attestation")
	}
}

// A restore that replays NOTHING is a failed drill, not a fast one.
//
// This is the drill most likely to give false confidence: it completes, returns
// no error, and proves nothing at all.
func TestARestoreThatReplaysNothingIsAFailedDrill(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, time.Hour)

	att, _ := backup.RunDrill(context.Background(), dir,
		func(context.Context) (int, error) { return 0, nil }, nil)
	if att.Outcome != backup.DrillFailed {
		t.Fatalf("a restore replaying zero events was attested as %q. It completed and proved "+
			"nothing, which is the drill most likely to be mistaken for reassurance", att.Outcome)
	}
}

// A backup that does not verify is not restored at all.
//
// Restoring a known-corrupt backup would bury the cause in a restore error when
// the manifest could have said it in a sentence.
func TestACorruptBackupIsNotRestored(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, time.Hour)
	// Same-length tamper: only re-hashing catches it.
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("event dawa"), 0o600); err != nil {
		t.Fatal(err)
	}

	restored := false
	att, _ := backup.RunDrill(context.Background(), dir,
		func(context.Context) (int, error) { restored = true; return 5, nil }, nil)
	if restored {
		t.Error("a backup that failed verification was still restored")
	}
	if att.Outcome != backup.DrillFailed {
		t.Errorf("outcome = %q, want failed", att.Outcome)
	}
}

// No ephemeral target means SKIPPED, recorded rather than absent.
func TestNoEphemeralTargetIsRecordedAsSkipped(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, time.Hour)

	att, err := backup.RunDrill(context.Background(), dir, nil, nil)
	if !errors.Is(err, backup.ErrNoEphemeralTarget) {
		t.Fatalf("err = %v, want ErrNoEphemeralTarget", err)
	}
	if att.Outcome != backup.DrillSkipped {
		t.Fatalf("outcome = %q, want skipped; a deployment that never drills must not be "+
			"mistaken for one whose drills pass", att.Outcome)
	}
}

// The signature covers the limitations, not just the verdict.
//
// A signature over only the outcome would let the caveats be edited off a
// document whose signature still verified — and the caveats are the part
// somebody quoting this in a compliance pack would most like to lose.
func TestTheSignedBytesCoverTheLimitations(t *testing.T) {
	t.Parallel()
	dir := drillableBackup(t, time.Hour)
	att, _ := backup.RunDrill(context.Background(), dir,
		func(context.Context) (int, error) { return 10, nil }, nil)

	if len(att.Limitations) == 0 {
		t.Fatal("a drill attestation carried no limitations; the RTO alone would read as a " +
			"production recovery time")
	}
	signable, err := att.Signable()
	if err != nil {
		t.Fatal(err)
	}
	var round backup.DrillAttestation
	if err := json.Unmarshal(signable, &round); err != nil {
		t.Fatal(err)
	}
	if len(round.Limitations) != len(att.Limitations) {
		t.Error("the signed bytes do not carry the limitations, so they could be removed from a " +
			"document whose signature still verifies")
	}
	// The RTO caveat specifically: this number will be quoted.
	var saysFloor bool
	for _, l := range att.Limitations {
		if strings.Contains(strings.ToLower(l), "floor") {
			saysFloor = true
		}
	}
	if !saysFloor {
		t.Error("the attestation does not say the measured RTO is a floor; it will be read as a " +
			"promise about real recovery time")
	}
}
