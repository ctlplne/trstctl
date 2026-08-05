// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Proving a backup restores, by restoring it (epic J2).
//
// A verified backup is one whose bytes still match what was recorded. That is
// necessary and it is not the claim an operator needs before an incident, which
// is that the backup RESTORES — that the artifacts, in the shape they are in,
// reproduce a working deployment.
//
// The gap between those is where disaster recovery actually fails: an intact
// artifact of a format the current binary no longer reads, a manifest missing a
// table added three migrations ago, an event log whose restore stops on a gap.
// Every one of those passes verification and fails a restore, and the usual way
// to find out is during the outage.
//
// So a drill restores into an EPHEMERAL target and throws it away. The
// attestation records what actually happened — including when it failed, which
// is the case worth having an attestation for.

// DrillOutcome is the closed set of results.
//
// Closed because this is signed evidence somebody reads under pressure, and each
// value implies a different response. A free-text status would produce prose
// that reads like a verdict and commits to nothing.
type DrillOutcome string

const (
	// DrillRestored: the backup reproduced state into the ephemeral target.
	DrillRestored DrillOutcome = "restored"
	// DrillFailed: the restore was attempted and did not complete. This is the
	// outcome an attestation exists for — a drill nobody ran and a drill that
	// failed look identical without one.
	DrillFailed DrillOutcome = "failed"
	// DrillSkipped: no drill ran. Recorded rather than left absent, so a
	// deployment that never drills cannot be mistaken for one whose drills pass.
	DrillSkipped DrillOutcome = "skipped"
)

// DrillAttestation is the signed record of one restore drill.
type DrillAttestation struct {
	Outcome DrillOutcome `json:"outcome"`
	// StartedAt and CompletedAt bound the attempt.
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	// BackupCreatedAt is when the backup being drilled was taken.
	BackupCreatedAt time.Time `json:"backup_created_at"`
	// RPOSeconds is how much time the restored state would have lost: the age of
	// the backup at the moment the drill ran.
	//
	// Measured from the backup's own manifest rather than configured. A
	// configured RPO is a target; this is the one that was actually achievable
	// with the artifacts on disk, and the two diverge precisely when a backup
	// job has been quietly failing.
	RPOSeconds int64 `json:"rpo_seconds"`
	// RTOSeconds is how long the restore took, wall clock.
	//
	// From an ephemeral target on the machine running the drill, which is not
	// the production restore time — real recovery includes provisioning,
	// networking and people. It is a floor, and the attestation says so rather
	// than letting it be read as a promise.
	RTOSeconds int64 `json:"rto_seconds"`
	// EventsRestored is how many events the restore replayed. Zero on a
	// successful drill is itself a finding: a backup that restores nothing has
	// verified and proved nothing.
	EventsRestored int `json:"events_restored"`
	// Detail explains the outcome in the terms an operator acts on.
	Detail string `json:"detail"`
	// Limitations states what this drill did NOT prove, carried in the
	// attestation itself so it cannot be separated from the claim.
	Limitations []string `json:"limitations"`
}

// ErrNoEphemeralTarget is returned when a drill is asked for with nowhere to
// restore into.
var ErrNoEphemeralTarget = errors.New("backup: a restore drill needs an ephemeral target to restore into")

// RestoreFunc performs the restore into an ephemeral target and reports how many
// events it replayed.
//
// A function rather than a concrete restorer so the drill exercises the SAME
// restore path production recovery uses. A drill with its own simplified restore
// would prove that the simplified one works.
type RestoreFunc func(ctx context.Context) (events int, err error)

// RunDrill restores a backup into an ephemeral target and attests what happened.
//
// It attests a FAILURE as readily as a success. An attestation that only exists
// when the drill passed makes "no attestation" ambiguous between "nobody ran it"
// and "it failed", and those are the two states most worth telling apart.
func RunDrill(ctx context.Context, backupDir string, restore RestoreFunc, now func() time.Time) (DrillAttestation, error) {
	if now == nil {
		now = time.Now
	}
	att := DrillAttestation{
		StartedAt: now().UTC(),
		Limitations: []string{
			"The restore ran into an ephemeral target on the machine performing the drill, so " +
				"the measured RTO is a floor: real recovery also includes provisioning, " +
				"networking, DNS and the people doing it.",
			"A drill proves the artifacts on disk reproduce state. It does not prove the " +
				"deployment they reproduce is correctly configured for your environment.",
		},
	}
	if restore == nil {
		att.Outcome = DrillSkipped
		att.CompletedAt = now().UTC()
		att.Detail = "No ephemeral restore target is configured, so no drill ran. This is recorded " +
			"rather than left absent: a deployment that never drills must not be mistaken for one " +
			"whose drills pass."
		return att, ErrNoEphemeralTarget
	}

	// Verify first. Restoring a backup already known to be corrupt would produce
	// a failed drill whose cause is buried in a restore error, when the manifest
	// could have said so in a sentence.
	report, verifyErr := VerifyFullBackup(backupDir)
	att.BackupCreatedAt = report.CreatedAt
	if verifyErr != nil || !report.Verified {
		att.Outcome = DrillFailed
		att.CompletedAt = now().UTC()
		att.Detail = "The backup did not verify, so no restore was attempted. Its artifacts no " +
			"longer match what was recorded when it was taken, which means a restore would not " +
			"reproduce the state it claims to hold."
		return att, nil
	}
	if !report.CreatedAt.IsZero() {
		att.RPOSeconds = int64(att.StartedAt.Sub(report.CreatedAt).Seconds())
	}

	events, err := restore(ctx)
	att.CompletedAt = now().UTC()
	att.RTOSeconds = int64(att.CompletedAt.Sub(att.StartedAt).Seconds())
	att.EventsRestored = events

	switch {
	case err != nil:
		att.Outcome = DrillFailed
		// The restore error can carry paths and internal detail. The attestation
		// is signed evidence that may travel, so it carries a closed sentence
		// and the operator reads the drill's own logs for the rest.
		att.Detail = "The backup verified and the restore did not complete. The artifacts are " +
			"intact and something about restoring them into a fresh deployment fails — which is " +
			"exactly the failure a drill exists to find before an incident does."
	case events == 0:
		// A restore that replayed nothing "succeeded" and proved nothing. Left
		// as a pass, this is the drill most likely to give false confidence.
		att.Outcome = DrillFailed
		att.Detail = "The restore completed and replayed no events. A backup that restores " +
			"nothing has verified and proved nothing; treat this as a failed drill rather than " +
			"a fast one."
	default:
		att.Outcome = DrillRestored
		att.Detail = fmt.Sprintf("The backup restored into an ephemeral target, replaying %d "+
			"events. The state it holds is %s old.", events, humaniseAge(att.RPOSeconds))
	}
	return att, nil
}

// humaniseAge renders an RPO in words an operator reads rather than seconds.
func humaniseAge(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// Signable returns the canonical bytes an attestation is signed over.
//
// Deterministic JSON of the whole attestation, so the signature covers the
// limitations too. A signature over only the outcome would let the caveats be
// edited off a document whose signature still verified — and the caveats are the
// part somebody quoting this in a compliance pack would most like to lose.
func (a DrillAttestation) Signable() ([]byte, error) {
	return json.Marshal(a)
}
