// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/backup"
)

// Whether this deployment could actually be restored (epic J2).
//
// Backup was CLI-only: an operator ran a command, read a manifest, and formed a
// private opinion about their disaster-recovery posture. Nothing was served, so
// nothing was monitored, and the first time the opinion was tested was during
// the incident it existed for.
//
// The number that matters here is not "when did a backup last run" — a cron job
// that writes a corrupt file every night runs perfectly. It is "when was a
// backup last VERIFIED", meaning its bytes were re-hashed and matched. This
// surface reports both, separately, because the gap between them is the thing
// worth seeing.

// DRPosture is the served disaster-recovery view.
type DRPosture struct {
	// BackupConfigured reports whether a backup directory is configured at all.
	//
	// False is not an error state to be shown in red — plenty of deployments
	// back up through infrastructure this product does not see — but it must be
	// distinguishable from "configured and failing", which it is not if both
	// render as an absence of good news.
	BackupConfigured bool `json:"backup_configured"`
	// LastBackupAt is when the most recent backup was taken, from its manifest.
	LastBackupAt string `json:"last_backup_at,omitempty"`
	// LastVerifiedAt is when its bytes were last re-hashed and matched. Empty
	// when no verification has run, which is DIFFERENT from a failed one.
	LastVerifiedAt string `json:"last_verified_at,omitempty"`
	// Verified is the verdict of the most recent verification.
	Verified bool `json:"verified"`
	// ArtifactsChecked and ArtifactsUnverifiable say how much of the backup the
	// verdict actually covers. A green verdict over two of eleven artifacts is
	// not the same claim as a green verdict over all eleven, and an operator
	// reading only a boolean cannot tell.
	ArtifactsChecked      int `json:"artifacts_checked"`
	ArtifactsUnverifiable int `json:"artifacts_unverifiable"`
	// Failures name what did not verify, so the page says which artifact rather
	// than only that something is wrong.
	Failures []DRArtifactFailure `json:"failures,omitempty"`
	// LastDrill is the most recent restore drill, if one has run (J2).
	//
	// Nil means no drill has run. That is deliberately distinct from a drill
	// that ran and failed: a deployment that never drills must not be mistaken
	// for one whose drills pass, and an absent field says so where a false
	// boolean would not.
	LastDrill *DRDrill `json:"last_drill,omitempty"`
	// Detail is the operator-facing sentence for the current posture.
	Detail   string `json:"detail"`
	Guidance string `json:"guidance"`
}

// DRDrill is the served summary of a restore drill.
type DRDrill struct {
	// Outcome is restored, failed or skipped.
	Outcome string `json:"outcome"`
	// RanAt is when the drill started.
	RanAt string `json:"ran_at"`
	// RPOSeconds is how old the restored state was — measured from the backup's
	// own manifest, so it is what was achievable rather than what was intended.
	RPOSeconds int64 `json:"rpo_seconds"`
	// RTOSeconds is how long the restore took into an ephemeral target. A
	// FLOOR, not a recovery-time promise, which Limitations states in the
	// attestation itself so the number cannot travel without its caveat.
	RTOSeconds     int64    `json:"rto_seconds"`
	EventsRestored int      `json:"events_restored"`
	Detail         string   `json:"detail"`
	Limitations    []string `json:"limitations"`
}

// DRArtifactFailure is one artifact that did not verify.
type DRArtifactFailure struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
}

const drGuidance = "This page reports when a backup was last VERIFIED, not when one last ran. " +
	"A nightly job that writes a corrupt file runs perfectly, so the useful question is whether " +
	"the bytes on disk still match what was recorded when they were written — which is checked by " +
	"re-hashing them, not by reading the manifest back. An artifact the backup never checksummed " +
	"is reported as unverifiable rather than verified: there is nothing to compare it against."

// drVerifier re-hashes the configured backup directory.
//
// A function rather than a path so a deployment with no backup directory serves
// an honest "not configured" instead of an error, and so tests can drive the
// surface without a filesystem.
type drVerifier func() (backup.VerifyReport, error)

func (a *API) listDRPosture(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := DRPosture{Guidance: drGuidance}
	if a.lastDrill != nil {
		if att := a.lastDrill(); att != nil {
			out.LastDrill = &DRDrill{
				Outcome: string(att.Outcome), RanAt: att.StartedAt.UTC().Format(time.RFC3339),
				RPOSeconds: att.RPOSeconds, RTOSeconds: att.RTOSeconds,
				EventsRestored: att.EventsRestored, Detail: att.Detail,
				Limitations: att.Limitations,
			}
		}
	}
	if a.drVerify == nil {
		out.Detail = "No backup directory is configured for this deployment, so this control " +
			"plane cannot report on backup integrity. That is not the same as having no backups " +
			"— many deployments back up through infrastructure this product does not see."
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	out.BackupConfigured = true

	report, err := a.drVerify()
	if err != nil {
		// A backup directory that cannot be read is a real finding, not a
		// missing feature: something is configured and this control plane
		// cannot see it, which is exactly the state that goes unnoticed until
		// a restore.
		out.Detail = "A backup directory is configured and could not be read, so its integrity " +
			"is unknown. Check the path and the permissions of the process serving this API."
		a.writeJSON(w, http.StatusOK, out)
		return
	}

	if !report.CreatedAt.IsZero() {
		out.LastBackupAt = report.CreatedAt.UTC().Format(time.RFC3339)
	}
	out.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339)
	out.Verified = report.Verified
	out.ArtifactsChecked = len(report.Checks)
	out.ArtifactsUnverifiable = report.Unverifiable
	for _, check := range report.Checks {
		if !check.Verified {
			out.Failures = append(out.Failures, DRArtifactFailure{
				Name: check.Name, Required: check.Required, Detail: check.Detail,
			})
		}
	}
	switch {
	case report.Verified && report.Unverifiable > 0:
		out.Detail = "Every required artifact re-hashed correctly. Some artifacts carry no " +
			"recorded checksum and could not be checked at all, so this verdict covers less " +
			"than the whole backup."
	case report.Verified:
		out.Detail = "Every artifact in this backup was re-hashed and matched what was recorded " +
			"when it was taken."
	default:
		out.Detail = "This backup did not verify. At least one required artifact's bytes no " +
			"longer match what was recorded, which means a restore from it would not reproduce " +
			"the state it claims to hold."
	}
	a.writeJSON(w, http.StatusOK, out)
}

// WithBackupDirectory configures the backup directory this API reports on.
//
// An option rather than a constructor argument so a deployment that does not
// configure one keeps the honest "not configured" posture instead of an
// invented default path that would report a missing directory as a failure.
func WithBackupDirectory(dir string) Option {
	return func(c *config) { c.backupDir = dir }
}

// backupVerifierFor returns a verifier for dir, or nil when none is configured.
//
// Nil rather than a verifier that always errors: "no backup directory is
// configured" and "a configured directory cannot be read" are different facts
// about a deployment, and only the second is something to go and fix.
func backupVerifierFor(dir string) drVerifier {
	if dir == "" {
		return nil
	}
	return func() (backup.VerifyReport, error) { return backup.VerifyFullBackup(dir) }
}

// WithRestoreDrill supplies the most recent restore drill (epic J2).
//
// A function returning nil rather than a value, so a deployment that has never
// drilled serves an absent field instead of a zero-valued one. A DRDrill full of
// zeros renders as "outcome: , RPO 0, RTO 0", which reads like a drill that ran
// instantly and perfectly — the single most misleading thing this page could
// show.
func WithRestoreDrill(fn func() *backup.DrillAttestation) Option {
	return func(c *config) { c.lastDrill = fn }
}
