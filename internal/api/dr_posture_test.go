// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
)

// The DR page must distinguish three states (epic J2).
//
// "No backup directory is configured", "one is configured and cannot be read",
// and "one was read and did not verify" are three different facts about a
// deployment, and only the last two are something to go and fix. A page that
// renders them all as an absence of good news teaches an operator to ignore it.

func TestAnUnconfiguredBackupIsNotReportedAsAFailure(t *testing.T) {
	t.Parallel()
	a := &API{}
	out := drPostureFor(a)
	if out.BackupConfigured {
		t.Error("a deployment with no backup directory reported one as configured")
	}
	if out.Verified {
		t.Error("an unconfigured deployment reported a verified backup")
	}
	if out.Detail == "" {
		t.Fatal("no explanation was given for an unconfigured deployment")
	}
	// It must not read as a fault: plenty of deployments back up through
	// infrastructure this product does not see.
	if out.Failures != nil {
		t.Errorf("an unconfigured deployment reported failures: %+v", out.Failures)
	}
}

func TestAnUnreadableBackupDirectoryIsAFindingRatherThanAnAbsence(t *testing.T) {
	t.Parallel()
	a := &API{drVerify: func() (backup.VerifyReport, error) {
		return backup.VerifyReport{}, errors.New("permission denied")
	}}
	out := drPostureFor(a)
	if !out.BackupConfigured {
		t.Error("a configured-but-unreadable directory reported as unconfigured; that is the " +
			"state that goes unnoticed until a restore")
	}
	if out.Verified {
		t.Error("an unreadable backup reported as verified")
	}
}

// A green verdict must say how much of the backup it covers.
//
// "Verified" over two of eleven artifacts is not the same claim as "verified"
// over all eleven, and an operator reading only a boolean cannot tell them
// apart.
func TestAGreenVerdictStatesItsCoverage(t *testing.T) {
	t.Parallel()
	a := &API{drVerify: func() (backup.VerifyReport, error) {
		return backup.VerifyReport{
			CreatedAt: time.Now().Add(-time.Hour), Verified: true, Unverifiable: 3,
			Checks: []backup.ArtifactCheck{
				{Name: "events", Verified: true, Required: true},
				{Name: "config", Verified: true},
			},
		}, nil
	}}
	out := drPostureFor(a)
	if !out.Verified {
		t.Fatal("a verified report was not served as verified")
	}
	if out.ArtifactsUnverifiable != 3 {
		t.Errorf("unverifiable = %d, want 3", out.ArtifactsUnverifiable)
	}
	// The sentence must admit the verdict is partial rather than reading as
	// unqualified reassurance.
	if out.Detail == "" || out.ArtifactsChecked != 2 {
		t.Errorf("posture did not state its coverage: checked=%d detail=%q",
			out.ArtifactsChecked, out.Detail)
	}
}

// A failed verification names which artifact.
func TestAFailedVerificationNamesTheArtifact(t *testing.T) {
	t.Parallel()
	a := &API{drVerify: func() (backup.VerifyReport, error) {
		return backup.VerifyReport{
			Verified: false,
			Checks: []backup.ArtifactCheck{
				{Name: "events.jsonl", Verified: false, Required: true,
					Detail: "the bytes on disk do not match the checksum recorded"},
				{Name: "config", Verified: true},
			},
		}, nil
	}}
	out := drPostureFor(a)
	if out.Verified {
		t.Fatal("a failed verification served as verified")
	}
	if len(out.Failures) != 1 || out.Failures[0].Name != "events.jsonl" {
		t.Fatalf("failures = %+v; the page must name which artifact rather than only that "+
			"something is wrong", out.Failures)
	}
	if !out.Failures[0].Required {
		t.Error("a required artifact's failure was not marked required; an operator cannot tell " +
			"whether this backup would still restore")
	}
}

// "Last verified" must not be reported from a backup that merely exists.
//
// The whole point of this surface is that a nightly job writing a corrupt file
// runs perfectly. Reporting its timestamp as a verification would restore
// exactly the false confidence the page exists to remove.
func TestLastVerifiedIsOnlySetWhenVerificationRan(t *testing.T) {
	t.Parallel()
	unconfigured := drPostureFor(&API{})
	if unconfigured.LastVerifiedAt != "" {
		t.Error("a deployment that never verified reported a verification time")
	}
	unreadable := drPostureFor(&API{drVerify: func() (backup.VerifyReport, error) {
		return backup.VerifyReport{}, errors.New("unreadable")
	}})
	if unreadable.LastVerifiedAt != "" {
		t.Error("a backup that could not be read reported a verification time")
	}
}

// drPostureFor drives the REAL handler and decodes what it served.
//
// Not a reimplementation of the assembly logic. A helper that rebuilt the
// posture would be testing a copy of the code — it would pass while the served
// handler did something else entirely, which is the failure this whole session
// keeps finding in other people's tests and would be no better in mine.
func drPostureFor(a *API) DRPosture {
	a.tenantFn = func(*http.Request) (string, error) { return "11111111-1111-1111-1111-111111111111", nil }
	rec := httptest.NewRecorder()
	a.listDRPosture(rec, httptest.NewRequest(http.MethodGet, "/api/v1/platform/dr-posture", nil))
	var out DRPosture
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// A deployment that has NEVER drilled must not look like one that drills
// perfectly (epic J2).
//
// A zero-valued DRDrill renders as "outcome: , RPO 0, RTO 0" — a drill that ran
// instantly and recovered everything. It is the single most misleading thing
// this page could show, and it is what a struct field rather than a pointer
// would produce on every deployment that has never run one.
func TestADeploymentThatNeverDrilledShowsNoDrillRatherThanAPerfectOne(t *testing.T) {
	t.Parallel()
	out := drPostureFor(&API{})
	if out.LastDrill != nil {
		t.Fatalf("a deployment that never drilled served a drill: %+v. Zeros render as an "+
			"instant, complete recovery", out.LastDrill)
	}
}

// A failed drill is served as failed, with its limitations intact.
func TestAFailedDrillIsServedWithItsLimitations(t *testing.T) {
	t.Parallel()
	att := &backup.DrillAttestation{
		Outcome: backup.DrillFailed, StartedAt: time.Now().UTC(),
		RPOSeconds: 3600, Detail: "the restore did not complete",
		Limitations: []string{"the measured RTO is a floor"},
	}
	out := drPostureFor(&API{lastDrill: func() *backup.DrillAttestation { return att }})
	if out.LastDrill == nil {
		t.Fatal("a failed drill was not served at all; absent reads as never-drilled")
	}
	if out.LastDrill.Outcome != string(backup.DrillFailed) {
		t.Errorf("outcome = %q, want failed", out.LastDrill.Outcome)
	}
	if len(out.LastDrill.Limitations) == 0 {
		t.Error("the drill's limitations were dropped on the way to the console; the RTO would " +
			"then be read as a production recovery time")
	}
}
