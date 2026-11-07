// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"errors"
	googleuuid "github.com/google/uuid"
	"time"
)

const ManifestNativeSucceeded = "native_succeeded"
const ManifestNotApplicable = "not_applicable"

// ManifestCursorAdvance records one exact transition. Advancing metadata never
// supplies a native success: that requires the separately signed current-head
// report bound by StepID and ReportDigest.
type ManifestCursorAdvance struct {
	RotationID       string         `json:"rotation_id"`
	IntentDigest     string         `json:"intent_digest"`
	PreviousSourceID string         `json:"previous_source_id"`
	From             ManifestCursor `json:"from"`
	To               ManifestCursor `json:"to"`
	Cause            string         `json:"cause"`
	StepID           string         `json:"step_id,omitempty"`
	ReportDigest     string         `json:"report_digest,omitempty"`
	At               time.Time      `json:"at"`
}

func ManifestCursorAdvanceSourceID(tenantID, rotationID, previousSourceID string) string {
	return googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.manifest-cursor-advance.v1\x00"+tenantID+"\x00"+rotationID+"\x00"+previousSourceID)).String()
}
func (a ManifestCursorAdvance) Validate(intent RotationIntent) error {
	digest, err := intent.Digest()
	if err != nil {
		return err
	}
	if intent.Plan.Version != RotationManifestPlanVersion || intent.Plan.Manifest == nil || a.RotationID != intent.Plan.ID || a.IntentDigest != digest || !canonicalID(a.PreviousSourceID) || a.At.IsZero() || a.At.Before(intent.Plan.CreatedAt) || a.From.Direction != a.To.Direction || a.From.Position.Stage == ManifestComplete {
		return errors.New("service dependents: exact versioned cursor transition authority required")
	}
	if err := a.From.Validate(*intent.Plan.Manifest); err != nil {
		return err
	}
	if err := a.To.Validate(*intent.Plan.Manifest); err != nil {
		return err
	}
	switch a.Cause {
	case ManifestNativeSucceeded:
		if !validRecoveryStepID(a.StepID) || !rotationDigestValid(a.ReportDigest) {
			return errors.New("service dependents: successful native transition needs exact step and report digest")
		}
	case ManifestNotApplicable:
		if a.StepID != "" || a.ReportDigest != "" {
			return errors.New("service dependents: idle transition cannot claim native success")
		}
	default:
		return errors.New("service dependents: unknown cursor transition cause")
	}
	return a.validateCoordinates(*intent.Plan.Manifest)
}

// Coordinate validation is constant-size. Full source-page adjacency, exact
// native eligibility and the current signed report are checked before append
// and by the transactional projection. Readers can trust that immutable record
// while still rejecting a skipped ordinal, stage or in-page position.
func (a ManifestCursorAdvance) validateCoordinates(seal RotationManifestSeal) error {
	from, to := a.From.Position, a.To.Position
	reverse := from.Stage == Stop
	end := from.EntryOrdinal == seal.EntryCount-1
	if reverse {
		end = from.EntryOrdinal == 0
	}
	refuse := errors.New("service dependents: cursor transition skips a native coordinate or global stage")
	if !end {
		delta := int64(1)
		if reverse {
			delta = -1
		}
		if to.Stage != from.Stage || to.EntryOrdinal != from.EntryOrdinal+delta {
			return refuse
		}
		if to.PageNumber == from.PageNumber {
			if int64(to.EntryIndex)-int64(from.EntryIndex) != delta {
				return refuse
			}
		} else if reverse {
			if to.PageNumber >= from.PageNumber {
				return refuse
			}
		} else if to.PageNumber <= from.PageNumber || to.EntryIndex != 0 {
			return refuse
		}
		return nil
	}
	expected := ""
	switch from.Stage {
	case Preflight:
		expected = Stop
	case Stop:
		expected = Update
	case Update:
		expected = Start
	case Start:
		expected = Probe
	case Probe:
		expected = ManifestComplete
	}
	if to.Stage != expected {
		return refuse
	}
	if expected == ManifestComplete {
		return nil
	} // Validate already checked the closed sentinel.
	ordinal := int64(0)
	if expected == Stop {
		ordinal = seal.EntryCount - 1
	}
	if to.EntryOrdinal != ordinal || expected != Stop && to.EntryIndex != 0 {
		return refuse
	}
	return nil
}
