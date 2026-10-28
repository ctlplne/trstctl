// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A213: what a CT log answered for a submission and whether the log proved the
// entry is in its tree.
const (
	EventCertificateSCTRecorded  = "ct.sct.recorded"
	EventCertificateSCTInclusion = "ct.inclusion.recorded"
)

// CertificateSCTRecorded is one log's SCT for one submission.
type CertificateSCTRecorded struct {
	SubmissionID         string   `json:"submission_id"`
	LeafFingerprint      string   `json:"leaf_fingerprint"`
	LogURL               string   `json:"log_url"`
	LogID                string   `json:"log_id"`
	EntryType            string   `json:"entry_type"`
	SCTTimestampMillis   uint64   `json:"sct_timestamp_ms"`
	SCTStatus            string   `json:"sct_status"`
	SCTReason            string   `json:"sct_reason,omitempty"`
	LeafHash             string   `json:"leaf_hash,omitempty"`
	LogPublicKey         []byte   `json:"log_public_key,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

// CertificateSCTInclusion is what an inclusion check found.
type CertificateSCTInclusion struct {
	SubmissionID string `json:"submission_id"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	LeafIndex    *int64 `json:"leaf_index,omitempty"`
	TreeSize     *int64 `json:"tree_size,omitempty"`
	RootHash     string `json:"root_hash,omitempty"`
}

// ValidateCertificateSCTRecorded checks an SCT record's closed vocabulary.
func ValidateCertificateSCTRecorded(pl CertificateSCTRecorded) error {
	if !canonicalUUID(pl.SubmissionID) || !lowerSHA256.MatchString(pl.LeafFingerprint) || pl.LogURL == "" ||
		(pl.EntryType != "certificate" && pl.EntryType != "precertificate") || pl.SCTTimestampMillis == 0 {
		return errors.New("an SCT record names its submission, certificate, log, entry type and time")
	}
	switch pl.SCTStatus {
	case store.SCTVerified:
		if !lowerSHA256.MatchString(pl.LeafHash) || len(pl.LogPublicKey) == 0 {
			return errors.New("a verified SCT carries its leaf hash and the log key it verified against")
		}
	case store.SCTInvalid, store.SCTUnverified:
		if pl.SCTReason == "" {
			return errors.New("an SCT that did not verify says why")
		}
	default:
		return errors.New("an SCT record has an unknown status")
	}
	return nil
}

func (p *Projector) applyCertificateSCTTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventCertificateSCTRecorded:
		var pl CertificateSCTRecorded
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateCertificateSCTRecorded(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		inclusion := store.InclusionNotChecked
		if pl.SCTStatus == store.SCTVerified {
			inclusion = store.InclusionPending
		}
		return true, p.store.ApplyCertificateSCTRecordedTx(ctx, tx, store.CertificateSCT{
			TenantID: e.TenantID, SubmissionID: pl.SubmissionID, LeafFingerprint: pl.LeafFingerprint,
			LogURL: pl.LogURL, LogID: pl.LogID, EntryType: pl.EntryType,
			SCTTimestamp: time.UnixMilli(int64(pl.SCTTimestampMillis)).UTC(), // #nosec G115 -- a log timestamp in milliseconds fits int64 (CWE-190)
			SCTStatus:    pl.SCTStatus, SCTReason: pl.SCTReason, LeafHash: pl.LeafHash, LogPublicKey: pl.LogPublicKey,
			AllowPrivateEndpoint: pl.AllowPrivateEndpoint, PrivateEgressCIDRs: pl.PrivateEgressCIDRs,
			InclusionStatus: inclusion, RecordedAt: e.Time, EventSequence: e.Sequence,
		})
	case EventCertificateSCTInclusion:
		var pl CertificateSCTInclusion
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if !canonicalUUID(pl.SubmissionID) {
			return true, fmt.Errorf("projections: %s: an inclusion result names its submission", e.Type)
		}
		switch pl.Status {
		case store.InclusionVerified:
			if pl.LeafIndex == nil || pl.TreeSize == nil || !lowerSHA256.MatchString(pl.RootHash) {
				return true, fmt.Errorf("projections: %s: a proven inclusion names its index, tree size and root", e.Type)
			}
		case store.InclusionNotIncluded, store.InclusionProofBad, store.InclusionNotChecked:
			if pl.Reason == "" {
				return true, fmt.Errorf("projections: %s: an unproven inclusion says why", e.Type)
			}
		default:
			return true, fmt.Errorf("projections: %s: unknown inclusion status", e.Type)
		}
		checked := e.Time
		return true, p.store.ApplyCertificateSCTInclusionTx(ctx, tx, store.CertificateSCT{
			TenantID: e.TenantID, SubmissionID: pl.SubmissionID, InclusionStatus: pl.Status, InclusionReason: pl.Reason,
			LeafIndex: pl.LeafIndex, TreeSize: pl.TreeSize, RootHash: pl.RootHash, InclusionCheckedAt: &checked,
			EventSequence: e.Sequence,
		})
	}
	return false, nil
}
