// SPDX-License-Identifier: BUSL-1.1

package rounds

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
)

const (
	EventTypeRoundInitiated = "xrec.round.initiated"
	EventTypeRoundAgreement = "xrec.round.agreement"
	EventTypeRoundStaleness = "xrec.round.staleness"

	DivergenceClassStaleness = "staleness"

	StalenessReasonStalled   = "watermark_stalled"
	StalenessReasonRegressed = "watermark_regressed"

	SemanticsAgreementAsOfWatermarks = "agreement_as_of_watermarks"
)

// EventAppender is the feature-neutral AN-2 append seam. *events.Log satisfies it
// without this package importing the NATS-backed event log implementation.
type EventAppender interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

// DigestSource supplies an already-signed state digest for one authority in a
// round. Rounds never sign; XREC-02 keeps signing inside the isolated signer.
//
// The observation carries the canonical set and Merkle tree ALONGSIDE the
// signed digest (epic C4): when two digests disagree, the round must hand a
// witness builder the sets those digests committed to. Re-observing at witness
// time would race the authorities — the witness would name a subset the
// compared digests never saw.
type DigestSource interface {
	DigestForRound(context.Context, DigestRequest) (PlaneObservation, error)
}

// PlaneObservation is one authority's contribution to a round: the signed
// digest plus the exact canonical set and tree the digest was built from.
type PlaneObservation struct {
	Digest digest.SignedDigest
	Set    canon.Set
	Tree   *digest.Tree
}

type DigestRequest struct {
	RoundID     string
	TenantID    string
	AuthorityID string
}

// Disagreement is a pair of planes in one round whose signed digests committed
// to different canonical state. The scheduler detects it; the sink turns it
// into a signed witness naming exactly the differing subset (XREC-claim-1).
type Disagreement struct {
	RoundID  string
	TenantID string
	Left     PlaneObservation
	Right    PlaneObservation
}

// DisagreementSink receives digest disagreements the round detected. Rounds
// never sign (XREC-02), so witness building and signing live behind this seam;
// the production sink builds, signs and records the witness and hands it to
// quarantine. A nil sink drops disagreements on the floor — which is exactly
// the pre-C4 defect — so the runtime always supplies one.
type DisagreementSink interface {
	RecordDisagreement(context.Context, Disagreement) error
}

type Config struct {
	TenantID string
	Cadence  time.Duration
	Jitter   time.Duration
	Liveness time.Duration
	Planes   []PlaneConfig
}

type PlaneConfig struct {
	AuthorityID string
	Liveness    time.Duration
}

type Watermark struct {
	Position   string    `json:"position"`
	ObservedAt time.Time `json:"observed_at"`
}

type RoundInitiated struct {
	RoundID        string   `json:"round_id"`
	TenantID       string   `json:"tenant_id"`
	PlaneIDs       []string `json:"plane_ids"`
	InitiatedAt    string   `json:"initiated_at"`
	CadenceSeconds int64    `json:"cadence_seconds"`
}

type DigestRef struct {
	AuthorityID       string    `json:"authority_id"`
	DigestHash        string    `json:"digest_hash"`
	WatermarkPosition string    `json:"watermark_position"`
	WatermarkTime     time.Time `json:"watermark_time"`
}

type RoundAgreement struct {
	RoundID    string      `json:"round_id"`
	TenantID   string      `json:"tenant_id"`
	Digests    []DigestRef `json:"digests"`
	Semantics  string      `json:"semantics"`
	RecordedAt string      `json:"recorded_at"`
}

type StalenessDivergence struct {
	RoundID         string    `json:"round_id"`
	TenantID        string    `json:"tenant_id"`
	AuthorityID     string    `json:"authority_id"`
	DivergenceClass string    `json:"divergence_class"`
	Reason          string    `json:"reason"`
	Watermark       Watermark `json:"watermark"`
	Previous        string    `json:"previous_position,omitempty"`
	RecordedAt      string    `json:"recorded_at"`
}

type Divergence struct {
	AuthorityID string
	Class       string
	Reason      string
	Watermark   Watermark
	Err         error
}

type RoundResult struct {
	RoundID     string
	Agreed      bool
	Digests     []DigestRef
	Divergences []Divergence
}
