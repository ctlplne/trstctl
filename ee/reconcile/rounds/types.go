// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds

import (
	"context"
	"time"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/eventspec"
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
type DigestSource interface {
	DigestForRound(context.Context, DigestRequest) (digest.SignedDigest, error)
}

type DigestRequest struct {
	RoundID     string
	TenantID    string
	AuthorityID string
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
