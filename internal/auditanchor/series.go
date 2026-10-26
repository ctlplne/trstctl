// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/tsa"
)

// Continuous anchoring at a known cadence (A147).
//
// One anchor taken when an export is made proves the export's head is no newer
// than its timestamp, and no more: a record withheld and slipped into the chain
// before that moment is indistinguishable from one written on time. Anchors
// over the tenant's FULL chain, taken on a schedule whenever the chain has
// grown and appended to the tenant's own audit log, close most of that gap.
// Every anchor is itself an audit record, so a later anchor covers the earlier
// ones. Two rules then follow from the records alone:
//
//   - a record that enters the chain after an anchor that did not include it,
//     but claims a time before that anchor, was withheld or back-dated;
//   - every record is covered by an anchor no later than one cadence after its
//     time — the first anchor whose head includes it, or, for the newest
//     records, the export's own anchor.
//
// What remains is a record withheld for less than one cadence plus the clock
// tolerance, which this check states rather than hides. An idle tenant is not
// anchored, and needs no anchor: a quiet stretch has no records to cover.

const (
	// EventTypeAnchored is appended to a tenant's audit log each time the
	// tenant's full audit chain is timestamped on the configured cadence.
	EventTypeAnchored = "audit.anchored"
	// AnchoredEventSchemaVersion is the payload version of EventTypeAnchored.
	AnchoredEventSchemaVersion = 1
	// DefaultSeriesSkew tolerates clock differences between the replicas that
	// wrote records and the timestamp authority.
	DefaultSeriesSkew = 5 * time.Minute
)

// AnchoredEvent is the payload of EventTypeAnchored: the timestamp over the
// tenant's full chain through ThroughSequence, and the cadence the deployment
// anchors at. The anchor's own record always comes after ThroughSequence.
type AnchoredEvent struct {
	ThroughSequence uint64 `json:"through_sequence"`
	CadenceSeconds  int64  `json:"cadence_seconds"`
	Anchor          Anchor `json:"anchor"`
}

// SeriesPolicy is the auditor's expectation of the anchor series. The zero
// Cadence verifies every anchor present and the order of records around them
// without requiring anchors at any particular rate.
type SeriesPolicy struct {
	// Cadence is the longest the auditor accepts between a record's time and
	// the first anchor that covers it.
	Cadence time.Duration
	// Skew tolerates clock differences; zero means DefaultSeriesSkew.
	Skew time.Duration
}

// SeriesResult reports what the verifier established about the anchor series
// inside one export.
type SeriesResult struct {
	// Applicable is false when the export is not one unbroken run of the
	// tenant's records; anchors over the full chain cannot be re-checked in it.
	Applicable bool   `json:"applicable"`
	Reason     string `json:"reason,omitempty"`
	// Anchors counts anchor records in the export; every one carried a
	// timestamp that verified against the pinned TSA root.
	Anchors int `json:"anchors"`
	// Verified anchors attest a head the export's own chain reproduces.
	Verified int `json:"verified"`
	// BeforeWindow anchors cover only records before this export's first
	// record, so their head cannot be re-checked here.
	BeforeWindow int `json:"before_window"`
	// SupersededByErasure anchors attest a head that a later subject erasure,
	// recorded in this export, changed.
	SupersededByErasure int       `json:"superseded_by_erasure"`
	FirstAnchoredAt     time.Time `json:"first_anchored_at,omitempty"`
	LastAnchoredAt      time.Time `json:"last_anchored_at,omitempty"`
	// LongestCoverageSeconds is the longest any record in the export waited
	// for the anchor that covers it (zero when none is covered).
	LongestCoverageSeconds int64 `json:"longest_coverage_seconds"`
	// CadenceSeconds is the cadence the series was held to, or zero when none
	// was enforced.
	CadenceSeconds int64 `json:"cadence_seconds"`
	SkewSeconds    int64 `json:"skew_seconds"`

	// tokens are the verified anchors' timestamps, whose TSA certificates the
	// revocation check covers.
	tokens []tsa.Token
}

type seriesAnchor struct {
	record  auditchain.Record
	payload AnchoredEvent
	at      time.Time
}

// VerifySeries checks every anchor record in records — an export continuing
// the chain head prevHash, carrying full-chain hashes when fullChain
// (audit.FullChain), whose own anchor (if any) is dated exportAnchoredAt —
// against the separately pinned TSA root, and then the order of records
// around those anchors under policy. It fails on a forged or mismatched anchor,
// on a record that entered the chain after an anchor that did not include it
// while claiming an earlier time, and, when the policy names a cadence, on a
// record that waited longer than the cadence for an anchor to cover it.
func VerifySeries(records []auditchain.Record, prevHash string, fullChain bool, exportAnchoredAt time.Time, tsaRootDER []byte, policy SeriesPolicy) (SeriesResult, error) {
	skew := policy.Skew
	if skew <= 0 {
		skew = DefaultSeriesSkew
	}
	result := SeriesResult{CadenceSeconds: int64(policy.Cadence / time.Second), SkewSeconds: int64(skew / time.Second)}
	if len(records) == 0 {
		result.Reason = "the export has no records"
		return result, nil
	}
	if !fullChain || !audit.Contiguous(records) {
		result.Reason = "the export is not an unbroken run of the tenant's records selected without a content filter, so it is a chain of its own and anchors over the tenant's full chain cannot be re-checked in it"
		if policy.Cadence > 0 {
			return result, errors.New("auditanchor: an anchor cadence was requested, but " + result.Reason)
		}
		return result, nil
	}
	if len(tsaRootDER) == 0 {
		return result, errors.New("auditanchor: verifying the anchor series requires a separately pinned TSA root certificate")
	}
	result.Applicable = true
	anchors, err := verifyAnchorRecords(records, prevHash, tsaRootDER, skew, &result)
	if err != nil {
		return result, err
	}
	result.Anchors = len(anchors)
	for _, anchor := range anchors {
		result.tokens = append(result.tokens, *anchor.payload.Anchor.Token)
	}
	for i, anchor := range anchors {
		if i == 0 || anchor.at.Before(result.FirstAnchoredAt) {
			result.FirstAnchoredAt = anchor.at
		}
		if anchor.at.After(result.LastAnchoredAt) {
			result.LastAnchoredAt = anchor.at
		}
	}

	byCoverage := append([]seriesAnchor(nil), anchors...)
	sort.SliceStable(byCoverage, func(i, j int) bool {
		return byCoverage[i].payload.ThroughSequence < byCoverage[j].payload.ThroughSequence
	})
	// A record that entered the chain after an anchor that did not include it
	// cannot be older than that anchor: it was withheld or back-dated.
	var latestBefore time.Time
	next := 0
	for _, record := range records {
		for next < len(byCoverage) && byCoverage[next].payload.ThroughSequence < record.Sequence {
			if byCoverage[next].at.After(latestBefore) {
				latestBefore = byCoverage[next].at
			}
			next++
		}
		if !latestBefore.IsZero() && record.Time.Before(latestBefore.Add(-skew)) {
			return result, fmt.Errorf("auditanchor: record %d is dated %s but entered the chain after an anchor taken at %s that did not include it; "+
				"it was withheld or back-dated", record.Sequence, record.Time.UTC().Format(time.RFC3339), latestBefore.Format(time.RFC3339))
		}
	}

	// Every record waits at most one cadence for the anchor that covers it: the
	// first anchor whose head includes it or, past the last one, the export's
	// own anchor. Anchor records carry their own timestamp and are not held to
	// it.
	covering := 0
	for _, record := range records {
		for covering < len(byCoverage) && byCoverage[covering].payload.ThroughSequence < record.Sequence {
			covering++
		}
		if record.Type == EventTypeAnchored {
			continue
		}
		var coveredAt time.Time
		switch {
		case covering < len(byCoverage):
			coveredAt = byCoverage[covering].at
		case !exportAnchoredAt.IsZero():
			coveredAt = exportAnchoredAt.UTC()
		default:
			if policy.Cadence > 0 {
				return result, fmt.Errorf("auditanchor: record %d has no anchor covering it in this export, and the export itself is unanchored", record.Sequence)
			}
			continue
		}
		wait := coveredAt.Sub(record.Time)
		if seconds := int64(wait / time.Second); seconds > result.LongestCoverageSeconds {
			result.LongestCoverageSeconds = seconds
		}
		if policy.Cadence > 0 && wait > policy.Cadence+skew {
			if covering < len(byCoverage) && covering == 0 {
				return result, fmt.Errorf("auditanchor: record %d from %s was first anchored at %s, later than the required cadence; "+
					"if anchoring began after that record, verify a window that starts after the first anchor",
					record.Sequence, record.Time.UTC().Format(time.RFC3339), coveredAt.Format(time.RFC3339))
			}
			if covering >= len(byCoverage) {
				return result, fmt.Errorf("auditanchor: record %d from %s has no anchor in this export, and the export was anchored at %s, later than the required cadence; "+
					"anchoring stopped, or the anchor that covers it lies after this window", record.Sequence, record.Time.UTC().Format(time.RFC3339), coveredAt.Format(time.RFC3339))
			}
			return result, fmt.Errorf("auditanchor: record %d from %s waited until %s for an anchor, longer than the required cadence",
				record.Sequence, record.Time.UTC().Format(time.RFC3339), coveredAt.Format(time.RFC3339))
		}
	}
	result.CadenceSeconds = int64(policy.Cadence / time.Second)
	return result, nil
}

// verifyAnchorRecords verifies every anchor record's timestamp and, where the
// export holds the covered position, the head it attests.
func verifyAnchorRecords(records []auditchain.Record, prevHash string, tsaRootDER []byte, skew time.Duration, result *SeriesResult) ([]seriesAnchor, error) {
	first, last := records[0].Sequence, records[len(records)-1].Sequence
	headAt := func(sequence uint64) (string, bool) {
		switch {
		case sequence+1 == first:
			return prevHash, true
		case sequence >= first && sequence <= last:
			return records[sequence-first].Hash, true
		default:
			return "", false
		}
	}
	var erasures []uint64
	for _, record := range records {
		if record.Type == eventledger.EventPrivacySubjectErased {
			erasures = append(erasures, record.Sequence)
		}
	}
	var anchors []seriesAnchor
	for _, record := range records {
		if record.Type != EventTypeAnchored {
			continue
		}
		var payload AnchoredEvent
		if err := decodeExactJSON(record.Data, &payload); err != nil {
			return nil, fmt.Errorf("auditanchor: anchor record %d is malformed: %w", record.Sequence, err)
		}
		if payload.ThroughSequence >= record.Sequence {
			return nil, fmt.Errorf("auditanchor: anchor record %d claims to cover record %d, which is not before it", record.Sequence, payload.ThroughSequence)
		}
		if payload.Anchor.Kind != KindRFC3161 || payload.Anchor.Token == nil || payload.Anchor.ChainHead == "" {
			return nil, fmt.Errorf("auditanchor: anchor record %d carries no timestamp", record.Sequence)
		}
		// The token is verified over the head it names; whether this export's
		// chain reproduces that head is the separate question below.
		if err := Verify(payload.Anchor, payload.Anchor.ChainHead, tsaRootDER); err != nil {
			return nil, fmt.Errorf("auditanchor: anchor record %d: %w", record.Sequence, err)
		}
		at := payload.Anchor.Token.Info.GenTime.UTC()
		if record.Time.Before(at.Add(-skew)) {
			return nil, fmt.Errorf("auditanchor: anchor record %d is dated %s, before the timestamp it records (%s)",
				record.Sequence, record.Time.UTC().Format(time.RFC3339), at.Format(time.RFC3339))
		}
		head, inWindow := headAt(payload.ThroughSequence)
		switch {
		case !inWindow:
			result.BeforeWindow++
		case head == payload.Anchor.ChainHead:
			result.Verified++
			if covered := payload.ThroughSequence; covered >= first {
				if newest := records[covered-first].Time; newest.After(at.Add(skew)) {
					return nil, fmt.Errorf("auditanchor: anchor record %d timestamps a head at %s that includes record %d from %s",
						record.Sequence, at.Format(time.RFC3339), covered, newest.UTC().Format(time.RFC3339))
				}
			}
		case erasedLater(erasures, payload.ThroughSequence):
			result.SupersededByErasure++
		default:
			return nil, fmt.Errorf("auditanchor: anchor record %d attests chain head %s through record %d, but this export's chain there is %s; "+
				"records at or before %d were changed after they were timestamped",
				record.Sequence, short(payload.Anchor.ChainHead), payload.ThroughSequence, short(head), payload.ThroughSequence)
		}
		anchors = append(anchors, seriesAnchor{record: record, payload: payload, at: at})
	}
	return anchors, nil
}

// erasedLater reports whether a subject erasure recorded after the covered
// record could have changed the redacted records an anchor timestamped.
func erasedLater(erasures []uint64, covered uint64) bool {
	for _, sequence := range erasures {
		if sequence > covered {
			return true
		}
	}
	return false
}
