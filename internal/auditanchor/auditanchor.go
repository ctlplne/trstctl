// SPDX-License-Identifier: MPL-2.0

// Package auditanchor binds an audit chain head to an external time source
// (epic J1).
//
// The hash chain in internal/auditchain is tamper-EVIDENT: change a record and
// every subsequent hash changes, so a verifier holding the head can tell. What
// it cannot tell you is WHEN the head came to exist, and that gap is the one an
// insider uses. Someone with write access to the audit store does not edit a
// record in place — that is detectable. They rebuild the chain from an earlier
// point with the record removed and publish the new head as though it had always
// been so. Every hash is internally consistent. The chain verifies. The evidence
// is gone.
//
// An anchor closes it by making a statement a rebuilt chain cannot reproduce:
// this head existed at this time, attested by a party that was not the audit
// store. The RFC 3161 timestamp is over the head hash, so a chain rebuilt today
// yields a different head, for which no earlier token exists. The attacker's
// options narrow to forging the TSA's signature or persuading it to back-date —
// both outside the audit store entirely, which is the whole point of anchoring
// to something else.
//
// SCOPE, stated plainly: an anchor proves the head is no NEWER than the
// timestamp. It cannot prove the chain was complete at that moment — a record
// withheld before anchoring was never in the chain to begin with. Detecting that
// needs a different control (continuous anchoring at a known cadence, so a gap
// in the anchor series is itself evidence), and this package does not claim it.
package auditanchor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tsa"
)

// Kind names the external authority an anchor was obtained from.
//
// A closed set. An anchor whose kind a verifier does not recognize must be
// treated as unverified rather than as trusted-by-default, so the vocabulary is
// small and every value has a verifier in this package.
type Kind string

const (
	// KindRFC3161 is an in-tree TSA timestamp token over the chain head.
	KindRFC3161 Kind = "rfc3161"
	// KindNone means no anchor was obtained. It is NOT a synonym for "the
	// export is fine": it says the head rests on the audit store's own word
	// about time, which is exactly the claim anchoring exists to replace.
	KindNone Kind = ""
)

// Anchor is an external attestation that a chain head existed at a point in time.
type Anchor struct {
	Kind Kind `json:"kind"`
	// ChainHead is the head this anchor covers. Carried explicitly so a
	// verifier never has to infer which head a token belongs to — an anchor
	// silently checked against the wrong head is worse than no anchor.
	ChainHead string `json:"chain_head"`
	// AnchoredAt is the authority's asserted time, not this process's clock.
	AnchoredAt time.Time `json:"anchored_at"`
	// Token is the RFC 3161 TimeStampToken.
	Token *tsa.Token `json:"token,omitempty"`
	// Detail explains an absent anchor in words an operator can act on.
	Detail string `json:"detail,omitempty"`
}

// Timestamper is the subset of the TSA this package needs.
type Timestamper interface {
	Timestamp(ctx context.Context, hashedMessage []byte) (tsa.Token, error)
}

// ErrNoTimestamper is returned when anchoring is requested and unconfigured.
var ErrNoTimestamper = errors.New("auditanchor: no timestamp authority is configured")

// headImprint is the message imprint an anchor is taken over.
//
// The head is already a SHA-256 hex digest, but it is hashed AGAIN rather than
// hex-decoded and passed through. The reason is domain separation: a raw digest
// handed to a timestamper could equally be the digest of a document, and a token
// obtained for one purpose would verify for the other. Hashing the head together
// with a fixed label means an audit anchor can only ever be read as an audit
// anchor.
func headImprint(chainHead string) []byte {
	return crypto.SHA256Sum([]byte("trstctl/auditchain/v1\x00" + chainHead))
}

// Anchor obtains an external timestamp over a chain head.
func AnchorHead(ctx context.Context, ts Timestamper, chainHead string) (Anchor, error) {
	if chainHead == "" {
		// An empty head means an empty chain. There is nothing to attest, and a
		// token over "" would be a true statement about nothing that later reads
		// as evidence about something.
		return Anchor{Kind: KindNone, Detail: "the chain is empty, so there is no head to anchor"}, nil
	}
	if ts == nil {
		return Anchor{Kind: KindNone, ChainHead: chainHead,
			Detail: "no timestamp authority is configured, so this head rests on this system's " +
				"own record of when it was written"}, ErrNoTimestamper
	}
	tok, err := ts.Timestamp(ctx, headImprint(chainHead))
	if err != nil {
		return Anchor{Kind: KindNone, ChainHead: chainHead,
				Detail: "the timestamp authority did not answer, so this export is unanchored"},
			fmt.Errorf("auditanchor: timestamp chain head: %w", err)
	}
	return Anchor{
		Kind: KindRFC3161, ChainHead: chainHead,
		AnchoredAt: tok.Info.GenTime.UTC(), Token: &tok,
	}, nil
}

// Verify checks an anchor against the head an auditor actually holds.
//
// The head parameter is what the auditor recomputed from the records in front of
// them, NOT the head recorded in the anchor. That distinction is the entire
// value of the function: passing anchor.ChainHead here would compare the anchor
// to itself and pass for any bundle whose records had been rewritten.
func Verify(anchor Anchor, recomputedHead string, tsaRootDER []byte) error {
	switch anchor.Kind {
	case KindNone:
		return errors.New("auditanchor: this bundle carries no external anchor, so nothing " +
			"attests when its chain head came to exist")
	case KindRFC3161:
	default:
		return fmt.Errorf("auditanchor: unrecognized anchor kind %q; treat this bundle as unanchored", anchor.Kind)
	}
	if anchor.Token == nil {
		return errors.New("auditanchor: the anchor names a timestamp but carries no token")
	}
	if anchor.ChainHead != recomputedHead {
		// The records were changed after anchoring. This is the tamper case, and
		// it reads as one.
		return fmt.Errorf("auditanchor: the records in this bundle hash to %s, but the anchor "+
			"attests %s; the records have been altered since they were timestamped",
			short(recomputedHead), short(anchor.ChainHead))
	}
	if err := tsa.Verify(*anchor.Token, headImprint(recomputedHead), tsaRootDER); err != nil {
		return fmt.Errorf("auditanchor: the timestamp does not attest this chain head: %w", err)
	}
	return nil
}

// VerifyNotBackdated additionally rejects an anchor whose asserted time is later
// than the export claims to cover.
//
// This is the back-dating case, and it is the subtler of the two. A rebuilt
// chain cannot produce an OLD token for a NEW head — but nothing stops someone
// producing a NEW token and presenting the bundle as historical. Comparing the
// authority's time against the newest record the bundle contains catches it: a
// bundle whose latest record predates its own timestamp by an implausible margin
// was assembled long after the events it describes.
//
// The tolerance is the caller's, because "implausible" is a policy question — an
// export run nightly and one run during an incident have very different normal
// gaps.
func VerifyNotBackdated(anchor Anchor, newestRecord time.Time, tolerance time.Duration) error {
	if anchor.Kind == KindNone || anchor.Token == nil {
		return errors.New("auditanchor: an unanchored bundle cannot be checked for back-dating")
	}
	stamped := anchor.Token.Info.GenTime.UTC()
	if newestRecord.IsZero() {
		return nil
	}
	if stamped.Before(newestRecord.UTC()) {
		// The token predates a record it supposedly covers, which is
		// impossible for an honest chain: the head could not have existed
		// before the last record that went into it.
		return fmt.Errorf("auditanchor: the anchor is dated %s but the bundle contains a record "+
			"from %s; a head cannot be timestamped before the records it covers",
			stamped.Format(time.RFC3339), newestRecord.UTC().Format(time.RFC3339))
	}
	if tolerance > 0 && stamped.Sub(newestRecord.UTC()) > tolerance {
		return fmt.Errorf("auditanchor: the anchor is dated %s, %s after the newest record it "+
			"covers; this bundle was assembled long after the events it describes",
			stamped.Format(time.RFC3339), stamped.Sub(newestRecord.UTC()).Round(time.Second))
	}
	return nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
