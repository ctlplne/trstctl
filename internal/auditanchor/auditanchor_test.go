// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tsa"
)

// Anchoring an audit chain head to an external time source (epic J1).
//
// The hash chain already detects an edited record. What it cannot detect is a
// REBUILT one: an insider who removes a record and re-seals the chain from that
// point produces a set of hashes that are internally perfect. Every existing
// verification passes. The evidence is simply gone.
//
// So the tests that matter here are the negative ones, and there are two
// distinct attacks to separate:
//
//   - TAMPER: the records were changed after the anchor was taken. The
//     recomputed head no longer matches what the token attests.
//   - BACK-DATE: the chain was rebuilt and freshly anchored, then presented as
//     historical. The head and token agree perfectly — what gives it away is
//     that the timestamp is far newer than the events the bundle describes.
//
// A verifier that catches only the first is the one an attacker plans for.

type harness struct {
	authority *tsa.Authority
	rootDER   []byte
	now       time.Time
}

func newHarness(t *testing.T, at time.Time) *harness {
	t.Helper()
	h := &harness{now: at}
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "TSA Root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h.rootDER = rootDER

	tsaKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "TSA"}, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaCert, err := crypto.SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tsa.New(tsa.Config{
		TenantID: "t1", TSACertDER: tsaCert, TSASigner: tsaKey,
		Audit: &auditsink.Recorder{},
		Clock: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.authority = a
	return h
}

func records(t *testing.T, at time.Time, ids ...string) ([]auditchain.Record, string) {
	t.Helper()
	recs := make([]auditchain.Record, 0, len(ids))
	for i, id := range ids {
		recs = append(recs, auditchain.Record{
			Sequence: uint64(i + 1), ID: id, Type: "identity.created",
			TenantID: "t1", Time: at.Add(time.Duration(i) * time.Second),
		})
	}
	return recs, auditchain.Seal(recs)
}

// The happy path, so the negative cases below cannot pass for the wrong reason.
func TestAnAnchoredHeadVerifiesAgainstTheRecordsItCovers(t *testing.T) {
	t.Parallel()
	eventTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, eventTime.Add(time.Minute))

	recs, head := records(t, eventTime, "a", "b", "c")
	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, head)
	if err != nil {
		t.Fatalf("AnchorHead: %v", err)
	}
	if anchor.Kind != auditanchor.KindRFC3161 {
		t.Fatalf("anchor kind = %q, want rfc3161", anchor.Kind)
	}

	// An auditor recomputes the head from the records in front of them.
	recomputed := auditchain.Seal(recs)
	if err := auditanchor.Verify(anchor, recomputed, h.rootDER); err != nil {
		t.Fatalf("an untampered bundle failed verification: %v", err)
	}
	newest := recs[len(recs)-1].Time
	if err := auditanchor.VerifyNotBackdated(anchor, newest, time.Hour); err != nil {
		t.Errorf("an anchor taken a minute after the last record was called back-dated: %v", err)
	}
}

// ATTACK 1 — TAMPER. A record is altered after anchoring.
func TestAlteredRecordsAreCaughtByTheAnchor(t *testing.T) {
	t.Parallel()
	eventTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, eventTime.Add(time.Minute))

	recs, head := records(t, eventTime, "a", "b", "c")
	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}

	// Change one record's type — the kind of edit that hides what happened
	// without changing how much happened.
	recs[1].Type = "identity.deleted"
	recomputed := auditchain.Seal(recs)

	if err := auditanchor.Verify(anchor, recomputed, h.rootDER); err == nil {
		t.Fatal("an altered record verified against its anchor; the chain would attest evidence " +
			"that no longer matches what it covers")
	}
}

// ATTACK 2 — BACK-DATE. The chain is REBUILT with a record removed, and then
// honestly anchored. Every hash is consistent and the token genuinely covers the
// head, so tamper detection passes. What betrays it is the clock.
func TestARebuiltChainAnchoredLaterIsCaughtAsBackdated(t *testing.T) {
	t.Parallel()
	eventTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	// The original chain, anchored at the time it happened.
	_, _ = records(t, eventTime, "a", "b", "c")

	// Months later, an insider rebuilds the chain without record "b" and takes a
	// fresh, entirely valid timestamp.
	rebuiltAt := eventTime.Add(90 * 24 * time.Hour)
	h := newHarness(t, rebuiltAt)
	rebuilt, rebuiltHead := records(t, eventTime, "a", "c")
	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, rebuiltHead)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper detection alone is FOOLED — and that is the point of this test.
	recomputed := auditchain.Seal(rebuilt)
	if err := auditanchor.Verify(anchor, recomputed, h.rootDER); err != nil {
		t.Fatalf("the rebuilt chain should be internally consistent; got %v", err)
	}

	// The clock catches it: the bundle claims to describe March and was
	// timestamped in June.
	newest := rebuilt[len(rebuilt)-1].Time
	if err := auditanchor.VerifyNotBackdated(anchor, newest, time.Hour); err == nil {
		t.Fatal("a chain rebuilt 90 days after the events it describes passed the back-dating " +
			"check; an insider who re-seals the chain and re-anchors it would be undetectable")
	}
}

// A token dated BEFORE a record it supposedly covers is impossible for an honest
// chain — the head cannot exist before its last input.
func TestATokenPredatingItsRecordsIsRefused(t *testing.T) {
	t.Parallel()
	eventTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, eventTime.Add(-time.Hour))

	recs, head := records(t, eventTime, "a", "b")
	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditanchor.VerifyNotBackdated(anchor, recs[len(recs)-1].Time, time.Hour); err == nil {
		t.Fatal("a timestamp predating the records it covers was accepted")
	}
}

// An unanchored bundle must READ as unanchored, not as fine.
func TestAnUnanchoredBundleIsNotSilentlyAccepted(t *testing.T) {
	t.Parallel()
	_, head := records(t, time.Now().UTC(), "a")

	anchor, err := auditanchor.AnchorHead(context.Background(), nil, head)
	if err == nil {
		t.Fatal("anchoring with no authority reported success")
	}
	if anchor.Kind != auditanchor.KindNone {
		t.Errorf("anchor kind = %q, want none", anchor.Kind)
	}
	if anchor.Detail == "" {
		t.Error("an unanchored result carries no explanation, so an operator cannot tell why")
	}
	if err := auditanchor.Verify(anchor, head, nil); err == nil {
		t.Fatal("an unanchored bundle passed verification; 'nobody attested this' must not read " +
			"the same as 'an authority attested this'")
	}
}

// An empty chain has no head to attest, and must not produce a token that later
// reads as evidence about records.
func TestAnEmptyChainProducesNoAnchor(t *testing.T) {
	t.Parallel()
	h := newHarness(t, time.Now().UTC())
	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, "")
	if err != nil {
		t.Fatalf("AnchorHead on an empty chain: %v", err)
	}
	if anchor.Kind != auditanchor.KindNone {
		t.Errorf("an empty chain produced a %q anchor", anchor.Kind)
	}
	if anchor.Token != nil {
		t.Error("an empty chain produced a timestamp token")
	}
}

// The imprint is domain-separated, so an audit anchor cannot be swapped for a
// timestamp taken over the same digest for another purpose.
func TestTheAnchorImprintIsDomainSeparated(t *testing.T) {
	t.Parallel()
	eventTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, eventTime)
	_, head := records(t, eventTime, "a")

	anchor, err := auditanchor.AnchorHead(context.Background(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	// A token taken over the RAW head — what a generic document-timestamping
	// endpoint would produce — must not verify as an audit anchor.
	raw, err := h.authority.Timestamp(context.Background(), crypto.SHA256Sum([]byte(head)))
	if err != nil {
		t.Fatal(err)
	}
	swapped := anchor
	swapped.Token = &raw
	if err := auditanchor.Verify(swapped, head, h.rootDER); err == nil {
		t.Fatal("a timestamp taken for another purpose verified as an audit anchor; tokens " +
			"would be interchangeable across uses")
	}
}
