// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/eventspec"
)

// seriesChain builds a tenant chain the way the anchoring worker extends it:
// ordinary records, and at each anchor a timestamp over the full chain so far
// appended as an audit.anchored record of its own.
type seriesChain struct {
	t    *testing.T
	h    *harness
	recs []auditchain.Record
}

func newSeriesChain(t *testing.T, h *harness) *seriesChain { return &seriesChain{t: t, h: h} }

func (c *seriesChain) add(typ string, at time.Time, actor string, data []byte) {
	c.t.Helper()
	if data == nil {
		data = []byte(`{}`)
	}
	record := auditchain.Record{
		Sequence: uint64(len(c.recs) + 1), ID: typ + "-" + at.Format("150405"), Type: typ,
		TenantID: "t1", Time: at, Data: data,
	}
	if actor != "" {
		record.Actor = &eventspec.Actor{Subject: actor}
	}
	c.recs = append(c.recs, record)
	auditchain.Seal(c.recs)
}

func (c *seriesChain) anchor(at time.Time) {
	c.t.Helper()
	c.h.now = at
	through := c.recs[len(c.recs)-1]
	anchor, err := auditanchor.AnchorHead(context.Background(), c.h.authority, through.Hash)
	if err != nil {
		c.t.Fatal(err)
	}
	data, err := json.Marshal(auditanchor.AnchoredEvent{ThroughSequence: through.Sequence, CadenceSeconds: 3600, Anchor: anchor})
	if err != nil {
		c.t.Fatal(err)
	}
	c.add(auditanchor.EventTypeAnchored, at.Add(time.Second), "", data)
}

func (c *seriesChain) records() []auditchain.Record {
	return append([]auditchain.Record(nil), c.recs...)
}

var seriesStart = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// exportAt is when an export of records is anchored: five minutes after its
// newest record.
func exportAt(records []auditchain.Record) time.Time {
	return records[len(records)-1].Time.Add(5 * time.Minute)
}

func hourly(t *testing.T) *seriesChain {
	t.Helper()
	c := newSeriesChain(t, newHarness(t, seriesStart))
	for hour := 0; hour < 3; hour++ {
		base := seriesStart.Add(time.Duration(hour) * time.Hour)
		c.add("identity.issued", base.Add(10*time.Minute), "alice", nil)
		c.add("identity.renewed", base.Add(40*time.Minute), "", nil)
		c.anchor(base.Add(time.Hour))
	}
	c.add("identity.revoked", seriesStart.Add(3*time.Hour+5*time.Minute), "", nil)
	return c
}

func TestAnchorSeriesVerifiesEveryAnchorAndTheCadence(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	result, err := auditanchor.VerifySeries(c.records(), "", true, exportAt(c.records()), c.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour})
	if err != nil {
		t.Fatalf("an honest hourly series failed: %v", err)
	}
	if !result.Applicable || result.Anchors != 3 || result.Verified != 3 || result.LongestCoverageSeconds != 50*60 ||
		result.CadenceSeconds != 3600 || !result.FirstAnchoredAt.Equal(seriesStart.Add(time.Hour)) || !result.LastAnchoredAt.Equal(seriesStart.Add(3*time.Hour)) {
		t.Fatalf("series = %+v", result)
	}

	// A window that starts mid-history continues the full chain from the head
	// before it; the first anchor in it covers records before the window.
	recs := c.records()
	window := recs[4:]
	result, err = auditanchor.VerifySeries(window, recs[3].Hash, true, exportAt(window), c.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour})
	if err != nil {
		t.Fatalf("a mid-history window failed: %v", err)
	}
	if result.Anchors != 2 || result.Verified != 2 || result.BeforeWindow != 0 {
		t.Fatalf("window series = %+v", result)
	}
	late := recs[6:]
	result, err = auditanchor.VerifySeries(late, recs[5].Hash, true, exportAt(late), c.h.rootDER, auditanchor.SeriesPolicy{})
	if err != nil || result.Anchors != 1 || result.Verified != 1 {
		t.Fatalf("late window series = %+v, %v", result, err)
	}
}

func TestAnchorSeriesCatchesRecordsChangedAfterTheyWereAnchored(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	recs[1].Data = []byte(`{"rewritten":true}`)
	auditchain.Seal(recs)
	_, err := auditanchor.VerifySeries(recs, "", true, exportAt(recs), c.h.rootDER, auditanchor.SeriesPolicy{})
	if err == nil || !strings.Contains(err.Error(), "changed after they were timestamped") {
		t.Fatalf("a rewritten, re-sealed chain = %v", err)
	}
}

func TestAnchorSeriesCatchesAWithheldRecordSlippedInLater(t *testing.T) {
	t.Parallel()
	h := newHarness(t, seriesStart)
	c := newSeriesChain(t, h)
	c.add("identity.issued", seriesStart.Add(10*time.Minute), "", nil)
	c.anchor(seriesStart.Add(time.Hour))
	// Written at 00:20 but added to the chain after the 01:00 anchor that did
	// not include it.
	c.add("identity.revoked", seriesStart.Add(20*time.Minute), "", nil)
	_, err := auditanchor.VerifySeries(c.records(), "", true, exportAt(c.records()), h.rootDER, auditanchor.SeriesPolicy{})
	if err == nil || !strings.Contains(err.Error(), "withheld or back-dated") {
		t.Fatalf("a withheld record = %v", err)
	}
	// Within the clock tolerance it is not called withheld.
	ok := newSeriesChain(t, newHarness(t, seriesStart))
	ok.add("identity.issued", seriesStart.Add(10*time.Minute), "", nil)
	ok.anchor(seriesStart.Add(time.Hour))
	ok.add("identity.revoked", seriesStart.Add(time.Hour-time.Minute), "", nil)
	if _, err := auditanchor.VerifySeries(ok.records(), "", true, exportAt(ok.records()), ok.h.rootDER, auditanchor.SeriesPolicy{}); err != nil {
		t.Fatalf("a record a minute before the anchor time, inside the tolerance, was refused: %v", err)
	}
}

func TestAnchorSeriesEnforcesTheCadence(t *testing.T) {
	t.Parallel()
	gap := newSeriesChain(t, newHarness(t, seriesStart))
	gap.add("identity.issued", seriesStart.Add(10*time.Minute), "", nil)
	gap.anchor(seriesStart.Add(time.Hour))
	gap.add("identity.issued", seriesStart.Add(2*time.Hour), "", nil)
	gap.anchor(seriesStart.Add(4 * time.Hour))
	if result, err := auditanchor.VerifySeries(gap.records(), "", true, exportAt(gap.records()), gap.h.rootDER, auditanchor.SeriesPolicy{}); err != nil || result.LongestCoverageSeconds != 2*3600 {
		t.Fatalf("without a cadence the wait is reported, not refused: %+v, %v", result, err)
	}
	if _, err := auditanchor.VerifySeries(gap.records(), "", true, exportAt(gap.records()), gap.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil || !strings.Contains(err.Error(), "waited until") {
		t.Fatalf("a record that waited two hours under an hourly cadence = %v", err)
	}

	// A quiet stretch needs no anchor: there is nothing in it to cover.
	quiet := newSeriesChain(t, newHarness(t, seriesStart))
	quiet.add("identity.issued", seriesStart.Add(10*time.Minute), "", nil)
	quiet.anchor(seriesStart.Add(time.Hour))
	quiet.add("identity.issued", seriesStart.Add(9*time.Hour), "", nil)
	quiet.anchor(seriesStart.Add(10 * time.Hour))
	if _, err := auditanchor.VerifySeries(quiet.records(), "", true, exportAt(quiet.records()), quiet.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err != nil {
		t.Fatalf("an idle tenant's quiet night = %v", err)
	}

	stopped := newSeriesChain(t, newHarness(t, seriesStart))
	stopped.add("identity.issued", seriesStart.Add(10*time.Minute), "", nil)
	stopped.anchor(seriesStart.Add(time.Hour))
	stopped.add("identity.issued", seriesStart.Add(90*time.Minute), "", nil)
	stopped.add("identity.issued", seriesStart.Add(3*time.Hour), "", nil)
	if _, err := auditanchor.VerifySeries(stopped.records(), "", true, exportAt(stopped.records()), stopped.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil || !strings.Contains(err.Error(), "anchoring stopped") {
		t.Fatalf("a record left unanchored for ninety minutes = %v", err)
	}

	unanchored := newSeriesChain(t, newHarness(t, seriesStart))
	unanchored.add("identity.issued", seriesStart, "", nil)
	unanchored.add("identity.issued", seriesStart.Add(3*time.Hour), "", nil)
	if _, err := auditanchor.VerifySeries(unanchored.records(), "", true, exportAt(unanchored.records()), unanchored.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil || !strings.Contains(err.Error(), "has no anchor in this export") {
		t.Fatalf("three hours of records with no anchor = %v", err)
	}
	if _, err := auditanchor.VerifySeries(unanchored.records(), "", true, time.Time{}, unanchored.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil || !strings.Contains(err.Error(), "unanchored") {
		t.Fatalf("an unanchored export under a cadence = %v", err)
	}

	history := newSeriesChain(t, newHarness(t, seriesStart))
	history.add("identity.issued", seriesStart.Add(-48*time.Hour), "", nil)
	history.anchor(seriesStart.Add(time.Hour))
	if _, err := auditanchor.VerifySeries(history.records(), "", true, exportAt(history.records()), history.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil || !strings.Contains(err.Error(), "starts after the first anchor") {
		t.Fatalf("history from before anchoring began = %v", err)
	}
}

func TestAnchorSeriesReportsAnchorsAnErasureSuperseded(t *testing.T) {
	t.Parallel()
	c := newSeriesChain(t, newHarness(t, seriesStart))
	c.add("identity.issued", seriesStart.Add(10*time.Minute), "alice", nil)
	c.anchor(seriesStart.Add(time.Hour))
	c.add(eventledger.EventPrivacySubjectErased, seriesStart.Add(90*time.Minute), "", nil)
	recs := c.records()
	recs[0].Actor = &eventspec.Actor{Subject: "erased"}
	auditchain.Seal(recs)
	result, err := auditanchor.VerifySeries(recs, "", true, exportAt(recs), c.h.rootDER, auditanchor.SeriesPolicy{})
	if err != nil || result.SupersededByErasure != 1 || result.Verified != 0 {
		t.Fatalf("an anchor superseded by a later erasure = %+v, %v", result, err)
	}
}

func TestAnchorSeriesRefusesForgedAndMalformedAnchors(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	other := newHarness(t, seriesStart)
	if _, err := auditanchor.VerifySeries(c.records(), "", true, exportAt(c.records()), other.rootDER, auditanchor.SeriesPolicy{}); err == nil {
		t.Fatal("anchors from a TSA the auditor did not pin were accepted")
	}
	for name, data := range map[string][]byte{
		"not json":         []byte(`{"through_sequence":`),
		"unknown field":    []byte(`{"through_sequence":1,"cadence_seconds":3600,"anchor":{"kind":"rfc3161","chain_head":"x","anchored_at":"2026-10-01T01:00:00Z"},"extra":1}`),
		"covers itself":    []byte(`{"through_sequence":9,"cadence_seconds":3600,"anchor":{"kind":"rfc3161","chain_head":"x","anchored_at":"2026-10-01T01:00:00Z"}}`),
		"no timestamp":     []byte(`{"through_sequence":1,"cadence_seconds":3600,"anchor":{"kind":"","chain_head":"x","anchored_at":"0001-01-01T00:00:00Z"}}`),
		"unknown kind":     []byte(`{"through_sequence":1,"cadence_seconds":3600,"anchor":{"kind":"blockchain","chain_head":"x","anchored_at":"2026-10-01T01:00:00Z"}}`),
		"a token for else": nil,
	} {
		m := newSeriesChain(t, newHarness(t, seriesStart))
		m.add("identity.issued", seriesStart, "", nil)
		if data == nil {
			anchor, err := auditanchor.AnchorHead(context.Background(), m.h.authority, "some-other-head")
			if err != nil {
				t.Fatal(err)
			}
			data, _ = json.Marshal(auditanchor.AnchoredEvent{ThroughSequence: 1, CadenceSeconds: 3600, Anchor: anchor})
			data = bytes.Replace(data, []byte(`"chain_head":"some-other-head"`), []byte(`"chain_head":"`+m.recs[0].Hash+`"`), 1)
		}
		m.add(auditanchor.EventTypeAnchored, seriesStart.Add(time.Minute), "", data)
		if _, err := auditanchor.VerifySeries(m.records(), "", true, exportAt(m.records()), m.h.rootDER, auditanchor.SeriesPolicy{}); err == nil {
			t.Fatalf("%s: a bad anchor record was accepted", name)
		}
	}
}

func TestAnchorSeriesNeedsAnUnbrokenRun(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	gapped := append(append([]auditchain.Record(nil), recs[:2]...), recs[3:]...)
	auditchain.Seal(gapped)
	result, err := auditanchor.VerifySeries(gapped, "", true, exportAt(gapped), c.h.rootDER, auditanchor.SeriesPolicy{})
	if err != nil || result.Applicable || result.Reason == "" {
		t.Fatalf("a filtered selection = %+v, %v", result, err)
	}
	if _, err := auditanchor.VerifySeries(gapped, "", true, exportAt(gapped), c.h.rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour}); err == nil {
		t.Fatal("a cadence was enforced over a selection that cannot carry it")
	}
}

// The saved artifact forms carry the series: the offline verifier checks it in
// a signed JWS export and in a record stream, and reports it in the receipt.
func TestOfflineVerifierChecksTheAnchorSeriesInSavedExports(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	head := recs[len(recs)-1].Hash
	c.h.now = recs[len(recs)-1].Time.Add(time.Minute)
	exportAnchor, err := auditanchor.AnchorHead(context.Background(), c.h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	policy := auditanchor.SeriesPolicy{Cadence: time.Hour}
	signer, envelope := signedEnvelopeAUD53(t, recs, head, exportAnchor)
	result, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatAuto, AuditKeys: signer.JWKS(), TSARootDER: c.h.rootDER, Series: policy,
	})
	if err != nil || result.AnchorSeries == nil || result.AnchorSeries.Verified != 3 {
		t.Fatalf("jws series = %+v, %v", result.AnchorSeries, err)
	}
	var stream bytes.Buffer
	if err := auditanchor.WriteRecordStream(&stream, auditanchor.FormatNDJSON, auditanchor.RecordStream{
		Records: recs, Head: head, Anchor: exportAnchor, FullChain: true,
	}); err != nil {
		t.Fatal(err)
	}
	result, err = auditanchor.VerifyArtifact(stream.Bytes(), auditanchor.VerificationOptions{
		Format: auditanchor.FormatAuto, TSARootDER: c.h.rootDER, Series: policy,
	})
	if err != nil || result.AnchorSeries == nil || result.AnchorSeries.Verified != 3 {
		t.Fatalf("ndjson series = %+v, %v", result.AnchorSeries, err)
	}
	if _, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatAuto, AuditKeys: signer.JWKS(), AllowUnanchoredJWS: true, Series: policy,
	}); err == nil {
		t.Fatal("a cadence was enforced without a pinned TSA root")
	}
	// A stream without the full-chain mark is a chain of its own: the series
	// is reported as not applicable, and a cadence cannot be held to it.
	var plain bytes.Buffer
	if err := auditanchor.WriteRecords(&plain, auditanchor.FormatNDJSON, recs, "", head, exportAnchor); err != nil {
		t.Fatal(err)
	}
	result, err = auditanchor.VerifyArtifact(plain.Bytes(), auditanchor.VerificationOptions{Format: auditanchor.FormatAuto, TSARootDER: c.h.rootDER})
	if err != nil || result.AnchorSeries == nil || result.AnchorSeries.Applicable {
		t.Fatalf("unmarked stream series = %+v, %v", result.AnchorSeries, err)
	}
	if _, err := auditanchor.VerifyArtifact(plain.Bytes(), auditanchor.VerificationOptions{Format: auditanchor.FormatAuto, TSARootDER: c.h.rootDER, Series: policy}); err == nil {
		t.Fatal("a cadence was held to a stream that does not continue the full chain")
	}
	marked := strings.Replace(stream.String(), `"chain":"tenant"`, `"chain":"forged"`, 1)
	if _, err := auditanchor.VerifyArtifact([]byte(marked), auditanchor.VerificationOptions{Format: auditanchor.FormatAuto, TSARootDER: c.h.rootDER}); err == nil {
		t.Fatal("an unknown chain mark was accepted")
	}
}
