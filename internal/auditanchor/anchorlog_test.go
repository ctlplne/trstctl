// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// anchorLogEntries is the anchor log the server keeps for the chain's anchor
// records, in order.
func anchorLogEntries(t *testing.T, records []auditchain.Record) []auditanchor.AnchorLogEntry {
	t.Helper()
	var entries []auditanchor.AnchorLogEntry
	for _, record := range records {
		if record.Type != auditanchor.EventTypeAnchored {
			continue
		}
		var payload auditanchor.AnchoredEvent
		if err := json.Unmarshal(record.Data, &payload); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, auditanchor.AnchorLogEntry{
			EventID: record.ID, ThroughSequence: payload.ThroughSequence, ChainHead: payload.Anchor.ChainHead,
			TokenSHA256: crypto.SHA256Hex(payload.Anchor.Token.DER),
		})
	}
	return entries
}

func anchorLogKey(t *testing.T) *jose.SigningKey {
	t.Helper()
	key, err := jose.GenerateRSASigningKey("anchor-log")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A148: an export carries a signed head of the tenant's anchor log and an
// inclusion proof for each anchor record it holds; the verifier recomputes each
// leaf from the record, refuses an anchor removed from between two it holds,
// tolerates only the newest anchors the log has not taken in yet, and, given an
// earlier signed head, proves the log only grew.
func TestAnchorLogProvesEveryAnchorRecordAndAppendOnlyGrowth(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	key := anchorLogKey(t)
	entries := anchorLogEntries(t, recs)
	issued := seriesStart.Add(4 * time.Hour)

	proof, err := auditanchor.BuildAnchorLogProof("t1", entries, recs, 0, issued, key)
	if err != nil || proof == nil || len(proof.Inclusions) != 3 {
		t.Fatalf("proof = %+v, %v", proof, err)
	}
	result, err := auditanchor.VerifyAnchorLog(recs, proof, key.JWKS(), "")
	if err != nil || !result.Checked || result.Proven != 3 || result.TreeSize != 3 || result.SignedHead == "" {
		t.Fatalf("result = %+v, %v", result, err)
	}

	// A window proves the anchors it holds against the whole log.
	window := recs[4:]
	windowProof, err := auditanchor.BuildAnchorLogProof("t1", entries, window, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := auditanchor.VerifyAnchorLog(window, windowProof, key.JWKS(), ""); err != nil || result.Proven != 2 {
		t.Fatalf("window = %+v, %v", result, err)
	}

	// The log grows; the earlier head is extended, and an export without the
	// consistency proof, or a rewritten log, is refused.
	earlier := result.SignedHead
	c.add("identity.renewed", seriesStart.Add(3*time.Hour+20*time.Minute), "", nil)
	c.anchor(seriesStart.Add(4 * time.Hour))
	grown := c.records()
	grownEntries := anchorLogEntries(t, grown)
	withConsistency, err := auditanchor.BuildAnchorLogProof("t1", grownEntries, grown, 3, issued.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := auditanchor.VerifyAnchorLog(grown, withConsistency, key.JWKS(), earlier); err != nil || !result.ConsistentWithPrevious || result.TreeSize != 4 {
		t.Fatalf("grown log against the earlier head = %+v, %v", result, err)
	}
	withoutConsistency, err := auditanchor.BuildAnchorLogProof("t1", grownEntries, grown, 0, issued.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyAnchorLog(grown, withoutConsistency, key.JWKS(), earlier); err == nil || !strings.Contains(err.Error(), "anchor_log_from=3") {
		t.Fatalf("no consistency proof = %v", err)
	}
	rewritten := append([]auditanchor.AnchorLogEntry(nil), grownEntries...)
	rewritten[0].ChainHead = strings.Repeat("0", 64)
	rewrittenProof, err := auditanchor.BuildAnchorLogProof("t1", rewritten, grown[4:], 3, issued.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyAnchorLog(grown[4:], rewrittenProof, key.JWKS(), earlier); err == nil || !strings.Contains(err.Error(), "does not extend") {
		t.Fatalf("a rewritten anchor log = %v", err)
	}
	if _, err := auditanchor.BuildAnchorLogProof("t1", grownEntries, grown, 9, issued, key); err == nil {
		t.Fatal("consistency from beyond the log was built")
	}
}

func TestAnchorLogRefusesMissingForgedAndUnsignedProofs(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	key := anchorLogKey(t)
	entries := anchorLogEntries(t, recs)
	issued := seriesStart.Add(4 * time.Hour)
	proof, err := auditanchor.BuildAnchorLogProof("t1", entries, recs, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}

	// The middle anchor record is cut out of the chain and the chain re-sealed:
	// the log still holds its entry, so the leaf indexes skip.
	cut := append(append([]auditchain.Record(nil), recs[:5]...), recs[6:]...)
	for i := range cut {
		cut[i].Sequence = uint64(i + 1)
	}
	auditchain.Seal(cut)
	cutProof, err := auditanchor.BuildAnchorLogProof("t1", entries, cut, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyAnchorLog(cut, cutProof, key.JWKS(), ""); err == nil || !strings.Contains(err.Error(), "that the export does not") {
		t.Fatalf("an anchor record cut from the chain = %v", err)
	}

	// The newest anchor not yet in the log is reported, not refused; an
	// unproven anchor before a proven one is refused.
	lagging, err := auditanchor.BuildAnchorLogProof("t1", entries[:2], recs, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := auditanchor.VerifyAnchorLog(recs, lagging, key.JWKS(), ""); err != nil || result.Proven != 2 || result.UnloggedTail != 1 {
		t.Fatalf("a lagging log = %+v, %v", result, err)
	}
	gapped := *proof
	gapped.Inclusions = []auditanchor.AnchorInclusion{proof.Inclusions[1], proof.Inclusions[2]}
	if _, err := auditanchor.VerifyAnchorLog(recs, &gapped, key.JWKS(), ""); err == nil {
		t.Fatal("an unproven anchor before proven ones was accepted")
	}

	forged := *proof
	forged.Inclusions = append([]auditanchor.AnchorInclusion(nil), proof.Inclusions...)
	forged.Inclusions[0].LeafIndex = 1
	if _, err := auditanchor.VerifyAnchorLog(recs, &forged, key.JWKS(), ""); err == nil {
		t.Fatal("a proof for the wrong leaf was accepted")
	}
	other := anchorLogKey(t)
	if _, err := auditanchor.VerifyAnchorLog(recs, proof, other.JWKS(), ""); err == nil {
		t.Fatal("a head signed by an unpinned key was accepted")
	}
	foreign, err := auditanchor.BuildAnchorLogProof("t2", entries, recs, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyAnchorLog(recs, foreign, key.JWKS(), ""); err == nil {
		t.Fatal("another tenant's anchor log head was accepted")
	}
	if result, err := auditanchor.VerifyAnchorLog(recs, proof, nil, ""); err != nil || result.Checked || result.Reason == "" {
		t.Fatalf("no audit keys = %+v, %v", result, err)
	}
	if _, err := auditanchor.VerifyAnchorLog(recs, nil, key.JWKS(), proof.SignedHead); err == nil {
		t.Fatal("an earlier head was accepted against an export with no anchor log")
	}
	if none, err := auditanchor.BuildAnchorLogProof("t1", nil, recs, 0, issued, key); err != nil || none != nil {
		t.Fatalf("a tenant with no anchors = %+v, %v", none, err)
	}
}

// The saved forms carry the anchor log: a JWS envelope moves to schema 2 and a
// record stream's trailer holds it; the offline verifier checks it with the
// pinned audit keys and, given the head kept from an earlier receipt, proves
// growth through the export's consistency proof.
func TestSavedExportsCarryAndVerifyTheAnchorLog(t *testing.T) {
	t.Parallel()
	c := hourly(t)
	recs := c.records()
	head := recs[len(recs)-1].Hash
	c.h.now = recs[len(recs)-1].Time.Add(time.Minute)
	exportAnchor, err := auditanchor.AnchorHead(t.Context(), c.h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	key := anchorLogKey(t)
	issued := seriesStart.Add(4 * time.Hour)
	proof, err := auditanchor.BuildAnchorLogProof("t1", anchorLogEntries(t, recs), recs, 0, issued, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		TenantID    string              `json:"tenant_id"`
		GeneratedAt time.Time           `json:"generated_at"`
		Query       map[string]string   `json:"query"`
		Records     []auditchain.Record `json:"records"`
		Count       int                 `json:"count"`
		ChainHead   string              `json:"chain_head"`
	}{TenantID: "t1", GeneratedAt: issued, Query: map[string]string{"tenant_id": "t1"}, Records: recs, Count: len(recs), ChainHead: head})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := key.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := auditanchor.NewEvidenceEnvelope(signed, head, exportAnchor, proof)
	if envelope.SchemaVersion != auditanchor.EvidenceEnvelopeAnchorLogSchemaVersion {
		t.Fatalf("an envelope with an anchor log is schema %d", envelope.SchemaVersion)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	opts := auditanchor.VerificationOptions{Format: auditanchor.FormatAuto, AuditKeys: key.JWKS(), TSARootDER: c.h.rootDER}
	result, err := auditanchor.VerifyArtifact(raw, opts)
	if err != nil || result.AnchorLog == nil || !result.AnchorLog.Checked || result.AnchorLog.Proven != 3 || result.AnchorSeries.Verified != 3 {
		t.Fatalf("jws with an anchor log = %+v, %v", result.AnchorLog, err)
	}
	earlier := result.AnchorLog.SignedHead

	for name, mutate := range map[string]func(*auditanchor.EvidenceEnvelope){
		"schema 1 with an anchor log": func(e *auditanchor.EvidenceEnvelope) { e.SchemaVersion = auditanchor.EvidenceEnvelopeSchemaVersion },
		"schema 2 without one":        func(e *auditanchor.EvidenceEnvelope) { e.AnchorLog = nil },
	} {
		bad := envelope
		mutate(&bad)
		badRaw, _ := json.Marshal(bad)
		if _, err := auditanchor.VerifyArtifact(badRaw, opts); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	var stream strings.Builder
	if err := auditanchor.WriteRecordStream(&stream, auditanchor.FormatNDJSON, auditanchor.RecordStream{
		Records: recs, Head: head, Anchor: exportAnchor, FullChain: true, AnchorLog: proof,
	}); err != nil {
		t.Fatal(err)
	}
	result, err = auditanchor.VerifyArtifact([]byte(stream.String()), opts)
	if err != nil || result.AnchorLog == nil || result.AnchorLog.Proven != 3 {
		t.Fatalf("ndjson with an anchor log = %+v, %v", result.AnchorLog, err)
	}
	noKeys := opts
	noKeys.AuditKeys = nil
	if result, err := auditanchor.VerifyArtifact([]byte(stream.String()), noKeys); err != nil || result.AnchorLog == nil || result.AnchorLog.Checked {
		t.Fatalf("a stream checked without audit keys = %+v, %v", result.AnchorLog, err)
	}

	// A later export proves the log grew from the earlier head.
	c.add("identity.renewed", seriesStart.Add(3*time.Hour+20*time.Minute), "", nil)
	c.anchor(seriesStart.Add(4 * time.Hour))
	grown := c.records()
	grownHead := grown[len(grown)-1].Hash
	c.h.now = grown[len(grown)-1].Time.Add(time.Minute)
	grownAnchor, err := auditanchor.AnchorHead(t.Context(), c.h.authority, grownHead)
	if err != nil {
		t.Fatal(err)
	}
	grownProof, err := auditanchor.BuildAnchorLogProof("t1", anchorLogEntries(t, grown), grown, 3, issued.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	var later strings.Builder
	if err := auditanchor.WriteRecordStream(&later, auditanchor.FormatNDJSON, auditanchor.RecordStream{
		Records: grown, Head: grownHead, Anchor: grownAnchor, FullChain: true, AnchorLog: grownProof,
	}); err != nil {
		t.Fatal(err)
	}
	withEarlier := opts
	withEarlier.PreviousAnchorLog = earlier
	if result, err := auditanchor.VerifyArtifact([]byte(later.String()), withEarlier); err != nil || !result.AnchorLog.ConsistentWithPrevious || result.AnchorLog.TreeSize != 4 {
		t.Fatalf("a later export against the earlier head = %+v, %v", result.AnchorLog, err)
	}
}
