// SPDX-License-Identifier: MPL-2.0

package auditanchor_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestSavedEvidenceEnvelopeVerifiesOfflineAndRejectsTamperTruncationAndBackdateAUD51(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	signer, err := jose.GenerateRSASigningKey("aud-51-envelope")
	if err != nil {
		t.Fatal(err)
	}
	bundle := audit.Bundle{
		TenantID: "t1", GeneratedAt: recs[len(recs)-1].Time.Add(time.Minute),
		Query: audit.Query{TenantID: "t1"}, Records: recs, Count: len(recs), ChainHead: head,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	envelope := auditanchor.EvidenceEnvelope{
		SchemaVersion: auditanchor.EvidenceEnvelopeSchemaVersion,
		Format:        auditanchor.FormatJWS, Bundle: signed, ChainHead: head, Anchor: anchor,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := auditanchor.VerifyEvidenceEnvelope(raw, signer.JWKS(), h.rootDER, time.Hour)
	if err != nil || verified.Count != len(recs) {
		t.Fatalf("saved evidence envelope did not verify offline: bundle=%+v err=%v", verified, err)
	}

	parts := strings.Split(envelope.Bundle, ".")
	parts[1] = "ZXZpbA" + parts[1][6:]
	tampered := envelope
	tampered.Bundle = strings.Join(parts, ".")
	tamperedRaw, _ := json.Marshal(tampered)
	if _, err := auditanchor.VerifyEvidenceEnvelope(tamperedRaw, signer.JWKS(), h.rootDER, time.Hour); err == nil {
		t.Fatal("evidence envelope with an altered JWS verified")
	}
	if _, err := auditanchor.VerifyEvidenceEnvelope(raw[:len(raw)-2], signer.JWKS(), h.rootDER, time.Hour); err == nil {
		t.Fatal("truncated evidence envelope verified")
	}
	duplicate := bytes.Replace(raw, []byte(`"format":"jws"`), []byte(`"format":"jws","format":"jws"`), 1)
	if _, err := auditanchor.VerifyEvidenceEnvelope(duplicate, signer.JWKS(), h.rootDER, time.Hour); err == nil {
		t.Fatal("evidence envelope with a duplicate authority field verified")
	}

	late := newHarness(t, recs[len(recs)-1].Time.Add(90*24*time.Hour))
	lateAnchor, err := auditanchor.AnchorHead(t.Context(), late.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	backdated := envelope
	backdated.Anchor = lateAnchor
	backdatedRaw, _ := json.Marshal(backdated)
	if _, err := auditanchor.VerifyEvidenceEnvelope(backdatedRaw, signer.JWKS(), late.rootDER, time.Hour); err == nil {
		t.Fatal("evidence envelope freshly re-anchored 90 days after its newest event passed back-date policy")
	}
}
