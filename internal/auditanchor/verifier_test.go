// SPDX-License-Identifier: MPL-2.0

package auditanchor_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestOfflineVerifierAcceptsEveryServedAuditFormatAUD53(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	h := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []auditanchor.Format{
		auditanchor.FormatCSV,
		auditanchor.FormatNDJSON,
		auditanchor.FormatSplunkHEC,
		auditanchor.FormatSentinel,
	} {
		format := format
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var artifact bytes.Buffer
			if err := auditanchor.WriteRecords(&artifact, format, recs, "", head, anchor); err != nil {
				t.Fatal(err)
			}
			result, err := auditanchor.VerifyArtifact(artifact.Bytes(), auditanchor.VerificationOptions{
				Format: auditanchor.FormatAuto, TSARootDER: h.rootDER, MaxAnchorDelay: time.Hour,
			})
			if err != nil {
				t.Fatalf("verify %s: %v", format, err)
			}
			if result.Format != format || result.RecordCount != len(recs) || result.ChainHead != head ||
				result.AnchorKind != auditanchor.KindRFC3161 || result.AnchoredAt.IsZero() {
				t.Fatalf("%s result = %+v", format, result)
			}
		})
	}

	signer, envelope := signedEnvelopeAUD53(t, recs, head, anchor)
	result, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatAuto, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER,
		MaxAnchorDelay: time.Hour,
	})
	if err != nil {
		t.Fatalf("verify jws: %v", err)
	}
	if result.Format != auditanchor.FormatJWS || result.RecordCount != len(recs) ||
		result.ChainHead != head || result.TenantID != "t1" {
		t.Fatalf("jws result = %+v", result)
	}
}

func TestOfflineVerifierFailsClosedOnStreamTamperTruncationDuplicateAndWrongTrustAUD53(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	h := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	wrongTrust := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))

	for _, format := range []auditanchor.Format{
		auditanchor.FormatNDJSON,
		auditanchor.FormatSplunkHEC,
		auditanchor.FormatSentinel,
	} {
		format := format
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var artifact bytes.Buffer
			if err := auditanchor.WriteRecords(&artifact, format, recs, "", head, anchor); err != nil {
				t.Fatal(err)
			}
			opts := auditanchor.VerificationOptions{Format: format, TSARootDER: h.rootDER, MaxAnchorDelay: time.Hour}
			tampered := bytes.Replace(artifact.Bytes(), []byte("api.example.test"), []byte("evil.example.test"), 1)
			if _, err := auditanchor.VerifyArtifact(tampered, opts); err == nil {
				t.Fatal("altered event verified")
			}
			lines := nonEmptyLines(artifact.String())
			truncated := []byte(strings.Join(lines[:len(lines)-1], "\n") + "\n")
			if _, err := auditanchor.VerifyArtifact(truncated, opts); err == nil {
				t.Fatal("artifact without trailer verified")
			}
			duplicate := bytes.Replace(artifact.Bytes(), []byte(`"count":2`), []byte(`"count":2,"count":2`), 1)
			if _, err := auditanchor.VerifyArtifact(duplicate, opts); err == nil {
				t.Fatal("duplicate trailer authority verified")
			}
			trailing := append(append([]byte(nil), artifact.Bytes()...), []byte("{}\n")...)
			if _, err := auditanchor.VerifyArtifact(trailing, opts); err == nil {
				t.Fatal("data after the integrity trailer verified")
			}
			headMismatch := bytes.Replace(artifact.Bytes(), []byte(head), []byte(strings.Repeat("0", len(head))), 1)
			if _, err := auditanchor.VerifyArtifact(headMismatch, opts); err == nil {
				t.Fatal("a trailer naming a different chain head verified")
			}
			opts.TSARootDER = wrongTrust.rootDER
			if _, err := auditanchor.VerifyArtifact(artifact.Bytes(), opts); err == nil {
				t.Fatal("artifact verified under the wrong TSA root")
			}
		})
	}
}

func TestOfflineVerifierRequiresPinnedAuditKeysAndEnforcesBackdatePolicyAUD53(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	h := newHarness(t, recs[len(recs)-1].Time.Add(90*24*time.Hour))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	signer, envelope := signedEnvelopeAUD53(t, recs, head, anchor)

	if _, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, TSARootDER: h.rootDER, MaxAnchorDelay: 0,
	}); err == nil {
		t.Fatal("JWS envelope verified without a separately pinned audit JWK set")
	}
	wrongSigner, err := jose.GenerateRSASigningKey("aud-53-wrong")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: wrongSigner.JWKS(), TSARootDER: h.rootDER,
	}); err == nil {
		t.Fatal("JWS envelope verified under the wrong audit JWK set")
	}
	if _, err := auditanchor.VerifyArtifact(envelope, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER,
		MaxAnchorDelay: time.Hour,
	}); err == nil {
		t.Fatal("bundle freshly anchored 90 days after its newest event passed the delay policy")
	}

	var malformedEnvelope auditanchor.EvidenceEnvelope
	if err := json.Unmarshal(envelope, &malformedEnvelope); err != nil {
		t.Fatal(err)
	}
	payload, err := signer.JWKS().VerifyArtifact(malformedEnvelope.Bundle, jose.ArtifactAuditExport)
	if err != nil {
		t.Fatal(err)
	}
	malformedPayload := bytes.Replace(payload, []byte(`"tenant_id":"t1"`), []byte(`"tenant_id":"t1","tenant_id":"t1"`), 1)
	if bytes.Equal(malformedPayload, payload) {
		t.Fatal("test fixture did not inject duplicate signed bundle authority")
	}
	malformedEnvelope.Bundle, err = signer.SignArtifact(jose.ArtifactAuditExport, malformedPayload)
	if err != nil {
		t.Fatal(err)
	}
	malformedRaw, err := json.Marshal(malformedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyArtifact(malformedRaw, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER,
	}); err == nil {
		t.Fatal("a signed JWS bundle with duplicate tenant authority verified")
	}

	var mismatchedHead auditanchor.EvidenceEnvelope
	if err := json.Unmarshal(envelope, &mismatchedHead); err != nil {
		t.Fatal(err)
	}
	mismatchedHead.ChainHead = strings.Repeat("0", len(mismatchedHead.ChainHead))
	mismatchedRaw, err := json.Marshal(mismatchedHead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyArtifact(mismatchedRaw, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER,
	}); err == nil {
		t.Fatal("a JWS envelope naming a different chain head verified")
	}
}

func TestOfflineVerifierRefusesCrossTenantRecordStreamsEvenUnderTrustedTSA_AUD53(t *testing.T) {
	t.Parallel()
	recs, _ := exportRecords(t)
	recs[1].TenantID = "different-tenant"
	head := auditchain.Seal(recs)
	h := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	if err := auditanchor.WriteRecords(&artifact, auditanchor.FormatNDJSON, recs, "", head, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := auditanchor.VerifyArtifact(artifact.Bytes(), auditanchor.VerificationOptions{
		Format: auditanchor.FormatNDJSON, TSARootDER: h.rootDER,
	}); err == nil {
		t.Fatal("a trusted timestamp made a cross-tenant record stream verify")
	}
}

func TestOfflineVerifierRoundTripsArbitraryRecordDataPropertyAUD53(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 13, 6, 53, 0, 0, time.UTC)
	h := newHarness(t, at.Add(time.Minute))

	property := func(input []byte) bool {
		data, err := json.Marshal(map[string]string{"value": hex.EncodeToString(input)})
		if err != nil {
			return false
		}
		records := []auditchain.Record{{
			Sequence: 7, ID: "property-record", Type: "audit.property",
			TenantID: "tenant-property", Time: at, Data: data,
		}}
		head := auditchain.SealFrom("archived-prefix-head", records)
		anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
		if err != nil {
			return false
		}
		for _, format := range []auditanchor.Format{
			auditanchor.FormatCSV,
			auditanchor.FormatNDJSON,
			auditanchor.FormatSplunkHEC,
			auditanchor.FormatSentinel,
		} {
			var artifact bytes.Buffer
			if err := auditanchor.WriteRecords(&artifact, format, records, "archived-prefix-head", head, anchor); err != nil {
				return false
			}
			result, err := auditanchor.VerifyArtifact(artifact.Bytes(), auditanchor.VerificationOptions{
				Format: auditanchor.FormatAuto, TSARootDER: h.rootDER, MaxAnchorDelay: time.Hour,
			})
			if err != nil || result.Format != format || result.PrevHash != "archived-prefix-head" || result.ChainHead != head {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 12}); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineVerifierBoundsUntrustedArtifactBytesAUD53(t *testing.T) {
	t.Parallel()
	oversized := bytes.Repeat([]byte{'x'}, auditanchor.MaxArtifactBytes+1)
	if _, err := auditanchor.VerifyArtifact(oversized, auditanchor.VerificationOptions{
		Format: auditanchor.FormatAuto, TSARootDER: []byte{1},
	}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized artifact error = %v", err)
	}
}

func signedEnvelopeAUD53(
	t *testing.T,
	recs []auditchain.Record,
	head string,
	anchor auditanchor.Anchor,
) (*jose.SigningKey, []byte) {
	t.Helper()
	signer, err := jose.GenerateRSASigningKey("aud-53-audit")
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
	raw, err := json.Marshal(auditanchor.EvidenceEnvelope{
		SchemaVersion: auditanchor.EvidenceEnvelopeSchemaVersion,
		Format:        auditanchor.FormatJWS, Bundle: signed, ChainHead: head, Anchor: anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signer, raw
}
