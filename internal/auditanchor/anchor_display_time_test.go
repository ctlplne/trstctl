// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
)

func TestOfflineVerifierNeverAttestsUnsignedOuterAnchorTime(t *testing.T) {
	recs, head := exportRecords(t)
	h := newHarness(t, recs[len(recs)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	signer, originalJWS := signedEnvelopeAUD53(t, recs, head, anchor)
	for _, format := range []auditanchor.Format{
		auditanchor.FormatJWS, auditanchor.FormatCSV, auditanchor.FormatNDJSON,
		auditanchor.FormatSplunkHEC, auditanchor.FormatSentinel,
	} {
		t.Run(string(format), func(t *testing.T) {
			opts := auditanchor.VerificationOptions{
				Format: format, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER,
				MaxAnchorDelay: time.Hour,
			}
			encode := func(outerTime time.Time) []byte {
				t.Helper()
				changed := anchor
				changed.AnchoredAt = outerTime
				if format == auditanchor.FormatJWS {
					var envelope auditanchor.EvidenceEnvelope
					if err := json.Unmarshal(originalJWS, &envelope); err != nil {
						t.Fatal(err)
					}
					envelope.Anchor = changed
					raw, err := json.Marshal(envelope)
					if err != nil {
						t.Fatal(err)
					}
					return raw
				}
				var out bytes.Buffer
				if err := auditanchor.WriteRecords(&out, format, recs, "", head, changed); err != nil {
					t.Fatal(err)
				}
				return out.Bytes()
			}
			verifiedAt := anchor.Token.Info.GenTime
			for _, tc := range []struct {
				name string
				at   time.Time
			}{
				{"valid", verifiedAt},
				{"same-instant-offset", verifiedAt.In(time.FixedZone("audit-display-offset", 5*60*60+30*60))},
			} {
				t.Run(tc.name, func(t *testing.T) {
					result, err := auditanchor.VerifyArtifact(encode(tc.at), opts)
					if err != nil {
						t.Fatalf("authentic timestamp must verify: %v", err)
					}
					if !result.AnchorVerified || !result.AnchoredAt.Equal(verifiedAt) {
						t.Fatalf("receipt does not report authenticated time %s: %+v", verifiedAt, result)
					}
				})
			}
			for _, tc := range []struct {
				name string
				at   time.Time
			}{
				{"zero", time.Time{}},
				{"earlier", verifiedAt.Add(-24 * time.Hour)},
				{"later", verifiedAt.Add(24 * time.Hour)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					result, err := auditanchor.VerifyArtifact(encode(tc.at), opts)
					if err == nil && !result.AnchoredAt.Equal(verifiedAt) {
						t.Fatalf("verified receipt attests unsigned outer time %s; signed token time is %s", result.AnchoredAt, verifiedAt)
					}
				})
			}
		})
	}
}
