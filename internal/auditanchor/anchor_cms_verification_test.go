// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
)

func TestOfflineReceiptDistinguishesVerifiedCMSFromLegacyManifest(t *testing.T) {
	records, head := exportRecords(t)
	h := newHarness(t, records[len(records)-1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	signer, original := signedEnvelopeAUD53(t, records, head, anchor)
	for _, format := range []auditanchor.Format{auditanchor.FormatJWS, auditanchor.FormatCSV, auditanchor.FormatNDJSON, auditanchor.FormatSplunkHEC, auditanchor.FormatSentinel} {
		t.Run(string(format), func(t *testing.T) {
			for _, variant := range []string{"present-authentic", "legacy-absent", "present-malformed"} {
				t.Run(variant, func(t *testing.T) {
					changed := anchor
					token := *anchor.Token
					changed.Token = &token
					switch variant {
					case "legacy-absent":
						token.DER = nil
					case "present-malformed":
						token.DER = append([]byte("not-a-CMS-token:"), token.TSACertDER...)
						token.DER = append(token.DER, token.Info.HashedMessage...)
					}
					var artifact []byte
					if format == auditanchor.FormatJWS {
						var envelope auditanchor.EvidenceEnvelope
						if err := json.Unmarshal(original, &envelope); err != nil {
							t.Fatal(err)
						}
						envelope.Anchor = changed
						artifact, err = json.Marshal(envelope)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						var out bytes.Buffer
						if err := auditanchor.WriteRecords(&out, format, records, "", head, changed); err != nil {
							t.Fatal(err)
						}
						artifact = out.Bytes()
					}
					result, err := auditanchor.VerifyArtifact(artifact, auditanchor.VerificationOptions{Format: format, AuditKeys: signer.JWKS(), TSARootDER: h.rootDER, MaxAnchorDelay: time.Hour})
					if variant == "present-malformed" {
						if err == nil {
							t.Fatal("malformed present CMS must not fall back to legacy verification")
						}
						return
					}
					if err != nil || !result.AnchorVerified {
						t.Fatalf("authenticated manifest must remain valid: %v", err)
					}
					raw, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					var receipt map[string]any
					if err := json.Unmarshal(raw, &receipt); err != nil {
						t.Fatal(err)
					}
					verified, present := receipt["timestamp_artifact_verified"].(bool)
					if !present || verified != (variant == "present-authentic") {
						t.Fatalf("receipt must distinguish verified CMS from a legacy manifest: %s", raw)
					}
				})
			}
		})
	}
}
