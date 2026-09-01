// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
)

func FuzzVerifyArtifactAUD53(f *testing.F) {
	f.Add([]byte(`{}`), uint8(0))
	f.Add([]byte("sequence,id,type,tenant_id,time\n"), uint8(2))
	f.Add([]byte("{\"trstctl_record\":\"chain_trailer\"}\n"), uint8(4))
	formats := []auditanchor.Format{
		auditanchor.FormatAuto,
		auditanchor.FormatJWS,
		auditanchor.FormatNDJSON,
		auditanchor.FormatCSV,
		auditanchor.FormatSplunkHEC,
		auditanchor.FormatSentinel,
	}
	f.Fuzz(func(t *testing.T, raw []byte, selector uint8) {
		if len(raw) > auditanchor.MaxArtifactBytes+1 {
			raw = raw[:auditanchor.MaxArtifactBytes+1]
		}
		_, _ = auditanchor.VerifyArtifact(raw, auditanchor.VerificationOptions{
			Format: formats[int(selector)%len(formats)],
			// Invalid trust is deliberate. A malformed artifact can reach every
			// parser, but must never panic or bypass authority verification.
			TSARootDER: []byte{0x30, 0x00}, MaxAnchorDelay: 24 * time.Hour,
		})
	})
}
