// SPDX-License-Identifier: BUSL-1.1

package gate

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

func FuzzGatedDestructionEvidenceStream(f *testing.F) {
	valid, err := EncodeLedgerSegment(1, []eventspec.Event{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"version":1,"final_epoch":1,"events":[`))
	f.Add([]byte(`{"version":1,"final_epoch":1,"events":[]}`))
	g, err := New(Config{SignerID: "fuzz-stream", Sink: NewMemorySink()})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		req := signing.GatedDestroyRequest{
			TenantID: "fuzz-tenant", Handle: "fuzz-handle", SubjectRef: "fuzz-key",
			AssertedFinalEpoch: 1, LedgerPosition: 1,
			AuditChainHead:             NewAuditChainHead(),
			SatisfactionEvidenceDigest: crypto.SHA256Sum(raw),
		}
		_, _ = g.VerifyGatedDestroyStream(context.Background(), req, bytes.NewReader(raw))
	})
}
