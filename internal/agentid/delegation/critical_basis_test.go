// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/signing"
)

func TestCR295SignerRejectsRepresentationWithoutChainOrAttestation(t *testing.T) {
	repr, err := jsonMarshal(mustRepr(t, "agent instructions", "search"))
	if err != nil {
		t.Fatal(err)
	}
	pre, err := encodePreconditionsForTest(PreconditionsBody{DesignatedClass: "tenant-admin"})
	if err != nil {
		t.Fatal(err)
	}
	f := newGateFixture(t, nil, nil, nil, time.Now)
	res := runGatedIssue(t, f.log, f.gate, signing.IssuancePreconditions{
		TenantID: "t1", TrustAnchorRef: "agent:anyone", Preconditions: pre,
		SubjectRepr: repr, NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour).Unix(),
	}, f.mintKeyOp(t))
	if res.decision.Approved || res.keyOpRan || f.keystore.keyOps() != 0 {
		t.Fatalf("unverified representation approved=%t, key op ran=%t, key ops=%d", res.decision.Approved, res.keyOpRan, f.keystore.keyOps())
	}
	if refusal := decodeRefusalForTest(t, res.decision.RefusalRecord); refusal.FailedCheck != CheckBindingTarget {
		t.Fatalf("refusal check = %q, want %q", refusal.FailedCheck, CheckBindingTarget)
	}
}
