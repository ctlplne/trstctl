// SPDX-License-Identifier: LicenseRef-trstctl-EE

package retirement

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func validRequested() RequestedV1 {
	required := []byte(`{"registered":["credential:leaf-1"]}`)
	return RequestedV1{
		TenantID: "11111111-1111-1111-1111-111111111111", KeyID: "ca-old", SignerHandle: "signer-ca-old",
		FinalEpoch: 7, LedgerPosition: 41, RequiredSet: required, RequiredSetDigest: crypto.SHA256Sum(required),
		AuditChainHead: crypto.SHA256Sum([]byte("audit")), CompletionEventsDigest: crypto.SHA256Sum([]byte("completion")),
		RevocationCompletionDigest: crypto.SHA256Sum([]byte("revocation")), KeyClass: "ca-signing-key",
	}
}

func TestRequestedCommandIdentityBindsEveryFrozenEvidenceByte(t *testing.T) {
	base := validRequested()
	first := CommandEventID(base)
	if first == "" || CommandEventID(base) != first {
		t.Fatalf("command identity is not stable: %q then %q", first, CommandEventID(base))
	}
	changed := base
	changed.AuditChainHead = crypto.SHA256Sum([]byte("different-audit-head"))
	if CommandEventID(changed) == first {
		t.Fatal("different audit evidence reused the same irreversible command identity")
	}
	if TerminalEventID(first, StatusRefused) == TerminalEventID(first, StatusDestroyed) {
		t.Fatal("refusal and destruction share a terminal event identity")
	}
}

func TestRequestedRejectsTruncatedPublicEvidenceDigests(t *testing.T) {
	for name, mutate := range map[string]func(*RequestedV1){
		"audit":      func(v *RequestedV1) { v.AuditChainHead = []byte{1} },
		"completion": func(v *RequestedV1) { v.CompletionEventsDigest = []byte{1} },
		"revocation": func(v *RequestedV1) { v.RevocationCompletionDigest = []byte{1} },
	} {
		t.Run(name, func(t *testing.T) {
			value := validRequested()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("truncated evidence digest was admitted")
			}
		})
	}
}

func TestFinalizationContextRejectsUnknownFieldsAndPreservesDigests(t *testing.T) {
	requested := validRequested()
	raw, err := EncodeFinalizationContext("command-1", requested)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"shadow_command":"command-2"}`)...)
	if _, err := DecodeFinalizationContext(raw); err == nil {
		t.Fatal("ambiguous signer finalization context accepted an unknown command field")
	}
}
