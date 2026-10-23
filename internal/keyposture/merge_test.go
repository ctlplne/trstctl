// SPDX-License-Identifier: BUSL-1.1

package keyposture

import (
	"reflect"
	"testing"
)

// Two readers' verdicts on one certificate combine: every weak-key reason once,
// and the first distrust match.
func TestVerdictMergeUnionsReasonsAndKeepsTheFirstDistrust(t *testing.T) {
	bytesVerdict := Verdict{WeakReasons: []string{"RSA-1024 is below the 2048-bit minimum"}, DistrustEntry: "EM OV TLS CA - G3C", DistrustHow: "issuer_key_id"}
	audit := Verdict{WeakReasons: []string{"the RSA modulus shares a prime with 1 other key(s) in this inventory, so each of them can be factored", "RSA-1024 is below the 2048-bit minimum"},
		DistrustEntry: "Other", DistrustHow: "itself"}
	got := bytesVerdict.Merge(audit)
	want := []string{"RSA-1024 is below the 2048-bit minimum", "the RSA modulus shares a prime with 1 other key(s) in this inventory, so each of them can be factored"}
	if !reflect.DeepEqual(got.WeakReasons, want) || got.DistrustEntry != "EM OV TLS CA - G3C" || got.DistrustHow != "issuer_key_id" {
		t.Fatalf("merge = %+v", got)
	}
	if got := (Verdict{}).Merge(audit); got.DistrustEntry != "Other" || len(got.WeakReasons) != 2 {
		t.Fatalf("merge into empty = %+v", got)
	}
	// The server's own weak-key reasons (its blocklists) join the reporter's.
	meta, risk := MergeReported(map[string]string{"key_weak_reason": "reported reason", "key_strength": "weak"}, Verdict{WeakReasons: []string{"the RSA key is on the blocklist b"}}, 10)
	if v := FromStringMetadata(meta); len(v.WeakReasons) != 2 || risk < RiskWeak {
		t.Fatalf("merged report = %+v risk %d", meta, risk)
	}
}
