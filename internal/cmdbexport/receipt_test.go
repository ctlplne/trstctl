// SPDX-License-Identifier: BUSL-1.1

package cmdbexport

import (
	"strings"
	"testing"
)

func TestIREReceiptRequiresOneSuccessfulCertificateItem(t *testing.T) {
	const good = `{"result":{"hasError":false,"items":[{"className":"cmdb_ci_certificate","sysId":"0123456789abcdef0123456789abcdef","operation":"INSERT","errorCount":0,"errors":[]}]}}`
	if id, err := ParseReceipt(strings.NewReader(good)); err != nil || id != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("receipt = %q %v", id, err)
	}
	for _, operation := range []string{"UPDATE", "NO_CHANGE"} {
		if _, err := ParseReceipt(strings.NewReader(strings.Replace(good, "INSERT", operation, 1))); err != nil {
			t.Fatalf("supported IRE operation %s: %v", operation, err)
		}
	}
	for _, bad := range []string{
		`{}`, `{"result":{"items":[]}}`,
		strings.Replace(good, `"hasError":false`, `"hasError":true`, 1),
		strings.Replace(good, `"errorCount":0`, `"errorCount":1`, 1),
		strings.Replace(good, `"errors":[]`, `"errors":[{"message":"reconciliation refused"}]`, 1),
		strings.Replace(good, "cmdb_ci_certificate", "cmdb_ci_server", 1),
		strings.Replace(good, "0123456789abcdef0123456789abcdef", "../../sys_user", 1),
		strings.Replace(good, "INSERT", "DELETE", 1), good + `{}`,
	} {
		if id, err := ParseReceipt(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted %q as %s", bad, id)
		}
	}
}

func TestReadbackRequiresExactCertificateValues(t *testing.T) {
	want := map[string]string{"fingerprint": strings.Repeat("a", 64), "state": "revoked", "valid_to": "2026-10-29 12:00:00"}
	const id = "0123456789abcdef0123456789abcdef"
	good := `{"result":{"sys_id":"` + id + `","fingerprint":"` + want["fingerprint"] + `","state":"revoked","valid_to":"2026-10-29 12:00:00"}}`
	if err := VerifyReadback(strings.NewReader(good), id, want); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(good, "revoked", "issued", 1), strings.Replace(good, id, "fedcba9876543210fedcba9876543210", 1), strings.Replace(good, want["fingerprint"], strings.Repeat("b", 64), 1), `{}`, good + `{}`} {
		if err := VerifyReadback(strings.NewReader(bad), id, want); err == nil {
			t.Fatalf("accepted false readback: %s", bad)
		}
	}
}

func FuzzIREReceiptCannotReturnAnUnsafeID(f *testing.F) {
	f.Add(`{"result":{"items":[]}}`)
	f.Add(`{"result":{"hasError":false,"items":[{"className":"cmdb_ci_certificate","sysId":"0123456789abcdef0123456789abcdef","operation":"INSERT","errorCount":0}]}}`)
	f.Fuzz(func(t *testing.T, body string) {
		id, err := ParseReceipt(strings.NewReader(body))
		_ = VerifyReadback(strings.NewReader(body), "0123456789abcdef0123456789abcdef", map[string]string{"state": "revoked"})
		if err == nil && !validSysID(id) {
			t.Fatalf("unsafe id %q", id)
		}
	})
}
