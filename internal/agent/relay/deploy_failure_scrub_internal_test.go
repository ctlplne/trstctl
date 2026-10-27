// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A192: what the failure log keeps of a connector's error holds no secret: the
// redeemed values, a private key in any PEM form, an authorization header or
// scheme token, and credential-shaped fields are removed, the entry is one
// line, and a long reason is cut on a character boundary.
func TestScrubFailureRemovesKeysTokensAndCredentialFields(t *testing.T) {
	material := Material{"secret://appliance-admin": []byte("hunter2-lab")}
	text := "login with hunter2-lab failed\n" +
		"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBl2c2VjcmV0a2V5bWF0ZXJpYWw=\n-----END EC PRIVATE KEY-----\n" +
		"retry with Authorization: Bearer eyJhbGciOi.c2Vzc2lvbg.c2ln or Basic YWRtaW46aHVudGVy and token=s3cr3t-value " +
		"password: \"p@ss\" api_key=AKIAEXAMPLE \x07 -----BEGIN RSA PRIVATE KEY-----\nMIIEtruncated"
	got := scrubFailure(text, material)
	for _, leaked := range []string{"hunter2-lab", "MHcCAQEEIBl2", "eyJhbGciOi", "YWRtaW46aHVudGVy", "s3cr3t-value", "p@ss", "AKIAEXAMPLE", "MIIEtruncated", "\x07", "\n"} {
		if strings.Contains(got, leaked) {
			t.Errorf("scrubbed reason keeps %q: %s", leaked, got)
		}
	}
	for _, kept := range []string{"login with [redacted] failed", "[redacted PEM]", "Authorization: [redacted]", "Basic [redacted]",
		"token=[redacted]", "api_key=[redacted]", "[redacted private key]"} {
		if !strings.Contains(got, kept) {
			t.Errorf("scrubbed reason lost %q: %s", kept, got)
		}
	}
	long := scrubFailure(strings.Repeat("é", deployFailureLogLimit), nil)
	if !utf8.ValidString(long) || len(long) > deployFailureLogLimit+len("…") || !strings.HasSuffix(long, "…") {
		t.Fatalf("a long reason was not cut on a character boundary: %d bytes, valid %v", len(long), utf8.ValidString(long))
	}
}
