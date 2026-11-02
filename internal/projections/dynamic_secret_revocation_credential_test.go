// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

// The projection keeps a revoked lease's sealed credential exactly when dynsecret
// would revoke it by presenting the credential: an OAuth access token, whose
// provider reference dynsecret writes and reads as "oauth:<digest>:<expiry>"
// (A239). Any other reference (a database user, an AWS STS session, a TOTP
// step) drops it at the transition.
func TestDynamicSecretRevocationNeedsCredentialMatchesOAuthReferencesA239(t *testing.T) {
	oauth := "oauth:00112233445566778899aabbccddeeff:1793620860"
	if expiry, ok := dynsecret.OAuthExpiration(oauth); !ok || !expiry.Equal(time.Unix(1793620860, 0).UTC()) {
		t.Fatalf("dynsecret does not read %q as an access-token reference", oauth)
	}
	if !dynamicSecretRevocationNeedsCredential(oauth) {
		t.Fatal("an access-token lease drops its credential at the revoke transition")
	}
	for _, ref := range []string{"trstctl_reader_7f3a", "totp-step-59787362", "arn:aws:sts::123456789012:assumed-role/app/lease", ""} {
		if dynamicSecretRevocationNeedsCredential(ref) {
			t.Errorf("a %q lease keeps its credential past revocation", ref)
		}
		if _, ok := dynsecret.OAuthExpiration(ref); ok {
			t.Errorf("dynsecret reads %q as an access-token reference", ref)
		}
	}
}
