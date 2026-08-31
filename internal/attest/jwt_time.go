// SPDX-License-Identifier: MPL-2.0

package attest

import (
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// ValidateJWTTimeWindow checks public timing claims AFTER signature verification.
// Workload JWT proofs must expire. Optional nbf (not before) and iat (issued at)
// cannot be in the future. The supported provider profiles use integer Unix
// seconds; null, strings and out-of-range numbers are not missing/optional times.
//
// No clock-skew allowance is silently added: expiry stays exclusive and a stated
// start time is inclusive. Operators must synchronize the verifier's clock.
// Signature, issuer, audience and provider-specific identity checks remain the
// caller's responsibility. This function does not record or authorize anything.
func ValidateJWTTimeWindow(claimsJSON []byte, at time.Time) error {
	// Map lookup is intentionally case-sensitive. encoding/json's struct-field
	// matching would otherwise accept eXp as the registered exp claim.
	var claims map[string]json.RawMessage
	defer func() {
		for _, raw := range claims {
			secret.Wipe(raw)
		}
	}()
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return fmt.Errorf("attest: malformed workload JWT time claims")
	}
	expiry, present, err := jwtTimeSeconds(claims["exp"])
	if err != nil || !present {
		return fmt.Errorf("attest: workload JWT requires an integer-second exp timestamp")
	}
	now := at.Unix()
	if now >= expiry {
		return fmt.Errorf("attest: workload JWT token expired")
	}
	for _, claim := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"nbf", claims["nbf"]},
		{"iat", claims["iat"]},
	} {
		seconds, present, err := jwtTimeSeconds(claim.raw)
		if err != nil {
			return fmt.Errorf("attest: workload JWT %s must be an integer-second timestamp", claim.name)
		}
		if present && now < seconds {
			return fmt.Errorf("attest: workload JWT %s is in the future", claim.name)
		}
	}
	return nil
}

func jwtTimeSeconds(raw json.RawMessage) (int64, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	var seconds *int64
	if err := json.Unmarshal(raw, &seconds); err != nil || seconds == nil {
		return 0, false, fmt.Errorf("attest: invalid integer-second timestamp")
	}
	return *seconds, true, nil
}
