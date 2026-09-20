// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
)

// The oracle independently checks every accepted window, including malformed
// optional values. Signature verification is covered by the signed matrix above.
func FuzzJWTTimeWindow(f *testing.F) {
	for _, seed := range []string{
		`{"exp":1900000060,"nbf":1900000000,"iat":1899999999}`,
		`{"exp":1900000060,"nbf":1900000001}`,
		`{"exp":1900000000}`, `{"exp":null}`, `{"exp":0}`,
		`{"exp":1900000060,"nbf":null}`, `{"exp":9223372036854775808}`,
		`{"exp":1900000060,"iat":"later"}`, `{}`, `null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		const now = int64(1_900_000_000)
		if attest.ValidateJWTTimeWindow(raw, time.Unix(now, 0)) != nil {
			return
		}
		var claims map[string]json.RawMessage
		if json.Unmarshal(raw, &claims) != nil {
			t.Fatal("accepted malformed JSON")
		}
		for _, name := range []string{"exp", "nbf", "iat"} {
			value, present := claims[name]
			if !present {
				if name == "exp" {
					t.Fatal("accepted a proof without expiry")
				}
				continue
			}
			var seconds *int64
			if json.Unmarshal(value, &seconds) != nil || seconds == nil {
				t.Fatal("accepted a noninteger time")
			}
			if (name == "exp" && *seconds <= now) || (name != "exp" && *seconds > now) {
				t.Fatal("accepted a proof outside its time window")
			}
		}
	})
}
