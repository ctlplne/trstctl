// SPDX-License-Identifier: BUSL-1.1

package inputtext

import (
	"testing"
)

func TestValidateJSONStringsRejectsPostgresJSONBPoison(t *testing.T) {
	for name, raw := range map[string]string{
		"lone high surrogate": `{"attributes":{"x":"\ud800"}}`,
		"lone low surrogate":  `{"attributes":{"x":"\udc00"}}`,
		"wrong second half":   `{"attributes":{"x":"\ud800\u0041"}}`,
		"numeric overflow":    `{"attributes":{"n":1e999999}}`,
		"tiny exponent":       `{"attributes":{"n":1e-999999}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateJSONStrings([]byte(raw)); err == nil {
				t.Fatal("accepted JSON that PostgreSQL jsonb cannot store")
			}
		})
	}
	for _, raw := range []string{
		`{"attributes":{"x":"\ud83d\ude00"}}`,
		`{"attributes":{"x":"\\ud800","n":"1e999999"}}`,
		`{"attributes":{"n":1e1000}}`,
	} {
		if err := ValidateJSONStrings([]byte(raw)); err != nil {
			t.Errorf("valid JSONB input %s rejected: %v", raw, err)
		}
	}
}
