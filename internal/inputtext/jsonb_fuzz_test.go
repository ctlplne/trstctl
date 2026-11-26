// SPDX-License-Identifier: BUSL-1.1

package inputtext

import (
	"encoding/json"
	"errors"
	"testing"
)

func FuzzValidateJSONStrings(f *testing.F) {
	for _, seed := range []string{
		`{"x":"\ud800"}`, `{"x":"\ud83d\ude00"}`, `{"x":"\\ud800"}`,
		`{"n":1e999999}`, `{"n":1e-999999}`, `{"n":1e1000}`,
		`{"nested":["\u0000",{"n":123.45}]}`, "opaque event body",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := ValidateJSONStrings(raw)
		if (errors.Is(err, ErrInvalidUnicodeEscape) || errors.Is(err, ErrJSONNumberRange)) && !json.Valid(raw) {
			t.Fatalf("rejected non-JSON opaque event as jsonb poison: %v", err)
		}
	})
}
