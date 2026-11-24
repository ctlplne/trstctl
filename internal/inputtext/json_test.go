// SPDX-License-Identifier: BUSL-1.1

package inputtext

import (
	"errors"
	"testing"
)

func TestValidateJSONStringsDecodesKeysAndValues(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"nested":{"bad\u0000key":"value"}}`),
		[]byte(`{"nested":["bad\u0000value"]}`),
	} {
		if err := ValidateJSONStrings(raw); !errors.Is(err, ErrNUL) {
			t.Errorf("%q: error = %v, want NUL", raw, err)
		}
	}
	if err := ValidateJSONStrings([]byte(`{"literal":"\\u0000"}`)); err != nil {
		t.Errorf("literal backslash escape was refused: %v", err)
	}
	if err := ValidateJSONStrings([]byte("public event")); err != nil {
		t.Errorf("opaque non-JSON event was refused: %v", err)
	}
	if err := ValidateJSONStrings([]byte{0}); err != nil {
		t.Errorf("opaque binary event was refused: %v", err)
	}
	if err := ValidateJSONStrings([]byte{'"', 0xff, '"'}); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("invalid UTF-8 JSON string: %v", err)
	}
}
