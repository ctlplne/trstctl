// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateFindingShapeBeforeAppend(t *testing.T) {
	for _, test := range []struct {
		name, kind, ref, metadata string
		valid                     bool
	}{
		{"ordinary", "api_key", "service", `{}`, true},
		{"empty ref", "api_key", " ", `{}`, false},
		{"oversized ref", "api_key", strings.Repeat("r", MaxFindingRefBytes+1), `{}`, false},
		{"metadata array", "api_key", "service", `[]`, false},
		{"malformed metadata", "api_key", "service", `{`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateFindingShape(test.kind, test.ref, "agent:service", "fingerprint", []byte(test.metadata))
			if test.valid && err != nil || !test.valid && !errors.Is(err, ErrFindingShape) {
				t.Fatalf("finding validation = %v, valid=%v", err, test.valid)
			}
		})
	}
}
