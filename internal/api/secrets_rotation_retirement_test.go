// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strconv"
	"strings"
	"testing"
)

// A240: the retirement gate takes up to 32 distinct consumer labels and an
// approved deadline of at most 30 days; consumers without a deadline are
// refused, because a consumer that never reports would hold the predecessor
// forever.
func TestStaticRotationRetirementGateValidation(t *testing.T) {
	many := make([]string, 33)
	for i := range many {
		many[i] = "consumer-" + strconv.Itoa(i)
	}
	for name, tc := range map[string]struct {
		consumers []string
		after     int
		want      string
	}{
		"none":                {nil, 0, ""},
		"deadline only":       {nil, 3600, ""},
		"consumers":           {[]string{"orders-api", "agent:host-1/orders@prod"}, 600, ""},
		"thirty days":         {[]string{"orders-api"}, 2592000, ""},
		"no deadline":         {[]string{"orders-api"}, 0, "consumers needs retire_after_seconds"},
		"negative":            {nil, -1, "retire_after_seconds is between 0 and 2592000"},
		"over thirty days":    {nil, 2592001, "retire_after_seconds is between 0 and 2592000"},
		"duplicate":           {[]string{"orders-api", "orders-api"}, 60, "distinct consumer labels"},
		"not a label":         {[]string{"orders api"}, 60, "distinct consumer labels"},
		"too long":            {[]string{strings.Repeat("a", 129)}, 60, "distinct consumer labels"},
		"thirty-three labels": {many, 60, "at most 32"},
	} {
		err := validateStaticRotationRetirement(tc.consumers, tc.after)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if refuseRetirementGateOutsideStatic("connector:edge", []string{"orders-api"}, 60) == nil ||
		refuseRetirementGateOutsideStatic("dynamic-lease:pg", nil, 60) == nil ||
		refuseRetirementGateOutsideStatic("orders-pg", []string{"orders-api"}, 60) != nil ||
		refuseRetirementGateOutsideStatic("connector:edge", nil, 0) != nil {
		t.Fatal("the gate fields belong to static-provider rotations only")
	}
}
