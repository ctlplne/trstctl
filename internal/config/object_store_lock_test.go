// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A208: Object Lock on the object store is opt-in, set as a mode and a
// retention together: GOVERNANCE or COMPLIANCE, for at least a day.
func TestObjectStoreObjectLockIsAModeAndARetentionOfADayOrMore(t *testing.T) {
	ok := validObjectStore()
	if errs := validateObjectStore(ok); len(errs) != 0 {
		t.Fatalf("a store without Object Lock = %v", errs)
	}
	ok.ObjectLockMode, ok.ObjectLockRetention = "governance", "2160h"
	if errs := validateObjectStore(ok); len(errs) != 0 {
		t.Fatalf("a valid Object Lock = %v", errs)
	}
	for name, tc := range map[string]struct {
		mode, retention, want string
	}{
		"mode without retention": {"COMPLIANCE", "", "set together"},
		"retention without mode": {"", "720h", "set together"},
		"unknown mode":           {"LEGAL", "720h", "GOVERNANCE or COMPLIANCE"},
		"short retention":        {"COMPLIANCE", "12h", "at least 24h"},
		"unparsable retention":   {"COMPLIANCE", "a month", "object_lock_retention"},
	} {
		o := validObjectStore()
		o.ObjectLockMode, o.ObjectLockRetention = tc.mode, tc.retention
		errs := validateObjectStore(o)
		var joined []string
		for _, err := range errs {
			joined = append(joined, err.Error())
		}
		if !strings.Contains(strings.Join(joined, "; "), tc.want) {
			t.Fatalf("%s: errs = %v, want %q", name, errs, tc.want)
		}
	}
}
