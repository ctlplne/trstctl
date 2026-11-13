// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// M4-L2: secrets.machine_auth_single_use_limit is 0 (the default) or a limit
// up to 10,000,000; a negative or larger value fails startup.
func TestMachineAuthSingleUseLimitIsValidatedM4L2(t *testing.T) {
	for _, n := range []int{0, 1, 2, DefaultMachineAuthSingleUseLimit, 10_000_000} {
		c := Default()
		c.Secrets.MachineAuthSingleUseLimit = n
		if err := c.Validate(); err != nil {
			t.Fatalf("limit %d rejected: %v", n, err)
		}
	}
	for _, n := range []int{-1, 10_000_001} {
		c := Default()
		c.Secrets.MachineAuthSingleUseLimit = n
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "secrets.machine_auth_single_use_limit") {
			t.Fatalf("limit %d error = %v; want the setting named", n, err)
		}
	}
}
