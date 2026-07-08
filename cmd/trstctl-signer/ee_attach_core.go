// SPDX-License-Identifier: MPL-2.0

//go:build trstctl_core

package main

import (
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendEEOptions is the core-build stub: no ee/ attaches, so no PCAS minter and no
// licensed key factory. The license manager is accepted for signature parity with
// the EE seam and ignored.
func appendEEOptions(opts []signing.ServerOption, _ *license.Manager, _ string, _ seal.KeyWrapper) []signing.ServerOption {
	return opts
}
