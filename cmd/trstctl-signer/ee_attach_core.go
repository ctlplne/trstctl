// SPDX-License-Identifier: MPL-2.0

//go:build trstctl_core

package main

import "trstctl.com/trstctl/internal/signing"

func appendEEOptions(opts []signing.ServerOption) []signing.ServerOption {
	return opts
}
