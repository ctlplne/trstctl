// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/signing"
)

func appendEEOptions(opts []signing.ServerOption) []signing.ServerOption {
	return append(opts, signing.WithKeyFactory(eepqc.NewSignerKeyFactory()))
}
