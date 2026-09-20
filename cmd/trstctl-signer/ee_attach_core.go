// SPDX-License-Identifier: BUSL-1.1

//go:build trstctl_core

package main

import (
	"fmt"

	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendManagedKeyOptions is inert in the core-only artifact. The provider
// implementation file is excluded by the same build tag, so this refusal cannot
// accidentally retain AWS/Azure/GCP/PKCS11/TPM/YubiHSM constructors in the link.
func appendManagedKeyOptions(opts []signing.ServerOption, _ *license.Manager, configPath, _ string) ([]signing.ServerOption, error) {
	if configPath != "" {
		return opts, fmt.Errorf("--managed-keys-config is unavailable in the trstctl_core signer")
	}
	return opts, nil
}
