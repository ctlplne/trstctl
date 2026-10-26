// SPDX-License-Identifier: BUSL-1.1

//go:build !trstctl_core

package main

import (
	"fmt"

	managedkeysigner "trstctl.com/trstctl/ee/managedkeys/signerwiring"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendManagedKeyOptions is the only signer composition seam that can attach
// Enterprise KMS/HSM provider implementations. Keeping it in this tagged file
// means a trstctl_core signer does not link the provider constructors at all.
func appendManagedKeyOptions(opts []signing.ServerOption, lic *license.Manager, configPath, journalDir string) ([]signing.ServerOption, error) {
	if configPath == "" {
		return opts, nil
	}
	if lic == nil || !lic.Has(license.FeatureBYOK) {
		return opts, fmt.Errorf("--managed-keys-config requires an active license with feature %s", license.FeatureBYOK)
	}
	option, err := managedkeysigner.ProviderOption(configPath, journalDir)
	if err != nil {
		return opts, err
	}
	return append(opts, option), nil
}

// appendTenantKEKOptions attaches the HSM-backed tenant domain KEK custody
// (A123): the signer keeps each tenant's domain KEK wrapped by an operator HSM
// key and wraps and unwraps the tenant's data keys itself.
func appendTenantKEKOptions(opts []signing.ServerOption, lic *license.Manager, configPath string) ([]signing.ServerOption, error) {
	if configPath == "" {
		return opts, nil
	}
	if lic == nil || !lic.Has(license.FeatureBYOK) {
		return opts, fmt.Errorf("--tenant-kek-config requires an active license with feature %s", license.FeatureBYOK)
	}
	option, err := managedkeysigner.TenantKEKOption(configPath)
	if err != nil {
		return opts, err
	}
	return append(opts, option), nil
}
