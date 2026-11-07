// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/dynsecret"
)

// configuredNetworkDeviceProvider is a network device provider (A270): its
// in-place rotation has a native inverse, so a failed rotation puts the
// predecessor back on the device and proves it signs in again.
type configuredNetworkDeviceProvider struct{ *configuredDynamicProvider }

func (p *configuredNetworkDeviceProvider) RestoreStaticCredential(ctx context.Context, role, ref string, credential []byte) error {
	if !p.AllowsStaticRotation(role) {
		return errors.New("server: network device restore role is not allowed")
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	restorer, ok := backend.(dynsecret.StaticCredentialRestorer)
	if !ok {
		return errors.New("server: network device backend cannot restore its credential")
	}
	return restorer.RestoreStaticCredential(ctx, role, ref, credential)
}

// openConfiguredNetworkDeviceBackend reads the administrator's password into
// a backend that changes the device's accounts through its CLI.
func openConfiguredNetworkDeviceBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewNetworkDeviceBackend(dynsecret.NetworkDeviceConfig{Vendor: cfg.Type, Address: cfg.Addr,
		HostKeyFingerprint: cfg.HostKeyFingerprint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleAccounts: cfg.RoleBindings})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}
