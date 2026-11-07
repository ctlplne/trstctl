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

// openConfiguredNetworkAPIBackend builds a backend that changes an EOS,
// FortiGate or BIG-IP device's accounts through its HTTPS management API,
// trusting only the pinned certificate and only the configured egress.
func openConfiguredNetworkAPIBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	caPEM, err := o.resolve(cfg.TLSCARef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClientWithTLS(cfg.Endpoint, cfg.AllowPrivate, false, cfg.PrivateEgressCIDRs, caPEM, cfg.TLSServerName, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	api := dynsecret.NetworkAPIConfig{Vendor: cfg.Type, Endpoint: cfg.Endpoint, HTTPClient: client, AdminUser: cfg.AdminUser, RoleAccounts: cfg.RoleBindings}
	if cfg.Type == "fortigate" {
		api.APIToken, err = o.resolve(cfg.APIKeyRef)
	} else {
		api.AdminPassword, err = o.resolve(cfg.PasswordRef)
	}
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewNetworkAPIBackend(api)
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}
