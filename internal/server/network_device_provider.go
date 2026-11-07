// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"strings"

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

// DynamicSecretGatewaySSH is a network device role's SSH route (A270): the
// device's SSH address and pinned host key (an iosxe or junos provider's own;
// an eos, fortigate or bigip provider's optional addr and
// host_key_fingerprint) and the account the role rotates, which a session
// signs in as. The enable secret has no sessions.
func (p *configuredNetworkDeviceProvider) DynamicSecretGatewaySSH(role string) (string, string, []string, error) {
	account := strings.TrimSpace(p.cfg.RoleBindings[role])
	switch {
	case !p.AllowsStaticRotation(role) || account == "":
		return "", "", nil, errors.New("the role rotates no device account")
	case account == dynsecret.NetworkEnableAccount:
		return "", "", nil, errors.New("the enable secret signs in no session")
	case strings.TrimSpace(p.cfg.Addr) == "" || p.cfg.HostKeyFingerprint == "":
		return "", "", nil, errors.New("the provider names no SSH address and host key pin for sessions")
	}
	return strings.TrimSpace(p.cfg.Addr), account, []string{p.cfg.HostKeyFingerprint}, nil
}

// openConfiguredRedfishBackend builds a backend that changes a server
// management controller's accounts through Redfish (A271), trusting only the
// pinned certificate and only the configured egress.
func openConfiguredRedfishBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	caPEM, err := o.resolve(cfg.TLSCARef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClientWithTLS(cfg.Endpoint, cfg.AllowPrivate, false, cfg.PrivateEgressCIDRs, caPEM, cfg.TLSServerName, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewRedfishBackend(dynsecret.RedfishConfig{Endpoint: cfg.Endpoint, HTTPClient: client, AdminUser: cfg.AdminUser,
		AdminPassword: password, RoleAccounts: cfg.RoleBindings})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredESXiBackend builds a backend that changes an ESXi host's
// local accounts through the vSphere Web Services API (A271), trusting only
// the pinned certificate and only the configured egress.
func openConfiguredESXiBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	caPEM, err := o.resolve(cfg.TLSCARef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClientWithTLS(cfg.Endpoint, cfg.AllowPrivate, false, cfg.PrivateEgressCIDRs, caPEM, cfg.TLSServerName, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewESXiBackend(dynsecret.ESXiConfig{Endpoint: cfg.Endpoint, HTTPClient: client, AdminUser: cfg.AdminUser,
		AdminPassword: password, RoleAccounts: cfg.RoleBindings})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredVCenterSSOBackend builds a backend that resets vCenter
// single sign-on users' passwords through dir-cli in the appliance's root
// shell and proves them through its REST API (A271).
func openConfiguredVCenterSSOBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	caPEM, err := o.resolve(cfg.TLSCARef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClientWithTLS(cfg.Endpoint, cfg.AllowPrivate, false, cfg.PrivateEgressCIDRs, caPEM, cfg.TLSServerName, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	rootKey, err := o.resolve(cfg.PrivateKeyRef)
	if err != nil {
		return o.fail(err)
	}
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewVCenterSSOBackend(dynsecret.VCenterSSOConfig{Endpoint: cfg.Endpoint, HTTPClient: client, SSHAddress: cfg.Addr,
		HostKeyFingerprint: cfg.HostKeyFingerprint, RootUser: cfg.AdminUser, RootKeyPKCS8: rootKey, SSOAdmin: cfg.SSOAdmin,
		SSOAdminPassword: password, RoleAccounts: cfg.RoleBindings})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredIdPAdminBackend builds a backend that sets an identity
// provider administrator's password through the provider's administration
// API (A272): Okta's SSWS token, Entra's application secret or Google's
// service account key.
func openConfiguredIdPAdminBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	idp := dynsecret.IdPAdminConfig{Vendor: cfg.Type, Endpoint: cfg.Endpoint, AuthorityHost: cfg.AuthorityHost, AllowInsecureLoopback: cfg.AllowInsecureLoopback,
		HTTPClient: client, ClientID: cfg.ClientID, AzureTenant: cfg.AzureTenant, ServiceAccountEmail: cfg.ServiceAccount, Subject: cfg.AdminUser,
		RoleAccounts: cfg.RoleBindings}
	switch cfg.Type {
	case "okta-user":
		idp.APIToken, err = o.resolve(cfg.APIKeyRef)
	case "entra-user":
		idp.ClientSecret, err = o.resolve(cfg.ClientSecretRef)
	case "google-workspace-user":
		idp.ServiceAccountKeyPEM, err = o.resolve(cfg.PrivateKeyRef)
	}
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewIdPAdminBackend(idp)
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// BreakGlassTOTPProvider is the totp provider holding a break-glass role's
// MFA seed, or none (A272).
func (p *configuredDynamicProvider) BreakGlassTOTPProvider(role string) string {
	return strings.TrimSpace(p.cfg.TOTPProviders[role])
}

// BreakGlassHardwareKeyHolders is who holds a break-glass role's hardware
// security keys (A272).
func (p *configuredDynamicProvider) BreakGlassHardwareKeyHolders(role string) []string {
	return append([]string(nil), p.cfg.HardwareKeyHolders[role]...)
}
