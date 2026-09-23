// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/server"
)

func requireTenantAuthAttachment(cfg *config.Config, deps *server.Deps) error {
	if (cfg.Auth.SAML.Enabled || cfg.Auth.LDAP.Enabled || cfg.Auth.SCIM.Enabled) && deps.TenantAuthFactory == nil {
		return server.ErrEnterpriseSSORequired
	}
	return nil
}
