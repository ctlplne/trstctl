// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"fmt"
	"trstctl.com/trstctl/internal/hostaccounts"
)

func validateNativeWindowsProvider(where string, c DynamicSecretProviderConfig) []error {
	var errs []error
	if c.Type != "windows" || !c.AllowStaticRotation || len(c.RotationAccounts) != 0 || c.Addr != "" || c.AdminUser != "" || c.PrivateKeyRef != "" || c.HostKeyFingerprint != "" || c.Sudo || c.PasswordRef != "" || c.Endpoint != "" || c.Gateway != nil || c.Desktop != nil || c.Console != nil {
		errs = append(errs, fmt.Errorf("%s native windows needs static rotation and exact host/SID bindings, without SSH, remote or paired-account settings", where))
	}
	seen := map[string]bool{}
	for _, role := range normalizedStrings(c.AllowedRoles) {
		sid := c.RoleBindings[role]
		// Validate the public grant grammar without widening the SSH name grammar.
		machine := sid
		for i := len(sid) - 1; i >= 0; i-- {
			if sid[i] == '-' {
				machine = sid[:i]
				break
			}
		}
		g := hostaccounts.RotationGrant{TenantID: c.TenantID, AgentID: c.WindowsHostAgentID, MachineSID: machine, AccountSID: sid}
		if g.Validate() != nil || seen[sid] {
			errs = append(errs, fmt.Errorf("%s role %q requires one distinct exact local SAM SID", where, role))
		}
		seen[sid] = true
	}
	for role := range c.RoleBindings {
		found := false
		for _, allowed := range normalizedStrings(c.AllowedRoles) {
			found = found || role == allowed
		}
		if !found {
			errs = append(errs, fmt.Errorf("%s native windows binding names an unallowed role", where))
		}
	}
	return errs
}
