// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

// ADReconcileConfig is the operator's separate reset authority. Identity pins
// prevent a replacement account at the same DN from inheriting this grant.
// Credential references are resolved only by the outbox worker.
type ADReconcileConfig struct {
	BindDN       string   `json:"bind_dn"`
	PasswordRef  string   `json:"password_ref"`
	SID          string   `json:"sid"`
	GUID         string   `json:"guid"`
	AllowedRoles []string `json:"allowed_roles"`
}

func validateADReconcile(where string, c DynamicSecretProviderConfig) []error {
	p := c.ADReconcile
	if p == nil {
		return nil
	}
	if c.Type != "ldap" || c.DirectoryMode != "active_directory" {
		return []error{fmt.Errorf("%s ad_reconcile is only valid for explicit active_directory", where)}
	}
	var errs []error
	dn, err := ldap.ParseDN(strings.TrimSpace(p.BindDN))
	if err != nil || strings.TrimSpace(p.BindDN) == "" {
		errs = append(errs, fmt.Errorf("%s ad_reconcile.bind_dn must name one directory principal", where))
	}
	same := func(other string) bool {
		parsed, e := ldap.ParseDN(strings.TrimSpace(other))
		return err == nil && e == nil && dn.EqualFold(parsed)
	}
	if same(c.BindDN) {
		errs = append(errs, fmt.Errorf("%s reconcile and ordinary rotation principals must differ", where))
	}
	if validateCredentialRef(p.PasswordRef) != nil || strings.TrimSpace(p.PasswordRef) == "" {
		errs = append(errs, fmt.Errorf("%s ad_reconcile.password_ref must name a protected credential reference", where))
	}
	canonicalRef := func(ref string) string {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "file:") {
			return "file:" + filepath.Clean(strings.TrimPrefix(ref, "file:"))
		}
		return ref
	}
	if canonicalRef(p.PasswordRef) == canonicalRef(c.PasswordRef) {
		errs = append(errs, fmt.Errorf("%s reconcile and ordinary credential references must differ", where))
	}
	if !windependents.ValidAccountSID(p.SID) || !strings.HasPrefix(p.SID, "S-1-5-21-") {
		errs = append(errs, fmt.Errorf("%s ad_reconcile.sid must pin a domain account SID", where))
	}
	guid, e := hex.DecodeString(p.GUID)
	if e != nil || len(guid) != 16 || strings.Trim(p.GUID, "0") == "" {
		errs = append(errs, fmt.Errorf("%s ad_reconcile.guid must pin the native object GUID", where))
	}
	if len(p.AllowedRoles) == 0 {
		errs = append(errs, fmt.Errorf("%s ad_reconcile.allowed_roles must name explicit single-account roles", where))
	}
	allowed := map[string]bool{}
	for _, role := range c.AllowedRoles {
		allowed[role] = true
	}
	seen := map[string]bool{}
	for _, role := range p.AllowedRoles {
		if role == "" || !allowed[role] || seen[role] || c.RoleBindings[role] == "" || len(c.RotationAccounts[role]) != 0 {
			errs = append(errs, fmt.Errorf("%s reconcile role %q must be unique, allowed and bound to one existing account", where, role))
		}
		seen[role] = true
		if same(c.RoleBindings[role]) {
			errs = append(errs, fmt.Errorf("%s reconcile principal cannot be its managed target", where))
		}
	}
	return errs
}
