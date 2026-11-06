// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// RestoreStaticCredential restores only a configured, single-account AD role.
// Restoring the vault alone cannot undo an in-place directory password change.
// The reset's undisclosed intermediate also invalidates the rejected successor
// during AD's old-password grace period. Native authentication must succeed
// before the worker publishes the recovered value.
func (b *LDAPBackend) RestoreStaticCredential(ctx context.Context, role, ref string, raw []byte) error {
	if !b.activeDirectory {
		return errors.New("dynsecret AD: native restoration requires the explicit directory profile")
	}
	dn, ok := b.roleGroups[role]
	if !ok || !sameADRestoreDN(dn, ref) {
		return errors.New("dynsecret AD: restoration changed the configured account")
	}
	if _, paired := b.rotationAccounts[role]; paired {
		return errors.New("dynsecret AD: paired roles do not use in-place restoration")
	}
	var c struct {
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	defer func() { secret.Wipe(c.Password) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || !sameADRestoreDN(c.BindDN, dn) || len(c.Password) < 16 || len(c.Password) > 1024 {
		return errors.New("dynsecret AD: predecessor does not bind the configured account")
	}
	if err := ldapbind.ValidateADRecoveryPassword(c.Password); err != nil {
		return err
	}
	held, err := secret.NewFrom(c.Password)
	secret.Wipe(c.Password)
	if err != nil {
		return err
	}
	defer held.Destroy()
	if _, err = b.inspectADAccount(ctx, dn, false); err != nil {
		return err
	}
	if err = held.Use(func(password []byte) error { return b.resetADPasswordWithRecovery(ctx, dn, password, true) }); err != nil {
		return err
	}
	// The recovery password remains locked; constructing another credential
	// document would only create an unnecessary plaintext copy.
	if _, err = b.inspectADAccount(ctx, dn, true); err != nil {
		return err
	}
	return held.Use(func(password []byte) error {
		conn, err := ldapbind.DialPinned(ctx, b.adRoute(), dn, password)
		if err != nil {
			return err
		}
		return conn.Close()
	})
}
func sameADRestoreDN(a, b string) bool {
	left, err := ldap.ParseDN(a)
	right, e := ldap.ParseDN(b)
	return err == nil && e == nil && left.EqualFold(right)
}
