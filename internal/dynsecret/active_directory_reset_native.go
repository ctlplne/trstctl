// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type adPreparedResetNative struct {
	backend     *LDAPBackend
	preparation adStaticPreparation
	route       ldapbind.PinnedTLS
}

func newADPreparedResetNative(b *LDAPBackend, p adStaticPreparation) *adPreparedResetNative {
	route := b.adRoute()
	route.Address = p.NativeAddress
	return &adPreparedResetNative{backend: b, preparation: p, route: route}
}
func (n *adPreparedResetNative) Observe(ctx context.Context) (adNativeResetIdentity, error) {
	return n.backend.inspectADResetIdentity(ctx, n.preparation.DN, n.route)
}
func (n *adPreparedResetNative) check(ctx context.Context, expected adNativeResetIdentity, forBind bool) error {
	observed, e := n.backend.inspectADResetIdentity(ctx, n.preparation.DN, n.route, forBind)
	if e != nil {
		return e
	}
	if _, e = n.preparation.resetPosition(observed); e != nil {
		return e
	}
	if observed != expected {
		return errors.New("dynsecret AD: native generation changed before its exact operation")
	}
	return nil
}
func (n *adPreparedResetNative) Prove(ctx context.Context, expected adNativeResetIdentity, password []byte) error {
	if e := n.check(ctx, expected, true); e != nil {
		return e
	}
	conn, e := ldapbind.DialPinned(ctx, n.route, n.preparation.DN, password)
	if e != nil {
		return e
	}
	return conn.Close()
}
func (n *adPreparedResetNative) Reset(ctx context.Context, expected adNativeResetIdentity, password []byte, recovery bool) error {
	if e := n.check(ctx, expected, false); e != nil {
		return e
	}
	// Recheck immediately before the native call on the fixed DC route. This
	// detects serial outside changes; AD's administrative reset has no atomic
	// expected-version condition against a concurrent higher-privilege admin.
	return n.backend.bindPassword.Use(func(admin []byte) error {
		if recovery {
			return ldapbind.ResetADRecoveryPassword(ctx, n.route, n.backend.bindDN, admin, n.preparation.DN, password)
		}
		return ldapbind.ResetADPassword(ctx, n.route, n.backend.bindDN, admin, n.preparation.DN, password)
	})
}
func decodeADPredecessorPassword(raw []byte, dn string) (*secret.Buffer, error) {
	var value struct {
		DN       string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	defer func() { secret.Wipe(value.Password) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &value) != nil || !sameADRestoreDN(value.DN, dn) || ldapbind.ValidateADRecoveryPassword(value.Password) != nil {
		return nil, errors.New("dynsecret AD: retained predecessor does not bind the exact native account")
	}
	return secret.NewFrom(value.Password)
}
func newADPreparedPassword() (*secret.Buffer, error) {
	random, e := randomSecretHex(24)
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(random)
	held, e := secret.New(4 + len(random))
	if e != nil {
		return nil, e
	}
	copy(held.Bytes(), []byte("Tr5!"))
	copy(held.Bytes()[4:], random)
	return held, nil
}

// ValidateADRecoveryCredential checks the exact account and native recovery
// password format without opening a connection or guessing a password.
func ValidateADRecoveryCredential(raw []byte, dn string) error {
	held, err := decodeADPredecessorPassword(raw, dn)
	if err != nil {
		return err
	}
	held.Destroy()
	return nil
}
