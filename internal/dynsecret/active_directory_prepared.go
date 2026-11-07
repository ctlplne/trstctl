// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type adStaticPreparation struct {
	held                     *secret.Buffer
	forwardHeld, inverseHeld *secret.Buffer
	KeyVersion               uint64           `json:"key_version,omitempty"`
	DCInvocationID           string           `json:"dc_invocation_id,omitempty"`
	NativeAddress            string           `json:"native_address,omitempty"`
	ForwardIntermediate      secret.JSONBytes `json:"forward_intermediate,omitempty"`
	InverseIntermediate      secret.JSONBytes `json:"inverse_intermediate,omitempty"`
	Version                  int              `json:"version"`
	Role                     string           `json:"role"`
	OperationID              string           `json:"operation_id"`
	Predecessor              string           `json:"predecessor"`
	ProviderBinding          string           `json:"provider_binding"`
	DN                       string           `json:"bind_dn"`
	Name                     string           `json:"username"`
	GUID                     string           `json:"native_guid"`
	SID                      string           `json:"native_sid"`
	PasswordSetAt            string           `json:"password_set_at"`
	Password                 secret.JSONBytes `json:"password,omitempty"`
}

func validADPreparationHash(v string, n int) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == n && v == strings.ToLower(v)
}
func decodeADStaticPreparation(raw []byte) (adStaticPreparation, error) {
	var p adStaticPreparation
	if len(raw) > 64<<10 {
		return p, errors.New("dynsecret AD: preparation exceeds bound")
	}
	if validateADPreparationFields(raw) != nil || json.Unmarshal(raw, &p) != nil || (p.Version != 1 && p.Version != 2) || len(p.Role) < 1 || len(p.Role) > 512 || len(p.OperationID) < 1 || len(p.OperationID) > 128 || len(p.DN) < 1 || len(p.DN) > 4096 || len(p.Name) < 1 || len(p.Name) > 128 || !validADPreparationHash(p.ProviderBinding, 32) || !validADPreparationHash(p.GUID, 16) || len(p.SID) < 16 || len(p.SID) > 136 || p.PasswordSetAt == "" || len(p.Password) < 16 || len(p.Password) > 1024 {
		p.destroy()
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid bound preparation")
	}
	if _, err := strconv.ParseUint(p.PasswordSetAt, 10, 64); err != nil {
		p.destroy()
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid native password stamp")
	}
	if _, err := hex.DecodeString(p.SID); err != nil {
		p.destroy()
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid native SID")
	}
	if p.Version == 2 {
		address, addressErr := netip.ParseAddrPort(p.NativeAddress)
		if addressErr != nil || address.Port() == 0 || address.String() != p.NativeAddress || p.KeyVersion < 1 || p.KeyVersion > uint64(1<<32-1)-4 || !validADPreparationHash(p.DCInvocationID, 16) || ldapbind.ValidateADGeneratedPassword(p.Password) != nil || ldapbind.ValidateADGeneratedPassword(p.ForwardIntermediate) != nil || ldapbind.ValidateADGeneratedPassword(p.InverseIntermediate) != nil || crypto.ConstantTimeEqual(p.Password, p.ForwardIntermediate) || crypto.ConstantTimeEqual(p.Password, p.InverseIntermediate) || crypto.ConstantTimeEqual(p.ForwardIntermediate, p.InverseIntermediate) {
			p.destroy()
			return adStaticPreparation{}, errors.New("dynsecret AD: incomplete or aliased durable reset generations")
		}
	} else if p.KeyVersion != 0 || p.DCInvocationID != "" || p.NativeAddress != "" || len(p.ForwardIntermediate) > 0 || len(p.InverseIntermediate) > 0 {
		p.destroy()
		return adStaticPreparation{}, errors.New("dynsecret AD: legacy preparation carries another reset format")
	}
	held, err := secret.NewFrom(p.Password)
	secret.Wipe(p.Password)
	if err != nil {
		p.destroy()
		return adStaticPreparation{}, err
	}
	p.held = held
	p.Password = held.Bytes()
	if p.Version == 2 {
		p.forwardHeld, err = secret.NewFrom(p.ForwardIntermediate)
		secret.Wipe(p.ForwardIntermediate)
		if err != nil {
			p.destroy()
			return adStaticPreparation{}, err
		}
		p.ForwardIntermediate = p.forwardHeld.Bytes()
		p.inverseHeld, err = secret.NewFrom(p.InverseIntermediate)
		secret.Wipe(p.InverseIntermediate)
		if err != nil {
			p.destroy()
			return adStaticPreparation{}, err
		}
		p.InverseIntermediate = p.inverseHeld.Bytes()
	}
	return p, nil
}
func (p *adStaticPreparation) destroy() {
	secret.Wipe(p.Password)
	secret.Wipe(p.ForwardIntermediate)
	secret.Wipe(p.InverseIntermediate)
	p.Password = nil
	p.ForwardIntermediate = nil
	p.InverseIntermediate = nil
	for _, held := range []*secret.Buffer{p.held, p.forwardHeld, p.inverseHeld} {
		if held != nil {
			held.Destroy()
		}
	}
	p.held = nil
	p.forwardHeld = nil
	p.inverseHeld = nil
}

// PrepareStaticCredential performs native read-only preflight, then creates the
// password locally. The worker seals it and the predecessor before any reset.
// This deliberately differs from PreparedProvider's local-only key preparation.
func (b *LDAPBackend) PrepareStaticCredential(ctx context.Context, req GenerateRequest, binding string) ([]byte, error) {
	dn, ok := b.roleGroups[req.Role]
	if !b.activeDirectory || !req.Static || !ok || req.LeaseID == "" || !sameADRestoreDN(req.Predecessor, dn) || !validADPreparationHash(binding, 32) {
		return nil, errors.New("dynsecret AD: static preparation changed its configured role/operation")
	}
	if _, paired := b.rotationAccounts[req.Role]; paired {
		return nil, errors.New("dynsecret AD: native in-place preparation is not a paired rotation")
	}
	identity, err := b.inspectADResetIdentity(ctx, dn, b.adRoute())
	if err != nil {
		return nil, err
	}
	if identity.KeyVersion > uint64(1<<32-1)-4 {
		return nil, errors.New("dynsecret AD: native version has no room for the complete reset/inverse sequence")
	}
	password, err := newADPreparedPassword()
	if err != nil {
		return nil, err
	}
	defer password.Destroy()
	forward, err := newADPreparedPassword()
	if err != nil {
		return nil, err
	}
	defer forward.Destroy()
	inverse, err := newADPreparedPassword()
	if err != nil {
		return nil, err
	}
	defer inverse.Destroy()
	p := adStaticPreparation{Version: 2, Role: req.Role, OperationID: req.LeaseID, Predecessor: req.Predecessor, ProviderBinding: binding, DN: dn, Name: identity.Name, GUID: identity.GUID, SID: identity.SID, PasswordSetAt: identity.PasswordSetAt, KeyVersion: identity.KeyVersion, DCInvocationID: identity.DCInvocationID, NativeAddress: identity.NativeAddress, Password: password.Bytes(), ForwardIntermediate: forward.Bytes(), InverseIntermediate: inverse.Bytes()}
	return marshalADStaticPreparation(p)
}

func (b *LDAPBackend) boundADPreparation(ctx context.Context, req GenerateRequest, raw []byte, binding string) (adStaticPreparation, adNativeIdentity, error) {
	p, err := decodeADStaticPreparation(raw)
	if err != nil {
		return p, adNativeIdentity{}, err
	}
	reject := func() (adStaticPreparation, adNativeIdentity, error) {
		p.destroy()
		return adStaticPreparation{}, adNativeIdentity{}, errors.New("dynsecret AD: preparation differs from the frozen native account/operation")
	}
	if b.reconcile != nil && p.Version != 2 {
		return reject()
	}
	if !b.activeDirectory || !req.Static || p.Role != req.Role || p.OperationID != req.LeaseID || p.Predecessor != req.Predecessor || p.ProviderBinding != binding || !sameADRestoreDN(b.roleGroups[req.Role], p.DN) {
		return reject()
	}
	if _, paired := b.rotationAccounts[req.Role]; paired {
		return reject()
	}
	var current adNativeIdentity
	if p.Version == 2 {
		observed, e := newADPreparedResetNative(b, p).Observe(ctx)
		if e != nil {
			p.destroy()
			return adStaticPreparation{}, current, e
		}
		if observed.Name != p.Name || observed.GUID != p.GUID || observed.SID != p.SID {
			return reject()
		}
		if _, e = p.resetPosition(observed); e != nil {
			p.destroy()
			return adStaticPreparation{}, current, e
		}
		current = observed.adNativeIdentity
	} else {
		current, err = b.inspectADIdentity(ctx, p.DN, false, true)
	}
	if err != nil {
		p.destroy()
		return adStaticPreparation{}, current, err
	}
	if current.Name != p.Name || current.GUID != p.GUID || current.SID != p.SID {
		return reject()
	}
	return p, current, nil
}
func (b *LDAPBackend) verifyBoundADPassword(ctx context.Context, dn string, password []byte) error {
	if _, err := b.inspectADAccount(ctx, dn, true); err != nil {
		return err
	}
	conn, err := ldapbind.DialPinned(ctx, b.adRoute(), dn, password)
	if err != nil {
		return err
	}
	return conn.Close()
}
func (b *LDAPBackend) GenerateStaticPrepared(ctx context.Context, req GenerateRequest, raw []byte, binding string) (string, []byte, error) {
	p, current, err := b.boundADPreparation(ctx, req, raw, binding)
	if err != nil {
		return "", nil, err
	}
	defer p.destroy()
	password := p.held
	if p.Version == 2 {
		if err := driveADPreparedReset(ctx, p, nil, false, newADPreparedResetNative(b, p)); err != nil {
			return "", nil, err
		}
	} else if current.PasswordSetAt != p.PasswordSetAt {
		// An ambiguous earlier apply may already be current. Verify that exact
		// preparation once; never overwrite an unrelated native password change.
		if err := password.Use(func(value []byte) error { return b.verifyBoundADPassword(ctx, p.DN, value) }); err != nil {
			return "", nil, errors.New("dynsecret AD: native password changed outside the retained preparation")
		}
	} else if err := password.Use(func(value []byte) error { return b.resetADPassword(ctx, p.DN, value) }); err != nil {
		return "", nil, err
	}
	metadata, err := json.Marshal(struct {
		URL  string `json:"url"`
		DN   string `json:"bind_dn"`
		Name string `json:"username"`
	}{b.url, p.DN, p.Name})
	if err != nil {
		return "", nil, err
	}
	credential, err := appendADCredentialPassword(metadata, password.Bytes())
	return p.DN, credential, err
}
func (b *LDAPBackend) RestorePreparedStaticCredential(ctx context.Context, req GenerateRequest, raw, old []byte, binding string) error {
	p, current, err := b.boundADPreparation(ctx, req, raw, binding)
	if err != nil {
		return err
	}
	defer p.destroy()
	if p.Version == 2 {
		predecessor, e := decodeADPredecessorPassword(old, p.DN)
		if e != nil {
			return e
		}
		defer predecessor.Destroy()
		return driveADPreparedReset(ctx, p, predecessor.Bytes(), true, newADPreparedResetNative(b, p))
	}
	if current.PasswordSetAt == p.PasswordSetAt {
		// Preparation never reached a native reset. Do not mutate the directory
		// merely to make an unverified imported vault value appear correct.
		return b.verifyADCredential(ctx, old)
	}
	password := p.held
	if err := password.Use(func(value []byte) error { return b.verifyBoundADPassword(ctx, p.DN, value) }); err != nil {
		return errors.New("dynsecret AD: cannot attribute the current native password to this preparation")
	}
	return b.RestoreStaticCredential(ctx, req.Role, req.Predecessor, old)
}
