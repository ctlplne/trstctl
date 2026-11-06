// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type adStaticPreparation struct {
	held            *secret.Buffer
	Version         int              `json:"version"`
	Role            string           `json:"role"`
	OperationID     string           `json:"operation_id"`
	Predecessor     string           `json:"predecessor"`
	ProviderBinding string           `json:"provider_binding"`
	DN              string           `json:"bind_dn"`
	Name            string           `json:"username"`
	GUID            string           `json:"native_guid"`
	SID             string           `json:"native_sid"`
	PasswordSetAt   string           `json:"password_set_at"`
	Password        secret.JSONBytes `json:"password,omitempty"`
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
	if validateADPreparationFields(raw) != nil || json.Unmarshal(raw, &p) != nil || p.Version != 1 || len(p.Role) < 1 || len(p.Role) > 512 || len(p.OperationID) < 1 || len(p.OperationID) > 128 || len(p.DN) < 1 || len(p.DN) > 4096 || len(p.Name) < 1 || len(p.Name) > 128 || !validADPreparationHash(p.ProviderBinding, 32) || !validADPreparationHash(p.GUID, 16) || len(p.SID) < 16 || len(p.SID) > 136 || p.PasswordSetAt == "" || len(p.Password) < 16 || len(p.Password) > 1024 {
		secret.Wipe(p.Password)
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid bound preparation")
	}
	if _, err := strconv.ParseUint(p.PasswordSetAt, 10, 64); err != nil {
		secret.Wipe(p.Password)
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid native password stamp")
	}
	if _, err := hex.DecodeString(p.SID); err != nil {
		secret.Wipe(p.Password)
		return adStaticPreparation{}, errors.New("dynsecret AD: invalid native SID")
	}
	held, err := secret.NewFrom(p.Password)
	secret.Wipe(p.Password)
	if err != nil {
		return adStaticPreparation{}, err
	}
	p.held = held
	p.Password = held.Bytes()
	return p, nil
}
func (p *adStaticPreparation) destroy() {
	if p.held != nil {
		p.Password = nil
		p.held.Destroy()
		p.held = nil
		return
	}
	secret.Wipe(p.Password)
	p.Password = nil
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
	identity, err := b.inspectADIdentity(ctx, dn, false, true)
	if err != nil {
		return nil, err
	}
	random, err := randomSecretHex(24)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(random)
	password, err := secret.New(4 + len(random))
	if err != nil {
		return nil, err
	}
	defer password.Destroy()
	copy(password.Bytes(), []byte("Tr5!"))
	copy(password.Bytes()[4:], random)
	p := adStaticPreparation{Version: 1, Role: req.Role, OperationID: req.LeaseID, Predecessor: req.Predecessor, ProviderBinding: binding, DN: dn, Name: identity.Name, GUID: identity.GUID, SID: identity.SID, PasswordSetAt: identity.PasswordSetAt, Password: password.Bytes()}
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
	if !b.activeDirectory || !req.Static || p.Role != req.Role || p.OperationID != req.LeaseID || p.Predecessor != req.Predecessor || p.ProviderBinding != binding || !sameADRestoreDN(b.roleGroups[req.Role], p.DN) {
		return reject()
	}
	if _, paired := b.rotationAccounts[req.Role]; paired {
		return reject()
	}
	current, err := b.inspectADIdentity(ctx, p.DN, false, true)
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
	if current.PasswordSetAt != p.PasswordSetAt {
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
