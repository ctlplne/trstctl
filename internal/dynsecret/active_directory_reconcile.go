// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

// This helper consumes only public native identity attributes over the already
// authenticated pinned connection. It neither guesses a password nor writes AD.
func (b *LDAPBackend) bindADReconcilePrincipal(targetDN string, target adNativeResetIdentity, read func(string) (*ldap.Entry, error)) (adNativeResetIdentity, error) {
	if b.reconcile == nil {
		return target, nil
	}
	authority := b.reconcile
	refused := errors.New("dynsecret AD: designated native reset principal differs from its exact authority")
	if !b.activeDirectory || !sameADRestoreDN(b.bindDN, authority.Principal.DN) || sameADRestoreDN(targetDN, b.bindDN) || sameADRestoreDN(authority.RotationBindDN, b.bindDN) {
		return target, refused
	}
	if !validADPreparationHash(strings.ToLower(authority.Principal.GUID), 16) {
		return target, refused
	}
	identity := func(dn string) (string, string, error) {
		entry, err := read(dn)
		if err != nil {
			return "", "", err
		}
		if entry == nil || !sameADRestoreDN(entry.DN, dn) {
			return "", "", refused
		}
		guids, sids := entry.GetRawAttributeValues("objectGUID"), entry.GetRawAttributeValues("objectSid")
		if len(guids) != 1 || len(sids) != 1 || len(guids[0]) != 16 {
			return "", "", refused
		}
		if _, err := adDiscoverySID(sids[0]); err != nil {
			return "", "", refused
		}
		return hex.EncodeToString(guids[0]), hex.EncodeToString(sids[0]), nil
	}
	guid, sid, err := identity(b.bindDN)
	if err != nil {
		return target, err
	}
	publicSID, err := CanonicalADSIDHex(sid)
	if err != nil || guid != strings.ToLower(authority.Principal.GUID) || publicSID != authority.Principal.SID || guid == target.GUID || sid == target.SID {
		return target, refused
	}
	ordinaryGUID, ordinarySID, err := identity(authority.RotationBindDN)
	if err != nil {
		return target, err
	}
	if ordinaryGUID == guid || ordinarySID == sid {
		return target, refused
	}
	target.ResetPrincipalDN = b.bindDN
	target.ResetPrincipalGUID = guid
	target.ResetPrincipalSID = sid
	return target, nil
}

func (b *LDAPBackend) configureADReconcile(authority *ADReconcileAuthority) error {
	if authority == nil {
		return nil
	}
	grant := *authority
	grant.Principal.DN = strings.TrimSpace(grant.Principal.DN)
	grant.Principal.GUID = strings.ToLower(grant.Principal.GUID)
	grant.RotationBindDN = strings.TrimSpace(grant.RotationBindDN)
	_, principalErr := ldap.ParseDN(grant.Principal.DN)
	_, ordinaryErr := ldap.ParseDN(grant.RotationBindDN)
	if !b.activeDirectory || !b.tls || principalErr != nil || ordinaryErr != nil || grant.Principal.DN == "" || grant.RotationBindDN == "" || !sameADRestoreDN(b.bindDN, grant.Principal.DN) || sameADRestoreDN(grant.Principal.DN, grant.RotationBindDN) || !windependents.ValidAccountSID(grant.Principal.SID) || !strings.HasPrefix(grant.Principal.SID, "S-1-5-21-") || !validADPreparationHash(grant.Principal.GUID, 16) {
		return errors.New("dynsecret AD: designated reconcile authority is incomplete or ambiguous")
	}
	for _, target := range b.roleGroups {
		if sameADRestoreDN(target, grant.Principal.DN) {
			return errors.New("dynsecret AD: designated reconcile principal is also a managed target")
		}
	}
	b.reconcile = &grant
	return nil
}
