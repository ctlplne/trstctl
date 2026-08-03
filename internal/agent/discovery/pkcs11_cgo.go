// SPDX-License-Identifier: MPL-2.0

//go:build cgo

package discovery

import (
	"context"
	"fmt"

	"github.com/miekg/pkcs11"
)

// The real PKCS#11 read path (epic C1).
//
// This is the only file in the agent tree that loads a vendor cryptographic
// module, and it is deliberately narrow: open the module, open a READ-ONLY
// session on each matching token, find objects of class CKO_CERTIFICATE, read
// their CKA_VALUE, close. There is no C_Sign here, no CKO_PRIVATE_KEY search,
// and no attempt to export anything — a token's private keys are not this
// source's business and are usually CKA_EXTRACTABLE=false regardless.
//
// It is behind a cgo build tag because PKCS#11 is a dlopen ABI. The default
// agent build stays cgo-free so a statically linked binary can be rolled across
// a fleet without vendor libraries; a build that wants token inventory opts in,
// and the shipped census reports which of the two this binary is.

// platformPKCS11Reader returns the module-backed reader in a cgo build.
func platformPKCS11Reader() pkcs11Reader { return modulePKCS11Reader{} }

// pkcs11Shipped reports that this build can collect PKCS#11.
func pkcs11Shipped() bool { return true }

type modulePKCS11Reader struct{}

// readTokens walks every matching token and returns each certificate object's
// DER blob, keyed by token and object label.
func (modulePKCS11Reader) readTokens(ctx context.Context, cfg PKCS11Config) (map[string][]byte, error) {
	module := pkcs11.New(cfg.ModulePath)
	if module == nil {
		return nil, fmt.Errorf("discovery: load PKCS#11 module %s: module did not initialize", cfg.ModulePath)
	}
	if err := module.Initialize(); err != nil {
		return nil, fmt.Errorf("discovery: initialize PKCS#11 module %s: %w", cfg.ModulePath, err)
	}
	defer func() {
		_ = module.Finalize()
		module.Destroy()
	}()

	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("discovery: list PKCS#11 slots: %w", err)
	}
	out := map[string][]byte{}
	for _, slot := range slots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			// A slot whose token info cannot be read is skipped: an empty or
			// malfunctioning reader in a multi-slot host must not cost the
			// inventory of the token beside it.
			continue
		}
		if cfg.TokenLabel != "" && trimTokenLabel(info.Label) != cfg.TokenLabel {
			continue
		}
		if err := readSlotCertificates(module, slot, trimTokenLabel(info.Label), cfg.UserPIN, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readSlotCertificates opens one read-only session and collects its certificates.
func readSlotCertificates(module *pkcs11.Ctx, slot uint, tokenLabel string, pin []byte, out map[string][]byte) error {
	// SERIAL_SESSION only — deliberately NOT CKF_RW_SESSION. A read-write
	// session would let a bug here alter a token an organization cannot easily
	// restore, and inventory has no reason to want one.
	session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return fmt.Errorf("discovery: open PKCS#11 session on token %q: %w", tokenLabel, err)
	}
	defer func() { _ = module.CloseSession(session) }()

	if len(pin) > 0 {
		// The PIN came from a file and is held as bytes (AN-8). The library's
		// Login takes a string; this is the one place it must cross, and the
		// value is not retained beyond the call.
		if err := module.Login(session, pkcs11.CKU_USER, string(pin)); err != nil {
			return fmt.Errorf("discovery: log in to PKCS#11 token %q: %w", tokenLabel, err)
		}
		defer func() { _ = module.Logout(session) }()
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}
	if err := module.FindObjectsInit(session, template); err != nil {
		return fmt.Errorf("discovery: search PKCS#11 token %q: %w", tokenLabel, err)
	}
	defer func() { _ = module.FindObjectsFinal(session) }()

	index := 0
	for {
		handles, _, err := module.FindObjects(session, 64)
		if err != nil {
			return fmt.Errorf("discovery: enumerate PKCS#11 token %q: %w", tokenLabel, err)
		}
		if len(handles) == 0 {
			return nil
		}
		for _, handle := range handles {
			attrs, err := module.GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			})
			if err != nil {
				// An object whose attributes cannot be read is skipped rather
				// than failing the token: tokens hold objects with restrictive
				// attribute policies, and one of them must not cost the rest.
				index++
				continue
			}
			var value, label []byte
			for _, attr := range attrs {
				switch attr.Type {
				case pkcs11.CKA_VALUE:
					value = attr.Value
				case pkcs11.CKA_LABEL:
					label = attr.Value
				}
			}
			if len(value) > 0 {
				out[pkcs11ObjectLabel(tokenLabel, string(label), index)] = value
			}
			index++
		}
	}
}

// trimTokenLabel normalizes the space-padded label PKCS#11 returns.
func trimTokenLabel(raw string) string {
	return trimSpacePadding(raw)
}
