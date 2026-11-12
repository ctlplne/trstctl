// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package tenantkek keeps tenant domain key-encryption keys inside the isolated
// signer under operator HSM keys (A123, owner decision 2026-10-26). The signer
// creates each tenant's domain KEK, keeps it wrapped by an AES-256 key the
// operator provisions on the HSM, and wraps and unwraps the tenant's data keys
// itself; the domain KEK never reaches the control plane, which persists only
// the wrapped form. Each call opens the KEK from its wrapped form inside the
// signer, uses it, and destroys it.
//
// A wrapper may instead be an AES-256 key kept wrapped by a cloud KMS key
// through the signer's KMS wrap adapter (OD-10, A200-L4): the custody seals
// and opens with it exactly as with an HSM key, and it is unwrapped through
// the KMS for each use unless the operator set a cache time limit, which
// keeps it in locked memory until the limit passes and Close wipes it.
//
// It is reached only through cmd/trstctl-signer's tagged EE attach seam after
// the BYOK license check. It starts no server and imports no SQL or event bus.
package tenantkek

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/signing"
)

var _ signing.TenantKEKCustody = (*Custody)(nil)

// Custody is the tenant KEK custody. Wrapper IDs map to the labels of HSM AES
// keys on one token session, or to wrapper keys under a cloud KMS key (OD-10).
type Custody struct {
	session pkcs11.Session
	keys    pkcs11.SecretKeySession
	labels  map[string]string
	kms     map[string]*kmswrap.WrapperKey
}

// New builds the custody over a logged-in session and the operator's wrapper
// table (wrapper ID to HSM key label). Every wrapper key is proven usable
// before the signer serves: a probe sealed and opened under it must round-trip,
// so a missing key, an extractable one, or a wrong label stops startup instead
// of failing tenants later. On error the caller still owns the session.
func New(session pkcs11.Session, wrappers map[string]string) (*Custody, error) {
	return NewWithKMS(session, wrappers, nil)
}

// NewWithKMS builds the custody over HSM wrappers (on session, which may be
// nil when there are none) and wrappers under a cloud KMS key (OD-10). A
// wrapper ID names one of them, never both. Every wrapper is proven usable
// before the signer serves, as New proves HSM keys. On error the caller still
// owns the session and the KMS wrapper keys.
func NewWithKMS(session pkcs11.Session, wrappers map[string]string, kms map[string]*kmswrap.WrapperKey) (*Custody, error) {
	if len(wrappers) == 0 && len(kms) == 0 {
		return nil, errors.New("tenantkek: no tenant KEK wrappers are configured")
	}
	var keys pkcs11.SecretKeySession
	if len(wrappers) > 0 {
		var ok bool
		keys, ok = session.(pkcs11.SecretKeySession)
		if !ok {
			return nil, errors.New("tenantkek: the PKCS#11 session cannot seal under an AES key")
		}
	}
	labels := make(map[string]string, len(wrappers))
	ids := make([]string, 0, len(wrappers)+len(kms))
	for id, label := range wrappers {
		if err := validWrapperID(id); err != nil {
			return nil, err
		}
		if label == "" || strings.TrimSpace(label) != label {
			return nil, fmt.Errorf("tenantkek: wrapper %q needs the label of its HSM AES key", id)
		}
		labels[id] = label
		ids = append(ids, id)
	}
	kmsKeys := make(map[string]*kmswrap.WrapperKey, len(kms))
	for id, key := range kms {
		if err := validWrapperID(id); err != nil {
			return nil, err
		}
		if _, dup := labels[id]; dup {
			return nil, fmt.Errorf("tenantkek: wrapper %q is both an HSM key and a KMS wrapper key", id)
		}
		if key == nil {
			return nil, fmt.Errorf("tenantkek: KMS wrapper %q has no key", id)
		}
		kmsKeys[id] = key
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c := &Custody{session: session, keys: keys, labels: labels, kms: kmsKeys}
	for _, id := range ids {
		if err := c.probe(id); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func validWrapperID(id string) error {
	if id == "" || strings.TrimSpace(id) != id || len(id) > 128 {
		return fmt.Errorf("tenantkek: wrapper ID %q must be 1 to 128 bytes with no surrounding space", id)
	}
	return nil
}

// probe seals and opens a random value under the wrapper's key.
func (c *Custody) probe(id string) error {
	value, err := crypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("tenantkek: probe wrapper %q: %w", id, err)
	}
	aad := []byte("trstctl.tenantkek.startup-probe.v1")
	if key, ok := c.kms[id]; ok {
		sealed, err := key.Seal(value, aad)
		if err != nil {
			return fmt.Errorf("tenantkek: KMS wrapper %q: %w", id, err)
		}
		opened, err := key.Open(sealed, aad)
		if err != nil || !crypto.ConstantTimeEqual(opened, value) {
			return fmt.Errorf("tenantkek: KMS wrapper %q does not open what it seals: %v", id, err)
		}
		return nil
	}
	sealed, err := c.keys.SealWithKey(c.labels[id], value, aad)
	if err != nil {
		return fmt.Errorf("tenantkek: wrapper %q (HSM key %q): %w", id, c.labels[id], err)
	}
	opened, err := c.keys.OpenWithKey(c.labels[id], sealed, aad)
	if err != nil || !crypto.ConstantTimeEqual(opened, value) {
		return fmt.Errorf("tenantkek: wrapper %q (HSM key %q) does not open what it seals: %v", id, c.labels[id], err)
	}
	return nil
}

// Wrappers lists the configured wrapper IDs, sorted.
func (c *Custody) Wrappers() []string {
	out := make([]string, 0, len(c.labels)+len(c.kms))
	for id := range c.labels {
		out = append(out, id)
	}
	for id := range c.kms {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (c *Custody) wrapper(id string) (tenantwrap.ExternalWrapper, error) {
	if key, ok := c.kms[id]; ok {
		return kmsWrapper{key: key}, nil
	}
	label, ok := c.labels[id]
	if !ok {
		return nil, signing.ErrTenantKEKWrapperUnknown
	}
	return hsmWrapper{keys: c.keys, label: label}, nil
}

func (c *Custody) CreateDomainKEK(ctx context.Context, wrapperID string, binding []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w, err := c.wrapper(wrapperID)
	if err != nil {
		return nil, err
	}
	kek, wrapped, err := tenantwrap.CreateDomainKEKExternal(w, binding)
	if err != nil {
		return nil, err
	}
	kek.Destroy()
	return wrapped, nil
}

func (c *Custody) OpenDomainKEK(ctx context.Context, wrapperID string, wrapped, binding []byte) error {
	kek, err := c.open(ctx, wrapperID, wrapped, binding)
	if err != nil {
		return err
	}
	kek.Destroy()
	return nil
}

func (c *Custody) WrapDataKey(ctx context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error) {
	kek, err := c.open(ctx, wrapperID, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	out, err := kek.WrapDEK(dataKey)
	if err != nil {
		return nil, tenantwrap.ErrCustody
	}
	return out, nil
}

func (c *Custody) UnwrapDataKey(ctx context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	kek, err := c.open(ctx, wrapperID, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	dek, err := kek.UnwrapDEK(wrappedDataKey)
	if err != nil {
		return nil, tenantwrap.ErrUnwrap
	}
	return dek, nil
}

// open opens the wrapped domain KEK for one call; the caller destroys it.
func (c *Custody) open(ctx context.Context, wrapperID string, wrapped, binding []byte) (*seal.LocalKEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w, err := c.wrapper(wrapperID)
	if err != nil {
		return nil, err
	}
	return tenantwrap.OpenDomainKEKExternal(w, wrapped, binding)
}

// Close wipes every cached KMS wrapper key and ends the HSM session.
func (c *Custody) Close() error {
	for _, key := range c.kms {
		key.Close()
	}
	if c.session == nil {
		return nil
	}
	return c.session.Close()
}

// kmsWrapper is one wrapper key under a cloud KMS key as a
// tenantwrap.ExternalWrapper (OD-10).
type kmsWrapper struct{ key *kmswrap.WrapperKey }

func (w kmsWrapper) Seal(plaintext, aad []byte) ([]byte, error) {
	out, err := w.key.Seal(plaintext, aad)
	if err != nil {
		return nil, kmsWrapperError(err)
	}
	return out, nil
}

func (w kmsWrapper) Open(sealed, aad []byte) ([]byte, error) {
	out, err := w.key.Open(sealed, aad)
	if err != nil {
		return nil, kmsWrapperError(err)
	}
	return out, nil
}

// kmsWrapperError: a value that does not authenticate is an unwrap failure;
// a KMS that does not unwrap the wrapper key makes the wrapper unavailable.
func kmsWrapperError(err error) error {
	if errors.Is(err, kmswrap.ErrWrapperKeySealedInvalid) {
		return tenantwrap.ErrUnwrap
	}
	return errors.Join(tenantwrap.ErrUnavailable, err)
}

// hsmWrapper is one HSM AES key as a tenantwrap.ExternalWrapper.
type hsmWrapper struct {
	keys  pkcs11.SecretKeySession
	label string
}

func (w hsmWrapper) Seal(plaintext, aad []byte) ([]byte, error) {
	out, err := w.keys.SealWithKey(w.label, plaintext, aad)
	if err != nil {
		return nil, wrapperError(err)
	}
	return out, nil
}

func (w hsmWrapper) Open(sealed, aad []byte) ([]byte, error) {
	out, err := w.keys.OpenWithKey(w.label, sealed, aad)
	if err != nil {
		return nil, wrapperError(err)
	}
	return out, nil
}

// wrapperError: a value that does not authenticate is an unwrap failure; a
// missing or refused key, or a failing token, is an unavailable wrapper.
func wrapperError(err error) error {
	if errors.Is(err, pkcs11.ErrSealedValueInvalid) {
		return tenantwrap.ErrUnwrap
	}
	return errors.Join(tenantwrap.ErrUnavailable, err)
}
