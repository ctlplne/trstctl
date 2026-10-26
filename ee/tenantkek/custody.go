// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package tenantkek keeps tenant domain key-encryption keys inside the isolated
// signer under operator HSM keys (A123, owner decision 2026-10-26). The signer
// creates each tenant's domain KEK, keeps it wrapped by an AES-256 key the
// operator provisions on the HSM, and wraps and unwraps the tenant's data keys
// itself; the domain KEK never reaches the control plane, which persists only
// the wrapped form. Each call opens the KEK from its wrapped form inside the
// signer, uses it, and destroys it.
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
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/signing"
)

var _ signing.TenantKEKCustody = (*Custody)(nil)

// Custody is the PKCS#11-backed tenant KEK custody. Wrapper IDs map to the
// labels of HSM AES keys on one token session.
type Custody struct {
	session pkcs11.Session
	keys    pkcs11.SecretKeySession
	labels  map[string]string
}

// New builds the custody over a logged-in session and the operator's wrapper
// table (wrapper ID to HSM key label). Every wrapper key is proven usable
// before the signer serves: a probe sealed and opened under it must round-trip,
// so a missing key, an extractable one, or a wrong label stops startup instead
// of failing tenants later. On error the caller still owns the session.
func New(session pkcs11.Session, wrappers map[string]string) (*Custody, error) {
	keys, ok := session.(pkcs11.SecretKeySession)
	if !ok {
		return nil, errors.New("tenantkek: the PKCS#11 session cannot seal under an AES key")
	}
	if len(wrappers) == 0 {
		return nil, errors.New("tenantkek: no tenant KEK wrappers are configured")
	}
	labels := make(map[string]string, len(wrappers))
	ids := make([]string, 0, len(wrappers))
	for id, label := range wrappers {
		if id == "" || strings.TrimSpace(id) != id || len(id) > 128 {
			return nil, fmt.Errorf("tenantkek: wrapper ID %q must be 1 to 128 bytes with no surrounding space", id)
		}
		if label == "" || strings.TrimSpace(label) != label {
			return nil, fmt.Errorf("tenantkek: wrapper %q needs the label of its HSM AES key", id)
		}
		labels[id] = label
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c := &Custody{session: session, keys: keys, labels: labels}
	for _, id := range ids {
		if err := c.probe(id); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// probe seals and opens a random value under the wrapper's key.
func (c *Custody) probe(id string) error {
	value, err := crypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("tenantkek: probe wrapper %q: %w", id, err)
	}
	aad := []byte("trstctl.tenantkek.startup-probe.v1")
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
	out := make([]string, 0, len(c.labels))
	for id := range c.labels {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (c *Custody) wrapper(id string) (tenantwrap.ExternalWrapper, error) {
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

// Close ends the custody's HSM session.
func (c *Custody) Close() error { return c.session.Close() }

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
