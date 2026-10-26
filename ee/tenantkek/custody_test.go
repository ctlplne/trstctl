// SPDX-License-Identifier: LicenseRef-trstctl-EE

package tenantkek_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/ee/tenantkek"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/signing"
)

// fakeToken is an HSM double: one AES-256 key per label, AES-GCM through the
// crypto boundary, and the refusals the real session makes.
type fakeToken struct {
	keys    map[string][]byte
	refused map[string]bool
	closed  bool
	seals   int
}

func newFakeToken(t *testing.T, labels ...string) *fakeToken {
	t.Helper()
	tok := &fakeToken{keys: map[string][]byte{}, refused: map[string]bool{}}
	for _, label := range labels {
		key, err := crypto.RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		tok.keys[label] = key
	}
	return tok
}

func (f *fakeToken) key(label string) ([]byte, error) {
	if f.closed {
		return nil, errors.New("pkcs11: session is closed")
	}
	if f.refused[label] {
		return nil, pkcs11.ErrSecretKeyPolicy
	}
	key, ok := f.keys[label]
	if !ok {
		return nil, pkcs11.ErrSecretKeyNotFound
	}
	return key, nil
}

func (f *fakeToken) SealWithKey(label string, plaintext, aad []byte) ([]byte, error) {
	key, err := f.key(label)
	if err != nil {
		return nil, err
	}
	f.seals++
	return crypto.AESGCMSeal(key, plaintext, aad)
}

func (f *fakeToken) OpenWithKey(label string, sealed, aad []byte) ([]byte, error) {
	key, err := f.key(label)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.AESGCMOpen(key, sealed, aad)
	if err != nil {
		return nil, pkcs11.ErrSealedValueInvalid
	}
	return plain, nil
}

func (f *fakeToken) GenerateKey(crypto.Algorithm) (string, []byte, error) {
	return "", nil, errors.New("not a signing token")
}

func (f *fakeToken) SignDigest(string, []byte, crypto.SignOptions) ([]byte, error) {
	return nil, errors.New("not a signing token")
}

func (f *fakeToken) Close() error {
	f.closed = true
	return nil
}

var bindingA = []byte("tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;domain=11111111-1111-4111-8111-111111111111;generation=1")

// A123: the signer creates a tenant domain KEK under an HSM wrapper and hands
// back only its wrapped form; later calls open it inside the signer to wrap and
// unwrap the tenant's data keys.
func TestCustodyKeepsTheDomainKEKAndWrapsDataKeys(t *testing.T) {
	tok := newFakeToken(t, "hsm-key-a", "hsm-key-b")
	c, err := tenantkek.New(tok, map[string]string{"wrapper-a": "hsm-key-a", "wrapper-b": "hsm-key-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Wrappers(), ","); got != "wrapper-a,wrapper-b" {
		t.Fatalf("wrappers = %s", got)
	}
	ctx := context.Background()
	wrapped, err := c.CreateDomainKEK(ctx, "wrapper-a", bindingA)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !bytes.HasPrefix(wrapped, []byte("TDH1")) {
		t.Fatalf("wrapped domain KEK is not an HSM-wrapped container: %q", wrapped[:4])
	}
	if err := c.OpenDomainKEK(ctx, "wrapper-a", wrapped, bindingA); err != nil {
		t.Fatalf("open: %v", err)
	}
	dek, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := c.WrapDataKey(ctx, "wrapper-a", wrapped, bindingA, dek)
	if err != nil || bytes.Contains(wrappedDEK, dek) {
		t.Fatalf("wrap a data key: %v", err)
	}
	back, err := c.UnwrapDataKey(ctx, "wrapper-a", wrapped, bindingA, wrappedDEK)
	if err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap the data key: %v", err)
	}
	again, err := c.CreateDomainKEK(ctx, "wrapper-a", bindingA)
	if err != nil || bytes.Equal(again, wrapped) {
		t.Fatalf("a second domain KEK for the same binding repeated the first: %v", err)
	}
	if err := c.Close(); err != nil || !tok.closed {
		t.Fatalf("close = %v, session closed %v", err, tok.closed)
	}
}

// Every failure keeps its class: an unknown wrapper, another binding, another
// wrapper key, a changed wrapped data key, a key that went missing from the
// HSM, and a canceled call.
func TestCustodyFailuresKeepTheirClass(t *testing.T) {
	tok := newFakeToken(t, "hsm-key-a", "hsm-key-b")
	c, err := tenantkek.New(tok, map[string]string{"wrapper-a": "hsm-key-a", "wrapper-b": "hsm-key-b"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	wrapped, err := c.CreateDomainKEK(ctx, "wrapper-a", bindingA)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{9}, 32)
	wrappedDEK, err := c.WrapDataKey(ctx, "wrapper-a", wrapped, bindingA, dek)
	if err != nil {
		t.Fatal(err)
	}
	changedDEK := append([]byte(nil), wrappedDEK...)
	changedDEK[len(changedDEK)-1] ^= 1
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for name, c := range map[string]struct {
		err   error
		class error
	}{
		"unknown wrapper": {c.OpenDomainKEK(ctx, "wrapper-z", wrapped, bindingA), signing.ErrTenantKEKWrapperUnknown},
		"another binding": {c.OpenDomainKEK(ctx, "wrapper-a", wrapped, []byte("tenant=b;domain=d;generation=1")), tenantwrap.ErrUnwrap},
		"another wrapper": {c.OpenDomainKEK(ctx, "wrapper-b", wrapped, bindingA), tenantwrap.ErrUnwrap},
		"changed data key": {func() error {
			_, err := c.UnwrapDataKey(ctx, "wrapper-a", wrapped, bindingA, changedDEK)
			return err
		}(), tenantwrap.ErrUnwrap},
		"canceled": {c.OpenDomainKEK(canceled, "wrapper-a", wrapped, bindingA), context.Canceled},
	} {
		if !errors.Is(c.err, c.class) {
			t.Errorf("%s = %v, want %v", name, c.err, c.class)
		}
	}
	delete(tok.keys, "hsm-key-a")
	if err := c.OpenDomainKEK(ctx, "wrapper-a", wrapped, bindingA); !errors.Is(err, tenantwrap.ErrUnavailable) {
		t.Fatalf("open after the HSM key went missing = %v, want an unavailable wrapper", err)
	}
	if _, err := c.CreateDomainKEK(ctx, "wrapper-a", bindingA); !errors.Is(err, tenantwrap.ErrUnavailable) {
		t.Fatalf("create after the HSM key went missing = %v, want an unavailable wrapper", err)
	}
}

// Startup proves every configured wrapper key works before the signer serves.
func TestCustodyStartupRefusesAnUnusableWrapper(t *testing.T) {
	tok := newFakeToken(t, "hsm-key-a")
	tok.refused["hsm-key-extractable"] = true
	for name, wrappers := range map[string]map[string]string{
		"no wrappers":     {},
		"missing key":     {"wrapper-a": "hsm-key-a", "wrapper-b": "no-such-key"},
		"refused key":     {"wrapper-x": "hsm-key-extractable"},
		"padded ID":       {" wrapper-a": "hsm-key-a"},
		"empty label":     {"wrapper-a": ""},
		"long wrapper ID": {strings.Repeat("w", 129): "hsm-key-a"},
	} {
		if _, err := tenantkek.New(tok, wrappers); err == nil {
			t.Errorf("%s: startup accepted %v", name, wrappers)
		}
	}
	if _, err := tenantkek.New(signOnly{}, map[string]string{"wrapper-a": "hsm-key-a"}); err == nil {
		t.Fatal("a session that cannot seal under an AES key was accepted")
	}
	before := tok.seals
	if _, err := tenantkek.New(tok, map[string]string{"wrapper-a": "hsm-key-a"}); err != nil || tok.seals != before+1 {
		t.Fatalf("startup did not probe the wrapper key (%d seals): %v", tok.seals-before, err)
	}
}

type signOnly struct{}

func (signOnly) GenerateKey(crypto.Algorithm) (string, []byte, error) { return "", nil, nil }
func (signOnly) SignDigest(string, []byte, crypto.SignOptions) ([]byte, error) {
	return nil, nil
}
func (signOnly) Close() error { return nil }
