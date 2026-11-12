// SPDX-License-Identifier: BUSL-1.1

package kmswrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A wrapper key under a cloud KMS key (OD-10, A200-L4). The tenant KEK
// custody wraps tenant domain KEKs with an AES-256 key; this one is kept
// wrapped by a KMS key through the signer's KMS wrap adapter, so the signer
// stores only its wrapped form. Every Seal and Open unwraps it through the
// adapter, one KMS call each, unless the operator set a cache time limit:
// then the unwrapped key stays in locked, non-dumpable memory until the limit
// passes, when it is wiped, and Close wipes it at shutdown. Caching is off by
// default.

const (
	wrapperKeySize = 32
	gcmNonceSize   = 12
	gcmTagSize     = 16
	// MaxWrapperKeyCache is the longest an operator may keep an unwrapped
	// wrapper key: past it, a KMS key's disablement or a revoked grant would
	// take too long to stop the custody.
	MaxWrapperKeyCache = 24 * time.Hour
)

var (
	// ErrWrapperKeyUnavailable means the KMS did not unwrap the wrapper key
	// (an unreachable KMS, a disabled key, a refused grant, a failing
	// adapter), or the wrapper key was closed.
	ErrWrapperKeyUnavailable = errors.New("kmswrap: the KMS wrapper key is unavailable")
	// ErrWrapperKeySealedInvalid means a sealed value does not authenticate
	// under the wrapper key.
	ErrWrapperKeySealedInvalid = errors.New("kmswrap: the sealed value does not open under the KMS wrapper key")
)

// CreateWrapperKey generates a fresh wrapper key and returns only its form
// wrapped by kms; the plaintext is wiped before it returns.
func CreateWrapperKey(kms seal.KeyWrapper) ([]byte, error) {
	if kms == nil {
		return nil, ErrWrapperKeyUnavailable
	}
	raw, err := secret.New(wrapperKeySize)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	var wrapped []byte
	err = raw.Use(func(key []byte) error {
		if _, err := rand.Read(key); err != nil {
			return err
		}
		var werr error
		wrapped, werr = kms.WrapDEK(key)
		return werr
	})
	if err != nil {
		return nil, errors.Join(ErrWrapperKeyUnavailable, err)
	}
	return wrapped, nil
}

// WrapperKey is one wrapper key kept wrapped by a KMS key. It is a
// tenantwrap.ExternalWrapper: Seal returns nonce || ciphertext || tag for
// AES-256-GCM with a 12-byte nonce and a 16-byte tag.
type WrapperKey struct {
	kms     seal.KeyWrapper
	wrapped []byte
	ttl     time.Duration

	mu      sync.Mutex
	cached  *secret.Buffer
	expires time.Time
	timer   *time.Timer
	closed  bool

	unwraps atomic.Int64
}

// NewWrapperKey holds a wrapper key in its KMS-wrapped form. cache is the
// operator's time limit for keeping the unwrapped key; zero keeps nothing and
// unwraps it through the KMS for every Seal and Open.
func NewWrapperKey(kms seal.KeyWrapper, wrapped []byte, cache time.Duration) (*WrapperKey, error) {
	if kms == nil || len(wrapped) == 0 {
		return nil, ErrWrapperKeyUnavailable
	}
	if cache < 0 || cache > MaxWrapperKeyCache {
		return nil, fmt.Errorf("kmswrap: a wrapper key cache time limit is zero (off) to %s", MaxWrapperKeyCache)
	}
	return &WrapperKey{kms: kms, wrapped: append([]byte(nil), wrapped...), ttl: cache}, nil
}

// Unwraps counts the KMS unwraps of this wrapper key so far.
func (k *WrapperKey) Unwraps() int64 { return k.unwraps.Load() }

// Cached reports whether the unwrapped key is held now.
func (k *WrapperKey) Cached() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.cached != nil
}

// CacheLimit is the operator's time limit; zero means caching is off.
func (k *WrapperKey) CacheLimit() time.Duration { return k.ttl }

// Close wipes the cached key, if any, and refuses every later call.
func (k *WrapperKey) Close() {
	k.mu.Lock()
	k.closed = true
	cached := k.cached
	k.cached = nil
	if k.timer != nil {
		k.timer.Stop()
		k.timer = nil
	}
	k.mu.Unlock()
	if cached != nil {
		cached.Destroy()
	}
}

// Seal seals plaintext under the wrapper key with aad.
func (k *WrapperKey) Seal(plaintext, aad []byte) ([]byte, error) {
	var out []byte
	err := k.use(func(key []byte) error {
		gcm, err := newWrapperGCM(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcmNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		out = gcm.Seal(nonce, nonce, plaintext, aad)
		return nil
	})
	return out, err
}

// Open opens what Seal sealed under this wrapper key with the same aad.
func (k *WrapperKey) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < gcmNonceSize+gcmTagSize {
		return nil, ErrWrapperKeySealedInvalid
	}
	var out []byte
	err := k.use(func(key []byte) error {
		gcm, err := newWrapperGCM(key)
		if err != nil {
			return err
		}
		plain, err := gcm.Open(nil, sealed[:gcmNonceSize], sealed[gcmNonceSize:], aad)
		if err != nil {
			return ErrWrapperKeySealedInvalid
		}
		out = plain
		return nil
	})
	return out, err
}

func newWrapperGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// use lends the unwrapped key to fn: the cached one while it is within its
// time limit, or one unwrapped through the KMS now. An uncached key lives in
// locked memory for fn alone and is wiped after it.
func (k *WrapperKey) use(fn func(key []byte) error) error {
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return ErrWrapperKeyUnavailable
	}
	if k.cached != nil && time.Now().Before(k.expires) {
		cached := k.cached
		k.mu.Unlock()
		err := cached.Use(fn)
		if !errors.Is(err, secret.ErrDestroyed) {
			return err
		}
		// It expired or was closed between the check and the borrow.
		k.mu.Lock()
		if k.closed {
			k.mu.Unlock()
			return ErrWrapperKeyUnavailable
		}
	}
	// A miss unwraps under the lock, so callers arriving together share one
	// KMS call; the adapter bounds it with its timeout.
	defer k.mu.Unlock()
	raw, err := k.kms.UnwrapDEK(k.wrapped)
	k.unwraps.Add(1)
	if err != nil {
		return errors.Join(ErrWrapperKeyUnavailable, err)
	}
	if len(raw) != wrapperKeySize {
		secret.Wipe(raw)
		return fmt.Errorf("%w: the KMS returned a %d-byte key", ErrWrapperKeyUnavailable, len(raw))
	}
	buf, err := secret.NewFrom(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	if k.ttl <= 0 {
		defer buf.Destroy()
		return buf.Use(fn)
	}
	if k.cached != nil {
		k.cached.Destroy()
	}
	k.cached, k.expires = buf, time.Now().Add(k.ttl)
	if k.timer != nil {
		k.timer.Stop()
	}
	k.timer = time.AfterFunc(k.ttl, k.expire)
	return buf.Use(fn)
}

// expire wipes the cached key once its time limit has passed.
func (k *WrapperKey) expire() {
	k.mu.Lock()
	cached := k.cached
	if cached == nil || time.Now().Before(k.expires) {
		k.mu.Unlock()
		return
	}
	k.cached = nil
	k.timer = nil
	k.mu.Unlock()
	cached.Destroy()
}
