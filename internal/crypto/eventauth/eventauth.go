// SPDX-License-Identifier: BUSL-1.1

// Package eventauth authenticates stored event envelopes with a deployment
// secret that the broker cannot read. Key bytes are protected for one operation.
package eventauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const keySize = 32

var ErrAuthentication = errors.New("events: stored envelope authentication failed")

// File names one stable deployment key; it never retains key material.
type File struct{ Path string }

// Provision creates one protected random key and refuses to replace an
// existing one. Concurrent provisioners may use the same completed file.
func Provision(path string) error {
	if existing, err := secretfile.LoadProtectedExact(path, keySize); err == nil {
		defer existing.Destroy()
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	key, err := secret.NewProtected(keySize)
	if err != nil {
		return fmt.Errorf("eventauth: protect new key: %w", err)
	}
	defer key.Destroy()
	return key.Use(func(held []byte) error {
		if _, err := rand.Read(held); err != nil {
			return fmt.Errorf("eventauth: generate key: %w", err)
		}
		if err := secretfile.Create(path, held); errors.Is(err, fs.ErrExist) {
			existing, loadErr := secretfile.LoadProtectedExact(path, keySize)
			if loadErr != nil {
				return loadErr
			}
			existing.Destroy()
			return nil
		} else {
			return err
		}
	})
}

// Validate refuses a missing or malformed key before the event log opens.
func (f File) Validate() error {
	key, err := secretfile.LoadProtectedExact(f.Path, keySize)
	if err != nil {
		return fmt.Errorf("eventauth: load key: %w", err)
	}
	key.Destroy()
	return nil
}

// Sign MACs one canonical stored envelope without retaining the secret.
func (f File) Sign(body []byte) ([]byte, error) {
	key, err := secretfile.LoadProtectedExact(f.Path, keySize)
	if err != nil {
		return nil, fmt.Errorf("eventauth: load key: %w", err)
	}
	defer key.Destroy()
	var tag []byte
	err = key.Use(func(held []byte) error {
		mac := hmac.New(sha256.New, held)
		if _, err := mac.Write(body); err != nil {
			return err
		}
		tag = mac.Sum(nil)
		return nil
	})
	return tag, err
}

// Verify compares a stored tag in constant time. A missing tag always fails.
func (f File) Verify(body, tag []byte) error {
	if len(tag) != sha256.Size {
		return ErrAuthentication
	}
	expected, err := f.Sign(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(expected)
	if !hmac.Equal(expected, tag) {
		return ErrAuthentication
	}
	return nil
}
