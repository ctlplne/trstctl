// SPDX-License-Identifier: BUSL-1.1

package jks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// IsJKS reports whether data starts with the JKS magic number.
func IsJKS(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data) == 0xFEEDFEED
}

// Entry is the public half of one keystore entry: its alias and certificate
// chain (leaf first). A key entry's private key is never decrypted.
type Entry struct {
	Alias    string
	KeyEntry bool
	ChainDER [][]byte
	// SecretKey marks a JCEKS secret key entry (X2-L2): listed by alias,
	// never unsealed, with no certificates.
	SecretKey bool
}

// errInvalidDigest is the library's answer when a password does not match the
// store's integrity digest; it reads every entry before it checks the digest.
const errInvalidDigest = "got invalid digest"

// Entries lists a JKS keystore's entries for inventory (X2). verified reports
// whether one of passwords matched the store's integrity digest. JKS keeps
// certificates in the clear and encrypts only private keys, so the entries are
// listed even when no password matched; the caller reports them as unverified.
func Entries(jksData []byte, passwords [][]byte) (entries []Entry, verified bool, err error) {
	var unverified *keystore.KeyStore
	candidates := append(append([][]byte(nil), passwords...), nil)
	for _, password := range candidates {
		ks := keystore.New(keystore.WithOrderedAliases())
		lerr := ks.Load(bytes.NewReader(jksData), password)
		if lerr == nil {
			out, err := entriesOf(ks)
			return out, true, err
		}
		if lerr.Error() != errInvalidDigest {
			return nil, false, fmt.Errorf("jks: load: %w", lerr)
		}
		if unverified == nil {
			unverified = &ks
		}
	}
	if unverified == nil {
		return nil, false, errors.New("jks: no entries")
	}
	out, err := entriesOf(*unverified)
	return out, false, err
}

func entriesOf(ks keystore.KeyStore) ([]Entry, error) {
	var out []Entry
	for _, alias := range ks.Aliases() {
		switch {
		case ks.IsPrivateKeyEntry(alias):
			chain, err := ks.GetPrivateKeyEntryCertificateChain(alias)
			if err != nil {
				return nil, fmt.Errorf("jks: chain of %q: %w", alias, err)
			}
			entry := Entry{Alias: alias, KeyEntry: true}
			for _, c := range chain {
				entry.ChainDER = append(entry.ChainDER, c.Content)
			}
			out = append(out, entry)
		case ks.IsTrustedCertificateEntry(alias):
			trusted, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return nil, fmt.Errorf("jks: trusted entry %q: %w", alias, err)
			}
			out = append(out, Entry{Alias: alias, ChainDER: [][]byte{trusted.Certificate.Content}})
		}
	}
	return out, nil
}
