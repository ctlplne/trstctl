// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"errors"
	"io"
	"os"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
)

const maxInstalledImportBytes = 2 * maxSealedImportKey

func installedImportDomain(handle string) []byte {
	return []byte("trstctl.ca-key-import.installed.v4\x00" + handle + "\x00")
}

// installedImportPublic reads public envelope metadata. Its bytes are only
// advisory until OpenDomain authenticates it and key readback agrees.
func installedImportPublic(handle string, sealed []byte) (spki, domain []byte, err error) {
	domain, err = seal.Domain(sealed)
	if err != nil || domain == nil {
		return nil, nil, err
	}
	prefix := installedImportDomain(handle)
	if !crypto.IsCanonicalCAHierarchyHandle(handle) || !bytes.HasPrefix(domain, prefix) {
		return nil, nil, errors.New("signing: invalid CA import custody domain")
	}
	spki = domain[len(prefix):]
	if err := crypto.ValidateKeyImportSPKI(spki); err != nil {
		return nil, nil, err
	}
	return spki, domain, nil
}

// inspectHierarchyPublicKey reads only the existing key file's public
// envelope. It does not ask the wrapper to open any key material.
func (ks *KeyStore) inspectHierarchyPublicKey(handle string) (spki []byte, legacy bool, err error) {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = root.Close() }()
	name := handle + keyFileExt
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("signing: CA hierarchy key is not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	sealed, err := io.ReadAll(io.LimitReader(file, maxInstalledImportBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(sealed) > maxInstalledImportBytes {
		return nil, false, errors.New("signing: CA hierarchy key exceeds the public readback limit")
	}
	spki, domain, err := installedImportPublic(handle, sealed)
	if err != nil {
		return nil, false, err
	}
	if domain != nil {
		return spki, false, nil
	}
	_, labeled, err := seal.ContainerWrappedDEK(sealed)
	return nil, err == nil && !labeled, err
}
