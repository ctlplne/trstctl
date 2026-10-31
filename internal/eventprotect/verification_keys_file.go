// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"errors"
	"io"
	"os"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// LoadVerificationKeysFile loads operator-pinned public receipt trust. Its file
// must stay outside managed data restore inputs and destinations. It never
// provisions tenant custody, fetches keys, or trusts keys supplied by a receipt.
func LoadVerificationKeysFile(path string, backupRoots []string) (set *jose.JWKSet, resultErr error) {
	if len(backupRoots) == 0 {
		return nil, errors.New("eventprotect: public verification trust requires explicit backup boundaries")
	}
	file, err := canonicalAbsolutePath(path)
	if err != nil {
		return nil, err
	}
	for _, source := range backupRoots {
		backup, err := canonicalAbsolutePath(source)
		if err != nil {
			return nil, err
		}
		if pathContains(file, backup) || pathContains(backup, file) {
			return nil, errors.New("eventprotect: public verification trust overlaps an ordinary backup root")
		}
		below, err := pathContainsIdentity(backup, file)
		if err != nil {
			return nil, err
		}
		above, err := pathContainsIdentity(file, backup)
		if err != nil {
			return nil, err
		}
		if below || above {
			return nil, errors.New("eventprotect: public verification trust aliases an ordinary backup root")
		}
	}
	// Open only a regular public file; a pipe or device must not stall startup.
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("eventprotect: public verification trust must be a regular file")
	}
	f, err := os.Open(file) // #nosec G304 -- Operator-pinned absolute public trust path is canonicalized outside managed restore roots; only a bounded regular file is read.
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("eventprotect: public verification trust must be a regular file")
	}
	const maxSize = 1 << 20
	wire, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxSize {
		return nil, errors.New("eventprotect: public verification trust exceeds 1 MiB")
	}
	return jose.ParseJWKSet(wire)
}
