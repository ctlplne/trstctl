// SPDX-License-Identifier: BUSL-1.1
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// LoadProtectedExact opens one exact-size secret through the same parent,
// owner, mode and same-file checks as Load, then reads directly into locked,
// non-dumpable memory. The caller owns and must Destroy the returned buffer.
func LoadProtectedExact(path string, size int) (*secret.Buffer, error) {
	if path == "" || size <= 0 || size > 16<<20 {
		return nil, errors.New("secretfile: protected read requires path and bounded size")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateParents(path); err != nil {
		return nil, err
	}
	if err := validateFile(path, info); err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured secret path; parent/file custody and opened identity checked below (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("secretfile: %s changed while opening", path)
	}
	if err := validateFile(path, opened); err != nil {
		return nil, err
	}
	if opened.Size() != int64(size) {
		return nil, errors.New("secretfile: protected material has wrong length")
	}
	buf, err := secret.NewProtected(size)
	if err != nil {
		return nil, err
	}
	if err := buf.Use(func(held []byte) error {
		if _, err := io.ReadFull(f, held); err != nil {
			return err
		}
		var extra [1]byte
		defer secret.Wipe(extra[:])
		if n, err := f.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
			return errors.New("secretfile: protected material changed length while reading")
		}
		return nil
	}); err != nil {
		buf.Destroy()
		return nil, err
	}
	return buf, nil
}
