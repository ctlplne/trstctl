// SPDX-License-Identifier: BUSL-1.1
package secretfile

import "errors"

// LoadBounded applies Load's exact file and parent custody checks, then reads
// through one fixed, caller-owned buffer. The caller must wipe returned bytes.
func LoadBounded(path string, limit int) ([]byte, error) {
	if limit <= 0 || limit > 16<<20 {
		return nil, errors.New("secretfile: invalid byte bound")
	}
	return load(path, limit)
}
