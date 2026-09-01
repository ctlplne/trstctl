// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// SourcePrivateKey is the agent inventory source for private-key-material
// discovery. It reports metadata only; key bytes never leave the host.
const SourcePrivateKey = "private-key"

const maxPrivateKeyFileSize = 1 << 20

// PrivateKeyFound is a metadata-only finding for private-key material. The
// fingerprint is derived from the public key when the key is parseable.
type PrivateKeyFound struct {
	Source           string
	Location         string
	Format           string
	Algorithm        cryptoboundary.Algorithm
	Fingerprint      string
	FingerprintBasis string
	Encrypted        bool
	Restricted       bool
	Metadata         map[string]string
}

// PrivateKeySource walks filesystem roots and classifies private-key material.
type PrivateKeySource struct {
	roots   []string
	maxSize int64
}

// NewPrivateKeySource discovers private-key files under the given roots.
func NewPrivateKeySource(roots ...string) *PrivateKeySource {
	return &PrivateKeySource{roots: roots, maxSize: maxPrivateKeyFileSize}
}

// Kind names the source.
func (s *PrivateKeySource) Kind() string { return SourcePrivateKey }

// Discover locates private-key material and returns classification metadata only.
func (s *PrivateKeySource) Discover(ctx context.Context) ([]PrivateKeyFound, error) {
	var out []PrivateKeyFound
	for _, root := range s.roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil || !fi.Mode().IsRegular() || fi.Size() > s.maxSize {
				return nil
			}
			data, rerr := os.ReadFile(path) // #nosec G122 G304 -- the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367)
			if rerr != nil {
				return nil
			}
			info, perr := cryptoboundary.InspectPrivateKey(data)
			secret.Wipe(data)
			if perr != nil {
				return nil
			}
			restricted, metadata := privateKeyPermissionState(path, fi)
			out = append(out, PrivateKeyFound{
				Source:           SourcePrivateKey,
				Location:         path,
				Format:           info.Format,
				Algorithm:        info.Algorithm,
				Fingerprint:      info.FingerprintSHA256,
				FingerprintBasis: info.FingerprintBasis,
				Encrypted:        info.Encrypted,
				Restricted:       restricted,
				Metadata:         metadata,
			})
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
