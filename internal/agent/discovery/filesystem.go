package discovery

import (
	"context"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// maxCertFileSize bounds how large a file the filesystem source will read and
// scan for certificates, so a stray large file in a watched directory is cheap
// to skip.
const maxCertFileSize = 1 << 20

// FilesystemSource discovers certificates in files under one or more directory
// roots. It reads each regular file, extracts every PEM CERTIFICATE block (or
// treats the file as a single DER certificate when it is not PEM), and inventories
// each. A file that is not a certificate, is unreadable, or is too large is
// skipped — discovery never fails because of one bad file.
type FilesystemSource struct {
	roots   []string
	maxSize int64
}

var _ Source = (*FilesystemSource)(nil)

// NewFilesystemSource discovers certificates under the given directory roots.
func NewFilesystemSource(roots ...string) *FilesystemSource {
	return &FilesystemSource{roots: roots, maxSize: maxCertFileSize}
}

// Kind names the source.
func (s *FilesystemSource) Kind() string { return SourceFilesystem }

// Discover walks the roots and returns every certificate found.
func (s *FilesystemSource) Discover(ctx context.Context) ([]Found, error) {
	var out []Found
	for _, root := range s.roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry; skip
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				return nil
			}
			if fi, ierr := d.Info(); ierr != nil || fi.Size() > s.maxSize {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, der := range certBlocks(data) {
				info, perr := certinfo.Inspect(der)
				if perr != nil {
					continue
				}
				out = append(out, Found{Source: SourceFilesystem, Location: path, Cert: info})
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// certBlocks returns the DER bytes of each PEM CERTIFICATE block in data, or the
// whole input as a single DER candidate when it contains no PEM.
func certBlocks(data []byte) [][]byte {
	var ders [][]byte
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	if len(ders) == 0 {
		ders = append(ders, data)
	}
	return ders
}
