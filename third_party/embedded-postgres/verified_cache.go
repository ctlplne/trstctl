// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// VerifiedCache holds the directory handles used to prepare a private archive
// namespace. Keep it open through acquisition and startup. It protects against
// other users redirecting a cache beneath a shared temporary directory; it does
// not isolate malicious code running as the same user.
type VerifiedCache struct {
	path  string
	roots []*os.Root
}

func (c *VerifiedCache) Path() string { return c.path }

func (c *VerifiedCache) Close() error {
	var err error
	for i := len(c.roots) - 1; i >= 0; i-- {
		err = errors.Join(err, c.roots[i].Close())
	}
	c.roots = nil
	return err
}

// OpenVerifiedCache treats anchor as an operator-selected trust boundary. Each
// child is created and opened relative to its held parent, never through a
// supplied symlink. A shared anchor needs the sticky bit and a trusted owner:
// an unrelated directory owner can rename entries even in a sticky directory.
func OpenVerifiedCache(anchor string, components ...string) (_ *VerifiedCache, err error) {
	if len(components) == 0 {
		return nil, errors.New("postgres cache requires a private namespace")
	}
	for _, name := range components {
		if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "/\\") {
			return nil, errors.New("invalid postgres cache component")
		}
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	cache := &VerifiedCache{path: anchor, roots: []*os.Root{root}}
	defer func() {
		if err != nil {
			err = errors.Join(err, cache.Close())
		}
	}()
	info, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	private := ownedByCurrentUser(info) && info.Mode().Perm()&0022 == 0
	shared := info.Mode()&os.ModeSticky != 0 && ownedByTrustedTempUser(info)
	if !info.IsDir() || (!private && !shared) {
		return nil, errors.New("postgres cache anchor must be private or a trusted sticky temporary directory")
	}
	for _, name := range components {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("postgres cache child must be an owned directory without links or shared write access")
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		cache.roots = append(cache.roots, child)
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			return nil, errors.Join(errors.New("postgres cache directory changed during open"), err)
		}
		root = child
		cache.path = filepath.Join(cache.path, name)
	}
	return cache, nil
}
