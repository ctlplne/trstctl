// Package secretfile loads persisted secret material from local files with
// custody checks before bytes enter process memory.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Load reads path after verifying the file and its parent directories are safe
// for secret material. The returned bytes belong to the caller and must be wiped
// after use.
func Load(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("secretfile: path is required")
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
	f, err := os.Open(path)
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
	return io.ReadAll(f)
}

// Create writes data to a new 0600 secret file after creating and validating the
// parent directory path. It refuses to overwrite an existing file.
func Create(path string, data []byte) error {
	if path == "" {
		return errors.New("secretfile: path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := validateParents(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateFile(path, info)
}

// LoadOrCreate loads an existing secret file or creates it with bytes returned
// by generate. If another process wins the create race, it validates and loads
// that file instead of truncating it.
func LoadOrCreate(path string, generate func() ([]byte, error)) ([]byte, error) {
	raw, err := Load(path)
	if err == nil {
		return raw, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	fresh, err := generate()
	if err != nil {
		return nil, err
	}
	if err := Create(path, fresh); err != nil {
		wipe(fresh)
		if errors.Is(err, fs.ErrExist) {
			return Load(path)
		}
		return nil, err
	}
	return fresh, nil
}

func validateParents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	start, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	for dir := start; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("secretfile: parent %s is not a directory", dir)
		}
		if err := validateParentMode(dir, info); err != nil {
			return err
		}
		next := filepath.Dir(dir)
		if next == dir {
			return nil
		}
	}
}

func validateParentMode(path string, info os.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&0o022 != 0 {
		return fmt.Errorf("secretfile: parent directory %s has unsafe mode %o", path, perm)
	}
	own, ok := fileOwner(info)
	if !ok {
		return nil
	}
	euid := os.Geteuid()
	if own.uid != euid && own.uid != 0 {
		return fmt.Errorf("secretfile: parent directory %s owner uid %d does not match process uid %d or root", path, own.uid, euid)
	}
	return nil
}

func validateFile(path string, info os.FileInfo) error {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("secretfile: %s is a symlink", path)
	}
	if !mode.IsRegular() {
		return fmt.Errorf("secretfile: %s is not a regular file", path)
	}
	perm := mode.Perm()
	if perm&0o111 != 0 {
		return fmt.Errorf("secretfile: %s has executable mode %o", path, perm)
	}
	own, ok := fileOwner(info)
	if !ok {
		if perm&0o077 != 0 || perm&0o400 == 0 {
			return fmt.Errorf("secretfile: %s has unsafe mode %o", path, perm)
		}
		return nil
	}
	euid := os.Geteuid()
	if own.uid == euid {
		if perm&0o077 != 0 || perm&0o400 == 0 {
			return fmt.Errorf("secretfile: %s has unsafe mode %o", path, perm)
		}
		return nil
	}
	if own.uid == 0 && processHasGroup(own.gid) {
		if perm&0o027 != 0 || perm&0o040 == 0 {
			return fmt.Errorf("secretfile: %s has unsafe Kubernetes secret mode %o", path, perm)
		}
		return nil
	}
	return fmt.Errorf("secretfile: %s owner uid %d does not match process uid %d or root", path, own.uid, euid)
}

func processHasGroup(gid int) bool {
	if gid == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
