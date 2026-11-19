// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
)

var (
	errHierarchyHandleAlias = errors.New("signing: a CA hierarchy storage slot requires its canonical handle")
	errKeyStoreLockBusy     = errors.New("signing: the shared keystore custody lock is busy")
)

func hierarchyCustodySlot(handle string) (bool, error) {
	folded := strings.ToLower(sanitizeHandle(handle))
	if !crypto.IsCanonicalCAHierarchyHandle(folded) {
		return false, nil
	}
	if handle != folded {
		return true, errHierarchyHandleAlias
	}
	return true, nil
}

// lockHierarchyCustody coordinates all access that can publish, load for
// first use, or retire a key in a reserved CA hierarchy slot.
func (ks *KeyStore) lockHierarchyCustody(handle string) (func(), error) {
	reserved, err := hierarchyCustodySlot(handle)
	if err != nil {
		return nil, err
	}
	if !reserved {
		return func() {}, nil
	}
	return ks.lockCustodyFile(crypto.SHA256Hex([]byte(handle))[:2] + ".lock")
}

func (ks *KeyStore) lockHierarchyWriter(handle string) (func(), error) {
	if err := ensureHierarchyDirectory(ks.dir); err != nil {
		return nil, err
	}
	// A different process may have created this directory and stopped
	// before its parent recorded the entry.
	if err := syncDirectory(filepath.Dir(filepath.Clean(ks.dir))); err != nil {
		return nil, err
	}
	return ks.lockHierarchyCustody(handle)
}

// Sync newly created parent entries before relying on a new keystore directory.
func ensureHierarchyDirectory(path string) error {
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return errors.New("signing: keystore path is not a directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(filepath.Clean(path))
	if err := ensureHierarchyDirectory(parent); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDirectory(parent)
}

func hierarchyCustodyStatus(action string, err error) error {
	switch {
	case errors.Is(err, errHierarchyHandleAlias):
		return status.Error(codes.InvalidArgument, errHierarchyHandleAlias.Error())
	case errors.Is(err, errKeyStoreLockBusy):
		return status.Error(codes.Unavailable, errKeyStoreLockBusy.Error())
	case errors.Is(err, ErrDestroyedKeyHandle), errors.Is(err, ErrRevokedKeyHandle):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, errKeyHandleExists):
		return status.Error(codes.AlreadyExists, "key handle already exists")
	default:
		return status.Errorf(codes.Internal, "%s: %v", action, err)
	}
}

func (ks *KeyStore) lockCustodyFile(name string) (func(), error) {
	// The stable inode under this directory remains in place for the life
	// of the store. There are at most 256 hierarchy slots plus identity setup.
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	const directory = ".custody-locks"
	if err := root.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	path := filepath.Join(directory, name)
	file, err := root.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	open := false
	defer func() {
		if !open {
			_ = file.Close()
		}
	}()
	if err := tryLockSignerCustody(file); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Join(ks.dir, directory)); err != nil {
		return nil, err
	}
	if err := syncDirectory(ks.dir); err != nil {
		return nil, err
	}
	open = true
	return func() { _ = file.Close() }, nil
}

func (ks *KeyStore) syncHierarchyDirectory() error {
	if ks.beforeHierarchySync != nil {
		if err := ks.beforeHierarchySync(); err != nil {
			return err
		}
	}
	return syncDirectory(ks.dir)
}

func (ks *KeyStore) syncCustodyFile(file *os.File, name string) error {
	if ks.beforeHierarchyFileSync != nil {
		if err := ks.beforeHierarchyFileSync(name); err != nil {
			return err
		}
	}
	return file.Sync()
}

func (ks *KeyStore) retireCustodyName(root *os.Root, name string) error {
	if ks.beforeHierarchyUnlink != nil {
		if err := ks.beforeHierarchyUnlink(name); err != nil {
			return err
		}
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// publishCustodyFile writes a complete file before making it visible at the
// authoritative name. The caller holds the shared lock for both entries.
func (ks *KeyStore) publishCustodyFile(name, stage string, sealed []byte) error {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := ks.retireCustodyName(root, stage); err != nil {
		return err
	}
	file, err := root.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		return err
	}
	if err := ks.syncCustodyFile(file, stage); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Link(stage, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if cleanupErr := ks.retireCustodyName(root, stage); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		return errors.Join(err, ks.syncHierarchyDirectory())
	}
	if err := ks.retireCustodyName(root, stage); err != nil {
		return err
	}
	return ks.syncHierarchyDirectory()
}

func (ks *KeyStore) retireCustodyNames(names ...string) error {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, name := range names {
		if err := ks.retireCustodyName(root, name); err != nil {
			return fmt.Errorf("signing: retire custody entry: %w", err)
		}
	}
	return ks.syncHierarchyDirectory()
}

func (ks *KeyStore) hierarchyStanding(handle string) error {
	destroyed, err := ks.IsDestroyed(handle)
	if err != nil {
		return err
	}
	if destroyed {
		return ErrDestroyedKeyHandle
	}
	revoked, err := ks.IsRevoked(handle)
	if err != nil {
		return err
	}
	if revoked {
		return ErrRevokedKeyHandle
	}
	return nil
}

func (ks *KeyStore) hierarchyEntryExists(name string) (bool, error) {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	_, err = root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (ks *KeyStore) hasHierarchyCustodyLocked(handle string) (bool, error) {
	key, preparation := handle+keyFileExt, keyImportPreparationName(handle)
	for _, name := range []string{key, key + custodyStageExt, preparation, preparation + custodyStageExt} {
		if present, err := ks.hierarchyEntryExists(name); present || err != nil {
			return present, err
		}
	}
	return false, nil
}

func (ks *KeyStore) retireHierarchyKeyLocked(handle string, retireFinal bool) error {
	key, preparation := handle+keyFileExt, keyImportPreparationName(handle)
	names := make([]string, 0, 4)
	if retireFinal {
		names = append(names, key)
	}
	names = append(names, key+custodyStageExt, preparation, preparation+custodyStageExt)
	return ks.retireCustodyNames(names...)
}

func (ks *KeyStore) saveHierarchyKeyLocked(handle string, key signerKey, constraints keyConstraints) error {
	if err := ks.hierarchyStanding(handle); err != nil {
		return err
	}
	name := handle + keyFileExt
	exists, err := ks.hierarchyEntryExists(name)
	if err != nil {
		return err
	}
	if exists {
		return errKeyHandleExists
	}
	sealed, err := ks.sealHeldKey(handle, key, constraints)
	if err != nil {
		return err
	}
	if err := ks.publishCustodyFile(name, name+custodyStageExt, sealed); errors.Is(err, os.ErrExist) {
		return errKeyHandleExists
	} else {
		return err
	}
}

// loadHierarchyKeyLocked establishes durability before handing a key to a
// cache. Revoked keys remain readable for public inspection.
func (ks *KeyStore) loadHierarchyKeyLocked(handle string) (*heldKey, error) {
	destroyed, err := ks.IsDestroyed(handle)
	if err != nil || destroyed {
		return nil, err
	}
	held, err := ks.readHierarchyKeyLocked(handle)
	if err != nil || held == nil {
		return held, err
	}
	if err := ks.syncHierarchyDirectory(); err != nil {
		held.signer.Destroy()
		return nil, err
	}
	standing := ks.hierarchyStanding(handle)
	if standing == nil || errors.Is(standing, ErrRevokedKeyHandle) {
		return held, nil
	}
	held.signer.Destroy()
	if errors.Is(standing, ErrDestroyedKeyHandle) {
		return nil, nil
	}
	return nil, standing
}

func (ks *KeyStore) readHierarchyKeyLocked(handle string) (*heldKey, error) {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	sealed, err := root.ReadFile(handle + keyFileExt)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ks.decodeHeldKey(handle, sealed)
}

func (s *Server) destroyHierarchyKey(handle string, gated bool) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	hierarchy, err := hierarchyCustodySlot(handle)
	if err != nil {
		return true, hierarchyCustodyStatus("destroy key", err)
	}
	if !hierarchy {
		return false, nil
	}
	unlock, err := s.store.lockHierarchyCustody(handle)
	if errors.Is(err, os.ErrNotExist) && !gated {
		return true, nil
	}
	if err != nil {
		return true, hierarchyCustodyStatus("lock key for destruction", err)
	}
	defer unlock()
	if !gated {
		destroyed, err := s.store.IsDestroyed(handle)
		if err != nil {
			return true, hierarchyCustodyStatus("read destroyed-key tombstone", err)
		}
		if !destroyed {
			occupied, err := s.store.hasHierarchyCustodyLocked(handle)
			if err != nil {
				return true, hierarchyCustodyStatus("check key for destruction", err)
			}
			if !occupied {
				return true, nil
			}
		}
	}
	if err := s.store.markHierarchyDestroyedLocked(handle); err != nil {
		return true, hierarchyCustodyStatus("persist destroyed-key tombstone", err)
	}
	if held := s.forgetKey(handle); held != nil {
		held.signer.Destroy()
	}
	if err := s.store.retireHierarchyKeyLocked(handle, true); err != nil {
		return true, hierarchyCustodyStatus("retire destroyed key material", err)
	}
	return true, nil
}

func (ks *KeyStore) markHierarchyDestroyedLocked(handle string) error {
	name := handle + destroyedKeyFileExt
	exists, err := ks.hierarchyEntryExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return ks.publishCustodyFile(name, name+custodyStageExt, []byte(destructionMarker))
	}
	// Presence fences all use, even if a pre-upgrade writer left a torn
	// marker. Repair it without ever removing the authoritative name.
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(destructionMarker)
	syncErr := ks.syncCustodyFile(file, name)
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		return err
	}
	return ks.retireCustodyNames(name + custodyStageExt)
}
