// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// KeyRef is public custody identity. Neither field contains key material.
type KeyRef struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"key_id"`
}

// KeyLocker must serialize the same key across every authority user. The
// control-plane adapter supplies a bounded PostgreSQL session lock; custody
// callers must not substitute a process-local lock in a replicated deployment.
type KeyLocker interface {
	WithKeyLock(context.Context, KeyRef, func(context.Context) error) error
}

type FileAuthorityConfig struct {
	Directory            string
	BackupRoots          []string
	Locker               KeyLocker
	DestructionAuthority DestructionAuthorizer
	EvidenceKey          *jose.SigningKey
}

// FileAuthority owns a separate private key directory. Its directory is not an
// ordinary data-backup source. A lost key never triggers implicit regeneration.
// This is logical software custody, not proof that independent host snapshots
// or forensic copies have been sanitized.
type FileAuthority struct {
	directory            string
	root                 *os.Root
	locker               KeyLocker
	mu                   sync.RWMutex
	closed               bool
	destructionAuthority DestructionAuthorizer
	evidenceKey          *jose.SigningKey
	now                  func() time.Time
}

type fileKeyRecord struct {
	Version     int              `json:"version"`
	Ref         KeyRef           `json:"ref"`
	Phase       string           `json:"phase"`
	CreatedAt   time.Time        `json:"created_at"`
	Destruction *fileDestruction `json:"destruction,omitempty"`
}

func NewFileAuthority(config FileAuthorityConfig) (*FileAuthority, error) {
	if config.Locker == nil || len(config.BackupRoots) == 0 {
		return nil, errors.New("eventprotect: independent custody requires a lock and explicit backup roots")
	}
	if (config.DestructionAuthority == nil) != (config.EvidenceKey == nil) {
		return nil, errors.New("eventprotect: destruction requires both source authority and evidence signing")
	}
	directory, err := canonicalAbsolutePath(config.Directory)
	if err != nil {
		return nil, err
	}
	for _, source := range config.BackupRoots {
		backup, err := canonicalAbsolutePath(source)
		if err != nil {
			return nil, err
		}
		if pathContains(directory, backup) || pathContains(backup, directory) {
			return nil, errors.New("eventprotect: key custody overlaps an ordinary backup root")
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	// Resolve again after creation. Case and Unicode aliases on some filesystems
	// identify the same directory without having identical path text. A future
	// backup child beneath such an alias still overlaps custody.
	for _, source := range config.BackupRoots {
		backup, err := canonicalAbsolutePath(source)
		if err != nil {
			return nil, err
		}
		belowCustody, err := pathContainsIdentity(directory, backup)
		if err != nil {
			return nil, err
		}
		aboveCustody, err := pathContainsIdentity(backup, directory)
		if err != nil {
			return nil, err
		}
		if belowCustody || aboveCustody {
			return nil, errors.New("eventprotect: key custody aliases an ordinary backup root")
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("eventprotect: key custody requires a private directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &FileAuthority{directory: directory, root: root, locker: config.Locker,
		destructionAuthority: config.DestructionAuthority, evidenceKey: config.EvidenceKey,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

func canonicalAbsolutePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("eventprotect: custody and backup paths must be absolute")
	}
	probe := filepath.Clean(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(probe) == probe {
			return "", err
		}
		// EvalSymlinks also reports ENOENT for an existing dangling link. Treating
		// that link as a new literal directory would conceal its future target.
		if info, statErr := os.Lstat(probe); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("eventprotect: unresolved symlink in custody or backup path")
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		suffix = append(suffix, filepath.Base(probe))
		probe = filepath.Dir(probe)
	}
}

func pathContainsIdentity(parent, child string) (bool, error) {
	parentInfo, err := os.Stat(parent)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for probe := child; ; probe = filepath.Dir(probe) {
		info, err := os.Stat(probe)
		if err == nil && os.SameFile(parentInfo, info) {
			return true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if filepath.Dir(probe) == probe {
			return false, nil
		}
	}
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) &&
		(len(relative) < 3 || relative[:3] != ".."+string(filepath.Separator))
}

func normalizedKeyRef(ref KeyRef) (KeyRef, error) {
	tenant, err := uuid.Parse(ref.TenantID)
	if err != nil || tenant == uuid.Nil {
		return KeyRef{}, ErrContext
	}
	id, err := uuid.Parse(ref.ID)
	if err != nil || id == uuid.Nil {
		return KeyRef{}, ErrContext
	}
	return KeyRef{TenantID: tenant.String(), ID: id.String()}, nil
}

func (a *FileAuthority) withLock(ctx context.Context, ref KeyRef, fn func(context.Context, KeyRef) error) error {
	if a == nil {
		return ErrKey
	}
	ref, err := normalizedKeyRef(ref)
	if err != nil {
		return err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return ErrKey
	}
	return a.locker.WithKeyLock(ctx, ref, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(ctx, ref)
	})
}

// Provision is private custody preparation. Production activation must record
// and independently verify this effect through its event/outbox workflow.
func (a *FileAuthority) Provision(ctx context.Context, ref KeyRef) error {
	return a.withLock(ctx, ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err != nil {
			return err
		}
		if found && record.Phase == "active" {
			key, err := a.loadKey(ref)
			if err != nil {
				return err
			}
			key.Destroy()
			return nil
		}
		if found && record.Phase != "creating" {
			if record.Phase == "destroyed" {
				return a.destroyedState(record)
			}
			return ErrKey
		}
		if !found {
			if _, err := a.root.Lstat(keyName(ref)); !errors.Is(err, os.ErrNotExist) {
				return ErrKey
			}
			if err := a.root.MkdirAll(ref.TenantID, 0o700); err != nil {
				return err
			}
			info, err := a.root.Lstat(ref.TenantID)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
				return ErrKey
			}
			rootDirectory, err := a.root.Open(".")
			if err != nil {
				return err
			}
			syncErr, closeErr := rootDirectory.Sync(), rootDirectory.Close()
			if syncErr != nil {
				return syncErr
			}
			if closeErr != nil {
				return closeErr
			}
			record = fileKeyRecord{Version: 1, Ref: ref, Phase: "creating", CreatedAt: a.now().UTC()}
			if err := a.writeRecord(record); err != nil {
				return err
			}
		}
		// Only a never-activated creating record may create absent material. A
		// crash after material creation reuses those exact bytes on resumption.
		raw, err := secretfile.LoadOrCreate(filepath.Join(a.directory, keyName(ref)), seal.GenerateKEK)
		if err != nil {
			return ErrKey
		}
		defer secret.Wipe(raw)
		if len(raw) != 32 {
			return ErrKey
		}
		file, err := a.root.Open(keyName(ref))
		if err != nil {
			return err
		}
		syncErr, closeErr := file.Sync(), file.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		record.Phase = "active"
		return a.writeRecord(record)
	})
}

func (a *FileAuthority) WithKey(ctx context.Context, ref KeyRef, fn func(seal.KeyWrapper) error) error {
	if fn == nil {
		return ErrContext
	}
	return a.withLock(ctx, ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err == nil && found && record.Phase == "destroyed" {
			return a.destroyedState(record)
		}
		if err != nil || !found || record.Phase != "active" {
			return ErrKey
		}
		key, err := a.loadKey(ref)
		if err != nil {
			return err
		}
		defer key.Destroy()
		return fn(key)
	})
}

func keyName(ref KeyRef) string    { return filepath.Join(ref.TenantID, ref.ID+".key") }
func recordName(ref KeyRef) string { return filepath.Join(ref.TenantID, ref.ID+".json") }

func (a *FileAuthority) loadKey(ref KeyRef) (*seal.LocalKEK, error) {
	info, err := a.root.Lstat(keyName(ref))
	if err != nil || !info.Mode().IsRegular() || info.Size() != 32 {
		return nil, ErrKey
	}
	raw, err := secretfile.Load(filepath.Join(a.directory, keyName(ref)))
	if err != nil {
		return nil, ErrKey
	}
	defer secret.Wipe(raw)
	if len(raw) != 32 {
		return nil, ErrKey
	}
	return seal.NewLocalKEK(raw)
}

func (a *FileAuthority) readRecord(ref KeyRef) (fileKeyRecord, bool, error) {
	info, err := a.root.Lstat(recordName(ref))
	if errors.Is(err, os.ErrNotExist) {
		return fileKeyRecord{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 || info.Mode().Perm()&0o077 != 0 {
		return fileKeyRecord{}, false, ErrKey
	}
	file, err := a.root.Open(recordName(ref))
	if err != nil {
		return fileKeyRecord{}, false, ErrKey
	}
	defer func() { _ = file.Close() }()
	wire, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(wire) > 16<<10 {
		return fileKeyRecord{}, false, ErrKey
	}
	var record fileKeyRecord
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Version != 1 || record.Ref != ref || record.CreatedAt.IsZero() ||
		(record.Phase != "creating" && record.Phase != "active" && record.Phase != "destroying" && record.Phase != "destroyed") {
		return fileKeyRecord{}, false, ErrKey
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fileKeyRecord{}, false, ErrKey
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fileKeyRecord{}, false, ErrKey
	}
	if (record.Phase == "creating" || record.Phase == "active") != (record.Destruction == nil) {
		return fileKeyRecord{}, false, ErrKey
	}
	return record, true, nil
}

func (a *FileAuthority) writeRecord(record fileKeyRecord) error {
	wire, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary := recordName(record.Ref) + ".new-" + uuid.NewString()
	file, err := a.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = a.root.Remove(temporary) }()
	written, writeErr := file.Write(wire)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(wire) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := a.root.Rename(temporary, recordName(record.Ref)); err != nil {
		return err
	}
	directory, err := a.root.Open(record.Ref.TenantID)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func (a *FileAuthority) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.root.Close()
}
