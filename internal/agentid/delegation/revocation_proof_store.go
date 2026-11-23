// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/fsatomic"
)

const spentProofDir = "agid-revocation-proof-spent"

// DurableProofConsumer keeps short-lived one-use receipts under the isolated
// signer's own floor. Exclusive creation blocks concurrent replay; fsync before
// the key op makes replay fail after a signer restart too.
type DurableProofConsumer struct {
	floorDir string
	mu       sync.Mutex
	uses     uint64
}

func NewDurableProofConsumer(floorDir string) *DurableProofConsumer {
	return &DurableProofConsumer{floorDir: floorDir}
}

func (s *DurableProofConsumer) ConsumeProofNonce(tenantID string, nonce []byte, expiresAt int64) error {
	if s == nil || s.floorDir == "" || tenantID == "" || len(nonce) != 32 {
		return errors.New("delegation: non-revocation proof custody is unconfigured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.floorDir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.floorDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	relDir := filepath.Join(spentProofDir, crypto.SHA256Hex([]byte(tenantID)))
	if err := root.MkdirAll(relDir, 0o700); err != nil {
		return err
	}
	relFile := filepath.Join(relDir, crypto.SHA256Hex(nonce)+".spent")
	f, err := root.OpenFile(relFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("delegation: non-revocation proof nonce was already spent")
	}
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d\n", expiresAt); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := fsatomic.SyncDirectory(filepath.Join(s.floorDir, relDir)); err != nil {
		return err
	}
	s.uses++
	if s.uses == 1 || s.uses%64 == 0 {
		// Only this feature's own expired receipts are removed. An unexpired
		// receipt remains spent even if the process restarts or a caller retries.
		if err := s.sweepExpired(root, relDir, time.Now().UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

func (s *DurableProofConsumer) sweepExpired(root *os.Root, relDir string, now int64) error {
	entries, err := os.ReadDir(filepath.Join(s.floorDir, relDir))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != 70 || !strings.HasSuffix(name, ".spent") {
			continue
		}
		rel := filepath.Join(relDir, name)
		raw, err := root.ReadFile(rel)
		if err != nil {
			return err
		}
		expiry, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || expiry > now {
			continue
		}
		if err := root.Remove(rel); err != nil {
			return err
		}
	}
	return fsatomic.SyncDirectory(filepath.Join(s.floorDir, relDir))
}
