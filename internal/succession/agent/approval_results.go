// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/fsatomic"
)

// ApprovalResultStore keeps the exact predecessor signature after a token is
// consumed. A lost RPC reply may return that result for the same token and
// commitment, without doing another private-key operation.
type ApprovalResultStore interface {
	Load(token, commitment []byte) ([]byte, bool, error)
	Save(token, commitment, signature []byte) error
}

type DurableApprovalResults struct{ dir string }

func NewDurableApprovalResults(stateDir string) (*DurableApprovalResults, error) {
	if stateDir == "" {
		return nil, errors.New("agent: approval result directory is required")
	}
	dir := filepath.Join(stateDir, "pcas-cosign-results")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: create approval results: %w", err)
	}
	if err := fsatomic.SyncDirectory(stateDir); err != nil {
		return nil, fmt.Errorf("agent: sync approval state: %w", err)
	}
	return &DurableApprovalResults{dir: dir}, nil
}

func (s *DurableApprovalResults) name(token, commitment []byte) string {
	bound := make([]byte, 0, len(token)+len(commitment)+1)
	bound = append(bound, token...)
	bound = append(bound, 0)
	bound = append(bound, commitment...)
	return crypto.SHA256Hex(bound) + ".sig"
}

func (s *DurableApprovalResults) Load(token, commitment []byte) ([]byte, bool, error) {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(s.name(token, commitment))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return nil, false, errors.New("agent: invalid saved co-sign result")
	}
	signature := make([]byte, info.Size())
	if _, err := io.ReadFull(f, signature); err != nil {
		return nil, false, errors.New("agent: read saved co-sign result")
	}
	return signature, true, nil
}

func (s *DurableApprovalResults) Save(token, commitment, signature []byte) error {
	if len(signature) == 0 || len(signature) > 4096 {
		return errors.New("agent: invalid co-signature size")
	}
	tmp, err := os.CreateTemp(s.dir, ".pcas-result-") // #nosec G304 -- agent-owned state directory, random filename
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(signature); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	target := filepath.Join(s.dir, s.name(token, commitment))
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	return fsatomic.SyncDirectory(s.dir)
}
