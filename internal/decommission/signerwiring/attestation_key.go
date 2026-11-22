// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/fsatomic"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	destructionRecordKeyFile = "vdec-destruction-record-attestation-v1.sealed"
	destructionRecordKeyAD   = "trstctl/vdec/destruction-record-attestation/v1"
)

// loadOrCreateDestructionRecordKey preserves one signer-held attestation key
// across restarts. A no-replace link makes concurrent signer processes accept
// the same first published key; a corrupt or unavailable sealed file fails
// closed instead of silently rotating the trust root.
func loadOrCreateDestructionRecordKey(floorDir string, wrapper seal.KeyWrapper) (*crypto.LockedSigner, error) {
	if floorDir == "" || wrapper == nil {
		return nil, errors.New("vdec signer runtime: persistent attestation key requires a signer floor and key wrapper")
	}
	if err := os.MkdirAll(floorDir, 0o700); err != nil {
		return nil, err
	}
	if key, err := openDestructionRecordKey(floorDir, wrapper); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vdec signer runtime: reopen destruction attestation key: %w", err)
	}
	generated, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	defer generated.Destroy()
	privateDER, err := generated.PKCS8()
	if err != nil {
		return nil, err
	}
	sealed, err := seal.SealDomain(wrapper, privateDER, []byte(destructionRecordKeyFile), []byte(destructionRecordKeyAD))
	secret.Wipe(privateDER)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(floorDir, destructionRecordKeyFile)
	tmp, err := os.CreateTemp(floorDir, ".vdec-attestation-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := fsatomic.SyncDirectory(floorDir); err != nil {
		return nil, err
	}
	key, err := openDestructionRecordKey(floorDir, wrapper)
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: read committed attestation key: %w", err)
	}
	return key, nil
}

func openDestructionRecordKey(floorDir string, wrapper seal.KeyWrapper) (*crypto.LockedSigner, error) {
	root, err := os.OpenRoot(floorDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	sealed, err := root.ReadFile(destructionRecordKeyFile)
	if err != nil {
		return nil, err
	}
	plain, err := seal.OpenDomain(wrapper, sealed, []byte(destructionRecordKeyFile), []byte(destructionRecordKeyAD))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plain)
	key, err := crypto.LockedKeyFromPKCS8(plain)
	if err != nil {
		return nil, err
	}
	if key.Algorithm() != crypto.ECDSAP256 {
		key.Destroy()
		return nil, errors.New("vdec signer runtime: destruction attestation algorithm changed")
	}
	return key, nil
}
