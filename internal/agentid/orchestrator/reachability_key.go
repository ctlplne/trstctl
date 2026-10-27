// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/editionseam"
)

const reachKeyFile = "agid-control-plane/reachability-verdict-v1.sealed"
const reachKeyDomain = "agid-control-plane-reachability-verdict/v1"

// provisionReachabilityVerdictSigner reopens one sealed control-plane key and
// binds its public half to the isolated signer over the authenticated RPC. The
// two processes deliberately have different volumes; no shared-file inference.
func provisionReachabilityVerdictSigner(floorDir string, wrapper seal.KeyWrapper, remote editionseam.AgentReachabilityKeyProvisioner) (crypto.Signer, reach.VerdictKeyRef, error) {
	if floorDir == "" || wrapper == nil || remote == nil {
		return nil, reach.VerdictKeyRef{}, errors.New("agentid outbox: sealed verdict custody and isolated signer provisioner are required")
	}
	locked, err := loadOrCreateReachabilityKey(floorDir, wrapper)
	if err != nil {
		return nil, reach.VerdictKeyRef{}, err
	}
	public := locked.Public()
	public.DER = append([]byte(nil), public.DER...)
	locked.Destroy()
	key := reach.VerdictKeyRef{ID: defaultReachabilityVerdictKeyID, Algorithm: string(public.Algorithm)}
	if err := remote.ProvisionAgentReachabilityKey(context.Background(), key.ID, public.DER); err != nil {
		return nil, reach.VerdictKeyRef{}, fmt.Errorf("agentid outbox: provision signer verdict trust: %w", err)
	}
	readback, err := remote.ReadAgentReachabilityKey(context.Background(), key.ID)
	if err != nil || !bytes.Equal(readback, public.DER) {
		return nil, reach.VerdictKeyRef{}, errors.New("agentid outbox: signer verdict trust readback differs from sealed key")
	}
	return &sealedReachabilitySigner{floorDir: floorDir, wrapper: wrapper, public: public}, key, nil
}

// sealedReachabilitySigner keeps only the public key in memory. Each signature
// opens the deployment-sealed private key into a locked buffer, checks that its
// public half still matches the signer trust binding, and destroys it before
// returning. Losing or replacing custody therefore fails closed immediately.
type sealedReachabilitySigner struct {
	floorDir string
	wrapper  seal.KeyWrapper
	public   crypto.PublicKey
}

func (s *sealedReachabilitySigner) Public() crypto.PublicKey {
	return crypto.PublicKey{Algorithm: s.public.Algorithm, DER: append([]byte(nil), s.public.DER...)}
}

func (s *sealedReachabilitySigner) Algorithm() crypto.Algorithm { return s.public.Algorithm }

func (s *sealedReachabilitySigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	locked, err := openReachabilityKey(s.floorDir, s.wrapper)
	if err != nil {
		return nil, fmt.Errorf("agentid outbox: reopen verdict custody for signing: %w", err)
	}
	defer locked.Destroy()
	if !bytes.Equal(locked.Public().DER, s.public.DER) {
		return nil, errors.New("agentid outbox: sealed verdict authority changed after signer trust binding")
	}
	return crypto.SignerFromDigestSigner(locked).Sign(message, opts)
}

func openReachabilityKey(floorDir string, wrapper seal.KeyWrapper) (*crypto.LockedSigner, error) {
	root, err := os.OpenRoot(floorDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	sealed, err := root.ReadFile(reachKeyFile)
	if err != nil {
		return nil, err
	}
	plain, err := seal.OpenDomain(wrapper, sealed, []byte(defaultReachabilityVerdictKeyID), []byte(reachKeyDomain))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plain)
	locked, err := crypto.LockedKeyFromPKCS8(plain)
	if err != nil {
		return nil, err
	}
	if locked.Algorithm() != crypto.ECDSAP256 {
		locked.Destroy()
		return nil, errors.New("agentid outbox: retained verdict key algorithm changed")
	}
	return locked, nil
}

// ReachabilityKeyPath is the sealed verdict key's file under floorDir; a
// deployment KEK rotation re-wraps it in place (A198).
func ReachabilityKeyPath(floorDir string) string { return filepath.Join(floorDir, reachKeyFile) }

// loadOrCreateReachabilityKey seals private PKCS#8 under the deployment wrapper.
// A synced temporary file plus no-replace link makes concurrent startup choose
// one first writer; a loser reopens the winner instead of rotating trust.
func loadOrCreateReachabilityKey(floorDir string, wrapper seal.KeyWrapper) (*crypto.LockedSigner, error) {
	path := ReachabilityKeyPath(floorDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if locked, err := openReachabilityKey(floorDir, wrapper); err == nil {
		return locked, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agentid outbox: reopen sealed verdict key: %w", err)
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
	sealed, err := seal.SealDomain(wrapper, privateDER, []byte(defaultReachabilityVerdictKeyID), []byte(reachKeyDomain))
	secret.Wipe(privateDER)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".reachability-key-*")
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
	dir, err := os.Open(filepath.Dir(path)) // #nosec G304 -- configured control-plane key directory; open only to fsync the sealed-key publication
	if err != nil {
		return nil, err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if err := dir.Close(); err != nil {
		return nil, err
	}
	locked, err := openReachabilityKey(floorDir, wrapper)
	if err != nil {
		return nil, fmt.Errorf("agentid outbox: read committed verdict key: %w", err)
	}
	return locked, nil
}
