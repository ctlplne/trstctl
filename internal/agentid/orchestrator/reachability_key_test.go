// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
)

type reachKeyProbe struct {
	store *delegation.DurableReachabilityTrustStore
}

func (p reachKeyProbe) ProvisionAgentReachabilityKey(ctx context.Context, id string, der []byte) error {
	stored, err := p.store.ReadVerdictSigner(ctx, id)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("operator has not installed signer verdict trust")
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, der) {
		return errors.New("signer verdict trust differs")
	}
	return nil
}
func (p reachKeyProbe) ReadAgentReachabilityKey(ctx context.Context, id string) ([]byte, error) {
	return p.store.ReadVerdictSigner(ctx, id)
}

func TestReachabilityVerdictKeySeparateVolumesAndColdRestart(t *testing.T) {
	controlDir, signerDir := t.TempDir(), t.TempDir()
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	remote := reachKeyProbe{store: delegation.NewDurableReachabilityTrustStore(signerDir)}
	key, public, err := PrepareReachabilityVerdictKey(controlDir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(ReachabilityPublicKeyPath(controlDir))
	if err != nil || !bytes.Equal(publicPEM, crypto.MarshalPublicKeyPEM(public.DER)) {
		t.Fatalf("operator public-key export differs from sealed custody: %v", err)
	}
	if _, _, err := provisionReachabilityVerdictSigner(controlDir, wrapper, remote); err == nil {
		t.Fatal("control plane auto-provisioned an absent signer verdict floor")
	}
	if _, err := remote.ReadAgentReachabilityKey(context.Background(), key.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("control plane wrote signer floor through RPC: %v", err)
	}
	if err := remote.store.PutVerdictSigner(context.Background(), key.ID, public.DER); err != nil {
		t.Fatalf("operator provision signer verdict floor: %v", err)
	}
	first, key, err := provisionReachabilityVerdictSigner(controlDir, wrapper, remote)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != defaultReachabilityVerdictKeyID {
		t.Fatalf("key id = %q", key.ID)
	}
	stored, err := remote.ReadAgentReachabilityKey(context.Background(), key.ID)
	if err != nil || !bytes.Equal(stored, first.Public().DER) {
		t.Fatal("isolated signer does not hold exact public key")
	}
	second, _, err := provisionReachabilityVerdictSigner(controlDir, wrapper, remote)
	if err != nil {
		t.Fatalf("cold control-plane restart: %v", err)
	}
	if !bytes.Equal(second.Public().DER, first.Public().DER) {
		t.Fatal("restart rotated the verdict authority")
	}
	message := []byte("tenant-bound-reachability-verdict")
	sig, err := second.Sign(message, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyMessage(stored, message, sig); err != nil {
		t.Fatalf("retained signer key did not verify: %v", err)
	}
	wrong, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Destroy()
	if _, _, err := provisionReachabilityVerdictSigner(controlDir, wrong, remote); err == nil {
		t.Fatal("wrong deployment wrapper silently replaced the sealed authority")
	}
	root, err := os.OpenRoot(controlDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	sealedBytes, err := root.ReadFile(reachKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Remove(reachKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Sign(message, crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("signing succeeded after sealed custody disappeared: private key was retained in RAM")
	}
	if err := root.WriteFile(reachKeyFile, sealedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Sign(message, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("sealed custody could not resume signing: %v", err)
	}
	otherDER, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ReachabilityPublicKeyPath(controlDir), crypto.MarshalPublicKeyPEM(otherDER), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provisionReachabilityVerdictSigner(controlDir, wrapper, remote); err == nil {
		t.Fatal("control plane accepted a public bootstrap file differing from sealed custody")
	}
}
