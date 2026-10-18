// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
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
	return p.store.PutVerdictSigner(ctx, id, der)
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
}
