// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func weakP384Signer(t *testing.T) *crypto.LockedSigner {
	t.Helper()
	der, err := weakkeytest.SmallScalarPKCS8("P-384", 4)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP384, der)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// weakKeyFactory stands for a key source that hands back a weak key: a
// broken random source, or an HSM generating keys the way eMudhra's did.
type weakKeyFactory struct {
	signing.KeyFactory
	t    *testing.T
	made []*crypto.LockedSigner
}

func (f *weakKeyFactory) GenerateSigningKeyFromProto(signerpb.Algorithm) (signing.Key, error) {
	key := weakP384Signer(f.t)
	f.made = append(f.made, key)
	return key, nil
}

// eMudhra, Part 4: the signer refuses a weak key before its handle exists,
// and destroys it.
func TestGenerateKeyRefusesAWeakKeyFromItsKeySource(t *testing.T) {
	factory := &weakKeyFactory{KeyFactory: signing.NewDefaultKeyFactory(), t: t}
	server := signing.NewServer(signing.WithKeyFactory(factory))
	_, err := server.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P384})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "refusing a weak key") || !strings.Contains(err.Error(), "its private key is 4") {
		t.Fatalf("GenerateKey with a weak key source: %v", err)
	}
	if len(factory.made) != 1 {
		t.Fatalf("factory made %d keys", len(factory.made))
	}
	if _, err := factory.made[0].SignDigest(make([]byte, 48), crypto.SignOptions{Hash: crypto.SHA384}); err == nil {
		t.Fatal("the refused key was left alive")
	}
}

// weakJournalProvider is an HSM or KMS that generates a weak key.
type weakJournalProvider struct {
	*journalProvider
	t *testing.T
}

func (p *weakJournalProvider) GenerateManagedKey(_ context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := weakP384Signer(p.t)
	p.next++
	p.generate++
	id := "weak-provider-key"
	p.keys[id] = key
	return journalSigner{key: key}, crypto.KeyRef{ID: id, Algorithm: alg}, nil
}

func (p *weakJournalProvider) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return p.GenerateManagedKey(ctx, ref.Algorithm)
}

// A managed key the provider made weak is refused and zeroized at the
// provider, so no handle to it is ever published. The failure is the
// signer's own closed code, journaled as final: a retry repeats it without
// another provider call.
func TestManagedKeyGenerationRefusesAWeakProviderKey(t *testing.T) {
	provider := &weakJournalProvider{journalProvider: newJournalProvider(), t: t}
	t.Cleanup(provider.cleanup)
	journal := t.TempDir()
	server := signing.NewServer(signing.WithManagedKeyProviders(journal, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}))
	req := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "create-weak-key",
		Action:    signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE,
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P384,
	}
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := server.ManageKey(context.Background(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "provider_key_weak") {
			t.Fatalf("attempt %d with a weak provider key: %v", attempt, err)
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.generate != 1 || provider.zeroize != 1 || len(provider.keys) != 0 {
		t.Fatalf("weak provider key: generate=%d zeroize=%d keys=%d", provider.generate, provider.zeroize, len(provider.keys))
	}
	if !journalContains(t, journal, `"failure":"provider_key_weak"`) {
		t.Fatal("the journal does not record the weak-key failure")
	}
}

func journalContains(t *testing.T, dir, want string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			if journalContains(t, filepath.Join(dir, e.Name()), want) {
				return true
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- the test's own temporary journal directory (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), want) {
			return true
		}
	}
	return false
}
