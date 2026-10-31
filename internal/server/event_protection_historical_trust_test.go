// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
)

// Exact-command fixture authority only; this test does not replace the real
// outbox/grant lifecycle or prove a separate signer process.
type historicalTrustFixtureAuthority struct {
	want eventprotect.DestructionRequest
}

func (a *historicalTrustFixtureAuthority) AuthorizeDestruction(_ context.Context, request eventprotect.DestructionRequest) error {
	if request != a.want {
		return eventprotect.ErrContext
	}
	return nil
}

type historicalTrustNoSigning struct{ calls int }

func (s *historicalTrustNoSigning) SignArtifact(string, []byte) (string, error) {
	s.calls++
	return "", errors.New("fixture: no current signing allowed")
}

func TestEventProtectionRuntimeUsesPinnedHistoricalPublicTrustWithoutNewSigning(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	originalKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := eventProtectionBackupRoots(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authority := &historicalTrustFixtureAuthority{}
	original, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: cfg.Privacy.EventProtection.KeyDirectory, BackupRoots: roots, Locker: st, EvidenceKey: originalKey, DestructionAuthority: authority})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	ref := eventprotect.KeyRef{TenantID: "d4e602b7-e4af-4fce-8f71-d523b3291e43", ID: "11dc8c29-5880-41c3-812a-f9d7215bd473"}
	if err := original.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := original.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	offboarded := creation.CreatedAt.Add(time.Nanosecond)
	authority.want = eventprotect.DestructionRequest{Ref: ref, OperationID: "1339f86c-1fc7-4f61-9d25-41fb8a72b76e", RegistrationIdentity: "historical-registration", ActivationEventID: ref.ID, ActivationSequence: 2, CreationDigest: creation.Digest(), OffboardEventID: "historical-offboard", OffboardSequence: 3, OffboardedAt: offboarded, NotBefore: offboarded.Add(time.Nanosecond)}
	receipt, err := original.Destroy(t.Context(), authority.want)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	locked, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Destroy)
	forbidden := &historicalTrustNoSigning{}
	currentKey, err := jose.NewArtifactSigningKey("audit-export", locked.Public(), forbidden)
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := newEventProtectionRuntime(cfg, st, currentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, erased, err := untrusted.custody.DestructionReceipt(t.Context(), ref); err == nil || erased {
		t.Fatal("rotated current key silently trusted historical receipt")
	}
	if err := untrusted.Close(); err != nil {
		t.Fatal(err)
	}
	foreign, err := currentKey.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	foreignFile := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, "foreign-public.json")
	if err := os.WriteFile(foreignFile, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Privacy.EventProtection.VerificationKeysFile = foreignFile
	wrong, err := newEventProtectionRuntime(cfg, st, currentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, erased, err := wrong.custody.DestructionReceipt(t.Context(), ref); err == nil || erased {
		t.Fatal("unrelated pinned public key accepted original receipt")
	}
	if err := wrong.Close(); err != nil {
		t.Fatal(err)
	}
	public, err := originalKey.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, "operator-pinned-verification.json")
	if err := os.WriteFile(file, public, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Privacy.EventProtection.VerificationKeysFile = file
	trusted, err := newEventProtectionRuntime(cfg, st, currentKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trusted.Close() })
	got, erased, err := trusted.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !erased || got != receipt {
		t.Fatalf("runtime lost original independently signed destruction: %v", err)
	}
	for name, keys := range map[string]*jose.JWKSet{"source": trusted.policy.VerificationKeys, "reader": trusted.reader.Policy.VerificationKeys, "admission": trusted.admission.Policy.VerificationKeys} {
		if keys == nil {
			t.Fatalf("%s omitted historical public trust", name)
		}
		if _, err := keys.VerifyArtifact(receipt, jose.ArtifactEventKeyDestruction); err != nil {
			t.Fatalf("%s lost original receipt verification: %v", name, err)
		}
	}
	if forbidden.calls != 0 {
		t.Fatal("read-only historical verification requested a new signature")
	}
	if _, err := os.Stat(filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, ref.TenantID, ref.ID+".key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("historical verification recreated destroyed material")
	}
	// Even a correctly pinned old signature cannot override actual material
	// reintroduced after the recorded destruction. Use public dummy bytes only.
	if err := os.WriteFile(filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, ref.TenantID, ref.ID+".key"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, erased, err := trusted.custody.DestructionReceipt(t.Context(), ref); !errors.Is(err, eventprotect.ErrKey) || erased {
		t.Fatal("historical public trust bypassed current material readback")
	}
	if forbidden.calls != 0 {
		t.Fatal("refused current material triggered signing")
	}
}

func TestEventProtectionRuntimeRefusesInvalidHistoricalVerificationFile(t *testing.T) {
	st := newServerTestStore(t)
	key := testAuditSigningKey(t)
	public, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "malformed", "empty-set", "oversized", "managed-source", "managed-destination", "actual-destination", "directory"} {
		t.Run(name, func(t *testing.T) {
			cfg := eventProtectionRuntimeConfigFixture(t)
			// Public trust must be validated even when tenant custody is disabled.
			cfg.Privacy.EventProtection.KeyDirectory = ""
			file := filepath.Join(t.TempDir(), "operator-pinned-public.json")
			body := public
			var extra []string
			switch name {
			case "missing":
			case "malformed":
				body = []byte(`{"keys":`)
			case "empty-set":
				body = []byte(`{"keys":[]}`)
			case "oversized":
				body = append(bytes.Repeat([]byte(" "), 1<<20), public...)
			case "managed-source":
				file = filepath.Join(cfg.NATS.StoreDir, "public.json")
			case "managed-destination":
				file = filepath.Join(cfg.Backup.Directory, "public.json")
			case "actual-destination":
				extra = []string{filepath.Dir(file)}
			case "directory":
				if err := os.Mkdir(file, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if name != "missing" && name != "directory" {
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg.Privacy.EventProtection.VerificationKeysFile = file
			runtime, err := newEventProtectionRuntime(cfg, st, key, extra...)
			if runtime != nil {
				_ = runtime.Close()
			}
			if err == nil {
				t.Fatal("configured invalid historical public trust silently fell back to current signer")
			}
		})
	}
}
