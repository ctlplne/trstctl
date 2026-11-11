// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func newRewrapTestKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	return wrapper
}

func publicKeysOf(t *testing.T, s *Server, handles ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, handle := range handles {
		resp, err := s.GetPublicKey(context.Background(), &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: handle}})
		if err != nil {
			t.Fatalf("public key of %s: %v", handle, err)
		}
		out[handle] = resp.GetPublicKey()
	}
	return out
}

// A200-L2 Done when (restore drill): a key store the local KEK sealed —
// keys, a destruction journal record and a public file — is re-wrapped onto
// another wrapper (standing in for the KMS adapter). The re-wrapped store
// serves the same keys and replays the journal under the new wrapper only,
// the public file is carried byte for byte, and the original is kept as the
// rollback copy that the local KEK still opens.
func TestRewrapKeyStoreMovesALocalKEKStoreOntoAnotherWrapperA200L2(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "keys")
	source, destination := newRewrapTestKEK(t), newRewrapTestKEK(t)
	req := GatedDestroyRequest{
		TenantID: "tenant-a", Handle: "ca-key", SubjectRef: "ca-old",
		AssertedFinalEpoch: 7, LedgerPosition: 41, RequiredSetDigest: []byte("required-digest"),
		SatisfactionEvidence: []byte("frozen-evidence"), AuditChainHead: []byte("audit-head"),
	}
	server, err := NewPersistentServer(NewKeyStore(dir, source), WithGatedDestruction(&fakeGatedDestroyer{decision: GatedDestroyDecision{RefusalRecord: []byte("signed-refusal")}}))
	if err != nil {
		t.Fatal(err)
	}
	generateGatedDestroyKey(t, ctx, server, req.Handle)
	generateGatedDestroyKey(t, ctx, server, "issuing-key")
	refusal, err := server.GatedDestroy(ctx, gatedDestroyRequestToProto(req))
	if err != nil || len(refusal.GetRefusalRecord()) == 0 {
		t.Fatalf("journaled refusal = %+v, %v", refusal, err)
	}
	before := publicKeysOf(t, server, req.Handle, "issuing-key")
	kit := []byte(`{"kit":"public"}`)
	if err := os.WriteFile(filepath.Join(dir, "offline-kit.json"), kit, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := RewrapKeyStore(dir, source, destination, time.Date(2026, 11, 11, 18, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}
	if report.Keys != 2 || report.Rewrapped < 3 || report.Copied < 1 || report.Backup != dir+".pre-rewrap-20261111T180000Z" {
		t.Fatalf("report = %+v", report)
	}

	restarted, err := NewPersistentServer(NewKeyStore(dir, destination), WithGatedDestruction(&fakeGatedDestroyer{err: errors.New("the gate is unavailable after the re-wrap")}))
	if err != nil {
		t.Fatalf("the re-wrapped store does not open under the destination: %v", err)
	}
	after := publicKeysOf(t, restarted, req.Handle, "issuing-key")
	for handle, pub := range before {
		if !bytes.Equal(after[handle], pub) {
			t.Fatalf("key %s changed across the re-wrap", handle)
		}
	}
	replayed, err := restarted.GatedDestroy(ctx, gatedDestroyRequestToProto(req))
	if err != nil || !bytes.Equal(replayed.GetRefusalRecord(), refusal.GetRefusalRecord()) {
		t.Fatalf("the destruction journal did not replay under the destination: %q, %v", replayed.GetRefusalRecord(), err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "offline-kit.json")); err != nil || !bytes.Equal(got, kit) { // #nosec G304 -- the test's own temp key store (CWE-22)
		t.Fatalf("public file = %q, %v; want it carried byte for byte", got, err)
	}
	if _, err := NewPersistentServer(NewKeyStore(dir, source)); err == nil {
		t.Fatal("the local KEK still opens the re-wrapped store")
	}
	rollback, err := NewPersistentServer(NewKeyStore(report.Backup, source))
	if err != nil {
		t.Fatalf("the rollback copy does not open under the local KEK: %v", err)
	}
	if kept := publicKeysOf(t, rollback, req.Handle, "issuing-key"); !bytes.Equal(kept[req.Handle], before[req.Handle]) {
		t.Fatal("the rollback copy holds another key")
	}
	if left, _ := filepath.Glob(filepath.Join(root, "keys.rewrap-*")); len(left) != 0 {
		t.Fatalf("staging copies left behind: %v", left)
	}
}

// changingWrapper wraps like the destination but adds a file to the key
// store on its first wrap, as a signer still running would.
type changingWrapper struct {
	seal.KeyWrapper
	dir  string
	done bool
}

func (c *changingWrapper) WrapDEK(dek []byte) ([]byte, error) {
	if !c.done {
		c.done = true
		if err := os.WriteFile(filepath.Join(c.dir, "late.key"), []byte("written by a running signer"), 0o600); err != nil {
			return nil, err
		}
	}
	return c.KeyWrapper.WrapDEK(dek)
}

// lyingWrapper returns another data key than the one it wrapped.
type lyingWrapper struct{ seal.KeyWrapper }

func (l lyingWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	dek, err := l.KeyWrapper.UnwrapDEK(wrapped)
	if err == nil && len(dek) > 0 {
		dek[0] ^= 0xff
	}
	return dek, err
}

// A200-L2: a re-wrap that cannot finish leaves the key store exactly as it
// was, keeps no staging copy and makes no backup.
func TestRewrapKeyStoreLeavesTheStoreUntouchedWhenItCannotFinishA200L2(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, dir string, source seal.KeyWrapper) seal.KeyWrapper
		want    string
	}{
		{"a container another key sealed", func(t *testing.T, dir string, source seal.KeyWrapper) seal.KeyWrapper {
			foreign, err := seal.Seal(newRewrapTestKEK(t), []byte("another custody"), []byte("foreign"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "foreign.key"), foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			return newRewrapTestKEK(t)
		}, "is not sealed under the source key"},
		{"a symbolic link", func(t *testing.T, dir string, source seal.KeyWrapper) seal.KeyWrapper {
			if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "link")); err != nil {
				t.Skipf("symlink: %v", err)
			}
			return newRewrapTestKEK(t)
		}, "symbolic link"},
		{"a signer still writing", func(t *testing.T, dir string, source seal.KeyWrapper) seal.KeyWrapper {
			return &changingWrapper{KeyWrapper: newRewrapTestKEK(t), dir: dir}
		}, "changed while it was copied"},
		{"a destination that gives back another key", func(t *testing.T, dir string, source seal.KeyWrapper) seal.KeyWrapper {
			return lyingWrapper{newRewrapTestKEK(t)}
		}, "different data key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "keys")
			source := newRewrapTestKEK(t)
			server, err := NewPersistentServer(NewKeyStore(dir, source))
			if err != nil {
				t.Fatal(err)
			}
			generateGatedDestroyKey(t, ctx, server, "ca-key")
			destination := tc.prepare(t, dir, source)
			snapshot, err := fingerprintTree(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, err = RewrapKeyStore(dir, source, destination, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("re-wrap = %v, want a refusal naming %q", err, tc.want)
			}
			if tc.name != "a signer still writing" {
				now, err := fingerprintTree(dir)
				if err != nil || !sameFingerprints(snapshot, now) {
					t.Fatalf("the key store changed after a refused re-wrap (%v)", err)
				}
			}
			for _, pattern := range []string{"keys.rewrap-*", "keys.pre-rewrap-*"} {
				if left, _ := filepath.Glob(filepath.Join(root, pattern)); len(left) != 0 {
					t.Fatalf("%s left behind: %v", pattern, left)
				}
			}
			if tc.name != "a container another key sealed" {
				if _, err := NewPersistentServer(NewKeyStore(dir, source)); err != nil && tc.name != "a signer still writing" {
					t.Fatalf("the original store no longer opens under the local KEK: %v", err)
				}
			}
		})
	}
}
