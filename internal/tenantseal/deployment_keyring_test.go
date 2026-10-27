// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/store"
)

type deploymentStateDouble struct {
	mu    sync.Mutex
	state *store.DeploymentKEKDomain
	reads int
}

func (s *deploymentStateDouble) DeploymentKEKDomain(context.Context) (store.DeploymentKEKDomain, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.state == nil {
		return store.DeploymentKEKDomain{}, false, nil
	}
	return *s.state, true, nil
}

func (s *deploymentStateDouble) set(d *store.DeploymentKEKDomain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = d
}

func deploymentTestFixtures(t *testing.T) (*seal.LocalKEK, *LocalWrapperRegistry) {
	t.Helper()
	local, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Destroy)
	dir := t.TempDir()
	var wrappers []LocalWrapper
	for id, fill := range map[string]byte{"deploy-a": 0x3a, "deploy-b": 0x3b} {
		path := filepath.Join(dir, id)
		if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		wrappers = append(wrappers, LocalWrapper{ID: id, Path: path})
	}
	registry, err := NewLocalWrapperRegistry(wrappers)
	if err != nil {
		t.Fatal(err)
	}
	return local, registry
}

// nextGeneration records a rotation to generation+1 under wrapper id, as
// DeploymentRotation.Begin does.
func nextGeneration(t *testing.T, registry DomainKEKManager, from *store.DeploymentKEKDomain, id string) *store.DeploymentKEKDomain {
	t.Helper()
	next := store.DeploymentKEKDomain{DomainID: "6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11"}
	if from != nil {
		next = *from
	}
	next.NextGeneration = next.Generation + 1
	binding, err := DeploymentBinding(next.DomainID, next.NextGeneration)
	if err != nil {
		t.Fatal(err)
	}
	key, wrapped, err := registry.CreateDomainKEK(context.Background(), WrapperRef{Kind: WrapperKindLocalFile, ID: id}, binding)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	next.NextWrapperKind, next.NextWrapperID, next.NextWrappedKEK = WrapperKindLocalFile, id, wrapped
	next.OperationStatus = store.DeploymentKEKOperationRunning
	return &next
}

func promoted(d *store.DeploymentKEKDomain) *store.DeploymentKEKDomain {
	out := *d
	out.PreviousGeneration = out.Generation
	out.Generation = out.NextGeneration
	out.WrapperKind, out.WrapperID, out.WrappedKEK = out.NextWrapperKind, out.NextWrapperID, out.NextWrappedKEK
	out.NextGeneration, out.NextWrapperKind, out.NextWrapperID, out.NextWrappedKEK = 0, "", "", nil
	out.OperationStatus = store.DeploymentKEKOperationCompleted
	return &out
}

// A198: before any rotation the keyring is the key file, byte for byte; while
// a rotation runs, new data is wrapped under the next generation and both
// generations open; once it completes, the key file's data keys are refused.
func TestDeploymentKeyringRoutesGenerationsAndRetiresThePrevious(t *testing.T) {
	local, registry := deploymentTestFixtures(t)
	source := &deploymentStateDouble{}
	ring, err := NewDeploymentKeyring(local, source, registry)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("credential")
	legacy, err := seal.Seal(local, []byte("sealed by the key file"), aad)
	if err != nil {
		t.Fatal(err)
	}
	fromRing, err := seal.Seal(ring, []byte("sealed by the keyring"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped, _, _ := seal.ContainerWrappedDEK(fromRing); len(wrapped) != seal.LocalWrappedDEKSize {
		t.Fatalf("an unrotated keyring wrapped a %d-byte key, want the key file's untagged form", len(wrapped))
	}
	for _, c := range []struct {
		wrapper   seal.KeyWrapper
		container []byte
	}{{local, fromRing}, {ring, legacy}} {
		if _, err := seal.Open(c.wrapper, c.container, aad); err != nil {
			t.Fatalf("generation 0 is not interchangeable with the key file: %v", err)
		}
	}

	rotating := nextGeneration(t, registry, nil, "deploy-a")
	source.set(rotating)
	view := ring.View(rotating)
	defer view.Destroy()
	underNext, err := seal.Seal(view, []byte("sealed during the rotation"), aad)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _, _ := seal.ContainerWrappedDEK(underNext)
	if generation, _, err := seal.WrappedGeneration(wrapped); err != nil || generation != 1 {
		t.Fatalf("data sealed during the rotation is generation %d (%v), want 1", generation, err)
	}
	if _, err := seal.Open(local, underNext, aad); err == nil {
		t.Fatal("the key file opened data sealed under the next generation")
	}
	for _, container := range [][]byte{legacy, underNext} {
		if _, err := seal.Open(view, container, aad); err != nil {
			t.Fatalf("a rotating view refused a live generation: %v", err)
		}
	}
	// The keyring itself re-reads the state when a data key names a
	// generation its cached state does not hold.
	if plain, err := seal.Open(ring, underNext, aad); err != nil || string(plain) != "sealed during the rotation" {
		t.Fatalf("the keyring did not refresh to the next generation: %q %v", plain, err)
	}

	done := promoted(rotating)
	source.set(done)
	ring.Observe(*done)
	completed := ring.View(done)
	defer completed.Destroy()
	if _, err := seal.Open(completed, legacy, aad); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("a completed rotation still opened the key file's data: %v", err)
	}
	if _, err := completed.UnwrapDEK(mustWrapped(t, legacy)); !errors.Is(err, ErrDeploymentGenerationNotLive) {
		t.Fatalf("a retired generation's data key = %v, want ErrDeploymentGenerationNotLive", err)
	}
	if plain, err := seal.Open(ring, underNext, aad); err != nil || string(plain) != "sealed during the rotation" {
		t.Fatalf("the promoted generation does not open: %q %v", plain, err)
	}

	digest, err := ring.KeyedDigest([]byte("domain"), []byte("material"))
	if err != nil {
		t.Fatal(err)
	}
	if fileDigest, _ := local.KeyedDigest([]byte("domain"), []byte("material")); !bytes.Equal(digest, fileDigest) {
		t.Fatal("the keyring's evidence MAC changed with the rotation")
	}
}

func mustWrapped(t *testing.T, container []byte) []byte {
	t.Helper()
	wrapped, _, err := seal.ContainerWrappedDEK(container)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

// A direct use reads the state at most deploymentKeyringRefresh old; a data
// key under a generation it does not hold forces one fresh read.
func TestDeploymentKeyringRefreshesItsState(t *testing.T) {
	local, registry := deploymentTestFixtures(t)
	source := &deploymentStateDouble{}
	ring, err := NewDeploymentKeyring(local, source, registry)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_800_000_000, 0)
	ring.now = func() time.Time { return clock }
	if _, err := ring.WrapDEK(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.WrapDEK(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if source.reads != 1 {
		t.Fatalf("two uses inside the refresh window read the state %d times, want 1", source.reads)
	}
	source.set(nextGeneration(t, registry, nil, "deploy-b"))
	clock = clock.Add(deploymentKeyringRefresh)
	wrapped, err := ring.WrapDEK(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if generation, _, _ := seal.WrappedGeneration(wrapped); generation != 1 || source.reads != 2 {
		t.Fatalf("after the window the keyring wrapped generation %d after %d reads, want 1 after 2", generation, source.reads)
	}
	if _, err := ring.WrapDEK([]byte("short")); err == nil {
		t.Fatal("the keyring wrapped a data key that is not 32 bytes")
	}
}

func TestDeploymentBindingIsNeverATenantBinding(t *testing.T) {
	binding, err := DeploymentBinding("6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11", 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(binding) != "deployment-kek;domain=6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11;generation=3" || strings.HasPrefix(string(binding), "tenant=") {
		t.Fatalf("binding = %q", binding)
	}
	for _, bad := range []struct {
		domain     string
		generation int64
	}{{"", 1}, {"a;b", 1}, {" a", 1}, {"a", 0}} {
		if _, err := DeploymentBinding(bad.domain, bad.generation); err == nil {
			t.Errorf("DeploymentBinding(%q, %d) accepted", bad.domain, bad.generation)
		}
	}
}

// A deployment pass moves every unlabeled container in an event, nested or
// not, to the writing generation, leaves a tenant domain's container
// byte-identical, and its pair validator accepts exactly that.
func TestDeploymentRewrapperMovesOnlyDeploymentContainers(t *testing.T) {
	local, registry := deploymentTestFixtures(t)
	ring, err := NewDeploymentKeyring(local, nil, registry)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("aad")
	legacy, err := seal.Seal(local, []byte("legacy"), aad)
	if err != nil {
		t.Fatal(err)
	}
	tenantKey, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x5c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer tenantKey.Destroy()
	labeled, err := seal.SealDomain(tenantKey, []byte("tenant"), aad, []byte("tenant=t;domain=d;generation=1"))
	if err != nil {
		t.Fatal(err)
	}
	nested, err := json.Marshal(map[string]any{"sealed": legacy})
	if err != nil {
		t.Fatal(err)
	}
	event, err := json.Marshal(map[string]any{
		"credential": legacy, "tenant": labeled,
		"outbox": base64.StdEncoding.EncodeToString(nested), "name": "unchanged",
	})
	if err != nil {
		t.Fatal(err)
	}
	view := ring.View(nextGeneration(t, registry, nil, "deploy-a"))
	defer view.Destroy()
	rewriter, err := NewDeploymentRewrapper(view)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := rewriter.Transform("secret.version_written", 1, event)
	if err != nil || !changed {
		t.Fatalf("transform changed=%v err=%v", changed, err)
	}
	if containers, rewrapped := rewriter.DeploymentCounts(); containers != 2 || rewrapped != 2 {
		t.Fatalf("counts = %d read, %d re-wrapped; want 2 and 2", containers, rewrapped)
	}
	var decoded map[string]any
	if err := json.Unmarshal(after, &decoded); err != nil {
		t.Fatal(err)
	}
	tenantAfter, _ := base64.StdEncoding.DecodeString(decoded["tenant"].(string))
	if !bytes.Equal(tenantAfter, labeled) || decoded["name"] != "unchanged" {
		t.Fatal("the pass touched a tenant domain's container or a plain field")
	}
	credential, _ := base64.StdEncoding.DecodeString(decoded["credential"].(string))
	if generation, _, _ := seal.WrappedGeneration(mustWrapped(t, credential)); generation != 1 {
		t.Fatalf("the credential's data key is generation %d, want 1", generation)
	}
	if err := rewriter.ValidatePair("secret.version_written", 1, event, after); err != nil {
		t.Fatalf("pair validation: %v", err)
	}
	again, changed, err := rewriter.Transform("secret.version_written", 1, after)
	if err != nil || changed || !bytes.Equal(again, after) {
		t.Fatalf("a second pass changed=%v err=%v; the containers are already in the writing generation", changed, err)
	}
	tampered := bytes.Replace(after, []byte(`"unchanged"`), []byte(`"changed!!"`), 1)
	if err := rewriter.ValidatePair("secret.version_written", 1, event, tampered); err == nil {
		t.Fatal("the validator accepted a pass that changed a plain field")
	}
}
