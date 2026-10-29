// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
)

type fixedDestructionAuthority struct {
	want  DestructionRequest
	err   error
	calls int
}

type interruptibleEvidenceSigner struct {
	key  *jose.SigningKey
	fail bool
}

func (s *interruptibleEvidenceSigner) SignArtifact(kind string, payload []byte) (string, error) {
	if s.fail {
		return "", errors.New("fixture: isolated signer unavailable")
	}
	return s.key.SignArtifact(kind, payload)
}

func TestFileAuthorityRecoversRemovalBeforeSignatureWithoutRegeneratingKey(t *testing.T) {
	authority, cfg, request, _, _ := destructionFixture(t)
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	locked, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Destroy)
	local, err := jose.NewDigestSigningKey("a233-interrupted-evidence", locked)
	if err != nil {
		t.Fatal(err)
	}
	remote := &interruptibleEvidenceSigner{key: local, fail: true}
	cfg.EvidenceKey, err = jose.NewArtifactSigningKey("a233-interrupted-evidence", locked.Public(), remote)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	interrupted.now = func() time.Time { return request.NotBefore }
	if receipt, err := interrupted.Destroy(t.Context(), request); err == nil || receipt != "" {
		t.Fatal("unavailable signer produced completed destruction evidence")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, keyName(request.Ref))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture did not reach the removal-before-signature boundary")
	}
	if err := interrupted.WithKey(t.Context(), request.Ref, func(seal.KeyWrapper) error { t.Fatal("pending destruction opened key"); return nil }); !errors.Is(err, ErrKey) {
		t.Fatalf("unsigned removal was reported as verified erasure: %v", err)
	}
	if err := interrupted.Close(); err != nil {
		t.Fatal(err)
	}
	remote.fail = false
	restarted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return request.NotBefore.Add(time.Minute) }
	t.Cleanup(func() { _ = restarted.Close() })
	receipt, err := restarted.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyDestructionReceipt(local.JWKS(), receipt)
	if err != nil || !claims.RemovedAt.Equal(request.NotBefore) {
		t.Fatalf("recovery lost the durable observed removal time: %v", err)
	}
}

func TestDestructionReceiptRejectsWrongTrustDomainAndAmbiguousClaims(t *testing.T) {
	authority, _, request, _, key := destructionFixture(t)
	receipt, err := authority.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	other, err := jose.GenerateRSASigningKey("a233-destruction-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDestructionReceipt(other.JWKS(), receipt); err == nil {
		t.Fatal("wrong evidence trust accepted")
	}
	wire, err := key.JWKS().VerifyArtifact(receipt, jose.ArtifactEventKeyDestruction)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain, err := key.SignArtifact(jose.ArtifactAuditExport, wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDestructionReceipt(key.JWKS(), wrongDomain); err == nil {
		t.Fatal("cross-domain evidence accepted")
	}
	ambiguous := append([]byte(`{"schema":"ignored",`), wire[1:]...)
	resigned, err := key.SignArtifact(jose.ArtifactEventKeyDestruction, ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDestructionReceipt(key.JWKS(), resigned); err == nil {
		t.Fatal("signed duplicate claim fields accepted")
	}
}

func (a *fixedDestructionAuthority) AuthorizeDestruction(_ context.Context, request DestructionRequest) error {
	a.calls++
	if a.err != nil {
		return a.err
	}
	want, _ := json.Marshal(a.want)
	got, _ := json.Marshal(request)
	if !bytes.Equal(want, got) {
		return errors.New("fixture: command does not match retained offboard authority")
	}
	return nil
}

func destructionFixture(t *testing.T) (*FileAuthority, FileAuthorityConfig, DestructionRequest, *fixedDestructionAuthority, *jose.SigningKey) {
	t.Helper()
	initial, cfg, ref := keyAuthorityFixture(t)
	if err := initial.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	offboarded := time.Now().UTC()
	request := DestructionRequest{
		Ref: ref, OperationID: "93ba00d2-9108-4f7f-8c9d-f6e887ba0612",
		OffboardEventID: "A233OffboardSource", OffboardSequence: 9,
		OffboardedAt: offboarded, NotBefore: offboarded.Add(time.Hour),
	}
	grant := &fixedDestructionAuthority{want: request}
	key, err := jose.GenerateRSASigningKey("a233-destruction-fixture")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DestructionAuthority, cfg.EvidenceKey = grant, key
	authority, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return request.NotBefore }
	t.Cleanup(func() { _ = authority.Close() })
	return authority, cfg, request, grant, key
}

func TestFileAuthorityDestructionRequiresOffboardAuthorityAndRetention(t *testing.T) {
	authority, cfg, request, grant, _ := destructionFixture(t)
	grant.err = errors.New("fixture: not an authorized durable outbox command")
	if _, err := authority.Destroy(t.Context(), request); err == nil {
		t.Fatal("unapproved destruction succeeded")
	}
	grant.err = nil
	authority.now = func() time.Time { return request.NotBefore.Add(-time.Nanosecond) }
	if _, err := authority.Destroy(t.Context(), request); !errors.Is(err, ErrRetention) {
		t.Fatalf("early destruction: %v", err)
	}
	if err := authority.WithKey(t.Context(), request.Ref, func(seal.KeyWrapper) error { return nil }); err != nil {
		t.Fatalf("rejected destruction affected active material: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, keyName(request.Ref))); err != nil {
		t.Fatal("rejected destruction removed the key")
	}
}

func TestFileAuthorityDestructionHasStableVerifiedReceiptAcrossRestart(t *testing.T) {
	authority, cfg, request, _, key := destructionFixture(t)
	receipt, err := authority.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil || claims.Request != request || claims.RemovedAt.Before(request.NotBefore) {
		t.Fatalf("receipt did not bind exact retention authority: %+v %v", claims, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, keyName(request.Ref))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("signed completion retained key material")
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	again, err := restarted.Destroy(t.Context(), request)
	if err != nil || again != receipt {
		t.Fatalf("restart did not recover exact signed result: %v", err)
	}
	called := false
	if err := restarted.WithKey(t.Context(), request.Ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrDestroyed) || called {
		t.Fatalf("destroyed key was not distinguished from missing custody: %v", err)
	}
	if err := restarted.Provision(t.Context(), request.Ref); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("destroyed identity could be provisioned again: %v", err)
	}
	changed := request
	changed.OperationID = "50a873e1-e185-4f4b-acb4-f2ae49519e56"
	cfg.DestructionAuthority.(*fixedDestructionAuthority).want = changed
	if _, err := restarted.Destroy(t.Context(), changed); !errors.Is(err, ErrDestructionConflict) {
		t.Fatalf("second command replaced destruction authority: %v", err)
	}
}

func TestFileAuthorityMissingKeyIsNotDestructionEvidence(t *testing.T) {
	authority, cfg, request, _, _ := destructionFixture(t)
	if err := os.Remove(filepath.Join(cfg.Directory, keyName(request.Ref))); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Destroy(t.Context(), request); !errors.Is(err, ErrKey) {
		t.Fatalf("preexisting unexplained key loss was certified as completed destruction: %v", err)
	}
}

func TestFileAuthorityRejectsAmbiguousCustodyMetadata(t *testing.T) {
	authority, _, ref := keyAuthorityFixture(t)
	if err := authority.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	file, err := authority.root.Open(recordName(ref))
	if err != nil {
		t.Fatal(err)
	}
	original, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read fixture custody record: %v %v", readErr, closeErr)
	}
	mutated := bytes.Replace(original, []byte(`"phase":"active"`), []byte(`"phase":"creating","phase":"active"`), 1)
	if bytes.Equal(original, mutated) {
		t.Fatal("fixture did not mutate metadata")
	}
	file, err = authority.root.OpenFile(recordName(ref), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := file.Write(mutated)
	closeErr = file.Close()
	if writeErr != nil || closeErr != nil || written != len(mutated) {
		t.Fatalf("mutate fixture custody record: %v %v", writeErr, closeErr)
	}
	called := false
	if err := authority.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, ErrKey) || called {
		t.Fatal("duplicate custody metadata fields were interpreted")
	}
}
