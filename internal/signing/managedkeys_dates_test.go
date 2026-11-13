// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// datedJournalProvider is an operation-aware provider that reports each key's
// own dates, like a cloud KMS (A168-L3).
type datedJournalProvider struct {
	*operationAwareJournalProvider
	mu        sync.Mutex
	created   map[string]time.Time
	deletes   map[string]time.Time
	failDates int
	reads     int
}

func newDatedJournalProvider() *datedJournalProvider {
	return &datedJournalProvider{operationAwareJournalProvider: newOperationAwareJournalProvider(),
		created: map[string]time.Time{}, deletes: map[string]time.Time{}}
}

func (p *datedJournalProvider) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, ref, err := p.operationAwareJournalProvider.GenerateManagedKeyForOperation(ctx, operationID, alg)
	if err == nil {
		p.mu.Lock()
		if _, ok := p.created[ref.ID]; !ok {
			p.created[ref.ID] = time.Date(2026, 11, 13, 7, 0, len(p.created)+1, 0, time.UTC)
		}
		p.mu.Unlock()
	}
	return signer, ref, err
}

func (p *datedJournalProvider) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	err := p.operationAwareJournalProvider.ZeroizeKeyForOperation(ctx, operationID, ref)
	if err == nil {
		p.mu.Lock()
		p.deletes[ref.ID] = p.created[ref.ID].Add(7 * 24 * time.Hour)
		p.mu.Unlock()
	}
	return err
}

func (p *datedJournalProvider) KeyDates(_ context.Context, ref crypto.KeyRef) (crypto.KeyDates, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	if p.failDates > 0 {
		p.failDates--
		return crypto.KeyDates{}, errors.New("provider unreachable")
	}
	return crypto.KeyDates{Created: p.created[ref.ID], DeletionScheduled: p.deletes[ref.ID]}, nil
}

// A168-L3: the signer reads the provider's own dates after each lifecycle
// action and returns them with the result; a replay returns the journaled
// dates without asking again; a provider that cannot report them leaves the
// operation to be retried, so a completed result always carries them.
func TestManagedKeyResultsCarryTheProvidersOwnDatesA168L3(t *testing.T) {
	provider := newDatedJournalProvider()
	t.Cleanup(provider.delegate.cleanup)
	journal := t.TempDir()
	server := signing.NewServer(signing.WithManagedKeyProviders(journal, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}))
	ctx := context.Background()
	generate := &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "a168l3-generate",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	}
	created := time.Date(2026, 11, 13, 7, 0, 1, 0, time.UTC)
	provider.failDates = 1
	if _, err := server.ManageKey(ctx, generate); err == nil {
		t.Fatal("a result was returned without the provider's dates")
	}
	// The retry reconciles the journaled intent (the provider already holds
	// the key) and now reads the dates.
	got, err := server.ManageKey(ctx, generate)
	if err != nil || got.GetProviderCreatedUnix() != created.Unix() || got.GetProviderDeletionUnix() != 0 {
		t.Fatalf("generate after the dates read recovered = %+v %v", got, err)
	}
	reads := provider.reads
	replay, err := server.ManageKey(ctx, generate)
	if err != nil || !replay.GetReplayed() || replay.GetProviderCreatedUnix() != created.Unix() || provider.reads != reads {
		t.Fatalf("replay = %+v %v (dates read %d → %d)", replay, err, reads, provider.reads)
	}
	zeroized, err := server.ManageKey(ctx, &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "aws-kms", OperationId: "a168l3-zeroize",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_ZEROIZE, KeyId: got.GetKeyId(), Algorithm: got.GetAlgorithm(),
	})
	if err != nil || zeroized.GetProviderCreatedUnix() != created.Unix() || zeroized.GetProviderDeletionUnix() != created.Add(7*24*time.Hour).Unix() {
		t.Fatalf("zeroize = %+v %v, want the scheduled deletion date", zeroized, err)
	}
	// The journal survives a signer restart with the dates.
	restarted := signing.NewServer(signing.WithManagedKeyProviders(journal, map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}))
	again, err := restarted.ManageKey(ctx, generate)
	if err != nil || !again.GetReplayed() || again.GetProviderCreatedUnix() != created.Unix() {
		t.Fatalf("replay after a restart = %+v %v", again, err)
	}
	// A provider without dates reports none and the operation completes.
	plain := newJournalProvider()
	t.Cleanup(plain.cleanup)
	undated := signing.NewServer(signing.WithManagedKeyProviders(t.TempDir(), map[string]crypto.RemoteKeyLifecycle{"pkcs11": plain}))
	res, err := undated.ManageKey(ctx, &signerpb.ManageKeyRequest{
		TenantId: "tenant-a", Provider: "pkcs11", OperationId: "a168l3-undated",
		Action: signerpb.ManagedKeyAction_MANAGED_KEY_ACTION_GENERATE, Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil || res.GetProviderCreatedUnix() != 0 || res.GetProviderDeletionUnix() != 0 {
		t.Fatalf("a provider without dates = %+v %v", res, err)
	}
}
