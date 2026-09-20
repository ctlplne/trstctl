// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestLifecycleIssuanceAndRevocationAreOrdered(t *testing.T) {
	for _, renew := range []bool{false, true} {
		name := "first issuance"
		if renew {
			name = "renewal"
		}
		t.Run(name, func(t *testing.T) {
			h := newIssuanceDispatcherHarness(t)
			ctx := t.Context()
			owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "revocation-order", "")
			if err != nil {
				t.Fatal(err)
			}
			ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "ordered.served.test", OwnerID: owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
				t.Fatal(err)
			}
			destination := "ca.issue"
			if renew {
				dispatchOutbox(t, h, 1)
				if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployment completed"); err != nil {
					t.Fatal(err)
				}
				if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "renew"); err != nil {
					t.Fatal(err)
				}
				destination = "ca.renew"
			}
			entry := pendingOutboxByDestination(t, h, destination)
			msg := orchestrator.Message{TenantID: h.tenant, Destination: destination, Payload: entry.Payload, IdempotencyKey: entry.IdempotencyKey}
			delegate := h.handler.issue
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			h.handler.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
				close(entered)
				select {
				case <-release:
					return delegate(ctx, csr, ttl, profile)
				case <-ctx.Done():
					return crypto.IssuedLeaf{}, ctx.Err()
				}
			}
			done := make(chan error, 1)
			go func() { done <- h.handler.Deliver(ctx, msg) }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("issuer did not reach signing: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("issuer did not enter")
			}
			revokeErr := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRevoked, "cessationOfOperation")
			unblock()
			var issueErr error
			select {
			case issueErr = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("issuance did not finish")
			}
			if !errors.Is(revokeErr, store.ErrIdentityIssuanceBusy) {
				t.Fatalf("revocation accepted while a signature was in progress: revocation=%v issuance=%v certificates=%d", revokeErr, issueErr, len(dispatcherCertificates(t, h)))
			}
			if issueErr != nil {
				t.Fatal(issueErr)
			}
			if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRevoked, "cessationOfOperation"); err != nil {
				t.Fatal(err)
			}
			before := len(dispatcherCertificates(t, h))
			if err := h.handler.Deliver(ctx, msg); err == nil {
				t.Fatal("revoked identity accepted replay of issuance")
			}
			if after := len(dispatcherCertificates(t, h)); after != before {
				t.Fatalf("revoked replay recorded another certificate: %d -> %d", before, after)
			}
		})
	}
}
