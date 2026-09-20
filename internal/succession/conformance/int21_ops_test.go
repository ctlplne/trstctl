// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
	pcasorch "trstctl.com/trstctl/internal/succession/orchestrator"
)

const int21TenantB = "33333333-3333-3333-3333-333333333333"

// TestINT21_PCASOpsSLOBackpressureAndCrash is the compact operations gate for
// PCAS-WIRING-DESIGN INT-21. It does not pretend to be a full benchmark; it proves
// the operational invariants a release gate can check deterministically:
// multi-tenant request bursts enqueue bounded durable outbox work, the outbox drains
// through the licensed production handler, duplicate redelivery is exactly-once, and
// the shipped feature metrics receive PCAS mint/publish signals.
func TestINT21_PCASOpsSLOBackpressureAndCrash(t *testing.T) {
	st := startINT20Stack(t)
	if err := st.store.UpsertTenant(st.ctx, corestore.Tenant{TenantID: int21TenantB, Name: "INT-21 Tenant B", EventSeq: 2}); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}

	tenants := []string{st.tenantID, int21TenantB}
	const perTenant = 2
	const targetQPS = 1
	start := time.Now()
	idsByTenant := map[string][]string{}
	for _, tenantID := range tenants {
		for i := 0; i < perTenant; i++ {
			id := fmt.Sprintf("spiffe://int21.example/%s/workload-%d", tenantID[:8], i)
			if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0)); err != nil {
				t.Fatalf("genesis %s: %v", id, err)
			}
			if _, err := st.svc.RequestSuccession(st.ctx, tenantID, succapi.RequestSuccessionRequest{
				IdentityID: id, CredentialType: "x509", TargetAlgorithm: string(crypto.ECDSAP384),
				PolicyRef: "policy:int21-load", DeploymentScope: "spiffe://int21.example",
			}); err != nil {
				t.Fatalf("request succession %s: %v", id, err)
			}
			idsByTenant[tenantID] = append(idsByTenant[tenantID], id)
		}
	}
	total := len(tenants) * perTenant
	if elapsed := time.Since(start); elapsed > time.Duration(total/targetQPS+5)*time.Second {
		t.Fatalf("PCAS enqueue SLO missed: %d requests took %s", total, elapsed)
	}
	for _, tenantID := range tenants {
		pending, err := st.outbox.Pending(st.ctx, tenantID)
		if err != nil {
			t.Fatalf("pending outbox for %s: %v", tenantID, err)
		}
		if len(pending) != perTenant {
			t.Fatalf("tenant %s pending outbox = %d, want %d", tenantID, len(pending), perTenant)
		}
	}

	st.dispatchAll(t)
	for tenantID, ids := range idsByTenant {
		for _, id := range ids {
			chain, err := st.svc.FetchChain(st.ctx, tenantID, id)
			if err != nil {
				t.Fatalf("fetch chain %s/%s: %v", tenantID, id, err)
			}
			if chain.Count != 1 {
				t.Fatalf("chain count for %s/%s = %d, want 1", tenantID, id, chain.Count)
			}
		}
		if pending, err := st.outbox.Pending(st.ctx, tenantID); err != nil || len(pending) != 0 {
			t.Fatalf("tenant %s pending after drain = %d err=%v, want 0,nil", tenantID, len(pending), err)
		}
	}
	if got := st.features.Count("pcas_succession", "mint", "success"); got < total {
		t.Fatalf("pcas mint metric count = %d, want at least %d", got, total)
	}
	if got := st.features.Count("pcas_succession", "publish", "success"); got < total {
		t.Fatalf("pcas publish metric count = %d, want at least %d", got, total)
	}

	st.assertDuplicateRedeliveryDoesNotDoubleMint(t)
}

func (st *int20Stack) assertDuplicateRedeliveryDoesNotDoubleMint(t *testing.T) {
	t.Helper()
	const id = "spiffe://int21.example/crash-redelivery"
	if _, err := st.signer.GenerateKeyHandle(st.ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0)); err != nil {
		t.Fatalf("redelivery genesis: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"request_id":       "int21-duplicate-redelivery",
		"identity_id":      id,
		"credential_type":  "x509",
		"target_algorithm": string(crypto.ECDSAP384),
		"policy_ref":       "policy:int21-redelivery",
		"deployment_scope": "spiffe://int21.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := coreorch.Message{TenantID: st.tenantID, Destination: pcasorch.RequestDestination, Payload: payload}
	for i := 0; i < 2; i++ {
		handled, err := st.handler.DeliverLicensed(st.ctx, msg)
		if !handled || err != nil {
			t.Fatalf("redelivery %d handled=%v err=%v, want true,nil", i+1, handled, err)
		}
	}
	rows, err := st.repo.FetchChain(st.ctx, st.tenantID, id)
	if err != nil {
		t.Fatalf("redelivery fetch chain: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("duplicate redelivery wrote %d records, want exactly 1", len(rows))
	}
	st.dispatchAll(t)
}

type featureRecord struct {
	feature string
	action  string
	outcome string
}

type featureRecorder struct {
	mu      sync.Mutex
	records []featureRecord
}

func (r *featureRecorder) Observe(feature, action, outcome string, _ float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, featureRecord{feature: feature, action: action, outcome: outcome})
}

func (r *featureRecorder) Count(feature, action, outcome string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int
	for _, rec := range r.records {
		if rec.feature == feature && rec.action == action && rec.outcome == outcome {
			count++
		}
	}
	return count
}

func (r *featureRecorder) WaitFor(ctx context.Context, feature, action, outcome string, want int) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.Count(feature, action, outcome) >= want {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
