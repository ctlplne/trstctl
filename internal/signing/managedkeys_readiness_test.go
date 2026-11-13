// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A169-L2: the signer exchanges each workload-identity provider's token as it
// starts, retries a failed exchange with backoff until it succeeds, and
// reports every provider in Health with a closed reason — a coded failure by
// its code, any other by token_exchange_failed — and Shutdown stops the
// retries.
func TestManagedKeyReadinessReportsTheStartupExchangeA169L2(t *testing.T) {
	var azure, gcp atomic.Int32
	server := signing.NewServer(signing.WithManagedKeyReadinessBackoff(10*time.Millisecond, 40*time.Millisecond), signing.WithManagedKeyReadinessProbes(map[string]signing.ManagedKeyReadinessProbe{
		"azure-key-vault": func(context.Context) error {
			if azure.Add(1) <= 2 {
				return &signing.ManagedKeyReadinessError{Code: signing.ReadinessExchangeRefused}
			}
			return nil
		},
		"gcp-kms": func(context.Context) error {
			gcp.Add(1)
			return errors.New("sts said no: the provider's own words")
		},
	}))
	health := func() map[string]*signerpb.ManagedKeyProviderReadiness {
		t.Helper()
		resp, err := server.Health(context.Background(), &signerpb.HealthRequest{})
		if err != nil || resp.GetStatus() != signerpb.HealthResponse_STATUS_SERVING {
			t.Fatalf("health = %v %v", resp, err)
		}
		out := map[string]*signerpb.ManagedKeyProviderReadiness{}
		for _, p := range resp.GetManagedKeyProviders() {
			out[p.GetProvider()] = p
		}
		return out
	}
	deadline := time.Now().Add(5 * time.Second)
	for !health()["azure-key-vault"].GetReady() {
		if time.Now().After(deadline) {
			t.Fatalf("azure never became ready: %+v (attempts %d)", health(), azure.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := health()
	if azure.Load() != 3 || got["azure-key-vault"].GetReason() != "" || got["azure-key-vault"].GetCheckedUnix() == 0 {
		t.Fatalf("azure after recovering = %+v (attempts %d)", got["azure-key-vault"], azure.Load())
	}
	if p := got["gcp-kms"]; p.GetReady() || p.GetReason() != signing.ReadinessExchangeFailed || p.GetCheckedUnix() == 0 {
		t.Fatalf("gcp = %+v; want not ready with the closed code, never the provider's words", p)
	}
	if len(got) != 2 {
		t.Fatalf("providers reported = %v", got)
	}
	server.Shutdown()
	time.Sleep(60 * time.Millisecond)
	stopped := gcp.Load()
	time.Sleep(120 * time.Millisecond)
	if gcp.Load() != stopped {
		t.Fatalf("probes kept running after Shutdown: %d → %d", stopped, gcp.Load())
	}
	// A server without probes reports no providers.
	if resp, err := signing.NewServer().Health(context.Background(), &signerpb.HealthRequest{}); err != nil || len(resp.GetManagedKeyProviders()) != 0 {
		t.Fatalf("a server without probes = %v %v", resp, err)
	}
}
