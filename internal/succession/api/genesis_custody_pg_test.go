// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	succapi "trstctl.com/trstctl/internal/succession/api"
)

// Workload custody on genesis needs the agent key's public half in the genesis
// algorithm; signer custody refuses a stray public key; unknown modes are
// refused before anything is queued.
func TestGenesisWorkloadCustodyValidation(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	svc := succapi.NewService(cs, log, orchestrator.NewOutbox(cs))
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pem := string(crypto.MarshalPublicKeyPEM(key.Public().DER))
	base := succapi.GenesisRegistrationRequest{IdentityID: "spiffe://qa.local/custody", Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://qa.local"}

	missing := base
	missing.PredecessorCustody = "workload"
	if _, err := svc.RegisterGenesis(ctx, tenantA, missing); !isStatus(err, http.StatusBadRequest) || !strings.Contains(err.Error(), "public_key_pem") {
		t.Fatalf("workload custody without a key: %v", err)
	}
	wrongAlg := base
	wrongAlg.PredecessorCustody, wrongAlg.PublicKeyPEM, wrongAlg.Algorithm = "workload", pem, string(crypto.ECDSAP384)
	if _, err := svc.RegisterGenesis(ctx, tenantA, wrongAlg); !isStatus(err, http.StatusBadRequest) || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("workload custody with a key of another algorithm: %v", err)
	}
	stray := base
	stray.PublicKeyPEM = pem
	if _, err := svc.RegisterGenesis(ctx, tenantA, stray); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("signer custody with a public key: %v", err)
	}
	unknown := base
	unknown.PredecessorCustody = "hsm"
	if _, err := svc.RegisterGenesis(ctx, tenantA, unknown); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("unknown custody: %v", err)
	}
	ok := base
	ok.PredecessorCustody, ok.PublicKeyPEM = "workload", pem
	queued, err := svc.RegisterGenesis(ctx, tenantA, ok)
	if err != nil || queued.Status != "queued" {
		t.Fatalf("workload custody genesis: %+v err=%v", queued, err)
	}
}
