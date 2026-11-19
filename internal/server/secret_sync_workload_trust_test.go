// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

func TestCloudWorkloadWorkersEnforceEffectiveGitHubTrust(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{})
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	const kid = "workflow-proof-fixture"
	jwk, err := crypto.PublicJWK(key.Public(), kid)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const trustID = "00000000-0000-4000-8000-000000038411"
	trust := projections.WorkloadAttesterTrustSourceUpserted{
		ID: trustID, Name: "immutable-workflow-policy", Method: "github_oidc",
		Audience: "trstctl", JWKS: jwks, Enabled: true,
		AllowedOwnerIDs: []string{servedGitHubOwnerID}, AllowedRepositoryIDs: []string{"456"},
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	appendPolicy := func(id string, policy projections.WorkloadAttesterTrustSourceUpserted) events.Event {
		t.Helper()
		data, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{
			ID: id, Type: projections.EventWorkloadAttesterTrustSourceUpserted, TenantID: h.tenant,
			Time: at, SchemaVersion: events.DefaultSchemaVersion, Data: data,
		}
	}
	if _, err := h.log.Append(ctx, appendPolicy("", trust)); err != nil {
		t.Fatal(err)
	}
	catchUpServedProjection(t, h)

	proof := githubWorkflowToken(t, key, kid, "acme")
	proofFile := filepath.Join(t.TempDir(), "proof")
	if err := os.WriteFile(proofFile, proof, 0600); err != nil {
		t.Fatal(err)
	}
	aws := newAWSFederatedSecretSyncFixture(t)
	gcp := newGCPFederatedSecretSyncFixture(t)
	azure := newAzureFederatedSecretSyncFixture(t)
	cache := cloudauth.NewMinter(time.Minute)
	t.Cleanup(cache.Close)
	type workerCase struct {
		provider string
		endpoint string
		calls    func() int32
		mint     func(*configuredSyncPusher, context.Context, string) (*cloudauth.Credential, error)
		cacheKey string
		source   store.SecretSyncWorkloadIdentitySource
	}
	workers := []workerCase{
		{provider: "aws", endpoint: aws.sts.URL, calls: aws.stsCalls.Load, mint: (*configuredSyncPusher).mintAWSWorkloadIdentity},
		{provider: "gcp", endpoint: gcp.server.URL + "/v1/token", calls: gcp.stsCalls.Load, mint: (*configuredSyncPusher).mintGCPWorkloadIdentity},
		{provider: "azure", endpoint: azure.server.URL + "/entra-token", calls: azure.tokenCalls.Load, mint: (*configuredSyncPusher).mintAzureWorkloadIdentity},
	}
	pusher := func(worker workerCase) *configuredSyncPusher {
		return &configuredSyncPusher{
			tenantID: h.tenant, store: h.store, log: h.log, minter: cache,
			cfg: config.SecretSyncTargetConfig{
				ID: worker.provider, WorkloadIdentityEndpoint: worker.endpoint, AllowInsecureLoopback: true,
			},
		}
	}
	const remoteKey = "prod/workflow/service"
	for i := range workers {
		worker := &workers[i]
		source := projections.SecretSyncWorkloadIdentitySourceUpserted{
			ID:   fmt.Sprintf("00000000-0000-4000-8000-00000003842%d", i),
			Name: worker.provider, Provider: worker.provider, TargetID: worker.provider,
			Audience: "trstctl", Subject: "repo:acme/payments:ref:refs/heads/main",
			AllowedRemoteKeyPrefixes: []string{"prod/workflow/"},
			WorkloadProofRef:         "file:" + proofFile, TrustSourceID: trustID, Enabled: true,
		}
		switch worker.provider {
		case "aws":
			source.RoleARN = "arn:aws:iam::123456789012:role/trstctl-secret-sync"
		case "azure":
			source.AzureTenantID = "00000000-0000-4000-8000-000000038430"
			source.ClientID = servedAzureClientID
			source.TargetScope = servedAzureTargetScope
		}
		data, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.log.Append(ctx, events.Event{
			Type: projections.EventSecretSyncWorkloadIdentityUpserted, TenantID: h.tenant, Data: data,
		}); err != nil {
			t.Fatal(err)
		}
		catchUpServedProjection(t, h)
		worker.source, err = h.store.GetSecretSyncWorkloadIdentitySource(ctx, h.tenant, source.ID)
		if err != nil {
			t.Fatal(err)
		}
		cacheKey, _, err := pusher(*worker).workloadIdentityTrust(ctx, worker.source)
		if err != nil {
			t.Fatal(err)
		}
		worker.cacheKey = cacheKey
		credential, err := worker.mint(pusher(*worker), secretsync.WithOperationID(ctx, "initial-"+worker.provider), remoteKey)
		credential.Destroy()
		if err != nil || credential == nil || worker.calls() != 1 {
			t.Fatalf("%s exchange for the configured IDs: calls=%d err=%v", worker.provider, worker.calls(), err)
		}
		credential, err = worker.mint(pusher(*worker), secretsync.WithOperationID(ctx, "cached-"+worker.provider), remoteKey)
		credential.Destroy()
		if err != nil || credential == nil || worker.calls() != 1 {
			t.Fatalf("%s warm cache control: calls=%d err=%v", worker.provider, worker.calls(), err)
		}
	}

	replacement := trust
	replacement.AllowedRepositoryIDs = []string{"789"}
	command, err := h.store.ClaimWorkloadAttesterTrustCommand(ctx, store.WorkloadAttesterTrustCommand{
		SourceID: trustID, BindingSHA256: strings.Repeat("a", 64), RequestBinding: strings.Repeat("b", 64),
		UpsertAdmission: store.WorkloadAttesterTrustUpsertAdmission{PinsExplicit: true},
		Event:           appendPolicy("00000000-0000-4000-8000-000000038412", replacement),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, worker := range workers {
		credential, err := worker.mint(pusher(worker), secretsync.WithOperationID(ctx, "pending-"+worker.provider), remoteKey)
		credential.Destroy()
		if credential != nil || err == nil || !strings.Contains(err.Error(), "trust source is unavailable") {
			t.Fatalf("%s used a warm cache while the authority change was pending: %v", worker.provider, err)
		}
	}

	if _, err := h.log.Append(ctx, command.Event); err != nil {
		t.Fatal(err)
	}
	catchUpServedProjection(t, h)
	for _, worker := range workers {
		p := pusher(worker)
		cacheKey, _, err := p.workloadIdentityTrust(ctx, worker.source)
		if err != nil || cacheKey == worker.cacheKey {
			t.Fatalf("%s cache scope did not change with the pins: %v", worker.provider, err)
		}
		credential, err := worker.mint(p, secretsync.WithOperationID(ctx, "projected-"+worker.provider), remoteKey)
		credential.Destroy()
		if credential != nil || !errors.Is(err, cloudauth.ErrInvalidWorkloadProof) || worker.calls() != 1 {
			t.Fatalf("%s refused proof must leave its upstream exchange count unchanged: calls=%d err=%v", worker.provider, worker.calls(), err)
		}
	}
	newProof := githubWorkflowAttemptTokenWithIDs(t, key, kid, "acme", "38441", "1", servedGitHubOwnerID, "789")
	if err := os.WriteFile(proofFile, newProof, 0600); err != nil {
		t.Fatal(err)
	}
	for _, worker := range workers {
		credential, err := worker.mint(pusher(worker), secretsync.WithOperationID(ctx, "replacement-"+worker.provider), remoteKey)
		credential.Destroy()
		if err != nil || credential == nil || worker.calls() != 2 {
			t.Fatalf("%s updated proof must receive a fresh credential: calls=%d err=%v", worker.provider, worker.calls(), err)
		}
	}
}
