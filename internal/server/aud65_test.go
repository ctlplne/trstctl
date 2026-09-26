// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestAUD65ServedReadinessActionAndSignedExportShareProductionDataset(t *testing.T) {
	signingKey, err := jose.GenerateRSASigningKey("aud65-readiness")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.AuditSigningKey = signingKey })
	ctx := context.Background()
	projector := projections.New(h.store)
	base := time.Date(2026, time.August, 13, 13, 15, 0, 0, time.UTC)
	apply := func(sequence uint64, eventType string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, events.Event{
			ID: fmt.Sprintf("66500000-0000-4000-8000-%012d", sequence), Type: eventType,
			TenantID: h.tenant, Sequence: sequence, Time: base.Add(time.Duration(sequence) * time.Second), Data: data, // #nosec G115 -- fixture sequences are single-digit seconds (CWE-190).
		}); err != nil {
			t.Fatalf("apply %s: %v", eventType, err)
		}
	}
	const (
		ownerID    = "66500000-0000-4000-8000-000000000001"
		identityID = "66500000-0000-4000-8000-000000000002"
		targetID   = "66500000-0000-4000-8000-000000000003"
		assetID    = "66500000-0000-4000-8000-000000000004"
		campaignID = "66500000-0000-4000-8000-000000000005"
	)
	apply(1, projections.EventOwnerCreated, projections.OwnerCreated{ID: ownerID, Kind: "service", Name: "payments-team"})
	apply(2, projections.EventDeploymentTargetUpserted, projections.DeploymentTargetUpserted{
		ID: targetID, Name: "lb-edge", Connector: "f5", Config: json.RawMessage(`{"address_ref":"lb-edge"}`),
	})
	apply(3, projections.EventIdentityCreated, projections.IdentityCreated{
		ID: identityID, Kind: "x509_certificate", Name: "lb-tls", OwnerID: ownerID,
		Attributes: json.RawMessage(`{"deployment_target":"lb-edge"}`),
	})
	apply(4, projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{
		ID: assetID, Kind: "public-key", Location: "lb-edge", Algorithm: "RSA", KeyBits: 1024,
		Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true,
	})

	token := seedScopedTokenSubject(t, h.store, h.tenant, "crypto-operator",
		"graph:read", "risk:read", "discovery:write", "audit:read")
	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/graph/crypto-readiness", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("read readiness = %d body=%s", status, body)
	}
	var initial struct {
		DatasetDigest string `json:"dataset_digest"`
		Items         []struct {
			Asset struct {
				ID string `json:"id"`
			} `json:"asset"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &initial); err != nil {
		t.Fatal(err)
	}
	if initial.DatasetDigest == "" || len(initial.Items) != 1 || initial.Items[0].Asset.ID != "crypto:"+assetID {
		t.Fatalf("initial canonical readiness = %+v body=%s", initial, body)
	}

	request := map[string]any{
		"id": campaignID, "name": "Payments crypto blocker", "owner": "payments-team",
		"deadline": base.Add(30 * 24 * time.Hour), "wave": "wave-1",
		"readiness_criteria": []string{"owner approved", "rollback documented"},
		"finding_ids":        []string{assetID},
	}
	bad := map[string]any{}
	for key, value := range request {
		bad[key] = value
	}
	bad["id"] = "66500000-0000-4000-8000-000000000006"
	bad["owner"] = "unobserved-owner"
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/graph/crypto-readiness/actions", token, "aud65-bad-owner", bad)
	if status != http.StatusBadRequest {
		t.Fatalf("unattributed owner action = %d body=%s, want 400", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/graph/crypto-readiness/actions", token, "aud65-create-action", request)
	if status != http.StatusCreated {
		t.Fatalf("create readiness action = %d body=%s", status, body)
	}
	var created struct {
		Findings []struct {
			FindingID       string `json:"finding_id"`
			ReadinessDigest string `json:"readiness_digest"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Findings) != 1 || created.Findings[0].FindingID != assetID || created.Findings[0].ReadinessDigest == "" {
		t.Fatalf("bound readiness action = %+v body=%s", created, body)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/graph/crypto-readiness", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("read readiness with action = %d body=%s", status, body)
	}
	var withAction struct {
		DatasetDigest string `json:"dataset_digest"`
		Items         []struct {
			Actions []struct {
				CampaignID string   `json:"campaign_id"`
				Owner      string   `json:"owner"`
				Evidence   []string `json:"evidence_refs"`
				Stale      bool     `json:"stale"`
			} `json:"actions"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &withAction); err != nil {
		t.Fatal(err)
	}
	if withAction.DatasetDigest == initial.DatasetDigest || len(withAction.Items) != 1 || len(withAction.Items[0].Actions) != 1 ||
		withAction.Items[0].Actions[0].CampaignID != campaignID || withAction.Items[0].Actions[0].Owner != "payments-team" ||
		withAction.Items[0].Actions[0].Stale {
		t.Fatalf("canonical readiness action join = %+v body=%s", withAction, body)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/graph/crypto-readiness/export", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("export readiness = %d body=%s", status, body)
	}
	var exported struct {
		Dataset       json.RawMessage `json:"dataset"`
		DatasetDigest string          `json:"dataset_digest"`
		CSV           string          `json:"csv"`
		NDJSON        string          `json:"ndjson"`
		SignedExport  string          `json:"signed_export"`
		PublicJWKS    json.RawMessage `json:"public_jwks"`
	}
	if err := json.Unmarshal(body, &exported); err != nil {
		t.Fatal(err)
	}
	if exported.DatasetDigest != withAction.DatasetDigest || exported.CSV == "" || exported.NDJSON == "" ||
		!strings.Contains(exported.CSV, campaignID) || !strings.Contains(exported.NDJSON, "payments-team") {
		t.Fatalf("readiness export diverged from JSON dataset: %+v", exported)
	}
	keys, err := jose.ParseJWKSet(exported.PublicJWKS)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := keys.VerifyArtifact(exported.SignedExport, "trstctl.audit-evidence/crypto-readiness-export/v1")
	if err != nil {
		t.Fatalf("verify readiness export offline: %v", err)
	}
	if !strings.Contains(string(payload), withAction.DatasetDigest) || !strings.Contains(string(payload), campaignID) {
		t.Fatalf("signed export omits canonical dataset/action: %s", payload)
	}

	// A newly observed dependency changes the exact topology row. The bound
	// action must become visibly stale and refuse evidence mutation until the
	// operator creates a new action against the new graph authority.
	apply(5, projections.EventIdentityCreated, projections.IdentityCreated{
		ID: "66500000-0000-4000-8000-000000000007", Kind: "x509_certificate", Name: "second-lb-client", OwnerID: ownerID,
		Attributes: json.RawMessage(`{"deployment_target":"lb-edge"}`),
	})
	status, body = doBearer(t, h.ts, http.MethodPost,
		"/api/v1/pqc/campaigns/"+campaignID+"/findings/"+assetID+"/disposition", token,
		"aud65-stale-action", map[string]any{
			"disposition": "remediated", "method": "manual", "reason": "stale topology must refuse this",
			"evidence_refs":    []string{"audit:replacement"},
			"evidence_digests": []string{"sha256:3cba1d17d83065bce8a540abfbe4c59ab8b3f4ea3f2f47fc5f99dba9246c1f9a"},
		})
	if status != http.StatusConflict {
		t.Fatalf("stale readiness action mutation = %d body=%s, want 409", status, body)
	}
}
