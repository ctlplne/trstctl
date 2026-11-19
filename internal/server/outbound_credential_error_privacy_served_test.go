// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboundcred"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

func TestServedDiscoveryReplaysRetainedProviderFailureFinding(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Retained provider failure fixture")
	ctx := t.Context()
	source, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Name: "fixture-path-retry", Kind: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.StartDiscoveryRun(ctx, h.tenant, run.ID); err != nil {
		t.Fatal(err)
	}
	const marker = "fixtureopaqueproviderdetail"
	const originalReason = "the provider could not be read: HTTP 403 " + marker
	obs := orchestrator.AttackPathObservation{Endpoint: orchestrator.AttackPathEndpoint{
		InventoryID: uuid.NewString(), Endpoint: "fixture.example.test:443", Address: "198.51.100.2:443",
	}, Metadata: map[string]any{"status": "unknown", "reason": originalReason}}
	finding, err := orchestrator.AttackPathFinding(run.ID, source.ID, obs, run.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	finding.ID = discovery.FindingIdentity(h.tenant, source.ID, finding.Kind, finding.Ref, finding.Fingerprint)
	var oldMetadata map[string]any
	if err := json.Unmarshal(finding.Metadata, &oldMetadata); err != nil {
		t.Fatal(err)
	}
	oldMetadata["reason"] = originalReason
	metadata, err := json.Marshal(oldMetadata)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(projections.DiscoveryFindingRecorded{
		ID: finding.ID, RunID: run.ID, SourceID: source.ID, Kind: finding.Kind,
		Ref: finding.Ref, Provenance: finding.Provenance, RiskScore: finding.RiskScore, Metadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := orchestrator.DiscoveryRelayEventID(h.tenant, run.ID, "attack-path-finding:"+finding.Ref)
	if _, err := h.log.Append(ctx, events.Event{ID: eventID, TenantID: h.tenant, Type: projections.EventDiscoveryFindingRecorded, Data: data}); err != nil {
		t.Fatal(err)
	}
	assertDiscoveryReceiptDefersDuringPrivacy(t, h.store, func(retryCtx context.Context) error {
		_, err := h.srv.orch.RecordAttackPathFindingWithEventID(retryCtx, h.tenant, eventID, finding)
		return err
	})
	if _, err := h.srv.orch.RecordAttackPathFindingWithEventID(ctx, h.tenant, eventID, finding); err != nil {
		t.Fatalf("replay retained finding after classification: %v", err)
	}
	wrong := finding
	wrong.RiskScore++
	if _, err := h.srv.orch.RecordAttackPathFindingWithEventID(ctx, h.tenant, eventID, wrong); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed finding facts reused a retained observation: %v", err)
	}
	if err := h.srv.orch.CompleteDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{ID: run.ID, Status: "succeeded", Targets: 1}); err != nil {
		t.Fatal(err)
	}
	canonical, found, err := h.log.EventByID(ctx, eventID)
	if err != nil || !found || !bytes.Equal(canonical.Data, data) {
		t.Fatalf("retained finding bytes changed: %v", err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+run.ID, token, nil)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(finding.ID)) || bytes.Contains(raw, []byte(marker)) || !bytes.Contains(raw, []byte("HTTP 403 Forbidden")) {
		t.Errorf("replayed finding did not produce a safe served diagnosis: status=%d", status)
	}
}

func TestDiscoveryDiagnosticRequiresAnObservedBoundLookup(t *testing.T) {
	const envName = "TRSTCTL_FIXTURE_UNUSED_REFERENCE"
	bindings, err := outboundcred.New([]outboundcred.Binding{{
		Ref: "env:" + envName, TenantID: servedTestTenant,
		Integrations: []string{"cloud_secret"}, Origins: []string{"https://fixture.example.test"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := &issuanceDispatcher{outboundCredentials: bindings}
	authority := d.discoveryDiagnosticAuthority(t.Context(), servedTestTenant, store.DiscoverySource{
		ID: uuid.NewString(), Kind: "cloud_secret",
	}, 0, nil)
	if authority.AllowsEnvironmentName != nil && authority.AllowsEnvironmentName(envName) {
		t.Fatal("an approved name that the worker never looked up became a diagnostic parameter")
	}
}

func assertDiscoveryReceiptDefersDuringPrivacy(t *testing.T, st *store.Store, retry func(context.Context) error) {
	t.Helper()
	if err := store.NewHistoryRewriteCoordinator(st).WithRewriteOperation(t.Context(), func(context.Context) error {
		retryCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := retry(retryCtx); !errors.Is(err, store.ErrPrivacyHistoryOperationActive) || !orchestrator.IsDeliveryDeferred(err) {
			t.Errorf("receipt bypassed the in-progress privacy operation: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServedDiscoveryDiagnosticsUseBoundedRequestPool(t *testing.T) {
	st := newServerTestStore(t, store.WithPoolSizes(store.PoolSizes{Request: 2}))
	ctx := t.Context()
	const tenantID = servedTestTenant
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "Bounded fixture tenant"}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("fixture-bounded-diagnostic")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, st, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	source, err := orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{Name: "fixture-bounded-source", Kind: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-operator"})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := orchestrator.AttackPathFinding(run.ID, source.ID, orchestrator.AttackPathObservation{
		Endpoint: orchestrator.AttackPathEndpoint{InventoryID: uuid.NewString(), Address: "198.51.100.4:443"},
		Metadata: map[string]any{"status": "unknown", "reason": "fixture diagnostic"},
	}, run.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordAttackPathFindingWithEventID(ctx, tenantID, uuid.NewString(), finding); err != nil {
		t.Errorf("a two-connection request pool could not record the finding: %v", err)
	}
	report := store.DiscoveryRun{ID: run.ID, Status: "failed", Targets: 1, Failed: 1, Error: "HTTP 403 Forbidden"}
	if err := orch.CompleteDiscoveryRunWithEventID(ctx, tenantID, uuid.NewString(), report); err != nil {
		t.Errorf("a two-connection request pool could not complete the run: %v", err)
	}
	if err := orch.CompleteDiscoveryRun(ctx, tenantID, report); err != nil {
		t.Errorf("a two-connection request pool could not publish an ordinary run completion: %v", err)
	}
}

func TestServedDiscoveryRefusedOriginObeysSubjectExportAndErasure(t *testing.T) {
	ctx := t.Context()
	const tenantID = servedTestTenant
	const subject = "fixture-operator.example.test"
	const origin = "https://" + subject
	st := newServerTestStore(t)
	auditKey, err := jose.GenerateRSASigningKey("fixture-origin-erasure")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registerServerTestTenant(t, st, log, tenantID, "Attack-path origin privacy fixture")
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	source, err := srv.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{Name: "fixture-privacy-source", Kind: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := srv.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-scan-initiator"})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	if err := outboundcred.PinClient(client, []string{"https://allowed.example.test"}); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, refusal := client.Do(request)
	observed := outboundcred.RefusedDestinationOrigin(refusal)
	if observed != origin {
		t.Fatal("fixture transport did not refuse the configured origin")
	}
	observation := orchestrator.AttackPathObservation{Endpoint: orchestrator.AttackPathEndpoint{
		InventoryID: uuid.NewString(), Endpoint: "fixture.example.test:443", Address: "198.51.100.2:443",
	}, Metadata: map[string]any{"status": "unknown", "reason": "the provider could not be read: " + refusal.Error()}, RefusedOrigin: observed}
	finding, err := orchestrator.AttackPathFinding(run.ID, source.ID, observation, run.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	eventID := orchestrator.DiscoveryRelayEventID(tenantID, run.ID, "attack-path-finding:"+finding.Ref)
	finding, err = srv.orch.RecordAttackPathFindingWithEventID(ctx, tenantID, eventID, finding)
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, tenantID, "discovery:read", string(authz.PrivacyRead), string(authz.PrivacyWrite))
	findingsPath := "/api/v1/discovery/findings?run_id=" + run.ID
	assertRead := func(wantOrigin bool) {
		t.Helper()
		status, raw := doBearer(t, ts, http.MethodGet, findingsPath, token, "", nil)
		if status != http.StatusOK || !bytes.Contains(raw, []byte(finding.ID)) || bytes.Contains(raw, []byte(origin)) != wantOrigin {
			t.Errorf("served finding origin visibility is wrong, status=%d wantOrigin=%v", status, wantOrigin)
		}
	}
	assertRead(true)
	exportStatus, exportBody := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-exports", token, "", map[string]string{"subject": subject})
	if exportStatus != http.StatusOK || !bytes.Contains(exportBody, []byte(finding.ID)) || !bytes.Contains(exportBody, []byte(origin)) {
		t.Errorf("subject export omitted the matching finding and its origin, status=%d", exportStatus)
	}
	exportStatus, exportBody = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-exports", token, "", map[string]string{"subject": "example.test"})
	if exportStatus != http.StatusOK || bytes.Contains(exportBody, []byte(finding.ID)) {
		t.Errorf("subject export treated a domain substring as the finding's subject, status=%d", exportStatus)
	}
	eraseStatus, raw := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", token, "fixture-erase-origin",
		map[string]string{"subject": subject, "reason": "data subject request"})
	var erased struct {
		Counts map[string]int `json:"counts"`
	}
	if eraseStatus != http.StatusCreated || json.Unmarshal(raw, &erased) != nil || erased.Counts["discovery_findings"] != 1 {
		t.Errorf("subject erasure omitted the matching finding, status=%d", eraseStatus)
	}
	if replayed, err := srv.orch.RecordAttackPathFindingWithEventID(ctx, tenantID, eventID, finding); err != nil || replayed.AttackPathRefusedOrigin != "" {
		t.Errorf("exact finding retry must use its erased receipt: %v", err)
	}
	changedFinding := finding
	changedFinding.RiskScore++
	if _, err := srv.orch.RecordAttackPathFindingWithEventID(ctx, tenantID, eventID, changedFinding); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("rewritten finding receipt accepted a changed risk score: %v", err)
	}
	assertRead(false)
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertRead(false)

	const runSubject = "fixture-completed-run.example.test"
	const runOrigin = "https://" + runSubject
	run, err = srv.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-scan-initiator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.orch.StartDiscoveryRun(ctx, tenantID, run.ID); err != nil {
		t.Fatal(err)
	}
	report := store.DiscoveryRun{
		ID: run.ID, Status: "failed", Targets: 2, Failed: 2, Error: "all cloud secret-manager providers failed",
		TargetResults: []store.DiscoveryTargetResult{
			{Kind: "cloud_provider", Target: "fixture-vault", Status: "failed", Error: orchestrator.DiscoveryDestinationPinRefusal},
			{Kind: "cloud_provider", Target: "fixture-kms", Status: "failed", Error: "HTTP 503 Service Unavailable"},
		},
	}
	authority := orchestrator.DiscoveryDiagnosticAuthority{RefusedOrigins: map[string]string{"fixture-vault": runOrigin}}
	completionID := uuid.NewString()
	if err := srv.orch.CompleteDiscoveryRunWithEventIDAndDiagnostics(ctx, tenantID, completionID, report, authority); err != nil {
		t.Fatal(err)
	}
	assertRun := func(wantOrigin bool) {
		t.Helper()
		status, raw := doBearer(t, ts, http.MethodGet, "/api/v1/discovery/runs/"+run.ID, token, "", nil)
		var receipt struct {
			Error   string `json:"error"`
			Targets []struct {
				Error string `json:"error"`
			} `json:"target_results"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &receipt) != nil || len(receipt.Targets) != 2 {
			t.Errorf("served run response is incomplete, status=%d", status)
			return
		}
		if strings.Contains(receipt.Error, runOrigin) != wantOrigin || strings.Contains(receipt.Targets[0].Error, runOrigin) != wantOrigin ||
			receipt.Targets[1].Error != "HTTP 503 Service Unavailable" {
			t.Errorf("wrong run, target, or unrelated diagnostic after privacy operation, wantOrigin=%v", wantOrigin)
		}
	}
	assertRun(true)
	exportStatus, exportBody = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-exports", token, "", map[string]string{"subject": runSubject})
	if exportStatus != http.StatusOK || !bytes.Contains(exportBody, []byte(run.ID)) || !bytes.Contains(exportBody, []byte(runOrigin)) {
		t.Errorf("subject export omitted diagnostics in the completed run, status=%d", exportStatus)
	}
	eraseStatus, raw = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", token, "fixture-erase-run-diagnostic",
		map[string]string{"subject": runSubject, "reason": "data subject request"})
	erased.Counts = nil
	if eraseStatus != http.StatusCreated || json.Unmarshal(raw, &erased) != nil || erased.Counts["discovery_runs"] != 1 {
		t.Errorf("subject erasure omitted diagnostics in the completed run, status=%d", eraseStatus)
	}
	if err := srv.orch.CompleteDiscoveryRunWithEventIDAndDiagnostics(ctx, tenantID, completionID, report, authority); err != nil {
		t.Errorf("exact completion retry must use its erased receipt: %v", err)
	}
	changedReport := report
	changedReport.Failed--
	if err := srv.orch.CompleteDiscoveryRunWithEventIDAndDiagnostics(ctx, tenantID, completionID, changedReport, authority); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("rewritten completion receipt accepted a changed failure count: %v", err)
	}
	assertRun(false)
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertRun(false)
}

func TestDiscoveryRunDiagnosticOriginRequiresSourceAuthority(t *testing.T) {
	const possibleOrigin = "https://fixture-unlisted-source-origin.example.test"
	d := &issuanceDispatcher{}
	source := store.DiscoverySource{ID: uuid.NewString(), Kind: "cloud_secret", Config: json.RawMessage(`{"providers":[]}`)}
	ctx := withDiscoveryCredentialFailures(t.Context(), servedTestTenant, source.ID, source.Kind)
	authority := d.discoveryDiagnosticAuthority(ctx, servedTestTenant, source, 0, []netscan.TargetResult{{
		Kind: "cloud_provider", Target: "fixture-provider", Status: "failed",
		Error: orchestrator.DiscoveryDestinationPinRefusal, RefusedOrigin: possibleOrigin,
	}})
	if authority.RefusedOrigins["fixture-provider"] != "" {
		t.Error("a transport refusal alone conveyed an origin into durable diagnostics")
	}
}

func TestDiscoveryDiagnosticDoesNotInferSharedNamespaceFromCappedTargets(t *testing.T) {
	d := &issuanceDispatcher{}
	const target = "Ingress:payments/fixture"
	authority := d.discoveryDiagnosticAuthority(t.Context(), servedTestTenant, store.DiscoverySource{
		ID: uuid.NewString(), Kind: "k8s_ingress_gateway", Config: json.RawMessage(`{}`),
	}, 201, []netscan.TargetResult{{Kind: "k8s_tls_auto_issuance", Target: target, Status: "not_delivered"}})
	if authority.KubernetesNamespace != "" || authority.KubernetesNamespaces[target] != "payments" {
		t.Fatal("a listed namespace conveyed authority for a summary of unlisted resources")
	}
}

func TestServedLegacyOutboundReferencesOmitTheRefFromFailures(t *testing.T) {
	const endpoint = "https://fixture.example.test"
	const envName = "TRSTCTL_FIXTURE_ANNOTATION_TOKEN"
	t.Setenv(envName, "fixture-annotation-value")
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("secret_third_party", []string{endpoint}, "env:"+envName))
	ctx := t.Context()
	encode := func(in any) []byte {
		t.Helper()
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const marker = "fixtureopaqueval"
	for _, destination := range []string{orchestrator.DestinationResponseJira, orchestrator.DestinationResponseSplunk} {
		message := orchestrator.Message{TenantID: h.tenant, Destination: destination, IdempotencyKey: "fixture-legacy-ref",
			Payload: encode(orchestrator.ResponseIntegrationPayload{EndpointURL: endpoint, TokenRef: marker})}
		err := h.srv.obHandler.Deliver(ctx, message)
		if err == nil || !strings.Contains(err.Error(), "use env:NAME") || strings.Contains(err.Error(), marker) {
			t.Errorf("%s did not refuse the stored reference using closed detail", destination)
		}
	}
	for _, tc := range []struct {
		name, sourceKind, findingKind, destination, field string
		connection                                        any
	}{
		{"scan-token", "secret_third_party", "leaked_secret", orchestrator.DestinationScanAnnotation, "annotation token reference",
			secretscan.ThirdPartyScanConfig{Annotation: &secretscan.AnnotationConfig{BaseURL: endpoint, TokenRef: marker}}},
		{"scan-username", "secret_third_party", "leaked_secret", orchestrator.DestinationScanAnnotation, "annotation username reference",
			secretscan.ThirdPartyScanConfig{Annotation: &secretscan.AnnotationConfig{BaseURL: endpoint, TokenRef: "env:" + envName, UsernameRef: marker}}},
		{"oauth-admin", "manual", "oauth_grant", orchestrator.DestinationOAuthProviderAction, "admin token reference",
			map[string]any{"providers": []map[string]string{{"provider": "okta", "base_url": endpoint, "token_ref": marker}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Seed the retained configuration through its event projector so the
			// test exercises worker behavior independently of current HTTP ingestion.
			src, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{
				Name: tc.name, Kind: tc.sourceKind, Config: encode(tc.connection),
			})
			if err != nil {
				t.Fatal(err)
			}
			run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: src.ID, RequestedBy: "fixture-operator"})
			if err != nil {
				t.Fatal(err)
			}
			finding, err := h.srv.orch.RecordDiscoveryFinding(ctx, h.tenant, store.DiscoveryFinding{
				RunID: run.ID, SourceID: src.ID, Kind: tc.findingKind, Ref: "fixture-resource", Fingerprint: "fixture-fingerprint",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := uuid.NewString()
			var payload any = orchestrator.FindingAnnotationIntent{RequestID: request, SourceID: src.ID, FindingID: finding.ID, Provider: "slack"}
			if tc.destination == orchestrator.DestinationOAuthProviderAction {
				payload = orchestrator.OAuthProviderActionIntent{RequestID: request, SourceID: src.ID,
					FindingID: finding.ID, Provider: "okta", Action: orchestrator.OAuthActionRevokeGrant, AppID: "fixture-app"}
			}
			err = h.srv.obHandler.Deliver(ctx, orchestrator.Message{TenantID: h.tenant, Destination: tc.destination, IdempotencyKey: request, Payload: encode(payload)})
			if err == nil || !strings.Contains(err.Error(), tc.field) || strings.Contains(err.Error(), marker) {
				t.Fatal("worker did not identify the refused reference field using closed detail")
			}
			current, err := h.store.GetDiscoveryFinding(ctx, h.tenant, finding.ID)
			if err != nil || bytes.Contains(current.Metadata, []byte(marker)) || !bytes.Contains(current.Metadata, []byte(tc.field)) {
				t.Fatalf("finding did not record a safe terminal refusal: %v", err)
			}
			seen := false
			if err := h.log.Replay(ctx, 0, func(e events.Event) error {
				if e.Type == projections.EventDiscoveryFindingProviderAction && bytes.Contains(e.Data, []byte(request)) {
					seen = true
					if bytes.Contains(e.Data, []byte(marker)) || !bytes.Contains(e.Data, []byte(tc.field)) {
						t.Error("immutable provider action did not retain only safe detail")
					}
				}
				return nil
			}); err != nil || !seen {
				t.Fatalf("retained refusal event missing: %v", err)
			}
		})
	}
	t.Run("run-completion", func(t *testing.T) {
		src, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{
			Name: "fixture-run-diagnostic", Kind: "manual", Config: json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: src.ID, RequestedBy: "fixture-operator"})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.orch.StartDiscoveryRun(ctx, h.tenant, run.ID); err != nil {
			t.Fatal(err)
		}
		detail := "provider replied with " + marker
		if err := h.srv.orch.CompleteDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{
			ID: run.ID, Status: "failed", Targets: 1, Failed: 1, Error: detail,
			TargetResults: []store.DiscoveryTargetResult{{Kind: "cloud_provider", Target: "gcp-secret-manager", Status: "failed", Error: detail}},
		}); err != nil {
			t.Fatal(err)
		}
		current, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
		if err != nil || len(current.TargetResults) != 1 || current.Error == "" || current.TargetResults[0].Error == "" ||
			strings.Contains(current.Error+current.TargetResults[0].Error, marker) {
			t.Fatalf("run must keep a class for both errors without retaining provider text: %v", err)
		}
		seen := false
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.Type == projections.EventDiscoveryRunCompleted && bytes.Contains(e.Data, []byte(run.ID)) {
				seen = true
				if bytes.Contains(e.Data, []byte(marker)) {
					t.Error("run completion event retained raw provider error text")
				}
			}
			return nil
		}); err != nil || !seen {
			t.Fatalf("run completion event missing: %v", err)
		}
	})
}

func TestServedDiscoveryReplaysRetainedCompletionWithHistoricalDiagnostics(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	source, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Name: "fixture-retained-completion", Kind: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-operator"})
	if err != nil {
		t.Fatal(err)
	}
	const marker = "fixture_opaque_value"
	detail := "env credential reference " + marker + " is not set"
	report := store.DiscoveryRun{
		ID: run.ID, Status: "failed", Targets: 1, Failed: 1, Error: detail,
		TargetResults: []store.DiscoveryTargetResult{{Kind: "cloud_provider", Target: "gcp-secret-manager", Status: "failed", Error: detail}},
	}
	data, err := json.Marshal(projections.DiscoveryRunCompleted{
		ID: run.ID, Status: report.Status, Targets: 1, Failed: 1, Error: detail,
		TargetResults: []projections.DiscoveryTargetResult{{Kind: "cloud_provider", Target: "gcp-secret-manager", Status: "failed", Error: detail}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewString()
	if _, err := h.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventDiscoveryRunCompleted,
		TenantID: h.tenant, SchemaVersion: projections.DiscoveryTargetResultsEventSchemaVersion, Data: data}); err != nil {
		t.Fatal(err)
	}
	// The canonical pre-upgrade completion already exists, but the worker did
	// not project it. A retry must finish it without publishing another event.
	assertDiscoveryReceiptDefersDuringPrivacy(t, h.store, func(retryCtx context.Context) error {
		return h.srv.orch.CompleteDiscoveryRunWithEventID(retryCtx, h.tenant, eventID, report)
	})
	other := report
	other.Discovered++
	if err := h.srv.orch.CompleteDiscoveryRunWithEventID(ctx, h.tenant, eventID, other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different completion facts reused the existing event: %v", err)
	}
	if err := h.srv.orch.CompleteDiscoveryRunWithEventID(ctx, h.tenant, eventID, report); err != nil {
		t.Fatalf("replay retained completion: %v", err)
	}
	current, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
	if err != nil || current.Status != "failed" || current.ErrorClassified {
		t.Fatalf("historical completion projection: status=%s classified=%t err=%v", current.Status, current.ErrorClassified, err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+run.ID, token, nil)
	if status != http.StatusOK || bytes.Contains(body, []byte(marker)) || !bytes.Contains(body, []byte("env credential reference is not set")) {
		t.Fatalf("historical run API did not use a closed failure class: HTTP %d", status)
	}
	count := 0
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventDiscoveryRunCompleted && event.ID == eventID {
			count++
		}
		return nil
	}); err != nil || count != 1 {
		t.Fatalf("retained completion event count=%d err=%v", count, err)
	}

	newRun, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-operator"})
	if err != nil {
		t.Fatal(err)
	}
	newEventID := uuid.NewString()
	newReport := store.DiscoveryRun{ID: newRun.ID, Status: "failed", Targets: 1, Failed: 1, Error: "HTTP 403 Forbidden"}
	if err := h.srv.orch.CompleteDiscoveryRunWithEventID(ctx, h.tenant, newEventID, newReport); err != nil {
		t.Fatal(err)
	}
	newReport.Error = "HTTP 503 Service Unavailable"
	if err := h.srv.orch.CompleteDiscoveryRunWithEventID(ctx, h.tenant, newEventID, newReport); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("new completion accepted a conflicting public diagnostic: %v", err)
	}
}
