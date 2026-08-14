// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	aud64PaymentsOwnerID = "64000000-0000-4000-8000-000000000001"
	aud64CheckoutOwnerID = "64000000-0000-4000-8000-000000000002"
	aud64IdentityID      = "64000000-0000-4000-8000-000000000003"
	aud64TargetID        = "64000000-0000-4000-8000-000000000004"
	aud64AssetID         = "64000000-0000-4000-8000-000000000005"
	aud64SourceID        = "64000000-0000-4000-8000-000000000006"
	aud64RunID           = "64000000-0000-4000-8000-000000000007"
	aud64FindingID       = "64000000-0000-4000-8000-000000000008"
)

func aud64Event(t *testing.T, tenantID, eventType string, sequence int, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", eventType, err)
	}
	return events.Event{
		ID:       fmt.Sprintf("64000000-0000-4000-8001-%012d", sequence),
		Sequence: uint64(sequence), // #nosec G115 -- every generated fixture sequence is a positive small integer (CWE-190).
		Type:     eventType,
		TenantID: tenantID,
		Time:     time.Date(2026, time.August, 13, 12, 30, sequence, 0, time.UTC),
		Data:     data,
	}
}

func aud64AuthorityEvents(t *testing.T, tenantID string, foreign bool) []events.Event {
	t.Helper()
	prefix := ""
	paymentsOwnerID := aud64PaymentsOwnerID
	checkoutOwnerID := aud64CheckoutOwnerID
	identityID := aud64IdentityID
	targetID := aud64TargetID
	assetID := aud64AssetID
	sourceID := aud64SourceID
	runID := aud64RunID
	findingID := aud64FindingID
	if foreign {
		prefix = "foreign-"
		paymentsOwnerID = "65000000-0000-4000-8000-000000000001"
		checkoutOwnerID = "65000000-0000-4000-8000-000000000002"
		identityID = "65000000-0000-4000-8000-000000000003"
		targetID = "65000000-0000-4000-8000-000000000004"
		assetID = "65000000-0000-4000-8000-000000000005"
		sourceID = "65000000-0000-4000-8000-000000000006"
		runID = "65000000-0000-4000-8000-000000000007"
		findingID = "65000000-0000-4000-8000-000000000008"
	}
	paymentsName := prefix + "payments-team"
	checkoutName := prefix + "checkout-service"
	return []events.Event{
		aud64Event(t, tenantID, projections.EventOwnerCreated, 1, projections.OwnerCreated{
			ID: paymentsOwnerID, Kind: "service", Name: paymentsName,
		}),
		aud64Event(t, tenantID, projections.EventOwnerCreated, 2, projections.OwnerCreated{
			ID: checkoutOwnerID, Kind: "service", Name: checkoutName,
		}),
		aud64Event(t, tenantID, projections.EventDeploymentTargetUpserted, 3, projections.DeploymentTargetUpserted{
			ID: targetID, Name: "lb-edge", Connector: "f5", Config: json.RawMessage(`{"address_ref":"lb-edge"}`),
		}),
		aud64Event(t, tenantID, projections.EventIdentityCreated, 4, projections.IdentityCreated{
			ID: identityID, Kind: "x509_certificate", Name: prefix + "lb-tls", OwnerID: paymentsOwnerID,
			Attributes: json.RawMessage(`{"deployment_target":"lb-edge"}`),
		}),
		aud64Event(t, tenantID, projections.EventCBOMAssetObserved, 5, projections.CBOMAssetObserved{
			ID: assetID, Kind: "public-key", Location: "lb-edge", Algorithm: "RSA", KeyBits: 1024,
			Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true,
		}),
		aud64Event(t, tenantID, projections.EventDiscoverySourceUpserted, 6, projections.DiscoverySourceUpserted{
			ID: sourceID, Kind: "agent", Name: prefix + "agent:relay-a:service_dependency", Config: json.RawMessage(`{"source_kind":"service_dependency"}`),
		}),
		aud64Event(t, tenantID, projections.EventDiscoveryRunQueued, 7, projections.DiscoveryRunQueued{
			ID: runID, SourceID: sourceID, RequestedBy: prefix + "agent:relay-a",
		}),
		aud64Event(t, tenantID, projections.EventDiscoveryFindingRecorded, 8, projections.DiscoveryFindingRecorded{
			ID: findingID, RunID: runID, SourceID: sourceID, Kind: "service_dependency", Ref: "lb-edge",
			Provenance: prefix + "agent:relay-a:lb-edge",
			Metadata:   json.RawMessage(fmt.Sprintf(`{"workload":%q,"target":"lb-edge","protocol":"https"}`, checkoutName)),
		}),
	}
}

func aud64Project(t *testing.T, st *store.Store, tenantID, tenantName string, authority []events.Event) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantName}); err != nil {
		t.Fatalf("seed tenant %s: %v", tenantID, err)
	}
	projector := projections.New(st)
	for _, event := range authority {
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("project %s for tenant %s: %v", event.Type, tenantID, err)
		}
	}
}

func aud64Readiness(t *testing.T, st *store.Store) []graph.CryptoReadinessRow {
	t.Helper()
	g, err := graph.Build(context.Background(), st, tenantA)
	if err != nil {
		t.Fatalf("build tenant A graph: %v", err)
	}
	for _, edge := range g.Edges() {
		if edge.From == "wl:"+aud64CheckoutOwnerID && edge.To == "res:lb-edge" && edge.Type == graph.EdgeConnectsTo {
			goto foundConnection
		}
	}
	t.Fatalf("production graph has no canonical workload-to-resource CONNECTS_TO edge from the projected service dependency: %+v", g.Edges())

foundConnection:
	for _, edge := range g.Edges() {
		if edge.From == "id:"+aud64IdentityID && edge.To == "wl:"+aud64PaymentsOwnerID && edge.Type == graph.EdgeOwns {
			t.Fatalf("production graph reversed OWNS to satisfy the test: %+v", edge)
		}
	}
	rows := g.CryptoReadiness()
	var row graph.CryptoReadinessRow
	foundRow := false
	for _, candidate := range rows {
		if candidate.Asset.ID == "crypto:"+aud64AssetID {
			row = candidate
			foundRow = true
			break
		}
	}
	if !foundRow {
		t.Fatalf("no readiness row for crypto:%s", aud64AssetID)
	}
	dependents := map[string]bool{}
	for _, dependent := range row.Dependents {
		dependents[dependent.Node.ID] = true
		if dependent.Via.ID != "res:lb-edge" {
			t.Fatalf("dependent %s has unexplained path via %s", dependent.Node.ID, dependent.Via.ID)
		}
	}
	for _, want := range []string{"id:" + aud64IdentityID, "wl:" + aud64CheckoutOwnerID} {
		if !dependents[want] {
			t.Fatalf("production readiness dependents = %v, missing %s", dependents, want)
		}
	}
	if dependents["wl:"+aud64PaymentsOwnerID] || dependents["wl:"+aud64SourceID] {
		t.Fatalf("readiness invented an unobserved dependent: %v", dependents)
	}
	owners := map[string]bool{}
	for _, owner := range row.Owners {
		owners[owner] = true
	}
	for _, want := range []string{"payments-team", "checkout-service"} {
		if !owners[want] {
			t.Fatalf("production readiness owners = %v, missing %q", row.Owners, want)
		}
	}
	if owners["foreign-payments-team"] || owners["foreign-checkout-service"] {
		t.Fatalf("tenant B owner leaked into tenant A readiness: %v", row.Owners)
	}
	return rows
}

func aud64ServedReadiness(t *testing.T, st *store.Store) []graph.CryptoReadinessRow {
	t.Helper()
	log := openLog(t)
	handler := api.New(st, orchestrator.NewIdempotency(st), orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st)), api.WithInsecureHeaderResolver())
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	status, _, body := do(t, srv, http.MethodGet, "/api/v1/graph/crypto-readiness", reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("served crypto readiness = %d body=%s", status, body)
	}
	var response struct {
		Items []graph.CryptoReadinessRow `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode served crypto readiness: %v", err)
	}
	if len(response.Items) != 1 {
		t.Fatalf("served crypto readiness items = %d body=%s, want one tenant-local row", len(response.Items), body)
	}
	return response.Items
}

func TestAUD64ProductionGraphBuildsOwnersAndDiscoveredRelyingParties(t *testing.T) {
	ctx := context.Background()
	authorityA := aud64AuthorityEvents(t, tenantA, false)
	authorityB := aud64AuthorityEvents(t, tenantB, true)

	first := newStore(t)
	aud64Project(t, first, tenantA, "Acme", authorityA)
	aud64Project(t, first, tenantB, "Beta", authorityB)
	first.Close()

	restarted, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	rowsAfterRestart := aud64Readiness(t, restarted)
	restarted.Close()

	// Cold projection replay is the authority test. The graph must not depend on
	// hand-built edges or a warm process: erase every read model through the
	// package reset, then apply the same owner/identity/target/CBOM/discovery
	// events and require byte-for-byte equivalent readiness.
	rebuilt := newStore(t)
	aud64Project(t, rebuilt, tenantA, "Acme", authorityA)
	aud64Project(t, rebuilt, tenantB, "Beta", authorityB)
	rowsAfterReplay := aud64Readiness(t, rebuilt)
	if !reflect.DeepEqual(rowsAfterRestart, rowsAfterReplay) {
		t.Fatalf("readiness changed across cold replay:\nrestart=%+v\nreplay=%+v", rowsAfterRestart, rowsAfterReplay)
	}
	if served := aud64ServedReadiness(t, rebuilt); !reflect.DeepEqual(rowsAfterReplay, served) {
		t.Fatalf("served readiness diverged from graph authority:\ngraph=%+v\nserved=%+v", rowsAfterReplay, served)
	}
	rebuilt.Close()

	// Mutation negatives keep the acceptance honest. Removing the exact owner
	// makes Build fail closed; it must not attach the observation to another
	// workload. Removing the immutable observation removes only the checkout
	// relying party; Build must not infer that edge from the shared target.
	authorityWithoutCheckoutOwner := append([]events.Event{}, authorityA[:1]...)
	authorityWithoutCheckoutOwner = append(authorityWithoutCheckoutOwner, authorityA[2:]...)
	missingOwner := newStore(t)
	aud64Project(t, missingOwner, tenantA, "Acme", authorityWithoutCheckoutOwner)
	if _, err := graph.Build(ctx, missingOwner, tenantA); err == nil {
		t.Fatal("graph accepted a service dependency after its exact workload owner was removed")
	}
	missingOwner.Close()

	missingDependency := newStore(t)
	aud64Project(t, missingDependency, tenantA, "Acme", authorityA[:len(authorityA)-1])
	withoutDependency, err := graph.Build(ctx, missingDependency, tenantA)
	if err != nil {
		t.Fatalf("build graph without dependency observation: %v", err)
	}
	for _, edge := range withoutDependency.Edges() {
		if edge.Type == graph.EdgeConnectsTo {
			t.Fatalf("graph invented CONNECTS_TO after dependency observation removal: %+v", edge)
		}
	}
	for _, row := range withoutDependency.CryptoReadiness() {
		for _, dependent := range row.Dependents {
			if dependent.Node.ID == "wl:"+aud64CheckoutOwnerID {
				t.Fatalf("readiness retained checkout relying party after dependency observation removal: %+v", row)
			}
		}
	}
}
