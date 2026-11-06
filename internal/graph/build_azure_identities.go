// SPDX-License-Identifier: BUSL-1.1
package graph

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/azureiam"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Azure role bindings remain observed metadata. This reader creates no effective
// GRANTS_ACCESS edge from captured Azure bindings or a limited audit window.
func addAzureMachineIdentities(ctx context.Context, st *store.Store, tenantID string, g *Graph, findings []store.DiscoveryFinding) (map[string]bool, error) {
	recognized := map[string]bool{}
	type candidate struct {
		finding store.DiscoveryFinding
		value   azureiam.Inventory
	}
	latest := map[string]candidate{}
	for _, finding := range findings {
		if finding.Kind != azureiam.FindingKind {
			continue
		}
		source, err := st.GetDiscoverySource(ctx, tenantID, finding.SourceID)
		if store.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if source.Kind != azureiam.SourceKind {
			continue
		}
		run, err := st.GetDiscoveryRun(ctx, tenantID, finding.RunID)
		if store.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if run.SourceID != source.ID || run.DryRun || (run.Status != "succeeded" && run.Status != "partial") {
			continue
		}
		value, err := azureiam.DecodeInventory(finding.Metadata)
		if err != nil {
			continue
		}
		fingerprint, err := azureiam.Fingerprint(value)
		if err != nil || fingerprint != finding.Fingerprint || finding.Ref != "azure-entra:"+value.TenantID+":"+value.Identity.ID || finding.Provenance != "azure-entra:subscriptions/"+value.SubscriptionID {
			continue
		}
		recognized[finding.ID] = true
		previous, exists := latest[value.TenantID+":"+value.Identity.ID]
		if !exists || finding.DiscoveredAt.After(previous.finding.DiscoveredAt) || (finding.DiscoveredAt.Equal(previous.finding.DiscoveredAt) && finding.ID > previous.finding.ID) {
			latest[value.TenantID+":"+value.Identity.ID] = candidate{finding, value}
		}
	}
	for _, current := range latest {
		finding, value := current.finding, current.value
		principalID := "azure-principal:" + crypto.SHA256Hex([]byte(value.TenantID+":"+value.Identity.ID))
		g.AddNode(Node{ID: principalID, Kind: KindWorkload, Name: value.Identity.Name, Attrs: map[string]string{"provider": "azure-entra", "principal_kind": "service_account", "native_id": value.Identity.ID, "application_id": value.Identity.AppID, "native_type": value.Identity.Type, "azure_tenant_id": value.TenantID, "subscription_id": value.SubscriptionID, "enabled": strconv.FormatBool(value.Identity.Enabled), "finding_id": finding.ID, "evidence": "native workload identity; effective access is unknown"}})
		for _, group := range [][]azureiam.Credential{value.Identity.Keys, value.Identity.Passwords} {
			for _, key := range group {
				id := "azure-key:" + crypto.SHA256Hex([]byte(value.TenantID+":"+value.Identity.ID+":"+key.ID))
				attrs := map[string]string{"provider": "azure-entra", "credential_kind": key.Kind, "native_id": key.ID, "long_lived": strconv.FormatBool(key.LongLived), "age_days": strconv.Itoa(key.AgeDays), "last_use_coverage": key.LastUseCoverage, "expires_at": key.End.UTC().Format(time.RFC3339), "finding_id": finding.ID}
				if key.LastObservedUse != nil {
					attrs["last_observed_use_at"] = key.LastObservedUse.UTC().Format(time.RFC3339)
				}
				g.AddNode(Node{ID: id, Kind: KindCredential, Name: key.ID, Attrs: attrs})
				g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHolds, Confidence: "observed", Source: "native Azure credential owner; finding " + finding.ID})
			}
		}
		for _, binding := range value.RBAC {
			raw, _ := json.Marshal(binding)
			id := "azure-rbac:" + crypto.SHA256Hex([]byte(value.TenantID+":"+binding.ID))
			g.AddNode(Node{ID: id, Kind: KindRole, Name: binding.Properties.RoleDefinitionID, Attrs: map[string]string{"provider": "azure-entra", "scope": binding.Properties.Scope, "condition": binding.Properties.Condition, "captured_binding": string(raw), "permission_coverage": binding.DefinitionCoverage, "finding_id": finding.ID, "evidence": "captured RBAC binding; effective access is unknown"}})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHasRole, Confidence: "observed", Source: "native Azure RBAC assignment; finding " + finding.ID})
		}
		for _, binding := range value.AppRoles {
			raw, _ := json.Marshal(binding)
			id := "azure-app-role:" + crypto.SHA256Hex([]byte(value.TenantID+":"+binding.ID))
			g.AddNode(Node{ID: id, Kind: KindRole, Name: binding.Value, Attrs: map[string]string{"provider": "azure-entra", "resource_id": binding.ResourceID, "native_id": binding.RoleID, "captured_binding": string(raw), "permission_coverage": binding.Coverage, "finding_id": finding.ID, "evidence": "captured application role; effective access is unknown"}})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHasRole, Confidence: "observed", Source: "native Graph app-role assignment; finding " + finding.ID})
		}
	}
	return recognized, nil
}
