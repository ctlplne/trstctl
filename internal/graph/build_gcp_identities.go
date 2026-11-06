// SPDX-License-Identifier: BUSL-1.1
package graph

import (
	"context"
	"encoding/json"
	"strconv"
	"trstctl.com/trstctl/internal/cloudentitlements/gcpiam"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// GCP role bindings remain observed metadata. This reader creates no effective
// GRANTS_ACCESS edge from a partial project policy or audit window.
func addGCPMachineIdentities(ctx context.Context, st *store.Store, tenantID string, g *Graph, findings []store.DiscoveryFinding) (map[string]bool, error) {
	recognized := map[string]bool{}
	type candidate struct {
		finding store.DiscoveryFinding
		value   gcpiam.Inventory
	}
	latest := map[string]candidate{}
	for _, finding := range findings {
		if finding.Kind != gcpiam.FindingKind {
			continue
		}
		source, err := st.GetDiscoverySource(ctx, tenantID, finding.SourceID)
		if store.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if source.Kind != gcpiam.SourceKind {
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
		value, err := gcpiam.DecodeInventory(finding.Metadata)
		if err != nil {
			continue
		}
		fingerprint, err := gcpiam.Fingerprint(value)
		if err != nil || fingerprint != finding.Fingerprint || finding.Ref != "gcp-iam:"+value.Identity.NativeID || finding.Provenance != "gcp-iam:projects/"+value.Identity.Project {
			continue
		}
		recognized[finding.ID] = true
		previous, exists := latest[value.Identity.NativeID]
		if !exists || finding.DiscoveredAt.After(previous.finding.DiscoveredAt) || (finding.DiscoveredAt.Equal(previous.finding.DiscoveredAt) && finding.ID > previous.finding.ID) {
			latest[value.Identity.NativeID] = candidate{finding, value}
		}
	}
	for _, current := range latest {
		finding, value := current.finding, current.value
		principalID := "gcp-principal:" + crypto.SHA256Hex([]byte(value.Identity.NativeID))
		g.AddNode(Node{ID: principalID, Kind: KindWorkload, Name: value.Identity.Email, Attrs: map[string]string{"provider": "gcp-iam", "principal_kind": "service_account", "native_id": value.Identity.NativeID, "project": value.Identity.Project, "disabled": strconv.FormatBool(value.Identity.Disabled), "finding_id": finding.ID, "evidence": "selected native service-account metadata; effective permissions not evaluated"}})
		for _, key := range value.Keys {
			id := "gcp-key:" + crypto.SHA256Hex([]byte(key.Name))
			attrs := map[string]string{"provider": "gcp-iam", "credential_kind": "service_account_key", "disabled": strconv.FormatBool(key.Disabled), "long_lived": strconv.FormatBool(key.LongLived), "age_days": strconv.Itoa(key.AgeDays), "last_use_coverage": key.LastUseCoverage, "finding_id": finding.ID}
			if key.LastObservedUse != nil {
				attrs["last_observed_use_at"] = key.LastObservedUse.UTC().Format("2006-01-02T15:04:05Z07:00")
			}
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: key.Name, Attrs: attrs})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHolds, Confidence: "observed", Source: "native GCP key owner; finding " + finding.ID})
		}
		for _, binding := range value.PolicyBindings {
			raw, _ := json.Marshal(binding.Condition)
			id := "gcp-policy-binding:" + crypto.SHA256Hex([]byte(value.Identity.NativeID+"|"+binding.Scope+"|"+binding.Role+"|"+string(raw)))
			permissions, _ := json.Marshal(binding.Permissions)
			g.AddNode(Node{ID: id, Kind: KindRole, Name: binding.Role, Attrs: map[string]string{"provider": "gcp-iam", "scope": binding.Scope, "condition": string(raw), "captured_permissions": string(permissions), "permission_coverage": binding.PermissionCoverage, "policy_etag": binding.PolicyETag, "finding_id": finding.ID, "evidence": "project policy binding and role definition only; effective access is unknown"}})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHasRole, Confidence: "observed", Source: "native project role binding; finding " + finding.ID})
		}
	}
	return recognized, nil
}
