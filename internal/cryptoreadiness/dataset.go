// SPDX-License-Identifier: BUSL-1.1

// Package cryptoreadiness builds the one tenant-bound crypto migration dataset
// consumed by JSON, CBOM/Posture, Risk, owner actions, and signed evidence.
// graph.Build remains topology authority; campaign projections add workflow
// state but never manufacture or override a graph edge.
package cryptoreadiness

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

const (
	Format          = "trstctl.crypto-readiness.v1"
	rowDigestFormat = "trstctl.crypto-readiness-row.v1"
)

// CoverageGuidance makes an unknown scan path travel with every consumer and
// export. A zero dependent count is never allowed to become a safe verdict.
const CoverageGuidance = "Sequenced by exposure, not severity alone: two identically weak " +
	"algorithms are ordered by how many parties actually depend on them, because severity says " +
	"which crypto is worst while only dependency says which change is hard. Dependents are what " +
	"DISCOVERY HAS OBSERVED — the graph is built from scans, so an asset with zero dependents reads " +
	"identically to one on a resource nothing has scanned. No row is ever labeled safe to rotate; " +
	"confirm coverage of an asset's exhibitors before treating a low count as a low-coordination change."

// Action is one real event-sourced migration-campaign item bound to an exact
// graph row digest. Stale means the current graph no longer matches the row the
// action was created against; such an action remains visible but cannot accept
// new evidence or close.
type Action struct {
	CampaignID      string    `json:"campaign_id"`
	Name            string    `json:"name"`
	Owner           string    `json:"owner"`
	Deadline        time.Time `json:"deadline"`
	Wave            string    `json:"wave"`
	Status          string    `json:"status"`
	ReadinessStatus string    `json:"readiness_status"`
	Disposition     string    `json:"disposition"`
	EvidenceRefs    []string  `json:"evidence_refs"`
	EvidenceDigests []string  `json:"evidence_digests"`
	ReadinessDigest string    `json:"readiness_digest"`
	Stale           bool      `json:"stale"`
}

// Item extends the graph row with workflow state. Anonymous embedding keeps the
// existing JSON row contract flat and backward compatible.
type Item struct {
	graph.CryptoReadinessRow
	Actions []Action `json:"actions"`
}

// Dataset is deterministic: it has no request-time clock. DatasetDigest binds
// the tenant, ordered graph rows, action/evidence state, counts, and coverage
// wording, so JSON and offline exports can prove they describe the same facts.
type Dataset struct {
	Format           string `json:"format"`
	TenantID         string `json:"tenant_id"`
	DatasetDigest    string `json:"dataset_digest"`
	Items            []Item `json:"items"`
	Urgent           int    `json:"urgent"`
	Unlocated        int    `json:"unlocated"`
	CoverageGuidance string `json:"coverage_guidance"`
}

type digestPayload struct {
	Format           string `json:"format"`
	TenantID         string `json:"tenant_id"`
	Items            []Item `json:"items"`
	Urgent           int    `json:"urgent"`
	Unlocated        int    `json:"unlocated"`
	CoverageGuidance string `json:"coverage_guidance"`
}

// Build constructs the graph and joins event-projected owner actions under the
// same tenant scope.
func Build(ctx context.Context, st *store.Store, tenantID string) (Dataset, error) {
	g, err := graph.Build(ctx, st, tenantID)
	if err != nil {
		return Dataset{}, err
	}
	return BuildFromGraph(ctx, st, tenantID, g)
}

// BuildFromGraph joins workflow state to an already built production graph.
func BuildFromGraph(ctx context.Context, st *store.Store, tenantID string, g *graph.Graph) (Dataset, error) {
	actions, err := st.ListCryptoReadinessActions(ctx, tenantID)
	if err != nil {
		return Dataset{}, err
	}
	return FromGraph(tenantID, g, actions)
}

// FromGraph makes a deterministic dataset from one graph plus already
// tenant-confined action rows. Governance uses it when it already owns the
// exact graph snapshot being signed.
func FromGraph(tenantID string, g *graph.Graph, actions []store.CryptoReadinessAction) (Dataset, error) {
	if tenantID == "" || g == nil {
		return Dataset{}, fmt.Errorf("crypto readiness requires tenant and graph")
	}
	byFinding := make(map[string][]store.CryptoReadinessAction)
	for _, action := range actions {
		if action.TenantID != tenantID {
			return Dataset{}, fmt.Errorf("crypto readiness action %s is outside tenant", action.CampaignID)
		}
		byFinding[action.FindingID] = append(byFinding[action.FindingID], action)
	}
	rows := g.CryptoReadiness()
	dataset := Dataset{
		Format: Format, TenantID: tenantID, Items: make([]Item, 0, len(rows)),
		CoverageGuidance: CoverageGuidance,
	}
	for _, row := range rows {
		item := Item{CryptoReadinessRow: row, Actions: []Action{}}
		rowDigest, err := RowDigest(tenantID, row)
		if err != nil {
			return Dataset{}, err
		}
		findingID := cryptoAssetFindingID(row.Asset.ID)
		for _, stored := range byFinding[findingID] {
			refs := append([]string(nil), stored.ReadinessEvidenceRefs...)
			refs = append(refs, stored.EvidenceRefs...)
			refs = sortedUnique(refs)
			item.Actions = append(item.Actions, Action{
				CampaignID: stored.CampaignID, Name: stored.Name, Owner: stored.OwnerRef,
				Deadline: stored.Deadline, Wave: stored.Wave, Status: stored.Status,
				ReadinessStatus: stored.ReadinessStatus, Disposition: stored.Disposition,
				EvidenceRefs: refs, EvidenceDigests: sortedUnique(stored.EvidenceDigests),
				ReadinessDigest: stored.ReadinessDigest,
				Stale:           stored.ReadinessDigest != rowDigest || !contains(row.Owners, stored.OwnerRef),
			})
		}
		sort.Slice(item.Actions, func(i, j int) bool { return item.Actions[i].CampaignID < item.Actions[j].CampaignID })
		if row.QuantumVulnerable || row.OutOfPolicy {
			dataset.Urgent++
		}
		if row.Unlocated {
			dataset.Unlocated++
		}
		dataset.Items = append(dataset.Items, item)
	}
	canonical := digestPayload{
		Format: dataset.Format, TenantID: dataset.TenantID, Items: dataset.Items,
		Urgent: dataset.Urgent, Unlocated: dataset.Unlocated,
		CoverageGuidance: dataset.CoverageGuidance,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return Dataset{}, err
	}
	dataset.DatasetDigest = "sha256:" + crypto.SHA256Hex(raw)
	return dataset, nil
}

// RowDigest binds only production topology and attribution, not mutable action
// state. It is stored inside the immutable campaign-start event.
func RowDigest(tenantID string, row graph.CryptoReadinessRow) (string, error) {
	payload := struct {
		Format   string                   `json:"format"`
		TenantID string                   `json:"tenant_id"`
		Row      graph.CryptoReadinessRow `json:"row"`
	}{Format: rowDigestFormat, TenantID: tenantID, Row: row}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "sha256:" + crypto.SHA256Hex(raw), nil
}

func cryptoAssetFindingID(nodeID string) string {
	const prefix = "crypto:"
	if len(nodeID) >= len(prefix) && nodeID[:len(prefix)] == prefix {
		return nodeID[len(prefix):]
	}
	return ""
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
