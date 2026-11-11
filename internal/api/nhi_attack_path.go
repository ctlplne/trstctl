// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Provider-native attack-path validation of exposed NHIs (A167). A probe
// (A102) shows what answered from a relay; this asks the cloud account that
// hosts an endpoint whether its routes, network ACLs and security groups admit
// the internet to it, through an operator's cloud_network_path discovery
// source, and the exposure posture then shows the verdict and the resource
// that decided it beside each record.

type nhiAttackPathRequest struct {
	SourceID     string   `json:"source_id"`
	InventoryIDs []string `json:"inventory_ids"`
}

type nhiAttackPathResult struct {
	RunID       string                     `json:"run_id"`
	SourceID    string                     `json:"source_id"`
	Endpoints   []nhiExposureProbeEndpoint `json:"endpoints"`
	Omitted     int                        `json:"omitted"`
	RequestedAt time.Time                  `json:"requested_at"`
}

type nhiExposureAttackPath struct {
	Status    string                         `json:"status"`
	CheckedAt time.Time                      `json:"checked_at"`
	Endpoints []nhiExposureAttackPathAddress `json:"endpoints"`
}

type nhiExposureAttackPathAddress struct {
	Address   string    `json:"address"`
	Status    string    `json:"status"`
	BlockedBy string    `json:"blocked_by,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Path      []string  `json:"path,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

//trstctl:mutation
func (a *API) validateNHIAttackPaths(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req nhiAttackPathRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.SourceID = strings.TrimSpace(req.SourceID)
		if req.SourceID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "source_id must name a cloud_network_path discovery source")
		}
		if len(req.InventoryIDs) > orchestrator.MaxAttackPathEndpoints {
			return 0, nil, errStatus(http.StatusBadRequest, "inventory_ids names at most 50 records")
		}
		posture, err := a.nhiExposurePosture(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		findings, err := nhiExposureSelectedFindings(posture.Findings, req.InventoryIDs)
		if err != nil {
			return 0, nil, err
		}
		endpoints, omitted := nhiExposureProbeEndpoints(findings, orchestrator.MaxAttackPathEndpoints)
		if len(endpoints) == 0 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "no selected record names a public endpoint or callback URL to validate")
		}
		validate := make([]orchestrator.AttackPathEndpoint, 0, len(endpoints))
		for _, e := range endpoints {
			validate = append(validate, orchestrator.AttackPathEndpoint{InventoryID: e.InventoryID, Endpoint: e.Endpoint, Address: e.Address})
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		runID, err := a.orch.QueueAttackPathValidation(ctx, tenantID, crypto.SHA256Hex([]byte(tenantID+"\x00attack-path\x00"+idempotencyKey)),
			principal.Subject, req.SourceID, validate)
		if errors.Is(err, orchestrator.ErrAttackPathSource) {
			return 0, nil, errStatus(http.StatusConflict, "source_id must name a cloud_network_path discovery source in this tenant; configure one under Discover → Sources with the account's read-only network credentials")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, nhiAttackPathResult{RunID: runID, SourceID: req.SourceID, Endpoints: endpoints,
			Omitted: omitted, RequestedAt: time.Now().UTC()}, nil
	})
}

// nhiExposureSelectedFindings narrows the posture to the named records, in
// request order without repeats; no names keeps every record.
func nhiExposureSelectedFindings(findings []nhiExposurePostureFinding, inventoryIDs []string) ([]nhiExposurePostureFinding, error) {
	if len(inventoryIDs) == 0 {
		return findings, nil
	}
	byID := make(map[string]nhiExposurePostureFinding, len(findings))
	for _, finding := range findings {
		byID[finding.InventoryID] = finding
	}
	out := make([]nhiExposurePostureFinding, 0, len(inventoryIDs))
	seen := map[string]bool{}
	for _, id := range inventoryIDs {
		id = strings.TrimSpace(id)
		finding, ok := byID[id]
		if !ok {
			return nil, errStatus(http.StatusUnprocessableEntity, "inventory_ids contains a record that is not in the exposure posture: "+id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, finding)
		}
	}
	return out, nil
}

// nhiExposureAttackPathsByInventory joins the latest verdict of each validated
// address to its inventory row.
func (a *API) nhiExposureAttackPathsByInventory(ctx context.Context, tenantID string) (map[string]*nhiExposureAttackPath, map[string][]string, error) {
	findings, err := a.store.LatestAttackPathFindings(ctx, tenantID, maxExposureProbeReads)
	if err != nil {
		return nil, nil, err
	}
	// A167-L4: each source's latest verdict per address arrives; an address
	// lives in one account, so a verdict that found it outranks another
	// source's "not in account", a decided one (open or blocked) outranks an
	// unreadable one, and among equals the newest wins.
	chosen := map[string]store.DiscoveryFinding{}
	refs := []string{}
	for _, finding := range findings {
		current, ok := chosen[finding.Ref]
		if !ok {
			refs = append(refs, finding.Ref)
		}
		if !ok || nhiAttackPathVerdictOutranks(finding, current) {
			chosen[finding.Ref] = finding
		}
	}
	sort.Strings(refs)
	out := map[string]*nhiExposureAttackPath{}
	evidence := map[string][]string{}
	for _, ref := range refs {
		finding := chosen[ref]
		row := nhiExposureAttackPathRow(finding)
		inventoryID := metadataString(decodeNHIInventoryMetadata(finding.Metadata), "inventory_id")
		if inventoryID == "" {
			continue
		}
		view := out[inventoryID]
		if view == nil {
			view = &nhiExposureAttackPath{}
			out[inventoryID] = view
		}
		view.Endpoints = append(view.Endpoints, row)
		if row.CheckedAt.After(view.CheckedAt) {
			view.CheckedAt = row.CheckedAt
		}
		evidence[inventoryID] = append(evidence[inventoryID], "attack_path:"+finding.ID)
	}
	for inventoryID, view := range out {
		sort.Slice(view.Endpoints, func(i, j int) bool { return view.Endpoints[i].Address < view.Endpoints[j].Address })
		view.Status = nhiExposureAttackPathStatus(view.Endpoints)
		sort.Strings(evidence[inventoryID])
	}
	return out, evidence, nil
}

func nhiExposureAttackPathRow(finding store.DiscoveryFinding) nhiExposureAttackPathAddress {
	meta := decodeNHIInventoryMetadata(finding.Metadata)
	row := nhiExposureAttackPathAddress{
		Address: metadataString(meta, "address"), Status: metadataString(meta, "status"),
		BlockedBy: metadataString(meta, "blocked_by"), Resource: metadataString(meta, "resource"),
		Rule: metadataString(meta, "rule"), Reason: metadataString(meta, "reason"), CheckedAt: finding.LastSeenAt.UTC(),
	}
	if path, ok := meta["path"].([]any); ok {
		for _, hop := range path {
			if s, ok := hop.(string); ok {
				row.Path = append(row.Path, s)
			}
		}
	}
	return row
}

// nhiAttackPathVerdictOutranks reports whether verdict a, from one source,
// should be shown for an address over verdict b from another.
func nhiAttackPathVerdictOutranks(a, b store.DiscoveryFinding) bool {
	rank := func(f store.DiscoveryFinding) int {
		switch metadataString(decodeNHIInventoryMetadata(f.Metadata), "status") {
		case "open", "blocked":
			return 2
		case "unknown":
			return 1
		default:
			return 0
		}
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra > rb
	}
	if !a.LastSeenAt.Equal(b.LastSeenAt) {
		return a.LastSeenAt.After(b.LastSeenAt)
	}
	return a.ID > b.ID
}

// AttackPathEndpoints names what a full or scheduled cloud_network_path run
// re-validates (A167-L4): every public endpoint and callback the tenant's
// exposure posture names, bounded as a manual validation is, and how many
// more there were.
func (a *API) AttackPathEndpoints(ctx context.Context, tenantID string) ([]orchestrator.AttackPathEndpoint, int, error) {
	posture, err := a.nhiExposurePosture(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	// One run validates a bounded number of endpoints, so the records never
	// validated go first and then the longest unchecked (in the posture's
	// severity order among equals): successive scheduled runs work through
	// the whole posture instead of re-checking its head.
	findings := append([]nhiExposurePostureFinding(nil), posture.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return nhiAttackPathCheckedAt(findings[i]).Before(nhiAttackPathCheckedAt(findings[j]))
	})
	endpoints, omitted := nhiExposureProbeEndpoints(findings, orchestrator.MaxAttackPathEndpoints)
	out := make([]orchestrator.AttackPathEndpoint, 0, len(endpoints))
	for _, e := range endpoints {
		out = append(out, orchestrator.AttackPathEndpoint{InventoryID: e.InventoryID, Endpoint: e.Endpoint, Address: e.Address})
	}
	return out, omitted, nil
}

// nhiAttackPathCheckedAt is when a record's cloud path was last validated;
// the zero time when it never was.
func nhiAttackPathCheckedAt(finding nhiExposurePostureFinding) time.Time {
	if finding.AttackPath == nil {
		return time.Time{}
	}
	return finding.AttackPath.CheckedAt
}

// nhiExposureAttackPathStatus: open when any address is open; unknown when
// none is open and any could not be judged; blocked when every judged address
// is blocked; not_in_account when no configured account holds any of them.
func nhiExposureAttackPathStatus(endpoints []nhiExposureAttackPathAddress) string {
	seen := map[string]bool{}
	for _, e := range endpoints {
		seen[e.Status] = true
	}
	for _, status := range []string{"open", "unknown", "blocked"} {
		if seen[status] {
			return status
		}
	}
	return "not_in_account"
}
