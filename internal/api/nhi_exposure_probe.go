// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Live reachability probing of exposed NHIs (A102). The exposure posture reads
// public endpoints and callback URLs out of discovery metadata; a probe asks a
// network relay to connect to them, public addresses only, and the posture
// then shows what answered from that vantage next to what the metadata
// claimed. The control plane never dials the endpoints itself.

// maxExposureProbeReads bounds the probe observations one posture read joins.
const maxExposureProbeReads = 5000

type nhiExposureProbeRequest struct {
	InventoryIDs []string `json:"inventory_ids"`
}

type nhiExposureProbeEndpoint struct {
	InventoryID string `json:"inventory_id"`
	Endpoint    string `json:"endpoint"`
	Address     string `json:"address"`
	ServerName  string `json:"server_name,omitempty"`
}

type nhiExposureProbeResult struct {
	RunID       string                     `json:"run_id"`
	Vantage     string                     `json:"vantage"`
	Endpoints   []nhiExposureProbeEndpoint `json:"endpoints"`
	Omitted     int                        `json:"omitted"`
	RequestedAt time.Time                  `json:"requested_at"`
}

type nhiExposureReachability struct {
	Status    string                         `json:"status"`
	ProbedAt  time.Time                      `json:"probed_at"`
	Endpoints []nhiExposureReachabilityProbe `json:"endpoints"`
}

type nhiExposureReachabilityProbe struct {
	Address             string    `json:"address"`
	ServerName          string    `json:"server_name,omitempty"`
	Outcome             string    `json:"outcome"`
	Reachable           bool      `json:"reachable"`
	ObservedAt          time.Time `json:"observed_at"`
	ObservedFingerprint string    `json:"observed_fingerprint,omitempty"`
	Error               string    `json:"error,omitempty"`
	Agent               string    `json:"agent,omitempty"`
}

//trstctl:mutation
func (a *API) probeNHIExposure(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req nhiExposureProbeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.InventoryIDs) > orchestrator.MaxExposureProbeEndpoints {
			return 0, nil, errStatus(http.StatusBadRequest, "inventory_ids names at most 50 records")
		}
		posture, err := a.nhiExposurePosture(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		findings := posture.Findings
		if len(req.InventoryIDs) > 0 {
			byID := make(map[string]nhiExposurePostureFinding, len(findings))
			for _, finding := range findings {
				byID[finding.InventoryID] = finding
			}
			findings = findings[:0:0]
			seen := map[string]bool{}
			for _, id := range req.InventoryIDs {
				id = strings.TrimSpace(id)
				finding, ok := byID[id]
				if !ok {
					return 0, nil, errStatus(http.StatusUnprocessableEntity, "inventory_ids contains a record that is not in the exposure posture: "+id)
				}
				if !seen[id] {
					seen[id] = true
					findings = append(findings, finding)
				}
			}
		}
		endpoints, omitted := nhiExposureProbeEndpoints(findings, orchestrator.MaxExposureProbeEndpoints)
		if len(endpoints) == 0 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "no selected record names a public endpoint or callback URL to probe")
		}
		probes := make([]orchestrator.ExposureProbeEndpoint, 0, len(endpoints))
		for _, e := range endpoints {
			probes = append(probes, orchestrator.ExposureProbeEndpoint{
				InventoryID: e.InventoryID, Endpoint: e.Endpoint, Address: e.Address, ServerName: e.ServerName,
			})
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		// The request key derives from the Idempotency-Key, so a retried
		// request converges on one run and one relay sweep.
		runID, err := a.orch.QueueExposureProbe(ctx, tenantID, crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey)), principal.Subject, probes)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, nhiExposureProbeResult{
			RunID: runID, Vantage: "relay", Endpoints: endpoints, Omitted: omitted, RequestedAt: time.Now().UTC(),
		}, nil
	})
}

// nhiExposureProbeEndpoints turns the findings' public endpoints and callback
// URLs into relay targets, in posture order (most severe first), one per
// address per record, at most limit; omitted counts the rest.
func nhiExposureProbeEndpoints(findings []nhiExposurePostureFinding, limit int) ([]nhiExposureProbeEndpoint, int) {
	var out []nhiExposureProbeEndpoint
	omitted := 0
	for _, finding := range findings {
		seen := map[string]bool{}
		for _, endpoint := range append(append([]string{}, finding.PublicEndpoints...), finding.CallbackURLs...) {
			address, serverName, ok := nhiExposureProbeAddress(endpoint)
			if !ok || seen[address] {
				continue
			}
			seen[address] = true
			if len(out) == limit {
				omitted++
				continue
			}
			out = append(out, nhiExposureProbeEndpoint{InventoryID: finding.InventoryID, Endpoint: endpoint, Address: address, ServerName: serverName})
		}
	}
	return out, omitted
}

// nhiExposureProbeAddress maps a posture endpoint to the host:port a relay
// connects to: an explicit port, else 443 for https/wss or a bare host and 80
// for http/ws. A URL of another scheme without a port has no known listener.
// The server name is the host name; an IP literal sends none.
func nhiExposureProbeAddress(endpoint string) (string, string, bool) {
	host, port := "", ""
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host, port = u.Hostname(), u.Port()
		if port == "" {
			switch strings.ToLower(u.Scheme) {
			case "https", "wss":
				port = "443"
			case "http", "ws":
				port = "80"
			default:
				return "", "", false
			}
		}
	} else if h, p, err := net.SplitHostPort(endpoint); err == nil {
		host, port = h, p
	} else {
		host, port = strings.Trim(endpoint, "[]"), "443"
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, "/ ") || port == "" || !isPublicNHIEndpoint(host) {
		return "", "", false
	}
	serverName := host
	if _, err := netip.ParseAddr(host); err == nil {
		serverName = ""
	}
	return net.JoinHostPort(host, port), serverName, true
}

// nhiExposureReachabilityByInventory reads each record's latest probe of each
// endpoint and folds them into the posture's reachability view.
func (a *API) nhiExposureReachabilityByInventory(ctx context.Context, tenantID string) (map[string]*nhiExposureReachability, map[string][]string, error) {
	probes, err := a.store.LatestExposureProbes(ctx, tenantID, maxExposureProbeReads)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]*nhiExposureReachability{}
	evidence := map[string][]string{}
	for _, probe := range probes {
		row := nhiExposureReachabilityRow(probe)
		inventoryID := metadataString(decodeNHIInventoryMetadata(probe.Metadata), "inventory_id")
		if inventoryID == "" {
			continue
		}
		view := out[inventoryID]
		if view == nil {
			view = &nhiExposureReachability{}
			out[inventoryID] = view
		}
		view.Endpoints = append(view.Endpoints, row)
		if row.ObservedAt.After(view.ProbedAt) {
			view.ProbedAt = row.ObservedAt
		}
		evidence[inventoryID] = append(evidence[inventoryID], "exposure_probe:"+probe.ID)
	}
	for inventoryID, view := range out {
		sort.Slice(view.Endpoints, func(i, j int) bool { return view.Endpoints[i].Address < view.Endpoints[j].Address })
		view.Status = nhiExposureReachabilityStatus(view.Endpoints)
		sort.Strings(evidence[inventoryID])
	}
	return out, evidence, nil
}

func nhiExposureReachabilityRow(probe store.DiscoveryFinding) nhiExposureReachabilityProbe {
	meta := decodeNHIInventoryMetadata(probe.Metadata)
	reachable, _ := meta["reachable"].(bool)
	return nhiExposureReachabilityProbe{
		Address: metadataString(meta, "address"), ServerName: metadataString(meta, "server_name"),
		Outcome: metadataString(meta, "outcome"), Reachable: reachable, ObservedAt: probe.LastSeenAt.UTC(),
		ObservedFingerprint: metadataString(meta, "observed_fingerprint"), Error: metadataString(meta, "error"),
		Agent: metadataString(meta, "agent"),
	}
}

// nhiExposureReachabilityStatus: reachable when any endpoint answered the
// relay, not_public when every endpoint resolved to a non-public address (the
// relay refused them), else unreachable.
func nhiExposureReachabilityStatus(endpoints []nhiExposureReachabilityProbe) string {
	notPublic := 0
	for _, e := range endpoints {
		if e.Reachable {
			return "reachable"
		}
		if e.Outcome == orchestrator.ExposureProbeNotPublic {
			notPublic++
		}
	}
	if notPublic == len(endpoints) {
		return "not_public"
	}
	return "unreachable"
}
