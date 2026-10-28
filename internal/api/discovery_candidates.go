// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

// A212: addresses trstctl's own sources saw outside every declared segment,
// listed as candidates for a declaration. Never a coverage claim: a network no
// source has seen cannot appear.

const (
	coverageCandidateWindow   = 30 * 24 * time.Hour
	coverageCandidatesScanned = 2000
	coverageCandidatesShown   = 200
	coverageCandidatesNote    = "Addresses trstctl's own sources saw outside every declared segment, excluded segments included. " +
		"An address no source has seen cannot appear, so this is never a complete list of undeclared networks."
)

// CoverageCandidate is one address seen outside every declared segment.
type CoverageCandidate struct {
	Address      string    `json:"address"`
	Sources      []string  `json:"sources"`
	LastSeen     time.Time `json:"last_seen"`
	Observations int       `json:"observations"`
}

// CoverageCandidates lists them with the window they were read over.
type CoverageCandidates struct {
	Items      []CoverageCandidate `json:"items"`
	Complete   bool                `json:"complete"`
	WindowDays int                 `json:"window_days"`
	Note       string              `json:"note"`
}

func (a *API) coverageCandidates(ctx context.Context, tenantID string) ([]CoverageCandidate, error) {
	segments, err := a.store.ListDiscoverySegments(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var declarations []string
	for _, segment := range segments {
		declarations = append(declarations, segment.Ranges...)
	}
	observed, err := a.store.ObservedAddresses(ctx, tenantID, time.Now().UTC().Add(-coverageCandidateWindow), coverageCandidatesScanned)
	if err != nil {
		return nil, err
	}
	out := []CoverageCandidate{}
	for _, seen := range observed {
		if len(out) == coverageCandidatesShown {
			break
		}
		if !networkAddress(seen.Address) || segmentscan.Covered(declarations, seen.Address) {
			continue
		}
		out = append(out, CoverageCandidate{Address: seen.Address, Sources: seen.Sources,
			LastSeen: seen.LastSeen, Observations: seen.Observations})
	}
	return out, nil
}

// networkAddress keeps values a source recorded as a network address, a
// host:port or a bare IP address, and drops file paths, Kubernetes references
// and other location labels; nothing is resolved.
func networkAddress(value string) bool {
	if value == "" || strings.ContainsAny(value, "/ \t") {
		return false
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		number, perr := strconv.Atoi(port)
		return host != "" && perr == nil && number > 0 && number < 65536
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

func (a *API) listCoverageCandidates(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := a.coverageCandidates(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, CoverageCandidates{Items: items, Complete: false,
		WindowDays: int(coverageCandidateWindow / (24 * time.Hour)), Note: coverageCandidatesNote})
}

// appendCoverageCandidates names the addresses seen outside every declared
// segment in the coverage register, so the coverage read says where a
// declaration may be missing.
func (a *API) appendCoverageCandidates(ctx context.Context, tenantID string, out *DiscoveryCoverageResponse) {
	candidates, err := a.coverageCandidates(ctx, tenantID)
	if err != nil || len(candidates) == 0 {
		return
	}
	subject := "1 address"
	if len(candidates) != 1 {
		subject = strconv.Itoa(len(candidates)) + " addresses"
	}
	out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
		Kind: "addresses_outside_segments", Subject: subject,
		Detail: "trstctl's own sources saw these addresses outside every declared segment in the last " +
			strconv.Itoa(int(coverageCandidateWindow/(24*time.Hour))) + " days; a network no source has seen cannot appear here",
		Action: "declare a segment that covers them, or declare them out of scope (GET /api/v1/discovery/coverage/candidates lists them)",
	})
}
