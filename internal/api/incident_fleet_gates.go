// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// The two run-level gates that stayed not_evaluated because nothing computed
// them (A20, A21). Both are derived at read time from evidence the control
// plane holds, under the same two rules as the replacement-deployment gate:
// failure dominates, and absence beats success. Neither overwrites a gate an
// operator asserted.
const (
	fleetGraphEnumerationGateName      = "graph enumeration"
	fleetRevocationPublicationGateName = "revocation publication"
)

// fleetEnumerationOutcome is the completeness oracle for the graph enumeration
// gate: the live store is re-read for every identity that still holds an
// active certificate signed by the compromised CA, and each one must be in the
// run's affected set. Anything the plan missed, or anything issued under the
// compromised CA after the plan, shows up as missing.
type fleetEnumerationOutcome struct {
	Evaluated bool
	Live      int
	Missing   []string
}

// fleetGraphEnumerationVerdict maps the oracle onto the gate vocabulary.
func fleetGraphEnumerationVerdict(o fleetEnumerationOutcome) string {
	switch {
	case !o.Evaluated:
		return servedstatus.FleetGateNotEvaluated
	case len(o.Missing) > 0:
		return servedstatus.FleetGateFailed
	default:
		return servedstatus.FleetGatePassed
	}
}

// fleetRevocationPublicationOutcome is R1's freshness signal narrowed to the
// compromised issuer: every revocation-health observation whose issuer is the
// compromised CA, and whether a fresh one postdates the run's revocations.
type fleetRevocationPublicationOutcome struct {
	Evaluated   bool
	Fresh       int
	Expiring    int
	Stale       int
	Unreachable int
	// Current is true when at least one fresh or expiring observation carries a
	// thisUpdate at or after the watermark, so the published artifact can
	// contain the run's predecessor revocations.
	Current bool
}

// fleetRevocationPublicationVerdict: a stale or unreachable endpoint fails the
// gate however many others are fresh; no observation at all, or only
// observations that predate the revocations, keeps it unevaluated.
func fleetRevocationPublicationVerdict(o fleetRevocationPublicationOutcome) string {
	switch {
	case !o.Evaluated:
		return servedstatus.FleetGateNotEvaluated
	case o.Stale > 0 || o.Unreachable > 0:
		return servedstatus.FleetGateFailed
	case !o.Current:
		return servedstatus.FleetGateNotEvaluated
	default:
		return servedstatus.FleetGatePassed
	}
}

// evaluateFleetComputedGate writes a computed verdict into the named gate. A
// gate an operator asserted is left alone; a gate the run never carried is
// appended, so every run reports the computed gates rather than only the ones
// its creator happened to name.
func evaluateFleetComputedGate(gates []store.FleetReissuanceHealthGate, operatorAsserted map[string]bool, name, verdict string) []store.FleetReissuanceHealthGate {
	key := strings.ToLower(strings.TrimSpace(name))
	for i, gate := range gates {
		if strings.ToLower(strings.TrimSpace(gate.Name)) != key {
			continue
		}
		if operatorAsserted[key] {
			return gates
		}
		gates[i].Status = verdict
		return gates
	}
	return append(gates, store.FleetReissuanceHealthGate{Name: name, Status: verdict})
}

// fleetEnumerationOracle re-enumerates the compromised issuer's live leaves.
func (a *API) fleetEnumerationOracle(ctx context.Context, tenantID, issuerID string, affected []string) fleetEnumerationOutcome {
	if a.store == nil || strings.TrimSpace(issuerID) == "" {
		return fleetEnumerationOutcome{}
	}
	issuer, err := a.store.GetIssuer(ctx, tenantID, issuerID)
	if err != nil || issuer.Kind != store.IssuerX509CA || len(issuer.Chain) == 0 {
		return fleetEnumerationOutcome{}
	}
	caDER, err := certinfo.LeafDER([]byte(issuer.Chain[0]))
	if err != nil {
		return fleetEnumerationOutcome{}
	}
	candidates, err := a.store.ListRevocableIdentitiesByIssuer(ctx, tenantID, issuerID)
	if err != nil {
		return fleetEnumerationOutcome{}
	}
	covered := make(map[string]bool, len(affected))
	for _, id := range affected {
		covered[id] = true
	}
	out := fleetEnumerationOutcome{Evaluated: true}
	for _, identity := range candidates {
		active, err := a.store.ListActiveIssuedCertificatesForIdentity(ctx, tenantID, identity.OwnerID, identity.Name)
		if err != nil {
			// A read that fails mid-enumeration cannot prove completeness.
			return fleetEnumerationOutcome{}
		}
		live := false
		for _, cert := range active {
			if crypto.VerifyLeafSignedByCA(cert.CertificateDER, caDER) == nil {
				live = true
				break
			}
		}
		if !live {
			continue
		}
		out.Live++
		if !covered[identity.ID] {
			out.Missing = append(out.Missing, identity.ID)
		}
	}
	sort.Strings(out.Missing)
	return out
}

// fleetRevocationPublicationOracle reads the compromised issuer's revocation
// endpoint observations. The watermark is the run's last state change once it
// has revoked predecessors: a published artifact older than that cannot carry
// those revocations yet.
func (a *API) fleetRevocationPublicationOracle(ctx context.Context, tenantID, issuerID string, revoked []string, watermark time.Time) fleetRevocationPublicationOutcome {
	if a.store == nil || strings.TrimSpace(issuerID) == "" {
		return fleetRevocationPublicationOutcome{}
	}
	issuer, err := a.store.GetIssuer(ctx, tenantID, issuerID)
	if err != nil || len(issuer.Chain) == 0 {
		return fleetRevocationPublicationOutcome{}
	}
	caDER, err := certinfo.LeafDER([]byte(issuer.Chain[0]))
	if err != nil {
		return fleetRevocationPublicationOutcome{}
	}
	info, err := certinfo.Inspect(caDER)
	if err != nil {
		return fleetRevocationPublicationOutcome{}
	}
	rows, err := a.store.ListRevocationEndpointHealth(ctx, tenantID, 500)
	if err != nil {
		return fleetRevocationPublicationOutcome{}
	}
	return fleetRevocationPublicationFromRows(rows, info.SHA256Fingerprint, len(revoked) > 0, watermark)
}

// fleetRevocationPublicationFromRows is the pure half of the oracle.
func fleetRevocationPublicationFromRows(rows []store.RevocationEndpointHealth, issuerFingerprint string, revokedAny bool, watermark time.Time) fleetRevocationPublicationOutcome {
	var out fleetRevocationPublicationOutcome
	for _, row := range rows {
		if !strings.EqualFold(strings.TrimSpace(row.IssuerFingerprint), strings.TrimSpace(issuerFingerprint)) {
			continue
		}
		out.Evaluated = true
		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case "fresh":
			out.Fresh++
		case "expiring":
			out.Expiring++
		case "stale":
			out.Stale++
		default:
			out.Unreachable++
			continue
		}
		if revokedAny && row.ThisUpdate != nil && !row.ThisUpdate.Before(watermark) && (strings.EqualFold(row.Status, "fresh") || strings.EqualFold(row.Status, "expiring")) {
			out.Current = true
		}
	}
	return out
}
