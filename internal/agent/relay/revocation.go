// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Revocation distribution-point health (epic R1).
//
// Every inventoried certificate already carries its CDP and OCSP URLs — they
// are parsed onto it by internal/crypto/certinfo — and nothing has ever fetched
// one. That gap is quietly serious: a CRL whose nextUpdate has passed does not
// announce itself. Relying parties either fail closed and break the service, or
// soft-fail and stop checking revocation at all, and neither shows up on any
// dashboard until an incident. Meanwhile the CA's operator believes revocation
// works because publishing succeeded once.
//
// It is a RELAY job for a specific reason: most CDPs that matter are internal.
// An AD CS CRL on http://pki.corp.internal/certenroll/ is unreachable from a
// SaaS control plane by design, and monitoring only the endpoints reachable
// from outside would inventory exactly the ones least likely to break.
//
// This probe reads. It fetches a CRL, parses it, and verifies its signature
// against the issuer when the caller supplies one. It never writes, and it
// never treats "unreachable" and "fresh" as the same answer.

// RevocationProbeIntent is the job payload: which endpoints to check, and the
// issuer to verify against.
type RevocationProbeIntent struct {
	// Endpoints are the distinct CDP URLs to probe. The control plane
	// deduplicates across the inventory before enqueueing, because one CA's CDP
	// is named by every certificate it issued and probing it ten thousand times
	// would be an outage the monitoring caused.
	Endpoints []string `json:"endpoints"`
	// IssuerDER is the issuing CA certificate, so a fetched CRL's signature can
	// be verified rather than merely parsed. Optional: without it the probe
	// still reports freshness and reachability and says the signature was not
	// checked, rather than implying it was.
	IssuerDER []byte `json:"issuer_der,omitempty"`
	// StaleWithin flags a CRL as approaching expiry this far before its
	// nextUpdate. Zero means only actually-expired CRLs are flagged, which is
	// too late to be useful — the control plane sets a real value.
	StaleWithinSeconds int `json:"stale_within_seconds,omitempty"`
}

// RevocationFindingStatus is one endpoint's verdict.
type RevocationFindingStatus string

const (
	// RevocationFresh means the CRL was fetched, parsed, and its nextUpdate is
	// comfortably ahead.
	RevocationFresh RevocationFindingStatus = "fresh"
	// RevocationExpiring means the CRL is valid but its nextUpdate falls inside
	// the warning window. This is the state worth alerting on: after nextUpdate
	// passes, relying parties are already failing.
	RevocationExpiring RevocationFindingStatus = "expiring"
	// RevocationStale means nextUpdate has passed. Relying parties that check
	// revocation are failing closed right now, or worse, silently soft-failing.
	RevocationStale RevocationFindingStatus = "stale"
	// RevocationUnreachable means the endpoint did not answer. Deliberately not
	// the same as stale: an unreachable CDP and an expired one need different
	// people, and reporting them alike sends operators to the wrong one.
	RevocationUnreachable RevocationFindingStatus = "unreachable"
	// RevocationUnparseable means something answered but it was not a CRL, or
	// its signature did not verify against the issuer. That is a different
	// failure again — usually a proxy or captive portal returning HTML, which
	// looks like success to anything that only checks the status code.
	RevocationUnparseable RevocationFindingStatus = "unparseable"
)

// RevocationFinding is one distribution point's health.
type RevocationFinding struct {
	Endpoint  string                  `json:"endpoint"`
	Status    RevocationFindingStatus `json:"status"`
	Detail    string                  `json:"detail,omitempty"`
	LatencyMS int64                   `json:"latency_ms,omitempty"`
	// ThisUpdate and NextUpdate are the CRL's own timestamps. They are the
	// evidence behind the status, so an operator can see how much room is left
	// rather than trusting a label.
	ThisUpdate *time.Time `json:"this_update,omitempty"`
	NextUpdate *time.Time `json:"next_update,omitempty"`
	// SignatureVerified says whether the CRL was checked against its issuer. It
	// is reported explicitly because "we did not check" and "it verified" must
	// never read the same.
	SignatureVerified bool `json:"signature_verified"`
	// RevokedCount is how many serials the CRL carries. Useful as a sanity
	// signal: a CRL that suddenly empties is as alarming as one that expires.
	RevokedCount int `json:"revoked_count,omitempty"`
}

// RevocationReport is what the relay returns for one probe job.
type RevocationReport struct {
	Findings []RevocationFinding `json:"findings"`
	// Healthy is true only when every endpoint answered with a fresh, verified
	// CRL. One unreachable endpoint makes the whole report unhealthy, because a
	// revocation check that cannot reach its distribution point does not
	// half-work.
	Healthy bool `json:"healthy"`
}

// revocationFetchTimeout bounds one endpoint. A CDP that takes longer than this
// is functionally unreachable to a relying party doing a TLS handshake.
const revocationFetchTimeout = 15 * time.Second

// revocationBodyLimit caps what is read from an endpoint. A CRL is large but
// bounded; anything past this is not one, and reading it would let a hostile or
// broken endpoint exhaust the relay's memory.
const revocationBodyLimit = 32 << 20

// ProbeRevocation walks each distribution point and reports its health.
//
// Every endpoint is probed even after one fails: an operator needs the whole
// picture, and stopping at the first failure would hide the other nine.
func ProbeRevocation(ctx context.Context, client *http.Client, intent RevocationProbeIntent) (RevocationReport, error) {
	if client == nil {
		return RevocationReport{}, errors.New("relay: revocation probe needs an HTTP client")
	}
	endpoints := dedupeEndpoints(intent.Endpoints)
	if len(endpoints) == 0 {
		return RevocationReport{}, errors.New("relay: revocation probe names no endpoints")
	}
	staleWithin := time.Duration(intent.StaleWithinSeconds) * time.Second

	report := RevocationReport{Healthy: true}
	for _, endpoint := range endpoints {
		finding := probeDistributionPoint(ctx, client, endpoint, intent.IssuerDER, staleWithin)
		if finding.Status != RevocationFresh {
			report.Healthy = false
		}
		report.Findings = append(report.Findings, finding)
	}
	return report, nil
}

// probeDistributionPoint fetches and evaluates one CDP.
func probeDistributionPoint(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	issuerDER []byte,
	staleWithin time.Duration,
) RevocationFinding {
	finding := RevocationFinding{Endpoint: endpoint}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		finding.Status = RevocationUnparseable
		finding.Detail = "distribution point is not a usable URL"
		return finding
	}
	// LDAP CDPs exist in AD CS estates and are not fetchable over HTTP. Saying
	// so is better than reporting them unreachable, which would send an operator
	// to check a network path that was never the problem.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		finding.Status = RevocationUnparseable
		finding.Detail = "distribution point uses " + parsed.Scheme + ", which this probe does not fetch"
		return finding
	}

	fetchCtx, cancel := context.WithTimeout(ctx, revocationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.Detail = "could not build a request for this distribution point"
		return finding
	}
	started := time.Now()
	resp, err := client.Do(req)
	finding.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.Detail = summarizeTransportError(err)
		return finding
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		finding.Status = RevocationUnreachable
		finding.Detail = fmt.Sprintf("distribution point answered HTTP %d", resp.StatusCode)
		return finding
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, revocationBodyLimit))
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.Detail = "could not read the CRL body"
		return finding
	}

	// Parse and, when an issuer is supplied, VERIFY. A proxy or captive portal
	// returning HTML with a 200 is the case this catches — it looks like
	// success to anything that only checks the status code.
	info, err := crypto.ParseCRL(body, issuerDER)
	if err != nil {
		finding.Status = RevocationUnparseable
		finding.Detail = "the distribution point answered but did not serve a valid CRL for this issuer"
		return finding
	}
	finding.SignatureVerified = len(issuerDER) > 0
	finding.RevokedCount = len(info.RevokedSerials)
	thisUpdate, nextUpdate := info.ThisUpdate, info.NextUpdate
	finding.ThisUpdate, finding.NextUpdate = &thisUpdate, &nextUpdate

	now := time.Now().UTC()
	switch {
	case nextUpdate.IsZero():
		// A CRL with no nextUpdate never expires by its own terms, which sounds
		// convenient and is not: relying parties cannot tell a current one from
		// one published years ago.
		finding.Status = RevocationUnparseable
		finding.Detail = "the CRL carries no nextUpdate, so no relying party can tell whether it is current"
	case now.After(nextUpdate):
		finding.Status = RevocationStale
		finding.Detail = "nextUpdate passed " + now.Sub(nextUpdate).Truncate(time.Second).String() +
			" ago; relying parties checking revocation are failing now"
	case staleWithin > 0 && nextUpdate.Sub(now) <= staleWithin:
		finding.Status = RevocationExpiring
		finding.Detail = "nextUpdate is " + nextUpdate.Sub(now).Truncate(time.Second).String() +
			" away; republish before it passes"
	default:
		finding.Status = RevocationFresh
		finding.Detail = "nextUpdate is " + nextUpdate.Sub(now).Truncate(time.Second).String() + " away"
	}
	if !finding.SignatureVerified && finding.Status == RevocationFresh {
		// Freshness without verification is a weaker claim, and the detail says
		// so rather than letting "fresh" imply more than was checked.
		finding.Detail += " (signature not checked: no issuer was supplied with this probe)"
	}
	return finding
}

// dedupeEndpoints normalizes and deduplicates. One CA's CDP is named by every
// certificate it issued, so probing the raw list would hit the same URL
// thousands of times — monitoring that causes the outage it watches for.
func dedupeEndpoints(raw []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, endpoint := range raw {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" || seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

// KindRevocationProbe is the job kind this executes.
const KindRevocationProbe = "revocation.probe"

// runRevocationProbe executes a revocation.probe job and reports the findings.
// Like the dry-run, an unhealthy result is a successful JOB — the probe ran and
// produced an answer. Reporting it as a failure would requeue it to be retried
// forever against a CDP that is genuinely down, which is exactly the state an
// operator needs to see rather than have retried at them.
func runRevocationProbe(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent RevocationProbeIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a revocation probe intent")
		return false
	}
	probeReport, err := ProbeRevocation(ctx, client, intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "revocation probe could not run")
		return false
	}
	detail, err := json.Marshal(probeReport)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "revocation findings could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return probeReport.Healthy
}
