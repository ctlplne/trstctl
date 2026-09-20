// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revocationhealth"
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

// Shared bounded command/report aliases retained at the relay API boundary.
type RevocationProbeIntent = revocationhealth.Intent
type RevocationFindingStatus = revocationhealth.FindingStatus
type RevocationFinding = revocationhealth.Finding
type RevocationReport = revocationhealth.Report

const (
	// RevocationFresh means the CRL was fetched, parsed, and its nextUpdate is
	// comfortably ahead.
	RevocationFresh = revocationhealth.StatusFresh
	// RevocationExpiring means the CRL is valid but its nextUpdate falls inside
	// the warning window. This is the state worth alerting on: after nextUpdate
	// passes, relying parties are already failing.
	RevocationExpiring = revocationhealth.StatusExpiring
	// RevocationStale means nextUpdate has passed. Relying parties that check
	// revocation are failing closed right now, or worse, silently soft-failing.
	RevocationStale = revocationhealth.StatusStale
	// RevocationUnreachable means the endpoint did not answer. Deliberately not
	// the same as stale: an unreachable CDP and an expired one need different
	// people, and reporting them alike sends operators to the wrong one.
	RevocationUnreachable = revocationhealth.StatusUnreachable
	// RevocationUnparseable means something answered but it was not a CRL, or
	// its signature did not verify against the issuer. That is a different
	// failure again — usually a proxy or captive portal returning HTML, which
	// looks like success to anything that only checks the status code.
	RevocationUnparseable = revocationhealth.StatusUnparseable
)

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
	targets := intent.Targets
	if len(targets) == 0 {
		// Compatibility for the original CRL-only library surface. Production
		// commands always use bounded Targets and pass ValidateIntent below.
		for _, endpoint := range dedupeEndpoints(intent.Endpoints) {
			targets = append(targets, revocationhealth.Target{
				Key:      crypto.SHA256Hex([]byte("legacy-crl\x00" + endpoint)),
				Protocol: revocationhealth.ProtocolCRL, Endpoint: endpoint,
				IssuerDER: intent.IssuerDER,
			})
		}
	} else if err := revocationhealth.ValidateIntent(intent); err != nil {
		return RevocationReport{}, err
	}
	if len(targets) == 0 {
		return RevocationReport{}, errors.New("relay: revocation probe names no endpoints")
	}
	staleWithin := time.Duration(intent.StaleWithinSeconds) * time.Second

	report := RevocationReport{Healthy: true}
	for _, target := range targets {
		finding := probeRevocationTarget(ctx, client, target, staleWithin)
		if finding.Status != RevocationFresh {
			report.Healthy = false
		}
		report.Findings = append(report.Findings, finding)
	}
	if len(intent.Targets) > 0 {
		if err := revocationhealth.ValidateReport(intent, report); err != nil {
			return RevocationReport{}, err
		}
	}
	return report, nil
}

func probeRevocationTarget(
	ctx context.Context,
	client *http.Client,
	target revocationhealth.Target,
	staleWithin time.Duration,
) RevocationFinding {
	finding := RevocationFinding{TargetKey: target.Key, Protocol: target.Protocol, Endpoint: target.Endpoint}
	parsed, err := url.Parse(target.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "invalid_endpoint"
		finding.Detail = "distribution point is not a usable URL"
		return finding
	}
	// LDAP CDPs exist in AD CS estates and are not fetchable over HTTP. Saying
	// so is better than reporting them unreachable, which would send an operator
	// to check a network path that was never the problem.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "unsupported_scheme"
		finding.Detail = "distribution point uses " + parsed.Scheme + ", which this probe does not fetch"
		return finding
	}
	if len(target.IssuerDER) == 0 && target.CertificateID != "" {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "issuer_unavailable"
		finding.Detail = "the issuer certificate is unavailable, so responder evidence cannot be verified"
		return finding
	}
	if target.Protocol == revocationhealth.ProtocolOCSP {
		return probeOCSP(ctx, client, target, staleWithin, finding)
	}
	return probeCRL(ctx, client, target, staleWithin, finding)
}

func probeCRL(ctx context.Context, client *http.Client, target revocationhealth.Target, staleWithin time.Duration, finding RevocationFinding) RevocationFinding {

	fetchCtx, cancel := context.WithTimeout(ctx, revocationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.Endpoint, nil)
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "request_build_failed"
		finding.Detail = "could not build a request for this distribution point"
		return finding
	}
	started := time.Now()
	resp, err := client.Do(req)
	finding.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "transport_failed"
		finding.Detail = summarizeTransportError(err)
		return finding
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "http_status"
		finding.Detail = fmt.Sprintf("distribution point answered HTTP %d", resp.StatusCode)
		return finding
	}
	body, err := readBoundedBody(resp.Body, revocationBodyLimit)
	if err != nil {
		if errors.Is(err, errRevocationBodyTooLarge) {
			finding.Status = RevocationUnparseable
			finding.DetailCode = "body_too_large"
			finding.Detail = "the CRL exceeds the bounded relay response size"
			return finding
		}
		finding.Status = RevocationUnreachable
		finding.DetailCode = "body_read_failed"
		finding.Detail = "could not read the CRL body"
		return finding
	}

	// Parse and, when an issuer is supplied, VERIFY. A proxy or captive portal
	// returning HTML with a 200 is the case this catches — it looks like
	// success to anything that only checks the status code.
	info, err := crypto.ParseCRL(body, target.IssuerDER)
	if err != nil {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "invalid_crl"
		finding.Detail = "the distribution point answered but did not serve a valid CRL for this issuer"
		return finding
	}
	finding.SignatureVerified = len(target.IssuerDER) > 0
	finding.RevokedCount = len(info.RevokedSerials)
	thisUpdate, nextUpdate := info.ThisUpdate, info.NextUpdate
	finding.ThisUpdate, finding.NextUpdate = &thisUpdate, &nextUpdate

	now := time.Now().UTC()
	switch {
	case thisUpdate.After(now.Add(5 * time.Minute)):
		finding.Status = RevocationUnparseable
		finding.DetailCode = "this_update_future"
		finding.Detail = "the signed CRL thisUpdate is implausibly far in the future"
	case nextUpdate.IsZero():
		// A CRL with no nextUpdate never expires by its own terms, which sounds
		// convenient and is not: relying parties cannot tell a current one from
		// one published years ago.
		finding.Status = RevocationUnparseable
		finding.DetailCode = "next_update_missing"
		finding.Detail = "the CRL carries no nextUpdate, so no relying party can tell whether it is current"
	case now.After(nextUpdate):
		finding.Status = RevocationStale
		finding.DetailCode = "next_update_passed"
		finding.Detail = "nextUpdate passed " + now.Sub(nextUpdate).Truncate(time.Second).String() +
			" ago; relying parties checking revocation are failing now"
	case staleWithin > 0 && nextUpdate.Sub(now) <= staleWithin:
		finding.Status = RevocationExpiring
		finding.DetailCode = "next_update_near"
		finding.Detail = "nextUpdate is " + nextUpdate.Sub(now).Truncate(time.Second).String() +
			" away; republish before it passes"
	default:
		finding.Status = RevocationFresh
		finding.DetailCode = "fresh"
		finding.Detail = "nextUpdate is " + nextUpdate.Sub(now).Truncate(time.Second).String() + " away"
	}
	return finding
}

const ocspBodyLimit = 1 << 20

func probeOCSP(ctx context.Context, client *http.Client, target revocationhealth.Target, staleWithin time.Duration, finding RevocationFinding) RevocationFinding {
	if len(target.CertificateDER) == 0 {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "certificate_unavailable"
		finding.Detail = "the representative certificate is unavailable, so an OCSP request cannot be built"
		return finding
	}
	requestDER, err := crypto.BuildOCSPRequest(target.CertificateDER, target.IssuerDER)
	if err != nil {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "request_invalid"
		finding.Detail = "the certificate and issuer cannot form a valid OCSP request"
		return finding
	}
	fetchCtx, cancel := context.WithTimeout(ctx, revocationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodPost, target.Endpoint, bytes.NewReader(requestDER))
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "request_build_failed"
		finding.Detail = "could not build an OCSP request"
		return finding
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	started := time.Now()
	resp, err := client.Do(req)
	finding.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "transport_failed"
		finding.Detail = summarizeTransportError(err)
		return finding
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "http_status"
		finding.Detail = fmt.Sprintf("OCSP responder answered HTTP %d", resp.StatusCode)
		return finding
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/ocsp-response" {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "invalid_content_type"
		finding.Detail = "the responder did not identify its body as an OCSP response"
		return finding
	}
	body, err := readBoundedBody(resp.Body, ocspBodyLimit)
	if err != nil {
		if errors.Is(err, errRevocationBodyTooLarge) {
			finding.Status = RevocationUnparseable
			finding.DetailCode = "body_too_large"
			finding.Detail = "the OCSP response exceeds the bounded relay response size"
			return finding
		}
		finding.Status = RevocationUnreachable
		finding.DetailCode = "body_read_failed"
		finding.Detail = "could not read the OCSP response"
		return finding
	}
	info, err := crypto.ParseOCSPResponse(body, target.IssuerDER)
	if err != nil {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "invalid_ocsp"
		finding.Detail = "the endpoint answered but did not serve a valid signed OCSP response for this issuer"
		return finding
	}
	finding.SignatureVerified = true
	finding.ResponseStatus = info.Status
	finding.ResponderSubject = info.ResponderSubject
	thisUpdate, nextUpdate := info.ThisUpdate.UTC(), info.NextUpdate.UTC()
	finding.ThisUpdate, finding.NextUpdate = &thisUpdate, &nextUpdate
	now := time.Now().UTC()
	switch {
	case !strings.EqualFold(info.Serial, target.CertificateSerial):
		finding.Status = RevocationUnparseable
		finding.DetailCode = "serial_mismatch"
		finding.Detail = "the signed OCSP response is for a different certificate serial"
	case thisUpdate.After(now.Add(5 * time.Minute)):
		finding.Status = RevocationUnparseable
		finding.DetailCode = "this_update_future"
		finding.Detail = "the signed OCSP response thisUpdate is implausibly far in the future"
	case info.Status != crypto.OCSPGood && info.Status != crypto.OCSPRevoked:
		finding.Status = RevocationUnparseable
		finding.DetailCode = "ocsp_unknown"
		finding.Detail = "the OCSP responder returned unknown for an inventoried certificate"
	case nextUpdate.IsZero():
		finding.Status = RevocationUnparseable
		finding.DetailCode = "next_update_missing"
		finding.Detail = "the OCSP response carries no nextUpdate, so freshness cannot be monitored"
	case now.After(nextUpdate):
		finding.Status = RevocationStale
		finding.DetailCode = "next_update_passed"
		finding.Detail = "OCSP nextUpdate has passed; clients checking revocation may fail or soft-fail"
	case staleWithin > 0 && nextUpdate.Sub(now) <= staleWithin:
		finding.Status = RevocationExpiring
		finding.DetailCode = "next_update_near"
		finding.Detail = "OCSP nextUpdate is inside the warning window"
	default:
		finding.Status = RevocationFresh
		finding.DetailCode = "fresh"
		finding.Detail = "the signed OCSP response is current"
	}
	return finding
}

var errRevocationBodyTooLarge = errors.New("relay: revocation response body exceeds limit")

func readBoundedBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errRevocationBodyTooLarge
	}
	return data, nil
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
const KindRevocationProbe = revocationhealth.JobKind

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
