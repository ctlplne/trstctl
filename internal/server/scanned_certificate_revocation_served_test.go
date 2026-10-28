// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

// scannedRevocationFixture is a CA that publishes a CRL and answers OCSP for
// one leaf, served at a loopback TLS listener with the CA after it.
type scannedRevocationFixture struct {
	caDER, leafDER []byte
	leaf           certinfo.Info
	responders     *httptest.Server
	listener       *tlsprobe.ServingTestServer
}

func newScannedRevocationFixture(t *testing.T) scannedRevocationFixture {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "A211 Scanned Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var crlDER, ocspDER []byte
	responders := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crlDER)
		case "/ocsp":
			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(ocspDER)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(responders.Close)
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "scanned.a211.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{
		CRLDistributionPoints: []string{responders.URL + "/crl"},
		OCSPServers:           []string{responders.URL + "/ocsp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err = crypto.CreateCRL(caDER, caKey, []crypto.RevokedSerial{{Serial: leaf.SerialNumber, RevokedAt: now.Add(-time.Minute), Reason: 1}},
		211, now.Add(-time.Minute), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ocspDER, err = crypto.SignOCSPResponse(caDER, caKey, crypto.OCSPRevoked, leaf.SerialNumber,
		now.Add(-time.Minute), now.Add(2*time.Hour), now.Add(-time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := leafKey.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tlsprobe.NewServingTestServerChain([][]byte{leafDER, caDER}, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listener.Close)
	return scannedRevocationFixture{caDER: caDER, leafDER: leafDER, leaf: leaf, responders: responders, listener: listener}
}

// sweepScannedListener queues a relay TLS sweep of the fixture's listener,
// runs it the way the relay does and reports it signed.
func sweepScannedListener(t *testing.T, h *roleHarness, f scannedRevocationFixture, token string) relay.DiscoveryScanIntent {
	t.Helper()
	segment, err := h.srv.orch.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{
		Name: "a211-loopback", Ranges: []string{"127.0.0.1"}, StalenessHours: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, map[string]any{
		"name": "a211-scan", "kind": "network",
		"config": map[string]any{"targets": []string{f.listener.Addr}, "allow_loopback": true, "segment": segment.Name,
			"relay_agent_id": agentRowID(h.tenant, h.agent)},
	})
	if status != http.StatusCreated {
		t.Fatalf("create source = %d %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &source)
	if status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token,
		map[string]any{"source_id": source.ID}); status != http.StatusCreated {
		t.Fatalf("queue run = %d %s", status, body)
	}
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{relay.KindDiscoveryRun}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim sweep = %+v err=%v", claimed, err)
	}
	var intent relay.DiscoveryScanIntent
	if err := json.Unmarshal(claimed.Jobs[0].Payload, &intent); err != nil {
		t.Fatal(err)
	}
	report, err := relay.Sweep(t.Context(), intent)
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("relay sweep = %+v err=%v", report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.client.ReportJobResult(t.Context(), h.report(t, claimed.Jobs[0].JobID, claimed.Jobs[0].Attempt,
		transport.JobOutcomeExecuted, string(encoded), "sha256:a211-relay-sweep"))
	if err != nil || !res.Accepted {
		t.Fatalf("report sweep = %+v err=%v", res, err)
	}
	return intent
}

// A211: with agent_channel.probe_scanned_certificates on, a relay's TLS sweep
// keeps the leaf it found and its served issuer; the scheduler checks that
// certificate's own serial at its CRL distribution point and OCSP responder,
// verified against the served issuer, and the certificate's detail read shows
// the relay's signed answers. The endpoint health list stays endpoint-only.
func TestServedScannedCertificateRevocationIsProbedAgainstItsServedIssuer(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork},
		[]string{relay.KindDiscoveryRun, relay.KindRevocationProbe}, func(d *Deps) { d.ProbeScannedCertificates = true })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a211-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	f := newScannedRevocationFixture(t)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	intent := sweepScannedListener(t, h, f, token)
	if !intent.KeepChain {
		t.Fatal("the sweep did not ask the relay to keep the certificates it finds")
	}
	stored, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, f.leaf.SHA256Fingerprint)
	if err != nil || !bytes.Equal(stored.CertificateDER, f.leafDER) || stored.Source != "discovery:network" {
		t.Fatalf("scanned leaf kept %d bytes, source %q (%v); want the served leaf", len(stored.CertificateDER), stored.Source, err)
	}
	chains, err := h.store.ScannedCertificateChains(ctx, h.tenant, []string{f.leaf.SHA256Fingerprint})
	if err != nil || len(chains[f.leaf.SHA256Fingerprint]) != 1 || !bytes.Equal(chains[f.leaf.SHA256Fingerprint][0].CertificateDER, f.caDER) {
		t.Fatalf("kept chain = %+v err=%v; want the served CA", chains, err)
	}

	if _, err := h.srv.RunRevocationHealthOnce(ctx); err != nil {
		t.Fatal(err)
	}
	_, probe := revocationProbeOutboxAUD38(t, ctx, h)
	certificateTargets := map[string]revocationhealth.Target{}
	for _, target := range probe.Targets {
		if target.Scope == revocationhealth.ScopeCertificate {
			certificateTargets[target.Protocol] = target
		}
	}
	for _, protocol := range []string{revocationhealth.ProtocolCRL, revocationhealth.ProtocolOCSP} {
		target, ok := certificateTargets[protocol]
		if !ok || !bytes.Equal(target.IssuerDER, f.caDER) || target.CertificateSerial != f.leaf.SerialNumber ||
			target.CertificateID != stored.ID {
			t.Fatalf("certificate-scope %s target = %+v; want the scanned leaf's own serial against its served issuer (all: %+v)",
				protocol, target, probe.Targets)
		}
	}

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindRevocationProbe}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim probe = %+v err=%v", claimed, err)
	}
	var claimedIntent revocationhealth.Intent
	if err := json.Unmarshal(claimed.Jobs[0].Payload, &claimedIntent); err != nil {
		t.Fatal(err)
	}
	report, err := relay.ProbeRevocation(ctx, f.responders.Client(), claimedIntent)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Hex(encoded)
	res, err := h.client.ReportJobResult(ctx, h.report(t, claimed.Jobs[0].JobID, claimed.Jobs[0].Attempt,
		transport.JobOutcomeExecuted, string(encoded), digest))
	if err != nil || !res.Accepted {
		t.Fatalf("report probe = %+v err=%v", res, err)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/certificates/"+stored.ID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("certificate detail = %d %s", status, body)
	}
	var detail struct {
		RevocationObservations []struct {
			Protocol          string `json:"protocol"`
			Scope             string `json:"scope"`
			SignatureVerified bool   `json:"signature_verified"`
			CertificateListed *bool  `json:"certificate_listed"`
			ResponseStatus    string `json:"response_status"`
			ObservedByAgentID string `json:"observed_by_agent_id"`
			EvidenceDigest    string `json:"evidence_digest"`
		} `json:"revocation_observations"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	var crlListed, ocspRevoked bool
	for _, observation := range detail.RevocationObservations {
		if observation.Scope != revocationhealth.ScopeCertificate || !observation.SignatureVerified ||
			observation.ObservedByAgentID != agentRowID(h.tenant, h.agent) || observation.EvidenceDigest != digest {
			continue
		}
		crlListed = crlListed || observation.Protocol == revocationhealth.ProtocolCRL && observation.CertificateListed != nil && *observation.CertificateListed
		ocspRevoked = ocspRevoked || observation.Protocol == revocationhealth.ProtocolOCSP && observation.ResponseStatus == crypto.OCSPRevoked
	}
	if !crlListed || !ocspRevoked {
		t.Fatalf("certificate detail lacks the relay's signed answers for its own serial: %s", body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/health", token, nil)
	if status != http.StatusOK || strings.Contains(string(body), `"scope":"certificate"`) {
		t.Fatalf("endpoint health listed certificate checks: %d %s", status, body)
	}
}

// With the setting off a sweep keeps no certificate bytes, so nothing about a
// scanned certificate is probed.
func TestServedScannedCertificatesKeepNoBytesByDefault(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindDiscoveryRun, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a211-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	f := newScannedRevocationFixture(t)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")
	if intent := sweepScannedListener(t, h, f, token); intent.KeepChain {
		t.Fatal("a sweep asked to keep certificate bytes while the setting is off")
	}
	stored, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, f.leaf.SHA256Fingerprint)
	if err != nil || len(stored.CertificateDER) != 0 {
		t.Fatalf("scanned leaf kept %d bytes with the setting off (%v)", len(stored.CertificateDER), err)
	}
	if n, err := h.srv.RunRevocationHealthOnce(ctx); err != nil || n != 0 {
		t.Fatalf("scheduler queued %d endpoints (%v) for a certificate known only from a scan", n, err)
	}
}
