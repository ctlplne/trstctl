// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// servedACMChainDouble is an ACM-compatible double whose GetCertificate
// answers each certificate with its chain, as ACM does.
func servedACMChainDouble(certs map[string][2]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "CertificateManager.ListCertificates":
			var summaries []map[string]string
			for arn := range certs {
				summaries = append(summaries, map[string]string{"CertificateArn": arn})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": summaries})
		case "CertificateManager.GetCertificate":
			var req struct{ CertificateArn string }
			_ = json.Unmarshal(body, &req)
			pair := certs[req.CertificateArn]
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": pair[0], "CertificateChain": pair[1]})
		default:
			http.Error(w, "unexpected target", http.StatusBadRequest)
		}
	}))
}

// runServedACMDiscovery creates an ACM cloud certificate source against the
// double and runs it to completion.
func runServedACMDiscovery(t *testing.T, h *servedHarness, acm *httptest.Server, token, name string) {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", token, map[string]any{
		"name": name, "kind": "cloud_certificate",
		"config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- fabricated fixture credential references; no value is real (CWE-798)
			"provider": "aws-acm", "region": "us-east-1", "endpoint": acm.URL, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, acm.URL)},
			"access_key_id_ref":    "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("create the ACM source: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", token, map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("start the ACM run: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestServedCloudCertificateRevocationIsProbedB13L1 is B13-L1: with
// probe_scanned_certificates on, a cloud listing keeps the certificate the
// provider returned, when its bytes are the certificate it listed, and the
// issuers returned after it. Revocation health then probes that certificate's
// own serial at its CRL distribution point and OCSP responder against the
// returned issuer, as it does for a TLS sweep's (A211). A listing whose bytes
// are another certificate keeps nothing (TestKeptCloudCertificateBytesB13L1),
// and with the setting off a listing keeps no bytes.
func TestServedCloudCertificateRevocationIsProbedB13L1(t *testing.T) {
	ctx := t.Context()
	t.Setenv("TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "SECRET")
	f := newScannedRevocationFixture(t)
	acm := servedACMChainDouble(map[string][2]string{
		"arn:aws:acm:us-east-1:111111111111:certificate/b13l1-edge": {certificatePEM(f.leafDER), certificatePEM(f.caDER)},
	})
	t.Cleanup(acm.Close)
	allow := allowOutboundEnvCredentialRefs("env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY")

	// Revocation probes run on an enrolled network agent.
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindRevocationProbe}, allow,
		func(d *Deps) { d.ProbeScannedCertificates = true })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "b13l1-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read", string(authz.PrivateEgress))
	runServedACMDiscovery(t, h.servedHarness, acm, token, "aws-acm-b13l1")
	stored, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, f.leaf.SHA256Fingerprint)
	if err != nil || !bytes.Equal(stored.CertificateDER, f.leafDER) || stored.Source != "discovery:cloud:aws-acm" {
		t.Fatalf("the cloud certificate kept %d bytes, source %q (%v); want the leaf ACM returned", len(stored.CertificateDER), stored.Source, err)
	}
	chains, err := h.store.ScannedCertificateChains(ctx, h.tenant, []string{f.leaf.SHA256Fingerprint})
	if err != nil || len(chains[f.leaf.SHA256Fingerprint]) != 1 || !bytes.Equal(chains[f.leaf.SHA256Fingerprint][0].CertificateDER, f.caDER) {
		t.Fatalf("kept chain = %+v err=%v; want the issuer ACM returned", chains, err)
	}
	if _, err := h.srv.RunRevocationHealthOnce(ctx); err != nil {
		t.Fatal(err)
	}
	_, probe := revocationProbeOutboxAUD38(t, ctx, h)
	targets := map[string]revocationhealth.Target{}
	for _, target := range probe.Targets {
		if target.Scope == revocationhealth.ScopeCertificate {
			targets[target.Protocol] = target
		}
	}
	for _, protocol := range []string{revocationhealth.ProtocolCRL, revocationhealth.ProtocolOCSP} {
		target, ok := targets[protocol]
		if !ok || !bytes.Equal(target.IssuerDER, f.caDER) || target.CertificateSerial != f.leaf.SerialNumber || target.CertificateID != stored.ID {
			t.Fatalf("certificate-scope %s target = %+v; want the cloud certificate's own serial against its returned issuer (all: %+v)",
				protocol, target, probe.Targets)
		}
	}

	// With the setting off a listing keeps no bytes.
	other := newScannedRevocationFixture(t)
	listed := servedACMChainDouble(map[string][2]string{
		"arn:aws:acm:us-east-1:111111111111:certificate/b13l1-off": {certificatePEM(other.leafDER), certificatePEM(other.caDER)},
	})
	t.Cleanup(listed.Close)
	off := newOperatingServedHarness(t, config.Protocols{}, allow)
	offToken := seedScopedToken(t, off.store, off.tenant, "discovery:read", "discovery:write", "certs:read", string(authz.PrivateEgress))
	runServedACMDiscovery(t, off, listed, offToken, "aws-acm-b13l1-off")
	if kept, err := off.store.GetCertificateByFingerprint(ctx, off.tenant, other.leaf.SHA256Fingerprint); err != nil || len(kept.CertificateDER) != 0 {
		t.Fatalf("with the setting off a cloud listing kept %d bytes (%v)", len(kept.CertificateDER), err)
	}
}
