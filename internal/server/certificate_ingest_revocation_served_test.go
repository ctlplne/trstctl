// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// B13-2, found proving A107 on the lab: a certificate imported with
// `certificates ingest` kept only its metadata. Revocation health reads each
// certificate's CRL and OCSP URLs and its issuer from the stored bytes, so it
// never probed an imported certificate's endpoints — the internal AD CS
// distribution points the relay design exists for. Ingest now keeps the
// public certificate it was given, still recorded as an observation.
func TestServedImportedCertificatesFeedRevocationHealth(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "b13-2-test", Status: "active"}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Imported Corp Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "imported.corp.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	const cdp = "http://pki.corp.example/certenroll/imported-corp-ca.crl"
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{CRLDistributionPoints: []string{cdp}})
	if err != nil {
		t.Fatal(err)
	}

	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	for i, der := range [][]byte{caDER, leafDER} {
		body := map[string]any{"pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
		if status, resp := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/certificates", token, fmt.Sprintf("b13-2-ingest-%d", i), body); status != http.StatusCreated {
			t.Fatalf("ingest %d = %d %s", i, status, resp)
		}
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leafInfo.SHA256Fingerprint)
	if err != nil || !bytes.Equal(stored.CertificateDER, leafDER) {
		t.Fatalf("imported leaf kept %d DER bytes (%v), want the %d bytes ingested", len(stored.CertificateDER), err, len(leafDER))
	}

	if n, err := h.srv.RunRevocationHealthOnce(ctx); err != nil || n != 1 {
		t.Fatalf("scheduler queued %d endpoints (%v), want the imported leaf's distribution point", n, err)
	}
	_, intent := revocationProbeOutboxAUD38(t, ctx, h)
	if len(intent.Targets) != 1 || intent.Targets[0].Endpoint != cdp || !bytes.Equal(intent.Targets[0].IssuerDER, caDER) {
		t.Fatalf("queued targets = %+v, want the imported leaf's CDP verified against the imported CA", intent.Targets)
	}
}
