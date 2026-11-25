// SPDX-License-Identifier: BUSL-1.1

package server

// R1 review S1a-L2 reproduction (review-2026-11): a revoked CMP protection
// certificate must not authenticate a new enrollment.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/protocols/cmp"
)

func TestR1S1aCMPRevokedProtectionIdentityIsRefused(t *testing.T) {
	ctx := context.Background()
	// 1. A device enrolls once through the stock served CMP mount (its own
	//    self-signed bootstrap certificate is the configured anchor, exactly as
	//    TestServedCMPEndToEnd) and receives D1 from the served issuing CA.
	bootCertDER, deviceKeyPKCS8, csrDER := newSCEPClient(t, "device-r1s1a")
	h := newServedHarness(t, config.Protocols{
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, bootCertDER),
	})
	registerServedTenant(t, h, "R1 S1a CMP revocation tenant")
	first, err := crypto.BuildCMPRequest(csrDER, bootCertDER, deviceKeyPKCS8, []byte("r1s1a-txn-1"), []byte("r1s1a-nonce-0001"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first CMP enrollment status %d: %s", resp.StatusCode, reply)
	}
	d1, err := crypto.ParseCMPResponse(reply)
	if err != nil {
		t.Fatal(err)
	}

	// 2. The operator lets devices renew their own served certificates over CMP:
	//    the served issuing CA is the protection anchor (cmp.go:141-146, "a device
	//    can renew or re-shape its own identity"). Build that mount exactly as
	//    production does (buildServedCMP).
	caDER := caCertDER(t, h.caPEM)
	issuer := h.srv.newProtocolIssuer()
	sp := &servedProtocols{}
	renewCfg := config.Protocols{
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, caDER),
	}
	if err := h.srv.buildServedCMP(renewCfg, servedTestTenant, issuer, h.srv.protoRACertDER, h.srv.protoRAKeyPKCS8, nil, sp); err != nil {
		t.Fatal(err)
	}
	handler := tenantCtxHandler(sp.cmp, func(ctx context.Context) context.Context { return cmp.WithTenant(ctx, sp.cmpTenant) })
	renew := func(txn string) (int, []byte) {
		t.Helper()
		newKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256) // the thief's fresh key
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(newKey.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-r1s1a"}, newKey)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := crypto.BuildCMPRequest(csr, d1, deviceKeyPKCS8, []byte(txn), []byte("r1s1a-nonce-"+txn))
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/cmp", bytes.NewReader(msg)))
		return rec.Code, rec.Body.Bytes()
	}

	// Baseline: while D1 is good, a renewal protected by D1 is served.
	if code, body := renew("r1s1a-txn-2"); code != http.StatusOK {
		t.Fatalf("baseline renewal protected by D1 (not revoked) status %d: %s", code, body)
	}

	// 3. D1's key is reported stolen: the platform revokes D1 (keyCompromise).
	info, err := certinfo.Inspect(d1)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.RevokeProtocolLeaf(ctx, servedTestTenant, "cmp", info.SHA256Fingerprint, info.SerialNumber, 1, d1); err != nil {
		t.Fatalf("revoke D1: %v", err)
	}
	if st := servedOCSPStatus(t, h.srv, h.tenant, d1, h.caPEM); st != "revoked" {
		t.Fatalf("D1 OCSP status after revocation = %q, want revoked", st)
	}

	// 4. A revoked credential must not authenticate a new enrollment.
	if code, body := renew("r1s1a-txn-3"); code == http.StatusOK {
		issued, perr := crypto.ParseCMPResponse(body)
		serial := ""
		if perr == nil {
			if leaf, ierr := certinfo.Inspect(issued); ierr == nil {
				serial = leaf.SerialNumber
			}
		}
		t.Fatalf("CMP issued a NEW certificate (serial %s) for a fresh key under a request protected by D1 (serial %s), which the platform revoked for keyCompromise and whose OCSP status is revoked", serial, info.SerialNumber)
	}
}
