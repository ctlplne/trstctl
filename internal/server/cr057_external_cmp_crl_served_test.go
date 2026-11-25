// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/protocols/cmp"
)

func TestCR057ServedCMPExternalAnchorNeedsCurrentIssuerCRL(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "CR-057 external client CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deviceKey.Destroy)
	const name = "device-cr057"
	deviceCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceDER, err := crypto.SignLeafFromCSR(caDER, caKey, deviceCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	devicePKCS8, err := deviceKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	deviceInfo, err := certinfo.Inspect(deviceDER)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(t.TempDir(), "external-client-ca.crl.pem")
	writeCRL := func(revoked []crypto.RevokedSerial, thisUpdate, nextUpdate time.Time) {
		t.Helper()
		der, err := crypto.CreateCRL(caDER, caKey, revoked, 1, thisUpdate, nextUpdate)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	writeCRL(nil, now.Add(-time.Minute), now.Add(time.Hour))
	h := newServedHarness(t, config.Protocols{
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, caDER),
		CMPClientCRLFile:         crlPath,
	})
	registerServedTenant(t, h, "CR-057 external CMP CA")
	served := tenantCtxHandler(h.srv.protocols.cmp, func(ctx context.Context) context.Context { return cmp.WithTenant(ctx, servedTestTenant) })
	request := func(txn string, handler http.Handler) int {
		t.Helper()
		newKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer newKey.Destroy()
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, newKey)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := crypto.BuildCMPRequest(csr, deviceDER, devicePKCS8, []byte(txn), []byte("cr057-nonce-"+txn))
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/cmp", bytes.NewReader(msg)))
		return rec.Code
	}
	if status := request("good", served); status != http.StatusOK {
		t.Fatalf("current issuer CRL rejected good external protection certificate: HTTP %d", status)
	}
	writeCRL([]crypto.RevokedSerial{{Serial: deviceInfo.SerialNumber, RevokedAt: now, Reason: 1}}, now.Add(-time.Minute), now.Add(time.Hour))
	if status := request("revoked", served); status != http.StatusForbidden {
		t.Fatalf("issuer-revoked external protection certificate: HTTP %d, want 403", status)
	}
	writeCRL(nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if status := request("stale", served); status != http.StatusForbidden {
		t.Fatalf("stale issuer CRL: HTTP %d, want 403", status)
	}
	sp := &servedProtocols{}
	cfg := config.Protocols{CMP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, caDER)}
	if err := h.srv.buildServedCMP(cfg, servedTestTenant, h.srv.newProtocolIssuer(), h.srv.protoRACertDER, h.srv.protoRAKeyPKCS8, nil, sp); err != nil {
		t.Fatal(err)
	}
	missingCRL := tenantCtxHandler(sp.cmp, func(ctx context.Context) context.Context { return cmp.WithTenant(ctx, sp.cmpTenant) })
	if status := request("missing", missingCRL); status != http.StatusForbidden {
		t.Fatalf("missing issuer CRL: HTTP %d, want 403", status)
	}
}
