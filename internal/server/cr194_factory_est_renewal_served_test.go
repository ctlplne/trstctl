// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// CR-194: factory EST renewal authenticates with a proof
// signed by the device's current operational key and never asks whether that
// operational certificate was revoked. A device certificate revoked for
// keyCompromise still renews into a fresh, valid certificate.
func TestCR194FactoryRenewalRefusesRevokedOperationalCertificate(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	ctx := context.Background()
	station := mintFactoryStation(t, h)
	owner := seedScopedToken(t, h.store, servedTestTenant, "certs:issue", "certs:read", "identities:write")

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "r1-sts10b-batch", map[string]any{
		"delegation_id": station.delegationID, "label": "r1 stitch", "quota": 1, "birth_ttl_seconds": 3600,
	})
	if code != http.StatusCreated {
		t.Fatalf("create the batch = %d %s", code, body)
	}
	var batch struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &batch); err != nil || batch.ID == "" {
		t.Fatalf("decode the batch: %v %s", err, body)
	}
	name := "sn-r1-0001." + station.permittedNames
	birthKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(birthKey.Destroy)
	birthCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, birthKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, station.delegationPEM, station.handle, station.provider,
		crypto.EdgeLeafRequest{CommonName: name, TTL: time.Hour, CSRDER: birthCSR, ClientAuthOnly: true}, time.Now().UTC())
	if err != nil {
		t.Fatalf("birth certificate: %v", err)
	}
	birth, err := certinfo.Inspect(leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	journal := map[string]any{"host": "r1-station", "batch_id": batch.ID,
		"certificates_pem": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.CertificateDER}))}}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches/"+batch.ID+"/reconcile", station.operator, "r1-sts10b-reconcile", journal); code != http.StatusOK {
		t.Fatalf("reconcile = %d %s", code, body)
	}

	controlPlane := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(controlPlane.Close)
	enroll := func(op string, signer *crypto.LockedSigner, kid, purpose string, csr []byte) (int, []byte, string) {
		t.Helper()
		token, err := crypto.SignJWT(signer, kid, FactoryProofClaims{Subject: name, Purpose: purpose, CSRSHA256: crypto.SHA256Hex(csr), IssuedAt: time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, controlPlane.URL+"/.well-known/est/factory/"+op, bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(csr))))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := controlPlane.Client().Do(req)
		if err != nil {
			t.Fatalf("EST %s: %v", op, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, nil, string(raw)
		}
		p7, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
		if err != nil {
			t.Fatal(err)
		}
		certs, err := crypto.CertsFromPKCS7(p7)
		if err != nil || len(certs) == 0 {
			t.Fatalf("EST %s returned no certificate: %v", op, err)
		}
		return resp.StatusCode, certs[0], ""
	}
	newCSR := func(key *crypto.LockedSigner) []byte {
		t.Helper()
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	newKey := func() *crypto.LockedSigner {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		return key
	}

	// First boot with the birth key.
	opKey := newKey()
	status, opDER, msg := enroll("simpleenroll", birthKey, birth.SHA256Fingerprint, factoryPurposeFirstBoot, newCSR(opKey))
	if status != http.StatusOK {
		t.Fatalf("first boot = %d %s", status, msg)
	}
	operational, err := certinfo.Inspect(opDER)
	if err != nil {
		t.Fatal(err)
	}

	// The operator revokes the device's operational certificate: its key leaked.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/certificates?q="+url.QueryEscape(name), owner, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: %d %s", status, raw)
	}
	var list struct {
		Items []struct {
			ID     string `json:"id"`
			Serial string `json:"serial_number"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, item := range list.Items {
		ids = append(ids, item.ID)
	}
	if len(ids) == 0 {
		t.Fatalf("factory operational certificate not in the inventory: %s", raw)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "r1-sts10b-revoke",
		map[string]any{"certificate_ids": ids, "reason": "keyCompromise"})
	if status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, raw)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, servedTestTenant, IssuingCAID(), strings.ToLower(operational.SerialNumber))
	if err != nil || !found || !issued.Revoked() {
		t.Fatalf("precondition: exact operational issuer+serial is revoked in the tenant CA ledger: found=%t revoked=%t err=%v", found, issued.Revoked(), err)
	}
	inventory, err := h.store.GetCertificateByFingerprint(ctx, servedTestTenant, operational.SHA256Fingerprint)
	if err != nil || inventory.Status != "revoked" || !strings.EqualFold(inventory.Serial, operational.SerialNumber) {
		t.Fatalf("precondition: exact factory operational certificate is revoked in inventory: status=%q serial_matches=%t err=%v",
			inventory.Status, strings.EqualFold(inventory.Serial, operational.SerialNumber), err)
	}

	// Control: the platform knows the key is compromised — a CSR for that same
	// key is refused at issuance.
	control, _, controlMsg := enroll("simplereenroll", opKey, operational.SHA256Fingerprint, factoryPurposeRenewal, newCSR(opKey))
	if control == http.StatusOK {
		t.Fatal("renewal CSR carrying a compromised key was accepted")
	}
	t.Logf("control: renewal CSR carrying the revoked (keyCompromise) key -> HTTP %d %s", control, strings.TrimSpace(controlMsg))

	// Attack: whoever holds the leaked operational key signs a renewal proof
	// with it for a CSR over a fresh key.
	status, renewedDER, msg := enroll("simplereenroll", opKey, operational.SHA256Fingerprint, factoryPurposeRenewal, newCSR(newKey()))
	if status != http.StatusForbidden {
		if status == http.StatusOK {
			renewed, _ := certinfo.Inspect(renewedDER)
			t.Fatalf("CR-194: factory renewal authenticated by the operational certificate revoked for keyCompromise (serial %s) "+
				"was answered 200 with a NEW certificate (serial %s, CN %s, NotAfter %s); want HTTP 403",
				operational.SerialNumber, renewed.SerialNumber, renewed.CommonName, renewed.NotAfter.UTC().Format(time.RFC3339))
		}
		t.Fatalf("renewal with revoked operational certificate = %d %s, want HTTP 403", status, msg)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/certificates?q="+url.QueryEscape(name), owner, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates after refused renewal: %d %s", status, raw)
	}
	var after struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &after); err != nil || len(after.Items) != len(ids) {
		t.Fatalf("refused renewal changed certificate inventory: before=%d after=%d decode=%v", len(ids), len(after.Items), err)
	}
}
