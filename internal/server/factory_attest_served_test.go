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
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// P12-L1: a factory batch that pins device attestation roots records each
// birth's device attestation when the journal reconciles — checked again
// against the batch's roots, not taken from the station — and enrolls on
// first boot only the births whose attestation verified. An attested device
// enrolls; a birth whose journal entry carries no attestation, and one whose
// attestation was made for another device, are recorded unattested and
// refused at first boot. Roots that are not CA certificates are refused when
// the batch is created.
func TestServedFactoryBatchEnrollsOnlyAttestedDevicesP12L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	ctx := context.Background()
	station := mintFactoryStation(t, h)
	now := time.Now().UTC()
	vendorA, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	vendorB, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	batchBody := func(roots []string) map[string]any {
		return map[string]any{"delegation_id": station.delegationID, "label": "line 1, attested lot", "quota": 5, "birth_ttl_seconds": 3600,
			"device_attestation_roots_pem": roots}
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "p12l1-bad-roots",
		batchBody([]string{"not a certificate"})); code != http.StatusBadRequest {
		t.Fatalf("a batch whose roots are no certificates = %d %s", code, body)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "p12l1-batch",
		batchBody([]string{string(vendorA.RootPEM()), string(vendorB.RootPEM())}))
	var batch struct {
		ID    string   `json:"id"`
		Roots []string `json:"device_attestation_roots_pem"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &batch) != nil || batch.ID == "" || len(batch.Roots) != 2 {
		t.Fatalf("create the attested batch = %d %s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/factory-batches/"+batch.ID+"/manifest", station.operator, "", nil)
	var manifest struct {
		Roots []string `json:"device_attestation_roots_pem"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &manifest) != nil || len(manifest.Roots) != 2 {
		t.Fatalf("the manifest gives the station the roots = %d %s", code, body)
	}

	// The station certifies each device's own TPM key; the journal carries the
	// device's attestation and CSR where the line made one.
	type attestedDevice struct {
		name     string
		birthKey *crypto.LockedSigner
		birth    certinfo.Info
	}
	journal := map[string]any{"host": "line-1-station", "batch_id": batch.ID, "certificates_pem": []string{}, "attestations": []map[string]any{}}
	issue := func(identity *deviceattesttest.TPMIdentity, name, attestedFor string) attestedDevice {
		t.Helper()
		csrDER, err := identity.CSRDERFor(name)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, station.delegationPEM, station.handle, station.provider,
			crypto.EdgeLeafRequest{CommonName: name, TTL: time.Hour, CSRDER: csrDER, ClientAuthOnly: true}, now)
		if err != nil {
			t.Fatalf("birth certificate for %s: %v", name, err)
		}
		journal["certificates_pem"] = append(journal["certificates_pem"].([]string), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.CertificateDER})))
		if attestedFor != "" {
			credential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, deviceattest.FactoryAttestationSegment(batch.ID, attestedFor), csrDER))
			if err != nil {
				t.Fatal(err)
			}
			journal["attestations"] = append(journal["attestations"].([]map[string]any), map[string]any{
				"certificate_sha256": crypto.SHA256Hex(leaf.CertificateDER),
				"csr_pem":            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
				"credential":         json.RawMessage(credential),
			})
		}
		keyPEM, err := identity.CredentialKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		key, err := crypto.LockedKeyFromPKCS8PEM(keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		info, err := certinfo.Inspect(leaf.CertificateDER)
		if err != nil {
			t.Fatal(err)
		}
		return attestedDevice{name: name, birthKey: key, birth: info}
	}
	names := func(i int) string { return "sn-a" + strconv.Itoa(i) + "." + station.permittedNames }
	attested := issue(vendorA, names(1), names(1))
	missing := issue(vendorB, names(2), "")
	misbound := issue(vendorB, names(3), names(1))

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches/"+batch.ID+"/reconcile", station.operator, "p12l1-reconcile", journal)
	var reconciled struct {
		Recorded   int `json:"recorded"`
		Unattested int `json:"unattested"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &reconciled) != nil || reconciled.Recorded != 3 || reconciled.Unattested != 2 {
		t.Fatalf("reconcile = %d %s; want three recorded, two of them unattested", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/factory-batches/"+batch.ID, station.operator, "", nil)
	var detail struct {
		Unattested int `json:"unattested"`
		Births     []struct {
			DeviceName  string `json:"device_name"`
			Attestation string `json:"attestation"`
		} `json:"births"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &detail) != nil || detail.Unattested != 2 {
		t.Fatalf("batch detail = %d %s", code, body)
	}
	byName := map[string]string{}
	for _, b := range detail.Births {
		byName[b.DeviceName] = b.Attestation
	}
	if byName[attested.name] != "verified" || byName[missing.name] != "missing" || byName[misbound.name] != "refused" {
		t.Fatalf("birth attestations = %v", byName)
	}

	// First boot: the attested device enrolls; the others are refused.
	controlPlane := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(controlPlane.Close)
	enroll := func(d attestedDevice) (int, string) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: d.name, DNSNames: []string{d.name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		token, err := crypto.SignJWT(d.birthKey, d.birth.SHA256Fingerprint, FactoryProofClaims{Subject: d.name, Purpose: factoryPurposeFirstBoot,
			CSRSHA256: crypto.SHA256Hex(csr), IssuedAt: time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, controlPlane.URL+"/.well-known/est/factory/simpleenroll", bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(csr))))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := controlPlane.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(raw)
	}
	for _, d := range []attestedDevice{missing, misbound} {
		if status, msg := enroll(d); status != http.StatusForbidden || !strings.Contains(msg, "device attestation") {
			t.Fatalf("first boot of %s = %d %s; want refused for its attestation", d.name, status, msg)
		}
	}
	if status, msg := enroll(attested); status != http.StatusOK {
		t.Fatalf("first boot of the attested device = %d %s", status, msg)
	}
	t.Logf("P12L1_ATTESTED_BIRTH_OK batch=%s verified=%s unattested=%d", batch.ID, attested.name, detail.Unattested)
}
