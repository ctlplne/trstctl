// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/enrollproxy"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/store"
)

// factoryStation is a TPM-attested edge delegation a factory station issues
// birth certificates under, with the station key's handle and provider.
type factoryStation struct {
	operator       string
	delegationID   string
	delegationPEM  []byte
	delegationDER  []byte
	handle         crypto.EdgeCAKeyHandle
	provider       crypto.EdgeCAKeyProvider
	permittedNames string
}

// mintFactoryStation mints a delegation for a station the way the edge served
// test does: a signer-backed root from a ceremony, an opted-in segment and a
// TPM-attested station key.
func mintFactoryStation(t *testing.T, h *servedHarness) factoryStation {
	t.Helper()
	ctx := context.Background()
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "factory-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "factory-custodian-one", []string{"issuers:write", "issuers:read"})
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "factory-custodian-two", []string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "factory parent", "max_path_len": 1, "ttl_seconds": int64((90 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.test"}, "extended_key_usages": []string{"clientAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "p12-root-ceremony")
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "p12-root-approve-1")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "p12-root-approve-2")
	root := createRootCA(t, h, operator, ceremony.ID, rootSpec, "p12-root-create")
	segment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{Name: "factory-line-1", Ranges: []string{"10.77.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	provider := identity.EdgeCAKeyProvider()
	handle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "factory-line-1-generation-1", "line 1 station", crypto.ECDSAP256, provider)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, csrDER))
	if err != nil {
		t.Fatal(err)
	}
	const names = "devices.example.test"
	if code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, "p12-segment", map[string]any{
		"enabled": true, "attestation_roots_pem": []string{string(identity.RootPEM())}, "permitted_dns_domains": []string{names},
	}); code != http.StatusOK {
		t.Fatalf("opt the line's segment in = %d %s", code, body)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, "p12-mint", map[string]any{
		"segment_id": segment.ID, "ca_id": root.ID, "host": "line-1-station", "common_name": "line 1 station",
		"ttl_seconds": 3600, "csr_der": csrDER, "attestation_credential_json": credential,
	})
	if code != http.StatusCreated {
		t.Fatalf("mint the station's delegation = %d %s", code, body)
	}
	var minted struct {
		ID             string `json:"id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &minted); err != nil || minted.ID == "" {
		t.Fatalf("decode the delegation: %v %s", err, body)
	}
	block, _ := pem.Decode([]byte(minted.CertificatePEM))
	return factoryStation{operator: operator, delegationID: minted.ID, delegationPEM: []byte(minted.CertificatePEM),
		delegationDER: block.Bytes, handle: handle, provider: provider, permittedNames: names}
}

type factoryDevice struct {
	name     string
	birthKey *crypto.LockedSigner
	birthDER []byte
	birth    certinfo.Info
}

// P12: factory provisioning. An offline station issues a batch within its
// quota (the shipped station refuses one more; here a tampered one issues
// it), the journal reconciles when it reconnects with the extra birth
// certificate recorded as over-production, a device with a birth certificate
// gets its operational certificate on first boot over EST through the relay
// enrollment proxy, and it renews in the field the same way.
func TestServedFactoryBatchFirstBootAndRenewalThroughTheRelayP12(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	ctx := context.Background()
	station := mintFactoryStation(t, h)

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "p12-batch", map[string]any{
		"delegation_id": station.delegationID, "label": "line 1, lot 7", "quota": 2, "birth_ttl_seconds": 3600,
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
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/factory-batches/"+batch.ID+"/manifest", station.operator, "", nil)
	var manifest struct {
		DelegationFingerprint string `json:"delegation_fingerprint"`
		Quota                 int    `json:"quota"`
		ESTPath               string `json:"est_path"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &manifest) != nil || manifest.Quota != 2 ||
		!strings.EqualFold(manifest.DelegationFingerprint, crypto.SHA256Hex(station.delegationDER)) || manifest.ESTPath != "/.well-known/est/factory" {
		t.Fatalf("manifest = %d %s", code, body)
	}

	// The station certifies each device's own request with its TPM-held key.
	issueBirth := func(name string) factoryDevice {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, station.delegationPEM, station.handle, station.provider,
			crypto.EdgeLeafRequest{CommonName: name, TTL: time.Hour, CSRDER: csr, ClientAuthOnly: true}, time.Now().UTC())
		if err != nil {
			t.Fatalf("birth certificate for %s: %v", name, err)
		}
		info, err := certinfo.Inspect(leaf.CertificateDER)
		if err != nil {
			t.Fatal(err)
		}
		return factoryDevice{name: name, birthKey: key, birthDER: leaf.CertificateDER, birth: info}
	}
	devices := []factoryDevice{}
	journal := map[string]any{"host": "line-1-station", "batch_id": batch.ID, "certificates_pem": []string{}}
	for i := 1; i <= 3; i++ {
		d := issueBirth(fmt.Sprintf("sn-%04d.%s", i, station.permittedNames))
		devices = append(devices, d)
		journal["certificates_pem"] = append(journal["certificates_pem"].([]string), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.birthDER})))
	}
	type reconciled struct {
		Recorded  int `json:"recorded"`
		OverQuota int `json:"over_quota"`
		Already   int `json:"already"`
		Rejected  int `json:"rejected"`
	}
	reconcile := func(key string) reconciled {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches/"+batch.ID+"/reconcile", station.operator, key, journal)
		var out reconciled
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("reconcile = %d %s", code, body)
		}
		return out
	}
	if got := reconcile("p12-reconcile"); got != (reconciled{Recorded: 2, OverQuota: 1}) {
		t.Fatalf("first reconcile = %+v; want two within the quota and one over it", got)
	}
	if got := reconcile("p12-reconcile-again"); got != (reconciled{Already: 3}) {
		t.Fatalf("replayed journal = %+v; want everything already recorded", got)
	}

	// First boot and renewal go through the relay enrollment proxy: the
	// control plane over TLS, the proxy on the device's segment.
	controlPlane := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(controlPlane.Close)
	proxy, err := enrollproxy.New(controlPlane.URL, controlPlane.Client())
	if err != nil {
		t.Fatal(err)
	}
	segment := httptest.NewServer(proxy)
	t.Cleanup(segment.Close)
	enrollBound := func(op string, signer *crypto.LockedSigner, kid, name, purpose string, issuedAt time.Time, csr, proofFor []byte) (int, []byte, string) {
		t.Helper()
		token, err := crypto.SignJWT(signer, kid, FactoryProofClaims{Subject: name, Purpose: purpose, CSRSHA256: crypto.SHA256Hex(proofFor), IssuedAt: issuedAt.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, segment.URL+"/.well-known/est/factory/"+op, bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(csr))))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
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
	enroll := func(op string, signer *crypto.LockedSigner, kid, name, purpose string, issuedAt time.Time, csr []byte) (int, []byte, string) {
		t.Helper()
		return enrollBound(op, signer, kid, name, purpose, issuedAt, csr, csr)
	}
	operationalCSR := func(name string) (*crypto.LockedSigner, []byte) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return key, csr
	}
	now := time.Now()
	first, second, over := devices[0], devices[1], devices[2]

	// Refusals first: nothing past the quota, nobody else's proof, nothing stale.
	_, csr := operationalCSR(over.name)
	if status, _, msg := enroll("simpleenroll", over.birthKey, over.birth.SHA256Fingerprint, over.name, factoryPurposeFirstBoot, now, csr); status != http.StatusForbidden || !strings.Contains(msg, "over-production") {
		t.Fatalf("first boot past the quota = %d %s", status, msg)
	}
	_, csr = operationalCSR(first.name)
	if status, _, msg := enroll("simpleenroll", second.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now, csr); status != http.StatusUnauthorized {
		t.Fatalf("a proof signed by another device's key = %d %s", status, msg)
	}
	if status, _, msg := enroll("simpleenroll", first.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now.Add(-10*time.Minute), csr); status != http.StatusUnauthorized {
		t.Fatalf("a stale proof = %d %s", status, msg)
	}
	_, otherNameCSR := operationalCSR(second.name)
	if status, _, msg := enroll("simpleenroll", first.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now, otherNameCSR); status != http.StatusForbidden {
		t.Fatalf("a request naming another device = %d %s", status, msg)
	}
	_, swappedCSR := operationalCSR(first.name)
	if status, _, msg := enrollBound("simpleenroll", first.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now, swappedCSR, csr); status != http.StatusUnauthorized {
		t.Fatalf("a proof for another request = %d %s", status, msg)
	}

	// First boot.
	opKey, opCSR := operationalCSR(first.name)
	status, opDER, msg := enroll("simpleenroll", first.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now, opCSR)
	if status != http.StatusOK {
		t.Fatalf("first boot = %d %s", status, msg)
	}
	operational, err := certinfo.Inspect(opDER)
	if err != nil || operational.CommonName != first.name {
		t.Fatalf("operational certificate %+v %v", operational, err)
	}
	_, againCSR := operationalCSR(first.name)
	if status, _, msg := enroll("simpleenroll", first.birthKey, first.birth.SHA256Fingerprint, first.name, factoryPurposeFirstBoot, now, againCSR); status != http.StatusConflict {
		t.Fatalf("a second first boot = %d %s", status, msg)
	}

	// Renewal in the field, with the operational key.
	_, renewCSR := operationalCSR(first.name)
	status, renewedDER, msg := enroll("simplereenroll", opKey, operational.SHA256Fingerprint, first.name, factoryPurposeRenewal, now, renewCSR)
	if status != http.StatusOK {
		t.Fatalf("renewal = %d %s", status, msg)
	}
	renewed, err := certinfo.Inspect(renewedDER)
	if err != nil || renewed.CommonName != first.name || renewed.SerialNumber == operational.SerialNumber {
		t.Fatalf("renewed certificate %+v %v", renewed, err)
	}
	_, staleCSR := operationalCSR(first.name)
	if status, _, msg := enroll("simplereenroll", opKey, operational.SHA256Fingerprint, first.name, factoryPurposeRenewal, now, staleCSR); status != http.StatusUnauthorized {
		t.Fatalf("a renewal with the superseded certificate = %d %s", status, msg)
	}

	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/factory-batches/"+batch.ID, station.operator, "", nil)
	var detail struct {
		Recorded  int `json:"recorded"`
		OverQuota int `json:"over_quota"`
		Enrolled  int `json:"enrolled"`
		Births    []struct {
			DeviceName        string `json:"device_name"`
			OverQuota         bool   `json:"over_quota"`
			Enrolled          bool   `json:"enrolled"`
			OperationalSerial string `json:"operational_serial"`
			Renewals          int    `json:"renewals"`
		} `json:"births"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &detail) != nil || detail.Recorded != 3 || detail.OverQuota != 1 || detail.Enrolled != 1 || len(detail.Births) != 3 {
		t.Fatalf("batch detail = %d %s", code, body)
	}
	for _, b := range detail.Births {
		switch b.DeviceName {
		case first.name:
			if !b.Enrolled || b.Renewals != 1 || !strings.EqualFold(b.OperationalSerial, renewed.SerialNumber) {
				t.Fatalf("enrolled device = %+v", b)
			}
		case over.name:
			if !b.OverQuota || b.Enrolled {
				t.Fatalf("over-production = %+v", b)
			}
		}
	}

	// A revoked station is no longer trusted for first boot.
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations/"+station.delegationID+"/revoke", station.operator,
		"p12-revoke", map[string]any{"reason": "line decommissioned"}); code != http.StatusOK {
		t.Fatalf("revoke the station = %d %s", code, body)
	}
	_, csr = operationalCSR(second.name)
	if status, _, msg := enroll("simpleenroll", second.birthKey, second.birth.SHA256Fingerprint, second.name, factoryPurposeFirstBoot, now, csr); status != http.StatusForbidden || !strings.Contains(msg, "revoked") {
		t.Fatalf("first boot under a revoked station = %d %s", status, msg)
	}
}
