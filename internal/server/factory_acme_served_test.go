// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	acme "trstctl.com/trstctl/internal/protocols/acme"
)

// P12-L2: ACME as a factory device's first-boot path. A stock ACME client
// orders a certificate for the device's name; the served directory offers
// device-attest-01 for it, and the device answers with its birth certificate
// and its birth key's signature over the challenge binding. The order
// finalizes with the device's new key and its certificate is recorded as the
// device's first boot. An answer signed by another key, one from a birth past
// the batch's quota, and a second first boot with another key are refused.
func TestServedFactoryDeviceFirstBootsOverACMEP12L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	station := mintFactoryStation(t, h)
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "p12l2-batch", map[string]any{
		"delegation_id": station.delegationID, "label": "line 1, ACME lot", "quota": 1, "birth_ttl_seconds": 3600,
	})
	var batch struct {
		ID string `json:"id"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &batch) != nil || batch.ID == "" {
		t.Fatalf("create the batch = %d %s", code, body)
	}
	type born struct {
		name     string
		birthKey *crypto.LockedSigner
		birthDER []byte
	}
	birth := func(name string) born {
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
		return born{name: name, birthKey: key, birthDER: leaf.CertificateDER}
	}
	device := birth(fmt.Sprintf("sn-acme-1.%s", station.permittedNames))
	extra := birth(fmt.Sprintf("sn-acme-2.%s", station.permittedNames)) // past the quota of one
	journal := map[string]any{"host": "line-1-station", "batch_id": batch.ID, "certificates_pem": []string{
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: device.birthDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: extra.birthDER})),
	}}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/factory-batches/"+batch.ID+"/reconcile", station.operator, "p12l2-reconcile", journal); code != http.StatusOK {
		t.Fatalf("reconcile = %d %s", code, body)
	}

	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	// firstBoot runs one ACME order for d's name, answering device-attest-01
	// with d's birth certificate signed by signer.
	firstBoot := func(d born, signer *crypto.LockedSigner) (*certinfo.Info, error) {
		t.Helper()
		order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(d.name))
		if err != nil {
			return nil, fmt.Errorf("authorize order: %w", err)
		}
		authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			return nil, err
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "device-attest-01" {
				chal = c
			}
		}
		if chal == nil {
			t.Fatalf("the directory offered no device-attest-01 for the factory device %s", d.name)
		}
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: d.name, DNSNames: []string{d.name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := deviceattest.CSRPublicKeySHA256(csr)
		if err != nil {
			t.Fatal(err)
		}
		issuedAt := time.Now().UTC()
		binding, err := acme.FactoryBirthBinding(acme.DeviceAttestationBinding{TenantID: h.tenant, AccountURL: string(client.KID),
			OrderID: path.Base(order.URI), ChallengeID: path.Base(chal.URI), Token: chal.Token, Identifier: d.name,
			CSRKeySHA256: digest, IssuedAt: issuedAt})
		if err != nil {
			t.Fatal(err)
		}
		signature, err := signer.SignDigest(crypto.SHA256Sum(binding), crypto.SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		chal.Payload, err = json.Marshal(acme.DeviceAttestationResponse{DeviceIdentifier: d.name, IssuedAt: issuedAt,
			CSR: base64.RawURLEncoding.EncodeToString(csr), Format: acme.FactoryBirthFormat,
			BirthCertificate: base64.RawURLEncoding.EncodeToString(d.birthDER), BirthSignature: base64.RawURLEncoding.EncodeToString(signature)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("device-attest-01: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, order.AuthzURLs[0]); err != nil {
			return nil, err
		}
		if order, err = client.WaitOrder(ctx, order.URI); err != nil {
			return nil, err
		}
		chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil {
			return nil, fmt.Errorf("finalize: %w", err)
		}
		info, err := certinfo.Inspect(chain[0])
		if err != nil {
			t.Fatal(err)
		}
		return &info, nil
	}

	// Refusals first: another key's signature, a birth past the quota.
	if _, err := firstBoot(device, extra.birthKey); err == nil || !strings.Contains(err.Error(), "did not sign") {
		t.Fatalf("an answer signed by another key = %v; want refused", err)
	}
	if _, err := firstBoot(extra, extra.birthKey); err == nil || !strings.Contains(err.Error(), "over-production") {
		t.Fatalf("a birth past the quota = %v; want refused", err)
	}

	// First boot over ACME.
	operational, err := firstBoot(device, device.birthKey)
	if err != nil {
		t.Fatalf("first boot over ACME: %v", err)
	}
	if operational.CommonName != device.name && (len(operational.DNSNames) != 1 || operational.DNSNames[0] != device.name) {
		t.Fatalf("operational certificate = %+v", operational)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/factory-batches/"+batch.ID, station.operator, "", nil)
	var detail struct {
		Enrolled int `json:"enrolled"`
		Births   []struct {
			DeviceName        string `json:"device_name"`
			Enrolled          bool   `json:"enrolled"`
			OperationalSerial string `json:"operational_serial"`
		} `json:"births"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &detail) != nil || detail.Enrolled != 1 {
		t.Fatalf("batch detail = %d %s", code, body)
	}
	for _, b := range detail.Births {
		if b.DeviceName == device.name && (!b.Enrolled || !strings.EqualFold(b.OperationalSerial, operational.SerialNumber)) {
			t.Fatalf("the device's first boot over ACME was not recorded: %+v (serial %s)", b, operational.SerialNumber)
		}
	}

	// A second first boot with another key is refused.
	if _, err := firstBoot(device, device.birthKey); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("a second first boot = %v; want refused", err)
	}
	t.Logf("P12L2_ACME_FIRST_BOOT_OK device=%s operational=%s", device.name, operational.SerialNumber)
}
