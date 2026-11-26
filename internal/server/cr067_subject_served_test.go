// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// CR-067: a certs:issue principal can request a name in the CA lane, but
// cannot put a different client-auth identity in the signed subject DN.
func TestCR067ServedAuthorityIssueBindsSubjectToApprovedName(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr067-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr067-approver", []string{"issuers:write", "issuers:read", "certs:issue"})
	requester := seedServedAPIToken(t, ctx, h.store, h.tenant, "cr067-requester", []string{"certs:issue"})
	spec := map[string]any{
		"common_name": "cr067 mTLS root", "max_path_len": 0,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"apps.example.test"},
		"extended_key_usages":   []string{"serverAuth", "clientAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", spec, 1, "cr067-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "cr067-root-approval")
	root := createRootCA(t, h, operator, ceremony.ID, spec, "cr067-root-create")
	issue := func(idem string, template crypto.CertificateRequestTemplate) (int, []byte) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		der, err := crypto.CreateCertificateRequest(template, key)
		if err != nil {
			t.Fatal(err)
		}
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", requester, idem, map[string]any{
			"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), "ttl_seconds": 3600,
		})
	}
	safe := crypto.CertificateRequestTemplate{CommonName: "svc.apps.example.test", DNSNames: []string{"svc.apps.example.test"}}
	code, body := issue("cr067-valid", safe)
	if code != http.StatusCreated {
		t.Fatalf("bound request = %d %s", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil || info.CommonName != safe.CommonName || info.IsCA {
		t.Fatalf("bound certificate = %+v, %v", info, err)
	}
	if code, body := issue("cr067-outside", crypto.CertificateRequestTemplate{CommonName: "outside.example.net", DNSNames: []string{"outside.example.net"}}); code/100 == 2 {
		t.Fatalf("out-of-lane request issued: %d %s", code, body)
	}
	for _, tc := range []struct {
		name     string
		template crypto.CertificateRequestTemplate
	}{
		{"unbound-cn", crypto.CertificateRequestTemplate{CommonName: "postgres", DNSNames: safe.DNSNames}},
		{"extra-rdn", crypto.CertificateRequestTemplate{CommonName: safe.CommonName, DNSNames: safe.DNSNames, Organization: []string{"system:masters"}, OrganizationalUnit: []string{"dba"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := issue("cr067-"+tc.name, tc.template); code/100 == 2 {
				t.Fatalf("requester-controlled subject issued: %d %s", code, body)
			}
		})
	}
}
