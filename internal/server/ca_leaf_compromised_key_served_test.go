// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The CA authority's leaf issue route refuses a key the tenant recorded as
// compromised, as every other issuance path does, naming why; the same
// authority still issues for a fresh key.
func TestServedCAAuthorityLeafIssueRefusesARecordedCompromisedKey(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-compromise-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-compromise-approver", []string{"issuers:write", "issuers:read", "certs:issue"})
	spec := map[string]any{
		"common_name": "compromise root", "max_path_len": 0, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"compromise.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", spec, 1, "compromise-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "compromise-root-approval")
	root := createRootCA(t, h, operator, ceremony.ID, spec, "compromise-root-create")

	csrFor := func(key *crypto.LockedSigner, name string) []byte {
		t.Helper()
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	issue := func(csrDER []byte, idem string) (int, []byte) {
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator, idem, map[string]any{
			"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), "ttl_seconds": 3600,
		})
	}

	stolen, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stolen.Destroy)
	stolenCSR := csrFor(stolen, "web.compromise.example.test")
	inspected, err := crypto.InspectOpaqueCSR(stolenCSR)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.RecordCompromisedSubjectKeyTx(ctx, tx, h.tenant,
			strings.Repeat("ab", 32), crypto.SHA256Hex(inspected.RawSubjectPublicKeyInfo), time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if code, body := issue(stolenCSR, "compromised-issue"); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "compromise") {
		t.Fatalf("issuing for a recorded-compromised key = %d %s; want 422 naming the compromise", code, body)
	}
	fresh, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Destroy)
	if code, body := issue(csrFor(fresh, "web.compromise.example.test"), "fresh-issue"); code != http.StatusCreated {
		t.Fatalf("issuing for a fresh key = %d %s; want 201", code, body)
	}
}
