// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
)

// A195: a CA authority answers whether it would issue a leaf request, by the
// checks issuance makes and without signing or recording anything. An
// in-profile request is allowed with the lifetime a signing would use and then
// issues; a name outside the authority's permitted domains, and a key the
// tenant recorded as compromised, are refused with the reason, as issuance
// refuses them.
func TestServedCAAuthorityEvaluatesALeafRequestAsIssuanceWould(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-evaluate-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-evaluate-approver", []string{"issuers:write", "issuers:read", "certs:issue"})
	spec := map[string]any{
		"common_name": "evaluate root", "max_path_len": 0, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"apps.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", spec, 1, "evaluate-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "evaluate-root-approval")
	root := createRootCA(t, h, operator, ceremony.ID, spec, "evaluate-root-create")

	csrPEM := func(name string) (string, []byte) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), der
	}
	evaluate := func(csr string) (allowed bool, reason string, ttl int64) {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue/evaluate", operator, "", map[string]any{
			"csr_pem": csr, "ttl_seconds": 7200,
		})
		var out struct {
			Allowed             bool   `json:"allowed"`
			Reason              string `json:"reason"`
			CAID                string `json:"ca_id"`
			EffectiveTTLSeconds int64  `json:"effective_ttl_seconds"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.CAID != root.ID {
			t.Fatalf("evaluate = %d %s", code, body)
		}
		return out.Allowed, out.Reason, out.EffectiveTTLSeconds
	}
	issued := func() int { return eventCount(t, h.log, h.tenant, projections.EventCAEndEntityIssued) }
	before := issued()

	inside, _ := csrPEM("web.apps.example.test")
	if allowed, reason, ttl := evaluate(inside); !allowed || reason != "" || ttl <= 0 || ttl > 7200 {
		t.Fatalf("an in-profile request = %v %q %d; want allowed with the signing lifetime", allowed, reason, ttl)
	}
	if issued() != before {
		t.Fatal("an evaluation issued or recorded a certificate")
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator, "evaluate-inside", map[string]any{
		"csr_pem": inside, "ttl_seconds": 7200,
	}); code != http.StatusCreated {
		t.Fatalf("issuing what evaluation allowed = %d %s", code, body)
	}

	outside, _ := csrPEM("web.other.example.net")
	allowed, reason, _ := evaluate(outside)
	if allowed || !strings.Contains(reason, "web.other.example.net") {
		t.Fatalf("an out-of-profile request = %v %q; want refused naming the name", allowed, reason)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator, "evaluate-outside", map[string]any{
		"csr_pem": outside, "ttl_seconds": 7200,
	}); code/100 == 2 {
		t.Fatalf("issuance accepted what evaluation refused: %d %s", code, body)
	}

	stolen, stolenDER := csrPEM("api.apps.example.test")
	inspected, err := crypto.InspectOpaqueCSR(stolenDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.RecordCompromisedSubjectKeyTx(ctx, tx, h.tenant, strings.Repeat("cd", 32),
			crypto.SHA256Hex(inspected.RawSubjectPublicKeyInfo), time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if allowed, reason, _ := evaluate(stolen); allowed || !strings.Contains(reason, "compromise") {
		t.Fatalf("a recorded-compromised key = %v %q; want refused naming the compromise", allowed, reason)
	}
	if issued() != before+1 {
		t.Fatalf("CA end-entity events = %d, want only the one issuance", issued()-before)
	}
}
