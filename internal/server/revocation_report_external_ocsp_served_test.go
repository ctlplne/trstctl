// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/store"
)

// ocspExternalCA stands in for an external CA (A245-L3): it issues leaves from
// its own CA naming its own OCSP responder, revokes when asked, and its
// responder answers each serial from what it has revoked.
type ocspExternalCA struct {
	caDER     []byte
	caKey     *crypto.LockedSigner
	responder *httptest.Server
	mu        sync.Mutex
	revoked   map[string]time.Time
	published bool // the CA publishes revocations on its responder
}

func (c *ocspExternalCA) Name() string { return "a245l3-ca" }

func (c *ocspExternalCA) Issue(_ context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	der, err := crypto.SignLeafFromCSRWithProfile(c.caDER, c.caKey, req.CSR, req.TTL, crypto.LeafProfile{OCSPServers: []string{c.responder.URL + "/ocsp"}})
	if err != nil {
		return ca.Certificate{}, err
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		return ca.Certificate{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caDER})...)
	return ca.Certificate{CertificatePEM: chain, Serial: info.SerialNumber, NotAfter: info.NotAfter, Issuer: info.Issuer}, nil
}

func (c *ocspExternalCA) Revoke(_ context.Context, req ca.RevokeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[req.Serial] = time.Now().UTC().Add(-time.Second)
	return nil
}

func (c *ocspExternalCA) answer(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	serial, err := crypto.ParseOCSPRequestSerial(body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	revokedAt, revoked := c.revoked[serial]
	published := c.published
	c.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	status := crypto.OCSPGood
	if revoked && published {
		status = crypto.OCSPRevoked
	}
	resp, err := crypto.SignOCSPResponse(c.caDER, c.caKey, status, serial, now.Add(-time.Minute), now.Add(time.Hour), revokedAt, 4)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(resp)
}

// A245-L3 Done-when (served): the revocation report reads an external CA's
// own status back from its OCSP responder. An identity bound to an external
// CA whose leaves name that CA's responder is issued and revoked; while the CA
// has not published the revocation the CA facet reads pending (the responder
// still answers good), and once it has, confirmed (it answers revoked), with
// the answer's time.
func TestServedRevocationReportReadsTheExternalCAsOCSPA245L3(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "A245-L3 External Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	external := &ocspExternalCA{caDER: caDER, caKey: caKey, revoked: map[string]time.Time{}}
	external.responder = httptest.NewServer(http.HandlerFunc(external.answer))
	t.Cleanup(external.responder.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = append(d.ExternalCAs, ExternalCA{ID: "a245l3-ca", Type: "external", Name: "A245-L3 External CA", CA: external})
		// The stand-in's responder is on loopback, which the default client refuses.
		d.APIOptions = append(d.APIOptions, api.WithExternalOCSPClient(netsec.InsecureLoopbackClient(5*time.Second)))
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:read", "identities:write", "certs:read",
		"certs:write", "certs:issue", "certs:revoke", "lifecycle:read")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", tok, "a245l3-owner", map[string]any{"kind": "workload", "name": "a245l3-owner"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &owner) != nil {
		t.Fatalf("owner: HTTP %d %s", status, raw)
	}
	attrs, _ := json.Marshal(map[string]string{"issuing_authority_source": "external", "issuing_authority_id": "a245l3-ca"})
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate,
		Name: "a245l3-orders.example.test", OwnerID: owner.ID, Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	transition := func(key, to string) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, key,
			map[string]any{"to": to, "reason": "cessationOfOperation"}); status != http.StatusOK {
			t.Fatalf("%s: HTTP %d %s", to, status, raw)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	transition("a245l3-issue", "issued")
	transition("a245l3-revoke", "revoked")
	type facet struct {
		State  string     `json:"state"`
		Detail string     `json:"detail"`
		At     *time.Time `json:"at"`
	}
	caStatus := func(stage string) facet {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+ident.ID+"/revocation-report", tok, nil)
		var report struct {
			Certificates []struct {
				CAStatus facet `json:"ca_status"`
			} `json:"certificates"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &report) != nil || len(report.Certificates) != 1 {
			t.Fatalf("%s: revocation report HTTP %d %s", stage, status, raw)
		}
		return report.Certificates[0].CAStatus
	}
	external.mu.Lock()
	asked := len(external.revoked)
	external.mu.Unlock()
	if asked != 1 {
		t.Fatalf("the external CA was asked to revoke %d serials, want 1", asked)
	}
	if got := caStatus("before the CA publishes"); got.State != "pending" || got.At == nil {
		t.Fatalf("before the CA publishes the CA facet reads %+v, want pending with the answer's time", got)
	}
	external.mu.Lock()
	external.published = true
	external.mu.Unlock()
	if got := caStatus("after the CA publishes"); got.State != "confirmed" || got.At == nil {
		t.Fatalf("after the CA publishes the CA facet reads %+v, want confirmed", got)
	}
	t.Log("A245L3_EXTERNAL_OCSP_OK")
}
