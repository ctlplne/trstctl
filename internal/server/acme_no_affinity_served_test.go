// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/profile"
)

// p15l7BadNonces counts the badNonce problems a client was answered.
type p15l7BadNonces struct {
	next  http.RoundTripper
	count atomic.Int64
}

func (b *p15l7BadNonces) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		return resp, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "badNonce") {
		b.count.Add(1)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// P15-L7: two served ACME replicas need no affinity. Behind a balancer that
// alternates on every request, a client registers, orders and finalizes
// without once meeting badNonce, because each nonce is minted and redeemed in
// PostgreSQL; and an order's finalize is one across replicas: while another
// replica holds its claim the finalize is refused as in progress, and once
// that claim is released it issues.
func TestServedACMEReplicasNeedNoAffinityP15L7(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x57}, 32)
	protocols := config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "p15l7", HMACKey: hmacKey, Profile: "internal-p15l7"},
		}},
	}
	h := newOperatingServedHarness(t, protocols)
	storeServerTestProfile(t, h.store, h.tenant, "internal-p15l7", profile.CertificateProfile{
		Name: "internal-p15l7", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	replicaB, err := h.srv.buildServedACME(ctx, protocols, servedTestTenant, h.srv.newProtocolIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	replicas := []http.Handler{h.ts.Config.Handler, replicaB}
	var turn atomic.Int64
	balancer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replicas[turn.Add(1)%2].ServeHTTP(w, r)
	}))
	t.Cleanup(balancer.Close)

	client, err := acmekey.NewClient(balancer.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	counter := &p15l7BadNonces{next: http.DefaultTransport}
	client.HTTPClient = &http.Client{Transport: counter, Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: "p15l7", Key: hmacKey}}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("p15l7.internal.test"))
	if err != nil || order.Status != xacme.StatusReady {
		t.Fatalf("order = %+v %v", order, err)
	}
	subject, err := crypto.GenerateHostSubjectKey("p15l7.internal.test", []string{"p15l7.internal.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()

	orderID := order.URI[strings.LastIndex(order.URI, "/")+1:]
	if held, err := h.store.ClaimACMEFinalize(ctx, servedTestTenant, orderID, "another-replica", time.Now().Add(time.Minute)); err != nil || !held {
		t.Fatalf("claim the order as another replica: %v %v", held, err)
	}
	if _, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, subject.CSRDER, true); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("a finalize while another replica holds the order = %v", err)
	}
	if err := h.store.ReleaseACMEFinalize(ctx, servedTestTenant, orderID, "another-replica"); err != nil {
		t.Fatal(err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, subject.CSRDER, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("finalize once the claim is released: %v", err)
	}
	if n := counter.count.Load(); n != 0 {
		t.Fatalf("the client met badNonce %d times across alternating replicas", n)
	}
	t.Logf("P15L7_NO_AFFINITY_OK requests=%d", turn.Load())
}
