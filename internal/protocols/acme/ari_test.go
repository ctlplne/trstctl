package acme_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto/acmekey"
	"certctl.io/certctl/internal/crypto/certinfo"
	acmesrv "certctl.io/certctl/internal/protocols/acme"
	"certctl.io/certctl/internal/protocols/ari"
)

func mustBuiltin(t *testing.T) ca.CA {
	t.Helper()
	b, err := ca.NewBuiltin("certctl ARI Test CA")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newHTTPTestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

// enrollForARI runs the ACME flow against srv and returns the issued leaf DER and
// its ARI certificate identifier.
func enrollForARI(t *testing.T, baseURL string) []byte {
	t.Helper()
	client, err := acmekey.NewRSAClient(baseURL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("ari.acme.test"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				if _, err := client.Accept(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := client.WaitAuthorization(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatal(err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, "ari.acme.test", []string{"ari.acme.test"}), true)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der[0]
}

// TestDirectoryAdvertisesRenewalInfo: the ACME directory exposes the ARI endpoint.
func TestDirectoryAdvertisesRenewalInfo(t *testing.T) {
	srv := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{})
	ts := newHTTPTestServer(t, srv)

	resp, err := http.Get(ts + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var dir map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatal(err)
	}
	if _, ok := dir["renewalInfo"]; !ok {
		t.Errorf("directory %v has no renewalInfo (ARI)", dir)
	}
}

// TestRenewalInfoServerAndEarlyRenewal is the acceptance: the server returns a
// valid renewal window for an issued cert with a Retry-After, and an injected
// early-renewal signal moves the window into the past so the client renews
// proactively.
func TestRenewalInfoServerAndEarlyRenewal(t *testing.T) {
	srv := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{})
	ts := newHTTPTestServer(t, srv)

	leafDER := enrollForARI(t, ts)
	certID, err := certinfo.ARICertID(leafDER)
	if err != nil {
		t.Fatalf("ARICertID: %v", err)
	}

	// The server returns a valid window with a Retry-After.
	info, retryAfter, err := fetchRenewalInfo(t, ts+"/acme/renewal-info", certID)
	if err != nil {
		t.Fatalf("fetch renewal info: %v", err)
	}
	if !info.SuggestedWindow.Start.Before(info.SuggestedWindow.End) {
		t.Errorf("window start %v not before end %v", info.SuggestedWindow.Start, info.SuggestedWindow.End)
	}
	if retryAfter <= 0 {
		t.Errorf("Retry-After = %v, want a positive cache hint", retryAfter)
	}
	if ari.RenewNow(info, time.Now()) {
		t.Error("a freshly-issued cert should not yet be due for renewal (future window)")
	}

	// Inject an early-renewal signal (mass-revocation scenario).
	srv.MarkEarlyRenewal(certID)
	info, _, err = fetchRenewalInfo(t, ts+"/acme/renewal-info", certID)
	if err != nil {
		t.Fatal(err)
	}
	if !ari.RenewNow(info, time.Now()) {
		t.Error("after an early-renewal signal, the cert should be due for renewal now")
	}
}

// TestARIClientConsumesWindow: the ARI client fetches the server's renewal info
// and its renew decision tracks the advertised window.
func TestARIClientConsumesWindow(t *testing.T) {
	srv := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{})
	ts := newHTTPTestServer(t, srv)
	leafDER := enrollForARI(t, ts)
	certID, err := certinfo.ARICertID(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	client := ari.NewClient(nil)
	info, retryAfter, err := client.FetchRenewalInfo(context.Background(), ts+"/acme/renewal-info", certID)
	if err != nil {
		t.Fatalf("client FetchRenewalInfo: %v", err)
	}
	if retryAfter <= 0 {
		t.Errorf("client got Retry-After %v, want positive", retryAfter)
	}
	if ari.RenewNow(info, time.Now()) {
		t.Error("client should not renew a fresh cert (window in the future)")
	}

	srv.MarkEarlyRenewal(certID)
	info, _, err = client.FetchRenewalInfo(context.Background(), ts+"/acme/renewal-info", certID)
	if err != nil {
		t.Fatal(err)
	}
	if !ari.RenewNow(info, time.Now()) {
		t.Error("client should renew now after the server signals early renewal")
	}
}

func fetchRenewalInfo(t *testing.T, base, certID string) (ari.RenewalInfo, time.Duration, error) {
	t.Helper()
	resp, err := http.Get(base + "/" + certID)
	if err != nil {
		return ari.RenewalInfo{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renewal-info status = %d", resp.StatusCode)
	}
	var info ari.RenewalInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ari.RenewalInfo{}, 0, err
	}
	var ra time.Duration
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, perr := time.ParseDuration(v + "s"); perr == nil {
			ra = secs
		}
	}
	return info, ra, nil
}
