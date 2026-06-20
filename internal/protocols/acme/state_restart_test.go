package acme_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

func openACMEStateLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open ACME state log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func rewriteBaseURL(t *testing.T, rawURL, base string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	b, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	u.Scheme = b.Scheme
	u.Host = b.Host
	return u.String()
}

func TestACMEStateRebuildsFromEventLogAfterRestart(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	const tenantID = "tenant-acme-state"

	srv1, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateLog(ctx, tenantID, log)
	if err != nil {
		t.Fatalf("first ACME state log bind: %v", err)
	}
	ts1 := httptest.NewServer(srv1)

	client, err := acmekey.NewRSAClient(ts1.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("restart.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		for _, chal := range authz.Challenges {
			if chal.Type != "http-01" {
				continue
			}
			if _, err := client.Accept(ctx, chal); err != nil {
				t.Fatalf("accept challenge: %v", err)
			}
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}
	der, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, "restart.acme.test", []string{"restart.acme.test"}), true)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("create cert returned no leaf")
	}
	leafDER := der[0]
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect leaf: %v", err)
	}
	certID, err := certinfo.ARICertID(leafDER)
	if err != nil {
		t.Fatalf("ARI certID: %v", err)
	}
	ts1.Close()

	srv2, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateLog(ctx, tenantID, log)
	if err != nil {
		t.Fatalf("restart ACME state log bind: %v", err)
	}
	ts2 := httptest.NewServer(srv2)
	t.Cleanup(ts2.Close)

	restartedClient := &xacme.Client{
		Key:          client.Key,
		DirectoryURL: ts2.URL + "/directory",
		KID:          client.KID,
	}
	fetched, err := restartedClient.FetchCert(ctx, rewriteBaseURL(t, certURL, ts2.URL), true)
	if err != nil {
		t.Fatalf("fetch cert after restart: %v", err)
	}
	if len(fetched) == 0 || !bytes.Equal(fetched[0], leafDER) {
		t.Fatalf("restarted fetch returned leaf %x, want %x", fetched, leafDER)
	}

	if _, _, err := fetchRenewalInfo(t, ts2.URL+"/acme/renewal-info", certID); err != nil {
		t.Fatalf("fetch ARI after restart: %v", err)
	}

	if err := restartedClient.RevokeCert(ctx, nil, leafDER, xacme.CRLReasonCessationOfOperation); err != nil {
		t.Fatalf("revoke after restart: %v", err)
	}
	if serial, ok := srv2.IsRevoked(leafInfo.SHA256Fingerprint); !ok || serial != leafInfo.SerialNumber {
		t.Fatalf("restarted server revocation = (%q, %v), want (%q, true)", serial, ok, leafInfo.SerialNumber)
	}
}
