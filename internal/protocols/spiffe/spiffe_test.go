package spiffe

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

func testIssuer(t *testing.T) *CAIssuer {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "example.org CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jwtKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jwtKey.Destroy)
	return &CAIssuer{CACertDER: caDER, CASigner: ca, JWTSigner: jwtKey, JWTKeyID: "jwt-1"}
}

func TestWorkloadAPIFetchesAndValidatesBothSVIDTypes(t *testing.T) {
	const id = "spiffe://example.org/ns/default/sa/web"
	g := graph.New()
	rec := &auditsink.Recorder{}
	srv, err := New(Config{
		Issuer: testIssuer(t), TenantID: "t1", Graph: g, Audit: rec,
		Entries: []RegistrationEntry{{SPIFFEID: id, Selectors: []string{"k8s:ns:default", "k8s:sa:web"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	sel := []string{"k8s:ns:default", "k8s:sa:web", "unix:uid:1000"}

	svids, err := srv.FetchX509SVIDs(context.Background(), wl.Public().DER, sel)
	if err != nil {
		t.Fatalf("FetchX509SVIDs: %v", err)
	}
	if len(svids) != 1 {
		t.Fatalf("got %d X509-SVIDs, want 1", len(svids))
	}
	if err := crypto.VerifyLeafSignedByCA(svids[0].CertChain[0], svids[0].Bundle[0]); err != nil {
		t.Fatalf("X509-SVID does not chain to bundle: %v", err)
	}
	if got, _ := crypto.SPIFFEIDFromCert(svids[0].CertChain[0]); got != id {
		t.Errorf("SVID id = %q, want %q", got, id)
	}

	jsvids, err := srv.FetchJWTSVIDs(context.Background(), []string{"trstctl"}, sel)
	if err != nil {
		t.Fatalf("FetchJWTSVIDs: %v", err)
	}
	if len(jsvids) != 1 {
		t.Fatalf("got %d JWT-SVIDs, want 1", len(jsvids))
	}
	bundle, err := srv.FetchJWTBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := crypto.VerifyJWT(jsvids[0].Token, bundle)
	if err != nil {
		t.Fatalf("JWT-SVID failed verification against trust bundle: %v", err)
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(claims, &c); err != nil {
		t.Fatal(err)
	}
	if c.Sub != id {
		t.Errorf("JWT-SVID sub = %q, want %q", c.Sub, id)
	}

	if rec.Count("spiffe.svid.issued") != 2 {
		t.Errorf("audit events = %d, want 2 (one per SVID)", rec.Count("spiffe.svid.issued"))
	}
	if _, ok := g.Node(id); !ok {
		t.Error("issued SPIFFE ID is not represented in the credential graph")
	}
}

func TestWorkloadAPIFailsClosedWithoutMatchingEntry(t *testing.T) {
	srv, err := New(Config{
		Issuer: testIssuer(t), TenantID: "t1",
		Entries: []RegistrationEntry{{SPIFFEID: "spiffe://example.org/a", Selectors: []string{"x:1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	if _, err := srv.FetchX509SVIDs(context.Background(), wl.Public().DER, []string{"y:2"}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
}

func TestNeedsRotationCrossesThreshold(t *testing.T) {
	srv, err := New(Config{
		Issuer: testIssuer(t), TenantID: "t1", DefaultX509TTL: time.Hour,
		Entries: []RegistrationEntry{{SPIFFEID: "spiffe://example.org/w", Selectors: []string{"s:1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	svids, err := srv.FetchX509SVIDs(context.Background(), wl.Public().DER, []string{"s:1"})
	if err != nil {
		t.Fatal(err)
	}
	nb, na, err := crypto.CertValidity(svids[0].CertChain[0])
	if err != nil {
		t.Fatal(err)
	}
	if need, _ := NeedsRotation(svids[0], nb.Add(time.Minute), 0.5); need {
		t.Error("rotation requested immediately after issuance")
	}
	mid := nb.Add(na.Sub(nb)/2 + time.Second)
	if need, _ := NeedsRotation(svids[0], mid, 0.5); !need {
		t.Error("rotation not requested past half-life (rotate-before-expiry failed)")
	}
}

func TestWorkloadAPIThroughBulkhead(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "spiffe", Workers: 2, Queue: 4})
	defer pool.Close()
	srv, err := New(Config{
		Issuer: testIssuer(t), TenantID: "t1", Pool: pool,
		Entries: []RegistrationEntry{{SPIFFEID: "spiffe://example.org/w", Selectors: []string{"s:1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	if _, err := srv.FetchX509SVIDs(context.Background(), wl.Public().DER, []string{"s:1"}); err != nil {
		t.Fatalf("bulkheaded fetch: %v", err)
	}
}
