// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"net/http/httptest"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// opaqueCapturingCA stands in for the licensed issuer behind the served CA
// adapter: it records exactly the CSR bytes ACME finalize hands it, then
// issues from a known-good CSR so the order can complete. It exists to pin
// the transparency property below.
type opaqueCapturingCA struct {
	ca.CA   // embed the full CA surface; only Issue is intercepted
	goodCSR []byte

	mu  sync.Mutex
	got [][]byte
}

func (c *opaqueCapturingCA) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	c.mu.Lock()
	c.got = append(c.got, append([]byte(nil), req.CSR...))
	c.mu.Unlock()
	req.CSR = c.goodCSR
	return c.CA.Issue(ctx, req)
}

// TestACMEFinalizePassesOpaqueCSRBytesToCA pins the property the licensed
// issuance path depends on: ACME finalize never parses or verifies the CSR
// itself — it hands the exact submitted bytes to the CA seam, where the
// licensed-aware issuer owns verification for subject algorithms the core
// toolchain cannot check (the same seam EST and CMP consult). The fixture CSR
// carries a proof-of-possession the core parser would reject; the order still
// completes because the CA (standing in for the licensed issuer) accepts it.
// If someone "hardens" finalize with a core-parser check, this test fails and
// points at the seam contract.
func TestACMEFinalizePassesOpaqueCSRBytesToCA(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME opaque-seam CA")
	if err != nil {
		t.Fatal(err)
	}
	goodCSR := buildCSR(t, "opaque.acme.test", []string{"opaque.acme.test"})
	capture := &opaqueCapturingCA{CA: builtin, goodCSR: goodCSR}

	ts := httptest.NewServer(acmesrv.New(capture, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("opaque.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			t.Fatal("server offered no http-01 challenge")
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}

	// A CSR whose proof-of-possession the CORE parser rejects: same subject,
	// one signature byte flipped. ACME must not care.
	opaqueCSR := append([]byte(nil), goodCSR...)
	opaqueCSR[len(opaqueCSR)-1] ^= 0x01

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, opaqueCSR, true)
	if err != nil {
		t.Fatalf("finalize with opaque CSR: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("no certificate chain returned")
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.got) != 1 {
		t.Fatalf("CA saw %d issuance calls, want 1", len(capture.got))
	}
	if !bytes.Equal(capture.got[0], opaqueCSR) {
		t.Fatal("CA did not receive the exact opaque CSR bytes ACME was handed")
	}
}
