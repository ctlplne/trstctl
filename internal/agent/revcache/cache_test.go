// SPDX-License-Identifier: BUSL-1.1

package revcache_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto"
)

// A stale CRL must not be served (epic R3).
//
// This is the property the package exists for, and the one that is easy to get
// wrong, because a stale CRL is dangerous precisely BECAUSE it still looks
// valid: nextUpdate has passed and the signature still verifies, so a relying
// party that accepts it will trust a certificate revoked yesterday.
//
// Serving nothing produces a fetch error somebody notices. Serving a stale list
// produces confident, wrong answers — and the relying parties in a dark segment
// are exactly the ones with nobody watching.

// testCA builds an issuing CA and a CRL signed by it.
func testCA(t *testing.T) (issuerDER []byte, signCRL func(nextUpdate time.Time, number int64) []byte) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "revcache.test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return caDER, func(nextUpdate time.Time, number int64) []byte {
		// thisUpdate is derived from nextUpdate, not from a second time.Now().
		//
		// It used to read time.Now().Add(-time.Minute), which is evaluated AFTER
		// the caller computed its own time.Now()-relative nextUpdate — so for an
		// already-expired CRL the two landed on the same instant and x509
		// rejected the template whenever the two clock reads straddled a second
		// boundary. That is a test which passes on most runs and fails on some,
		// and a flaky test in a revocation gate is one somebody re-runs until it
		// goes green. Deriving the ordering makes it structural.
		der, err := crypto.CreateCRL(caDER, key, nil, number, nextUpdate.Add(-time.Hour), nextUpdate)
		if err != nil {
			t.Fatalf("sign CRL: %v", err)
		}
		return der
	}
}

func crlServer(t *testing.T, der []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAFreshCRLIsServedToALANRelyingParty(t *testing.T) {
	t.Parallel()
	issuer, signCRL := testCA(t)
	der := signCRL(time.Now().Add(time.Hour), 1)
	up := crlServer(t, der)

	c, err := revcache.New(up.URL, issuer, revcache.Options{Client: up.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	got, err := c.Serve()
	if err != nil {
		t.Fatalf("a fresh CRL was not served: %v", err)
	}
	// It must be the CA's bytes, unaltered — a relying party validates the
	// signature itself, so anything the relay changed would simply fail.
	if string(got) != string(der) {
		t.Error("the served CRL is not the bytes the CA signed")
	}
	if _, err := crypto.ParseCRL(got, issuer); err != nil {
		t.Errorf("the served CRL does not verify against the issuer: %v", err)
	}
}

// THE test: past nextUpdate, nothing is served.
func TestAStaleCRLIsRefusedRatherThanServed(t *testing.T) {
	t.Parallel()
	issuer, signCRL := testCA(t)
	// Already expired when it arrives.
	der := signCRL(time.Now().Add(-time.Minute), 1)
	up := crlServer(t, der)

	c, err := revcache.New(up.URL, issuer, revcache.Options{Client: up.Client()})
	if err != nil {
		t.Fatal(err)
	}
	// The fetch itself succeeds: the list is genuine and signed, just expired.
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh of a genuine but expired CRL: %v", err)
	}

	if _, err := c.Serve(); !errors.Is(err, revcache.ErrNoFreshCRL) {
		t.Fatalf("a CRL past nextUpdate was served (err=%v). Its signature still verifies, so a "+
			"relying party would accept it and trust a certificate revoked yesterday", err)
	}
	// And the HTTP surface says unavailable rather than handing bytes over.
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://relay.local/crl", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; a client must not receive a stale list", rec.Code)
	}
	if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/pkix-crl" {
		t.Error("a stale CRL was written to the response body")
	}

	// The status must show the state an operator needs: we HAVE a list and are
	// refusing to serve it, which is correct and looks like an outage.
	st := c.Status()
	if !st.Cached || st.Fresh {
		t.Errorf("status = cached:%v fresh:%v, want cached and not fresh", st.Cached, st.Fresh)
	}
}

// A CRL that does not verify is never cached.
//
// Not the relay adding trust — a relying party checks the signature regardless.
// It is the relay declining to spend its one outbound fetch storing something no
// client would accept, and declining to serve a captive portal's login page to a
// segment full of TLS clients.
func TestACRLThatDoesNotVerifyIsNotCached(t *testing.T) {
	t.Parallel()
	issuer, _ := testCA(t)
	// A different CA's CRL: genuine, signed, and not by our issuer.
	_, otherSign := testCA(t)
	up := crlServer(t, otherSign(time.Now().Add(time.Hour), 1))

	c, err := revcache.New(up.URL, issuer, revcache.Options{Client: up.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("a CRL signed by a different CA was cached")
	}
	if _, err := c.Serve(); !errors.Is(err, revcache.ErrNoFreshCRL) {
		t.Errorf("something was served after a failed refresh: %v", err)
	}
}

// A CRL number going BACKWARDS is refused.
//
// Whoever served it is either badly out of date or replaying an older list to
// un-revoke something, and neither is a reason to replace a newer one.
func TestACRLRollbackIsRefused(t *testing.T) {
	t.Parallel()
	issuer, signCRL := testCA(t)

	newer := signCRL(time.Now().Add(time.Hour), 7)
	older := signCRL(time.Now().Add(time.Hour), 3)

	serve := newer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(serve)
	}))
	defer srv.Close()

	c, err := revcache.New(srv.URL, issuer, revcache.Options{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	serve = older
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("an older CRL number replaced a newer one; replaying an old list is how a " +
			"revoked certificate comes back to life")
	}
	if st := c.Status(); st.Number != 7 {
		t.Errorf("cached CRL number = %d, want the newer 7", st.Number)
	}
}

// A transient fetch failure does not discard a still-valid cached list.
func TestATransientFetchFailureKeepsAValidCachedList(t *testing.T) {
	t.Parallel()
	issuer, signCRL := testCA(t)
	der := signCRL(time.Now().Add(time.Hour), 1)

	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(der)
	}))
	defer srv.Close()

	c, err := revcache.New(srv.URL, issuer, revcache.Options{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := c.Refresh(context.Background()); err == nil {
		t.Error("a failing fetch reported success")
	}
	// The still-valid list survives: a transient outage must not throw away a
	// CRL that is inside its own validity window.
	if _, err := c.Serve(); err != nil {
		t.Errorf("a valid cached CRL was discarded by a failed refresh: %v", err)
	}
}

// A cache with no issuer is refused: it could not tell a CRL from anything else.
func TestACacheWithoutAnIssuerIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := revcache.New("https://cp.internal/crl", nil, revcache.Options{}); err == nil {
		t.Fatal("a cache with no issuer was built; it would store whatever a captive portal returned")
	}
}
