// SPDX-License-Identifier: MPL-2.0

package revcache_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revcacheposture"
)

type aud39Issuer struct {
	der []byte
	key *crypto.LockedSigner
}

func newAUD39Issuer(t *testing.T, name string) aud39Issuer {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, name, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return aud39Issuer{der: der, key: key}
}

func (i aud39Issuer) crl(t *testing.T, now time.Time, number int64) []byte {
	t.Helper()
	der, err := crypto.CreateCRL(i.der, i.key, nil, number, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (i aud39Issuer) ocsp(t *testing.T, request []byte, now time.Time) []byte {
	t.Helper()
	serial, err := crypto.ParseOCSPRequestSerial(request)
	if err != nil {
		t.Fatal(err)
	}
	nonce, present, err := crypto.ParseOCSPRequestNonce(request)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		nonce = nil
	}
	der, err := crypto.SignOCSPResponseWithNonce(i.der, i.key, crypto.OCSPGood, serial,
		now.Add(-time.Minute), now.Add(time.Hour), time.Time{}, 0, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestManagerServesMultipleIssuerCRLsAndValidatingOCSPFailClosedAUD39(t *testing.T) {
	issuerA := newAUD39Issuer(t, "AUD-39 issuer A")
	issuerB := newAUD39Issuer(t, "AUD-39 issuer B")
	now := time.Now().UTC().Round(time.Second)
	var mu sync.Mutex
	ocspCalls := map[string]int{}
	upstreamFailed := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if upstreamFailed {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/issuer-a.crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(issuerA.crl(t, now, 7))
		case "/issuer-b.crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(issuerB.crl(t, now, 9))
		case "/issuer-a.ocsp", "/issuer-b.ocsp":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				t.Errorf("read OCSP request: %v", err)
				return
			}
			ocspCalls[r.URL.Path]++
			w.Header().Set("Content-Type", "application/ocsp-response")
			if r.URL.Path == "/issuer-a.ocsp" {
				_, _ = w.Write(issuerA.ocsp(t, body, now))
			} else {
				_, _ = w.Write(issuerB.ocsp(t, body, now))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	manager, err := revcache.NewManager(revcache.ManagerConfig{
		Segment: "plant-7",
		Issuers: []revcache.IssuerConfig{
			{ID: "issuer-a", IssuerDER: issuerA.der,
				CRL:  &revcache.CRLConfig{UpstreamURL: upstream.URL + "/issuer-a.crl", LocalPath: "/crl/issuer-a"},
				OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL + "/issuer-a.ocsp", LocalPath: "/ocsp/issuer-a"}},
			{ID: "issuer-b", IssuerDER: issuerB.der,
				CRL:  &revcache.CRLConfig{UpstreamURL: upstream.URL + "/issuer-b.crl", LocalPath: "/crl/issuer-b"},
				OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL + "/issuer-b.ocsp", LocalPath: "/ocsp/issuer-b"}},
		},
	}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new multi-issuer manager: %v", err)
	}
	if err := manager.RefreshCRLs(context.Background()); err != nil {
		t.Fatalf("refresh both CRLs: %v", err)
	}
	local := httptest.NewServer(manager)
	t.Cleanup(local.Close)

	for _, tc := range []struct {
		path   string
		issuer []byte
		number int64
	}{{"/crl/issuer-a", issuerA.der, 7}, {"/crl/issuer-b", issuerB.der, 9}} {
		resp, err := local.Client().Get(local.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		info, parseErr := crypto.ParseCRL(body, tc.issuer)
		if resp.StatusCode != http.StatusOK || parseErr != nil || info.Number != tc.number {
			t.Fatalf("GET %s = %d number=%d parse=%v", tc.path, resp.StatusCode, info.Number, parseErr)
		}
	}

	request, err := crypto.BuildOCSPRequestForSerial(issuerA.der, "42")
	if err != nil {
		t.Fatal(err)
	}
	postOCSP := func(body []byte) (*http.Response, []byte) {
		t.Helper()
		resp, postErr := local.Client().Post(local.URL+"/ocsp/issuer-a", "application/ocsp-request", bytes.NewReader(body))
		if postErr != nil {
			t.Fatal(postErr)
		}
		responseBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, responseBody
	}
	for range 2 {
		resp, body := postOCSP(request)
		info, parseErr := crypto.ParseOCSPResponse(body, issuerA.der)
		if resp.StatusCode != http.StatusOK || parseErr != nil || info.Status != crypto.OCSPGood || info.Serial != "42" {
			t.Fatalf("cached OCSP = %d info=%+v parse=%v body=%x", resp.StatusCode, info, parseErr, body)
		}
	}
	mu.Lock()
	if ocspCalls["/issuer-a.ocsp"] != 1 {
		t.Fatalf("nonce-free identical OCSP upstream calls = %d, want 1 cached response", ocspCalls["/issuer-a.ocsp"])
	}
	mu.Unlock()

	nonceRequest, err := crypto.BuildOCSPRequestForSerialWithNonce(issuerA.der, "42", []byte("aud39-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, body := postOCSP(nonceRequest)
		info, parseErr := crypto.ParseOCSPResponse(body, issuerA.der)
		if resp.StatusCode != http.StatusOK || parseErr != nil || !info.HasNonce || !bytes.Equal(info.Nonce, []byte("aud39-nonce")) {
			t.Fatalf("nonce OCSP = %d info=%+v parse=%v", resp.StatusCode, info, parseErr)
		}
	}
	mu.Lock()
	if ocspCalls["/issuer-a.ocsp"] != 3 {
		t.Fatalf("nonce-bound OCSP was reused: calls=%d, want 3 total", ocspCalls["/issuer-a.ocsp"])
	}
	mu.Unlock()
	requestB, err := crypto.BuildOCSPRequestForSerial(issuerB.der, "43")
	if err != nil {
		t.Fatal(err)
	}
	respB, err := local.Client().Post(local.URL+"/ocsp/issuer-b", "application/ocsp-request", bytes.NewReader(requestB))
	if err != nil {
		t.Fatal(err)
	}
	bodyB, _ := io.ReadAll(respB.Body)
	_ = respB.Body.Close()
	infoB, parseB := crypto.ParseOCSPResponse(bodyB, issuerB.der)
	if respB.StatusCode != http.StatusOK || parseB != nil || infoB.Serial != "43" {
		t.Fatalf("issuer B OCSP = %d info=%+v parse=%v", respB.StatusCode, infoB, parseB)
	}

	statuses := manager.Statuses()
	if len(statuses) != 4 {
		t.Fatalf("signed posture rows = %d, want two protocols for two issuers: %+v", len(statuses), statuses)
	}
	for _, row := range statuses {
		if row.Segment != "plant-7" || !row.Fresh || !row.SignatureVerified || row.Status != revcacheposture.StatusFresh {
			t.Fatalf("fresh posture row = %+v", row)
		}
	}

	// Once nextUpdate passes, neither a CRL nor an OCSP response may be served
	// from cache. If the upstream is also down, the local service returns 503;
	// it never hands a still-signed but expired object to the isolated client.
	now = now.Add(2 * time.Hour)
	mu.Lock()
	upstreamFailed = true
	mu.Unlock()
	resp, err := local.Client().Get(local.URL + "/crl/issuer-a")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stale CRL status = %d, want 503", resp.StatusCode)
	}
	resp, body := postOCSP(request)
	if resp.StatusCode != http.StatusServiceUnavailable || bytes.Contains(body, []byte("0")) {
		t.Fatalf("stale OCSP status=%d body=%q, want fail-closed 503", resp.StatusCode, body)
	}
	for _, row := range manager.Statuses() {
		if row.Fresh || (row.Status != revcacheposture.StatusStale && row.Status != revcacheposture.StatusError) {
			t.Fatalf("post-expiry posture manufactured health: %+v", row)
		}
	}
}

func TestManagerRefusesWrongIssuerOCSPAndDuplicateLocalRoutesAUD39(t *testing.T) {
	issuerA := newAUD39Issuer(t, "AUD-39 issuer A")
	issuerB := newAUD39Issuer(t, "AUD-39 issuer B")
	now := time.Now().UTC().Round(time.Second)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(issuerB.ocsp(t, body, now))
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-8", Issuers: []revcache.IssuerConfig{{
		ID: "issuer-a", IssuerDER: issuerA.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer-a"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(manager)
	t.Cleanup(local.Close)
	request, _ := crypto.BuildOCSPRequestForSerial(issuerA.der, "44")
	resp, err := local.Client().Post(local.URL+"/ocsp/issuer-a", "application/ocsp-request", bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("wrong-issuer OCSP status=%d, want 503", resp.StatusCode)
	}
	rows := manager.Statuses()
	if len(rows) != 1 || rows[0].SignatureVerified || rows[0].DetailCode != "invalid_signature" {
		t.Fatalf("wrong-issuer posture = %+v", rows)
	}

	_, err = revcache.NewManager(revcache.ManagerConfig{Segment: "plant-8", Issuers: []revcache.IssuerConfig{
		{ID: "a", IssuerDER: issuerA.der, CRL: &revcache.CRLConfig{UpstreamURL: "https://a.example/crl", LocalPath: "/same"}},
		{ID: "b", IssuerDER: issuerB.der, OCSP: &revcache.OCSPConfig{UpstreamURL: "https://b.example/ocsp", LocalPath: "/same"}},
	}}, revcache.ManagerOptions{Client: upstream.Client()})
	if err == nil {
		t.Fatal("duplicate local revocation routes were accepted")
	}
	_ = fmt.Sprint(err)
}
