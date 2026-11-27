// SPDX-License-Identifier: BUSL-1.1

package revcache_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

func TestManagerRejectsLargeOCSPBodyBeforeUpstream(t *testing.T) {
	issuer := newAUD39Issuer(t, "request-size issuer")
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-size", Issuers: []revcache.IssuerConfig{{
		ID: "issuer", IssuerDER: issuer.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer"},
	}}}, revcache.ManagerOptions{Client: upstream.Client()})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://relay.local/ocsp/issuer", bytes.NewReader(bytes.Repeat([]byte("x"), (8<<10)+1)))
	req.Header.Set("Content-Type", "application/ocsp-request")
	manager.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || upstreamCalls != 0 {
		t.Fatalf("oversized OCSP request status=%d upstream calls=%d, want local 413", rec.Code, upstreamCalls)
	}
	if rows := manager.Statuses(); len(rows) != 1 || rows[0].Status != revcacheposture.StatusEmpty || rows[0].DetailCode != "" || rows[0].RefusedRequests != 1 {
		t.Fatalf("client-owned oversized body fabricated upstream cache failure: %+v", rows)
	}
}

func TestUnknownOCSPSerialCannotFillTheResponseCache(t *testing.T) {
	issuer := newAUD39Issuer(t, "unknown serial issuer")
	now := time.Now().UTC().Round(time.Second)
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		body, _ := io.ReadAll(r.Body)
		serial, err := crypto.ParseOCSPRequestSerial(body)
		if err != nil {
			t.Error(err)
			return
		}
		der, err := crypto.SignOCSPResponseWithNonce(issuer.der, issuer.key, crypto.OCSPUnknown, serial,
			now.Add(-time.Minute), now.Add(time.Hour), time.Time{}, 0, nil)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-unknown", Issuers: []revcache.IssuerConfig{{
		ID: "issuer", IssuerDER: issuer.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request, err := crypto.BuildOCSPRequestForSerial(issuer.der, "44")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://relay.local/ocsp/issuer", bytes.NewReader(request))
		req.Header.Set("Content-Type", "application/ocsp-request")
		manager.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("unknown serial response status=%d", rec.Code)
		}
	}
	if upstreamCalls != 2 {
		t.Fatalf("unknown serial was cached after %d upstream calls; attacker can evict valid cached responses", upstreamCalls)
	}
}

func TestConcurrentIdenticalOCSPRequestsShareOneUpstreamFetch(t *testing.T) {
	issuer := newAUD39Issuer(t, "singleflight issuer")
	now := time.Now().UTC().Round(time.Second)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(issuer.ocsp(t, body, now))
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-flight", Issuers: []revcache.IssuerConfig{{
		ID: "issuer", IssuerDER: issuer.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request, err := crypto.BuildOCSPRequestForSerial(issuer.der, "42")
	if err != nil {
		t.Fatal(err)
	}
	const workers = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan int, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://relay.local/ocsp/issuer", bytes.NewReader(request))
			req.Header.Set("Content-Type", "application/ocsp-request")
			manager.ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}
	close(start)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("no upstream fetch started")
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	for code := range results {
		if code != http.StatusOK {
			t.Fatalf("concurrent OCSP request status=%d", code)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("%d identical OCSP requests generated %d upstream fetches, want one", workers, got)
	}
}

func TestNonceOCSPRequestsHaveABoundedUpstreamRate(t *testing.T) {
	issuer := newAUD39Issuer(t, "nonce-rate issuer")
	now := time.Now().UTC().Round(time.Second)
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(issuer.ocsp(t, body, now))
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-nonce-rate", Issuers: []revcache.IssuerConfig{{
		ID: "issuer", IssuerDER: issuer.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request, err := crypto.BuildOCSPRequestForSerialWithNonce(issuer.der, "42", []byte("client-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 65; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://relay.local/ocsp/issuer", bytes.NewReader(request))
		req.Header.Set("Content-Type", "application/ocsp-request")
		manager.ServeHTTP(rec, req)
		want := http.StatusOK
		if i == 64 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("nonce request %d status=%d, want %d", i+1, rec.Code, want)
		}
	}
	if calls != 64 {
		t.Fatalf("nonce flood forwarded %d requests, want bounded 64", calls)
	}
}

func TestOCSPFetchPoolRejectsWhenSixteenDifferentUpstreamsAreInFlight(t *testing.T) {
	issuer := newAUD39Issuer(t, "bounded-fetch issuer")
	now := time.Now().UTC().Round(time.Second)
	entered := make(chan struct{}, 17)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		entered <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(issuer.ocsp(t, body, now))
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-fetch-limit", Issuers: []revcache.IssuerConfig{{
		ID: "issuer", IssuerDER: issuer.der,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuer"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(serial string) int {
		der, err := crypto.BuildOCSPRequestForSerial(issuer.der, serial)
		if err != nil {
			t.Error(err)
			return 0
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://relay.local/ocsp/issuer", bytes.NewReader(der))
		req.Header.Set("Content-Type", "application/ocsp-request")
		manager.ServeHTTP(rec, req)
		return rec.Code
	}
	results := make(chan int, 16)
	for i := 1; i <= 16; i++ {
		serial := fmt.Sprintf("%x", i)
		go func() { results <- request(serial) }()
	}
	for range 16 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("sixteen unique OCSP fetches did not enter the upstream")
		}
	}
	extra := make(chan int, 1)
	go func() { extra <- request("11") }()
	select {
	case status := <-extra:
		if status != http.StatusServiceUnavailable {
			close(release)
			t.Fatalf("seventeenth unique fetch status=%d, want fast 503", status)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("seventeenth unique fetch blocked instead of rejecting fast")
	}
	close(release)
	for range 16 {
		if code := <-results; code != http.StatusOK {
			t.Fatalf("admitted fetch status=%d", code)
		}
	}
}
