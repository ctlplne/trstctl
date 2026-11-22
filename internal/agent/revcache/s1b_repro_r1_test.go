// SPDX-License-Identifier: BUSL-1.1

package revcache_test

// R1 review reproduction (S1b-L1). The served CA publishes, next to every full
// CRL N, at least four partition ("shard") CRLs numbered N+1.. signed by the same
// CA with a subset of the revoked serials and no IssuingDistributionPoint
// (internal/server/revocation.go:337-386, crlMinShardCount = 4). Handing the
// cache a shard in place of the full CRL must not replace the list it serves.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto"
)

func TestAPartitionCRLDoesNotReplaceTheFullCRLR1S1b(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "R1 partitioned CRL CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	thisUpdate, nextUpdate := now.Add(-time.Minute), now.Add(time.Hour)
	revoked := []crypto.RevokedSerial{{Serial: "10", RevokedAt: now.Add(-2 * time.Minute), Reason: 1}}
	// Full CRL number 7 (what /crl/{tenant} serves) ...
	full, err := crypto.CreateCRL(caDER, key, revoked, 7, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}
	// ... and an empty shard exactly as generateCRLFromCurrentProjection signs it:
	// crypto.CreateCRL(caCertDER, caSigner, shardEntries, shardNumber, now, nextUpdate)
	// with shardNumber from the same NextCRLNumber sequence.
	shard, err := crypto.CreateCRL(caDER, key, nil, 8, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}

	serve := full
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(serve)
	}))
	t.Cleanup(srv.Close)
	c, err := revcache.New(srv.URL, caDER, revcache.Options{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("full CRL refused: %v", err)
	}

	// An on-path attacker (or a poisoned proxy) answers the next fetch with the
	// publicly downloadable shard.
	serve = shard
	refreshErr := c.Refresh(context.Background())
	served, err := c.Serve()
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	info, err := crypto.ParseCRL(served, caDER)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(info.RevokedSerials, "10") {
		t.Fatalf("the cache replaced CRL 7 (revokes serial 10) with the CA-signed partition CRL %d (refresh err=%v) and now "+
			"serves a list on which serial 10 is not revoked; HasDeltaCRLIndicator=%t, no scope extension to tell them apart",
			info.Number, refreshErr, info.HasDeltaCRLIndicator)
	}
}

func TestADeltaCRLDoesNotReplaceTheCompleteCRLR1S1b(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "R1 delta CRL CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	full, err := crypto.CreateCRL(caDER, key, []crypto.RevokedSerial{{Serial: "10", RevokedAt: now.Add(-time.Minute), Reason: 1}}, 7, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	delta, err := crypto.CreateCRLWithOptions(caDER, key, nil, 8, now, now.Add(time.Hour), crypto.CRLOptions{DeltaBaseNumber: 7})
	if err != nil {
		t.Fatal(err)
	}
	serve := full
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(serve)
	}))
	t.Cleanup(srv.Close)
	c, err := revcache.New(srv.URL, caDER, revcache.Options{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("full CRL refused: %v", err)
	}
	serve = delta
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("a delta CRL replaced a complete list without merging its base")
	}
	served, err := c.Serve()
	if err != nil {
		t.Fatal(err)
	}
	info, err := crypto.ParseCRL(served, caDER)
	if err != nil || !slices.Contains(info.RevokedSerials, "10") {
		t.Fatalf("cache lost the full CRL after delta rejection: %+v, %v", info, err)
	}
}

func TestTenantCRLRouteRequiresSignedScopeBeforeFirstCacheFillCR069(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	issuer, err := crypto.SelfSignedCACert(key, "tenant CRL scope CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	legacy, err := crypto.CreateCRL(issuer, key, nil, 7, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(legacy) }))
	defer server.Close()
	const tenant = "88888888-8888-4888-8888-888888888888"
	cache, err := revcache.New(server.URL+"/crl/"+tenant, issuer, revcache.Options{Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("tenant CRL route accepted an unscoped legacy CRL before its first cache fill")
	}
	if _, err := cache.Serve(); err == nil {
		t.Fatal("tenant CRL route served an unscoped legacy CRL")
	}
}
