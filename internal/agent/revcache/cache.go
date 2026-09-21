// SPDX-License-Identifier: BUSL-1.1

// Package revcache serves the control plane's CRLs inside a dark segment
// (epic R3).
//
// Revocation checking is the part of PKI that fails quietly. A relying party
// that cannot reach a CRL distribution point usually does not refuse the
// connection — it proceeds, because refusing would break more than it protects —
// so a segment with no route to the control plane silently stops checking
// revocation at all, and nobody finds out until a compromised certificate is
// used.
//
// The relay already has the one outbound pipe those segments allow, so it can
// hold the CRL locally and serve it to relying parties that cannot reach the
// control plane themselves.
//
// IT SIGNS NOTHING. The CRL is signed by the CA; this cache holds bytes and
// hands them over. A relying party validates the signature exactly as it would
// against the control plane, so a compromised relay can withhold a CRL — which
// is visible, because the fetch fails — but cannot forge one, which would not be.
//
// AND IT FAILS CLOSED ON STALENESS. That is the property this package exists
// for and the one that is easy to get wrong, because a stale CRL is dangerous
// precisely BECAUSE it still looks valid: nextUpdate has passed but the
// signature verifies, so a relying party that accepts it will happily trust a
// certificate revoked yesterday. Serving nothing produces a fetch error somebody
// notices. Serving a stale list produces confident, wrong answers.
package revcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// ErrNoFreshCRL is returned when the cache holds nothing it may serve.
//
// Distinct from a transport error on purpose: "I could not reach the control
// plane" and "I reached it and what I have is too old to serve" call for
// different responses, and only the second means a relying party should treat
// revocation as unavailable rather than retry.
var ErrNoFreshCRL = errors.New("revcache: no CRL fresh enough to serve")

// Cache holds one tenant's CRL and serves it while it is fresh.
type Cache struct {
	upstream string
	client   *http.Client
	// issuerDER is the CA certificate the cached CRL must verify against.
	//
	// Held so the relay can refuse to cache a CRL that does not verify. That is
	// not the relay adding trust — a relying party checks the signature itself
	// regardless — it is the relay declining to spend its one outbound fetch
	// storing something no client would accept.
	issuerDER []byte
	// grace is how long past nextUpdate a CRL may still be served.
	//
	// Zero by default, and that is deliberate. A grace period is a decision to
	// serve a list the CA said had expired, and the only party who can weigh
	// that against their own risk is the operator. A library default would make
	// it somebody else's choice, silently.
	grace time.Duration

	mu      sync.RWMutex
	der     []byte
	info    crypto.CRLInfo
	fetched time.Time
	now     func() time.Time
}

// Options configure a cache.
type Options struct {
	// Grace extends how long past nextUpdate a cached CRL may be served.
	// Zero — the default — serves nothing past nextUpdate.
	Grace time.Duration
	// Client is the HTTP client used to fetch. Nil uses an SSRF-checked default.
	Client *http.Client
}

// New builds a cache for one CRL distribution point.
func New(upstream string, issuerDER []byte, opts Options) (*Cache, error) {
	if upstream == "" {
		return nil, errors.New("revcache: no upstream CRL URL")
	}
	if len(issuerDER) == 0 {
		// Without the issuer the relay cannot tell a CRL from a page of HTML,
		// and would cache whatever a captive portal returned.
		return nil, errors.New("revcache: an issuer certificate is required to validate fetched CRLs")
	}
	c := &Cache{
		upstream: upstream, issuerDER: issuerDER,
		grace: opts.Grace, client: opts.Client, now: time.Now,
	}
	return c, nil
}

// Refresh fetches the CRL and caches it if it verifies.
//
// A fetch that fails leaves the previous CRL in place: a transient outage should
// not throw away a list that is still within its validity window. What it must
// never do is extend that window, which is why serving checks freshness rather
// than trusting that a refresh happened.
func (c *Cache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.upstream, nil)
	if err != nil {
		return err
	}
	client := c.client
	if client == nil {
		return errors.New("revcache: no HTTP client configured")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("revcache: fetch CRL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("revcache: fetch CRL: status %d", resp.StatusCode)
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("revcache: read CRL: %w", err)
	}

	// Verified against the issuer before it is stored. A relay that cached
	// unverified bytes would serve them confidently to a segment full of
	// clients, and the one that noticed would be the last one to check.
	info, err := crypto.ParseCRL(der, c.issuerDER)
	if err != nil {
		return fmt.Errorf("revcache: fetched CRL does not verify against the issuer: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A CRL number that went BACKWARD is a rollback, and the cache refuses it.
	// Whoever served it is either badly out of date or replaying an older list
	// to un-revoke something, and neither is a reason to replace a newer one.
	if len(c.der) > 0 && info.Number < c.info.Number {
		return fmt.Errorf("revcache: refusing CRL number %d, older than the cached %d",
			info.Number, c.info.Number)
	}
	c.der = der
	c.info = info
	c.fetched = c.now()
	return nil
}

// Serve returns the cached CRL if it is fresh enough to serve.
func (c *Cache) Serve() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.der) == 0 {
		return nil, ErrNoFreshCRL
	}
	if !c.freshAt(c.now()) {
		// Nothing is returned. Not the stale list with a warning header, not a
		// best-effort copy: a relying party that receives bytes will use them,
		// and a header it does not read cannot stop it trusting a certificate
		// revoked yesterday.
		return nil, ErrNoFreshCRL
	}
	return append([]byte(nil), c.der...), nil
}

// freshAt reports whether the cached CRL may be served at t.
func (c *Cache) freshAt(t time.Time) bool {
	if c.info.NextUpdate.IsZero() {
		// A CRL with no nextUpdate never expires by its own terms, which means
		// nothing here can tell when it went stale. Refusing is the only answer
		// that does not amount to serving it forever.
		return false
	}
	return !t.After(c.info.NextUpdate.Add(c.grace))
}

// Status is what the agent reports about this cache.
type Status struct {
	// Cached is whether any CRL is held at all.
	Cached bool
	// Fresh is whether it may currently be served. False with Cached true is
	// the state an operator most needs to see: the relay has a list and is
	// refusing to serve it, which is correct and looks like an outage.
	Fresh      bool
	Number     int64
	ThisUpdate time.Time
	NextUpdate time.Time
	FetchedAt  time.Time
}

// Status snapshots the cache.
func (c *Cache) Status() Status {
	if c == nil {
		return Status{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.der) == 0 {
		return Status{}
	}
	return Status{
		Cached: true, Fresh: c.freshAt(c.now()),
		Number: c.info.Number, ThisUpdate: c.info.ThisUpdate,
		NextUpdate: c.info.NextUpdate, FetchedAt: c.fetched,
	}
}

// ServeHTTP serves the cached CRL to a LAN relying party.
func (c *Cache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	der, err := c.Serve()
	if err != nil {
		// 503, not 404. The distinction is real: 404 says this distribution
		// point does not exist and a client may stop looking, while 503 says it
		// exists and has nothing valid right now, which is what a client should
		// retry and an operator should investigate.
		http.Error(w, "no fresh CRL is available from this relay", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}
