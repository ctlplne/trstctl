// SPDX-License-Identifier: MPL-2.0

package revcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revcacheposture"
)

const (
	ocspResponseLimit     = 1 << 20
	maxOCSPCacheResponses = 4096
)

// ManagerConfig describes every issuer whose signed revocation objects are
// mirrored into one dark segment. Upstream URLs and issuer bytes never appear
// in the signed posture returned by Statuses.
type ManagerConfig struct {
	Segment string         `json:"segment"`
	Issuers []IssuerConfig `json:"issuers"`
}

type IssuerConfig struct {
	ID        string      `json:"id"`
	IssuerDER []byte      `json:"-"`
	CRL       *CRLConfig  `json:"crl,omitempty"`
	OCSP      *OCSPConfig `json:"ocsp,omitempty"`
}

type CRLConfig struct {
	UpstreamURL string        `json:"upstream_url"`
	LocalPath   string        `json:"local_path"`
	Grace       time.Duration `json:"grace,omitempty"`
}

type OCSPConfig struct {
	UpstreamURL string `json:"upstream_url"`
	LocalPath   string `json:"local_path"`
}

type ManagerOptions struct {
	Client *http.Client
	Now    func() time.Time
}

type Manager struct {
	segment string
	client  *http.Client
	now     func() time.Time
	routes  map[string]http.HandlerFunc
	crls    []*managedCRL
	ocsps   []*managedOCSP
}

type managedCRL struct {
	id, segment, localPath, issuerFingerprint string
	cache                                     *Cache
	served, refused                           atomic.Int64
	mu                                        sync.RWMutex
	detailCode                                string
}

type ocspCachedResponse struct {
	der                    []byte
	serial                 string
	thisUpdate, nextUpdate time.Time
	validatedAt            time.Time
}

type managedOCSP struct {
	id, segment, upstream, localPath, issuerFingerprint string
	issuerDER                                           []byte
	client                                              *http.Client
	now                                                 func() time.Time
	served, refused                                     atomic.Int64
	mu                                                  sync.RWMutex
	responses                                           map[string]ocspCachedResponse
	lastThisUpdate, lastNextUpdate, lastValidatedAt     time.Time
	lastSignatureVerified                               bool
	detailCode                                          string
}

// NewManager builds a bounded multi-issuer HTTP surface. Every local route is
// explicit; duplicate routes are refused so one issuer cannot shadow another.
func NewManager(cfg ManagerConfig, opts ManagerOptions) (*Manager, error) {
	segment := strings.TrimSpace(cfg.Segment)
	if !safePostureToken(segment) {
		return nil, errors.New("revcache: a bounded segment identity is required")
	}
	if len(cfg.Issuers) == 0 || len(cfg.Issuers) > revcacheposture.MaxEntries/2 {
		return nil, fmt.Errorf("revcache: issuer count must be between 1 and %d", revcacheposture.MaxEntries/2)
	}
	if opts.Client == nil {
		return nil, errors.New("revcache: no HTTP client configured")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	m := &Manager{segment: segment, client: opts.Client, now: now, routes: map[string]http.HandlerFunc{}}
	issuerIDs := map[string]bool{}
	for _, cfgIssuer := range cfg.Issuers {
		id := strings.TrimSpace(cfgIssuer.ID)
		if !safePostureToken(id) || issuerIDs[id] {
			return nil, fmt.Errorf("revcache: issuer id %q is empty, duplicated, or unsafe", id)
		}
		issuerIDs[id] = true
		if len(cfgIssuer.IssuerDER) == 0 {
			return nil, fmt.Errorf("revcache: issuer %q has no certificate", id)
		}
		fingerprint := "sha256:" + crypto.SHA256Hex(cfgIssuer.IssuerDER)
		if cfgIssuer.CRL == nil && cfgIssuer.OCSP == nil {
			return nil, fmt.Errorf("revcache: issuer %q has no CRL or OCSP cache", id)
		}
		if cfgIssuer.CRL != nil {
			if err := validateUpstreamURL(cfgIssuer.CRL.UpstreamURL); err != nil {
				return nil, fmt.Errorf("revcache: issuer %q CRL: %w", id, err)
			}
			cache, err := New(strings.TrimSpace(cfgIssuer.CRL.UpstreamURL), cfgIssuer.IssuerDER,
				Options{Grace: cfgIssuer.CRL.Grace, Client: opts.Client})
			if err != nil {
				return nil, fmt.Errorf("revcache: issuer %q CRL: %w", id, err)
			}
			cache.now = now
			row := &managedCRL{id: id, segment: segment, localPath: cfgIssuer.CRL.LocalPath,
				issuerFingerprint: fingerprint, cache: cache}
			if err := m.addRoute(row.localPath, row.serveHTTP); err != nil {
				return nil, err
			}
			m.crls = append(m.crls, row)
		}
		if cfgIssuer.OCSP != nil {
			if err := validateUpstreamURL(cfgIssuer.OCSP.UpstreamURL); err != nil {
				return nil, fmt.Errorf("revcache: issuer %q OCSP: %w", id, err)
			}
			row := &managedOCSP{id: id, segment: segment, upstream: strings.TrimSpace(cfgIssuer.OCSP.UpstreamURL),
				localPath: cfgIssuer.OCSP.LocalPath, issuerFingerprint: fingerprint,
				issuerDER: append([]byte(nil), cfgIssuer.IssuerDER...), client: opts.Client, now: now,
				responses: map[string]ocspCachedResponse{}}
			if row.upstream == "" {
				return nil, fmt.Errorf("revcache: issuer %q OCSP has no upstream", id)
			}
			if err := m.addRoute(row.localPath, row.serveHTTP); err != nil {
				return nil, err
			}
			m.ocsps = append(m.ocsps, row)
		}
	}
	return m, nil
}

func validateUpstreamURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("upstream must be an HTTP(S) URL without credentials or fragment")
	}
	return nil
}

func (m *Manager) addRoute(path string, handler http.HandlerFunc) error {
	if !safeLocalPath(path) {
		return fmt.Errorf("revcache: unsafe local path %q", path)
	}
	if _, exists := m.routes[path]; exists {
		return fmt.Errorf("revcache: duplicate local path %q", path)
	}
	m.routes[path] = handler
	return nil
}

func safeLocalPath(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && len(path) <= 512 &&
		!strings.ContainsAny(path, "?#\r\n\x00") && !strings.Contains(path, "..")
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := m.routes[r.URL.Path]
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	handler(w, r)
}

// RefreshCRLs refreshes every configured distribution point. All entries are
// attempted so one broken issuer cannot starve the rest.
func (m *Manager) RefreshCRLs(ctx context.Context) error {
	var failures []error
	for _, row := range m.crls {
		if err := row.cache.Refresh(ctx); err != nil {
			row.mu.Lock()
			row.detailCode = "upstream_refresh_failed"
			row.mu.Unlock()
			failures = append(failures, fmt.Errorf("%s: %w", row.id, err))
			continue
		}
		row.mu.Lock()
		row.detailCode = ""
		row.mu.Unlock()
	}
	return errors.Join(failures...)
}

func (c *managedCRL) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		c.refused.Add(1)
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	der, err := c.cache.Serve()
	if err != nil {
		c.refused.Add(1)
		http.Error(w, "no fresh CRL is available from this relay", http.StatusServiceUnavailable)
		return
	}
	c.served.Add(1)
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(der)
	}
}

func (o *managedOCSP) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		o.refuse(w, http.StatusMethodNotAllowed, "method_not_allowed", "OCSP cache accepts POST only")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/ocsp-request" {
		o.refuse(w, http.StatusBadRequest, "invalid_content_type", "expected application/ocsp-request")
		return
	}
	requestDER, err := io.ReadAll(io.LimitReader(r.Body, ocspResponseLimit+1))
	if err != nil || len(requestDER) == 0 || len(requestDER) > ocspResponseLimit {
		o.refuse(w, http.StatusBadRequest, "invalid_request", "OCSP request is empty, unreadable, or oversized")
		return
	}
	serial, err := crypto.ValidateOCSPRequestForIssuer(requestDER, o.issuerDER)
	if err != nil {
		o.refuse(w, http.StatusBadRequest, "invalid_request", "OCSP request is malformed")
		return
	}
	nonce, noncePresent, err := crypto.ParseOCSPRequestNonce(requestDER)
	if err != nil {
		o.refuse(w, http.StatusBadRequest, "invalid_nonce", "OCSP request nonce is malformed")
		return
	}
	key := crypto.SHA256Hex(requestDER)
	if !noncePresent {
		if cached, ok := o.cached(key); ok {
			o.writeResponse(w, cached.der)
			return
		}
	}
	validated, detailCode, err := o.fetch(r.Context(), requestDER, serial, nonce, noncePresent)
	if err != nil {
		o.mu.Lock()
		o.detailCode = detailCode
		if len(o.responses) == 0 {
			o.lastSignatureVerified = false
		}
		o.mu.Unlock()
		o.refused.Add(1)
		http.Error(w, "no valid fresh OCSP response is available from this relay", http.StatusServiceUnavailable)
		return
	}
	if !noncePresent {
		o.mu.Lock()
		o.makeCacheRoomLocked()
		o.responses[key] = validated
		o.mu.Unlock()
	}
	o.writeResponse(w, validated.der)
}

func (o *managedOCSP) cached(key string) (ocspCachedResponse, bool) {
	o.mu.RLock()
	row, ok := o.responses[key]
	o.mu.RUnlock()
	return row, ok && o.fresh(row.nextUpdate)
}

func (o *managedOCSP) fetch(ctx context.Context, requestDER []byte, serial string, nonce []byte, noncePresent bool) (ocspCachedResponse, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.upstream, bytes.NewReader(requestDER))
	if err != nil {
		return ocspCachedResponse{}, "upstream_request_failed", err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := o.client.Do(req)
	if err != nil {
		return ocspCachedResponse{}, "upstream_unreachable", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return ocspCachedResponse{}, "upstream_http_error", fmt.Errorf("OCSP upstream status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/ocsp-response" {
		return ocspCachedResponse{}, "invalid_content_type", errors.New("OCSP upstream content type is invalid")
	}
	responseDER, err := io.ReadAll(io.LimitReader(resp.Body, ocspResponseLimit+1))
	if err != nil || len(responseDER) == 0 || len(responseDER) > ocspResponseLimit {
		return ocspCachedResponse{}, "invalid_response", errors.New("OCSP upstream response is empty, unreadable, or oversized")
	}
	info, err := crypto.ParseOCSPResponse(responseDER, o.issuerDER)
	if err != nil {
		return ocspCachedResponse{}, "invalid_signature", err
	}
	if normalizeSerialHex(info.Serial) != normalizeSerialHex(serial) {
		return ocspCachedResponse{}, "wrong_serial", errors.New("OCSP response serial does not match request")
	}
	if noncePresent != info.HasNonce || (noncePresent && !bytes.Equal(nonce, info.Nonce)) {
		return ocspCachedResponse{}, "nonce_mismatch", errors.New("OCSP response nonce does not exactly match request")
	}
	now := o.now().UTC()
	if info.ThisUpdate.IsZero() || info.ThisUpdate.After(now.Add(5*time.Minute)) || info.NextUpdate.IsZero() || now.After(info.NextUpdate) {
		return ocspCachedResponse{}, "stale_response", errors.New("OCSP response is not inside its signed freshness window")
	}
	row := ocspCachedResponse{der: append([]byte(nil), responseDER...), serial: info.Serial,
		thisUpdate: info.ThisUpdate.UTC(), nextUpdate: info.NextUpdate.UTC(), validatedAt: now}
	o.mu.Lock()
	o.lastThisUpdate, o.lastNextUpdate, o.lastValidatedAt = row.thisUpdate, row.nextUpdate, row.validatedAt
	o.lastSignatureVerified = true
	o.detailCode = ""
	o.mu.Unlock()
	return row, "", nil
}

func (o *managedOCSP) fresh(nextUpdate time.Time) bool {
	return !nextUpdate.IsZero() && !o.now().UTC().After(nextUpdate)
}

// makeCacheRoomLocked bounds memory even when a client probes many serials.
// Expired responses are evicted first; otherwise the oldest validation loses.
func (o *managedOCSP) makeCacheRoomLocked() {
	for key, cached := range o.responses {
		if !o.fresh(cached.nextUpdate) {
			delete(o.responses, key)
		}
	}
	for len(o.responses) >= maxOCSPCacheResponses {
		var oldestKey string
		var oldestAt time.Time
		for key, cached := range o.responses {
			if oldestKey == "" || cached.validatedAt.Before(oldestAt) ||
				(cached.validatedAt.Equal(oldestAt) && key < oldestKey) {
				oldestKey, oldestAt = key, cached.validatedAt
			}
		}
		delete(o.responses, oldestKey)
	}
}

func normalizeSerialHex(serial string) string {
	normalized := strings.TrimLeft(strings.ToLower(serial), "0")
	if normalized == "" {
		return "0"
	}
	return normalized
}

func safePostureToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			(i > 0 && (r == '.' || r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func (o *managedOCSP) writeResponse(w http.ResponseWriter, der []byte) {
	o.served.Add(1)
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func (o *managedOCSP) refuse(w http.ResponseWriter, code int, detailCode, detail string) {
	o.refused.Add(1)
	o.mu.Lock()
	o.detailCode = detailCode
	o.mu.Unlock()
	http.Error(w, detail, code)
}

// Statuses returns stable metadata-only rows for the signed heartbeat.
func (m *Manager) Statuses() []revcacheposture.Entry {
	rows := make([]revcacheposture.Entry, 0, len(m.crls)+len(m.ocsps))
	for _, c := range m.crls {
		st := c.cache.Status()
		c.mu.RLock()
		detail := c.detailCode
		c.mu.RUnlock()
		status := revcacheposture.StatusEmpty
		if st.Cached && st.Fresh {
			status = revcacheposture.StatusFresh
		} else if st.Cached {
			status = revcacheposture.StatusStale
			if detail == "" {
				detail = "next_update_passed"
			}
		} else if detail != "" {
			status = revcacheposture.StatusError
		}
		row := revcacheposture.Entry{CacheID: c.id, Segment: c.segment, Protocol: revcacheposture.ProtocolCRL,
			IssuerFingerprint: c.issuerFingerprint, LocalPath: c.localPath, Status: status, DetailCode: detail,
			Fresh: st.Fresh, SignatureVerified: st.Cached, ServedRequests: c.served.Load(), RefusedRequests: c.refused.Load()}
		if st.Cached {
			row.CachedResponses = 1
			row.ThisUpdateUnix = st.ThisUpdate.UTC().Unix()
			row.NextUpdateUnix = st.NextUpdate.UTC().Unix()
			row.LastValidatedAtUnix = st.FetchedAt.UTC().Unix()
		}
		rows = append(rows, row)
	}
	for _, o := range m.ocsps {
		o.mu.Lock()
		freshCount := 0
		cachedCount := len(o.responses)
		var newestCached ocspCachedResponse
		for _, cached := range o.responses {
			if o.fresh(cached.nextUpdate) {
				freshCount++
			}
			if newestCached.validatedAt.IsZero() || cached.validatedAt.After(newestCached.validatedAt) {
				newestCached = cached
			}
		}
		status := revcacheposture.StatusEmpty
		fresh := freshCount > 0
		if fresh {
			status = revcacheposture.StatusFresh
		} else if cachedCount > 0 {
			status = revcacheposture.StatusStale
			if o.detailCode == "" {
				o.detailCode = "next_update_passed"
			}
		} else if o.detailCode != "" {
			status = revcacheposture.StatusError
		}
		row := revcacheposture.Entry{CacheID: o.id, Segment: o.segment, Protocol: revcacheposture.ProtocolOCSP,
			IssuerFingerprint: o.issuerFingerprint, LocalPath: o.localPath, Status: status, DetailCode: o.detailCode,
			CachedResponses: cachedCount, Fresh: fresh, SignatureVerified: cachedCount > 0 || o.lastSignatureVerified,
			ServedRequests: o.served.Load(), RefusedRequests: o.refused.Load()}
		if !newestCached.validatedAt.IsZero() {
			row.ThisUpdateUnix = newestCached.thisUpdate.UTC().Unix()
			row.NextUpdateUnix = newestCached.nextUpdate.UTC().Unix()
			row.LastValidatedAtUnix = newestCached.validatedAt.UTC().Unix()
		} else if !o.lastThisUpdate.IsZero() {
			row.ThisUpdateUnix = o.lastThisUpdate.UTC().Unix()
			row.NextUpdateUnix = o.lastNextUpdate.UTC().Unix()
			row.LastValidatedAtUnix = o.lastValidatedAt.UTC().Unix()
		}
		o.mu.Unlock()
		rows = append(rows, row)
	}
	normalized, err := revcacheposture.Normalize(rows)
	if err != nil {
		panic("revcache: internal posture is not normalizable: " + err.Error())
	}
	sort.SliceStable(normalized, func(i, j int) bool { return normalized[i].CacheID < normalized[j].CacheID })
	return normalized
}
