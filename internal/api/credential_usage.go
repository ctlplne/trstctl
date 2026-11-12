// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Credential usage (M1). Each authenticated API-token request is noted off the
// request path: the first use of a token from a client network for an action
// in an hour is queued at once, and later uses in that hour only when the
// hour's count reaches 2, 4, … 1024. One recorder per process drains a bounded
// queue into the event log. A use that cannot be queued or recorded becomes a
// recorded gap, so missing telemetry is never read as non-use.

const (
	credentialUsageQueueSize = 4096
	credentialUsageMaxKeys   = 100_000
	credentialUsageMaxCount  = 1024
)

var credentialUsageNamespace = googleuuid.MustParse("5d2a8c71-0e4f-4b9a-9c3d-7f1e6a2b8d40")

// WithCredentialUsageClock sets the clock the usage recorder stamps uses with.
// Production uses the wall clock; tests drive windows and days with it.
func WithCredentialUsageClock(now func() time.Time) Option {
	return func(c *config) { c.credentialUsageClock = now }
}

type credentialUseKey struct{ tenant, credential, source, action string }

type credentialUseNote struct {
	tenant string
	used   projections.CredentialUsed
}

type credentialUsageGapNote struct {
	from, to time.Time
	dropped  int64
}

// credentialUsageSink is where noted uses are recorded (the orchestrator).
type credentialUsageSink interface {
	RecordCredentialUse(ctx context.Context, tenantID, eventID string, used projections.CredentialUsed) error
	RecordCredentialUsageGap(ctx context.Context, tenantID, eventID string, gap projections.CredentialUsageGap) error
}

type credentialUsageRecorder struct {
	now    func() time.Time
	queue  chan credentialUseNote
	mu     sync.Mutex
	window time.Time
	counts map[credentialUseKey]int
	gaps   map[string]*credentialUsageGapNote
}

func newCredentialUsageRecorder(now func() time.Time) *credentialUsageRecorder {
	if now == nil {
		now = time.Now
	}
	return &credentialUsageRecorder{
		now: now, queue: make(chan credentialUseNote, credentialUsageQueueSize),
		counts: map[credentialUseKey]int{}, gaps: map[string]*credentialUsageGapNote{},
	}
}

// note records one authenticated use of an API token.
func (r *credentialUsageRecorder) note(tenantID, credentialID, principal, source, action string) {
	at := r.now().UTC()
	window := at.Truncate(time.Hour)
	key := credentialUseKey{tenant: tenantID, credential: credentialID, source: source, action: action}
	r.mu.Lock()
	if !window.Equal(r.window) {
		r.window, r.counts = window, map[credentialUseKey]int{}
	}
	count, seen := r.counts[key]
	if !seen && len(r.counts) >= credentialUsageMaxKeys {
		r.dropLocked(tenantID, at)
		r.mu.Unlock()
		return
	}
	count++
	r.counts[key] = count
	r.mu.Unlock()
	if count > 1 && (count > credentialUsageMaxCount || count&(count-1) != 0) {
		return
	}
	n := credentialUseNote{tenant: tenantID, used: projections.CredentialUsed{
		Kind: store.CredentialUsageAPIToken, CredentialID: credentialID, Principal: principal,
		SourceKind: store.CredentialUsageSourceNetwork, Source: source, Action: action,
		WindowStart: window, UsedAt: at, Count: count,
	}}
	select {
	case r.queue <- n:
	default:
		r.mu.Lock()
		r.dropLocked(tenantID, at)
		r.mu.Unlock()
	}
}

func (r *credentialUsageRecorder) dropLocked(tenantID string, at time.Time) {
	gap := r.gaps[tenantID]
	if gap == nil {
		gap = &credentialUsageGapNote{from: at, to: at}
		r.gaps[tenantID] = gap
	}
	if at.Before(gap.from) {
		gap.from = at
	}
	if at.After(gap.to) {
		gap.to = at
	}
	gap.dropped++
}

// drain records every queued use, then every gap. A use that cannot be
// recorded becomes part of a gap; a gap that cannot be recorded waits for the
// next drain.
func (r *credentialUsageRecorder) drain(ctx context.Context, sink credentialUsageSink) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for drained := false; !drained; {
		select {
		case n := <-r.queue:
			if err := sink.RecordCredentialUse(ctx, n.tenant, credentialUseEventID(n), n.used); err != nil {
				r.mu.Lock()
				r.dropLocked(n.tenant, n.used.UsedAt)
				r.mu.Unlock()
				note(err)
			}
		default:
			drained = true
		}
	}
	r.mu.Lock()
	gaps := r.gaps
	r.gaps = map[string]*credentialUsageGapNote{}
	r.mu.Unlock()
	for tenantID, gap := range gaps {
		id := googleuuid.NewSHA1(credentialUsageNamespace, []byte("gap\x00"+tenantID+"\x00"+gap.from.Format(time.RFC3339Nano)+"\x00"+
			gap.to.Format(time.RFC3339Nano)+"\x00"+strconv.FormatInt(gap.dropped, 10))).String()
		if err := sink.RecordCredentialUsageGap(ctx, tenantID, id, projections.CredentialUsageGap{From: gap.from, To: gap.to, Dropped: gap.dropped}); err != nil {
			r.mu.Lock()
			if kept := r.gaps[tenantID]; kept == nil {
				r.gaps[tenantID] = gap
			} else {
				kept.dropped += gap.dropped
				if gap.from.Before(kept.from) {
					kept.from = gap.from
				}
				if gap.to.After(kept.to) {
					kept.to = gap.to
				}
			}
			r.mu.Unlock()
			note(err)
		}
	}
	return firstErr
}

// credentialUseEventID names a note by its token, network, action, window and
// count, so replicas that note the same use record one event.
func credentialUseEventID(n credentialUseNote) string {
	digest := crypto.SHA256Hex([]byte(n.used.CredentialID + "\x00" + n.used.Source + "\x00" + n.used.Action))
	return googleuuid.NewSHA1(credentialUsageNamespace, []byte(n.tenant+"\x00"+digest+"\x00"+
		n.used.WindowStart.Format(time.RFC3339)+"\x00"+strconv.Itoa(n.used.Count))).String()
}

// noteAPITokenUse notes an authenticated API-token request for usage posture.
func (a *API) noteAPITokenUse(r *http.Request, rec store.APITokenRecord) {
	if a.usage == nil {
		return
	}
	a.usage.note(rec.TenantID, rec.ID, rec.Subject, credentialUseNetwork(netsec.ClientIP(r)), credentialUseAction(r))
}

// credentialUseNetwork is the client network a request came from: its /24 for
// IPv4, its /64 for IPv6. The client is the connection's peer, or behind a
// load balancer in server.trusted_proxies the address it forwarded (M1-L1); a
// forwarded-for header from any other peer is not trusted.
func credentialUseNetwork(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return "unknown"
	}
	addr = addr.Unmap().WithZone("")
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "unknown"
	}
	return prefix.String()
}

// credentialUseAction classes a request as a secret read, a lease request or
// another API call.
func credentialUseAction(r *http.Request) string {
	pattern := r.Pattern
	switch {
	case pattern == "POST /api/v1/secrets/leases" ||
		(r.Method == http.MethodGet && strings.HasPrefix(pattern, "GET /v1/") && strings.Contains(pattern, "/creds/")):
		return projections.CredentialActionLeaseRequest
	case pattern == "GET /api/v1/secrets/store/{name...}" || pattern == "GET /api/v1/secrets/store/history/{name...}" ||
		(strings.HasPrefix(pattern, "GET /v1/") && strings.Contains(pattern, "/data/")):
		return projections.CredentialActionSecretRead
	default:
		return projections.CredentialActionAPICall
	}
}

// RunCredentialUsageRecorder records noted API-token uses until ctx ends, then
// drains once more.
func (a *API) RunCredentialUsageRecorder(ctx context.Context) {
	if a.usage == nil || a.orch == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = a.usage.drain(final, a.orch)
			cancel()
			return
		case <-ticker.C:
			if err := a.usage.drain(ctx, a.orch); err != nil {
				slog.Warn("credential usage recorder could not record every use; the rest is recorded as a gap", slog.String("error", err.Error()))
			}
		}
	}
}

// DrainCredentialUsage records every noted use now.
func (a *API) DrainCredentialUsage(ctx context.Context) error {
	if a.usage == nil || a.orch == nil {
		return nil
	}
	return a.usage.drain(ctx, a.orch)
}
