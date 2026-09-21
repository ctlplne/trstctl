// SPDX-License-Identifier: BUSL-1.1

package enrollproxy

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Surviving the loss of a relay (epic A4).
//
// One relay in a dark segment is a single point of failure for every enrollment
// in it, and the failure is silent until a certificate expires. Multiple relays
// fix that, but only if a client that was talking to one can finish with
// another — and the interesting question is what "finish" means.
//
// It does NOT mean resuming a half-finished exchange. An ACME order lives in the
// control plane, not in a relay, so a client whose relay dies mid-order retries
// and the control plane still has its order: the relay was never holding
// anything. That is a property of having built the proxy stateless, and it is
// what makes failover a routing problem rather than a replication problem.
//
// So this is deliberately small. It picks a healthy upstream, notices when one
// stops answering, and stops sending to it. Anything cleverer — sticky sessions,
// request replay, partial-state handoff — would be inventing state the design
// went to some trouble not to have.

// Pool routes enrollment traffic across several control-plane endpoints.
//
// The endpoints are the CONTROL PLANE's, not other relays'. A relay chaining to
// a relay would multiply the trust surface for no benefit: each hop is another
// process inside the customer's network that could be compromised, and none of
// them is any closer to the answer.
type Pool struct {
	mu      sync.Mutex
	targets []*poolTarget
	next    int
	// cooldown is how long an endpoint stays out after failing.
	//
	// Short, because the common cause is a rolling restart rather than an
	// outage: a long cooldown turns a thirty-second deploy into minutes of
	// reduced capacity, and the retry costs one request.
	cooldown time.Duration
	now      func() time.Time
	// lastFailoverUnixNano records a transport failure that made this relay
	// choose another control-plane endpoint. The timestamp survives as evidence
	// in the control plane's immutable heartbeat stream.
	lastFailoverUnixNano int64
	// refused counts attempts to turn the pool into a general control-plane
	// tunnel. Pool-level allowlisting happens before any target Proxy sees the
	// request, so this counter must live here rather than only on each target.
	refused atomic.Int64
}

type poolTarget struct {
	proxy     *Proxy
	unhealthy bool
	recoverAt time.Time
	failures  int
	successes int
}

// ErrNoHealthyUpstream is returned when every endpoint is in cooldown.
var ErrNoHealthyUpstream = errors.New("enrollproxy: no control-plane endpoint is answering")

// NewPool builds a pool over the given control-plane endpoints.
func NewPool(upstreams []string, client *http.Client, cooldown time.Duration) (*Pool, error) {
	return newPool(upstreams, "", client, cooldown)
}

// NewPoolWithPublicURL builds a pool whose every endpoint presents the same
// stable segment URL to the control plane. Multiple relay processes behind the
// same segment URL can therefore continue one stock-client ACME flow.
func NewPoolWithPublicURL(upstreams []string, publicURL string, client *http.Client, cooldown time.Duration) (*Pool, error) {
	if publicURL == "" {
		return nil, errors.New("enrollproxy: public URL is required")
	}
	return newPool(upstreams, publicURL, client, cooldown)
}

func newPool(upstreams []string, publicURL string, client *http.Client, cooldown time.Duration) (*Pool, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("enrollproxy: a proxy pool needs at least one control-plane endpoint")
	}
	if cooldown <= 0 {
		cooldown = 15 * time.Second
	}
	p := &Pool{cooldown: cooldown, now: time.Now}
	for _, u := range upstreams {
		var proxy *Proxy
		var err error
		if publicURL == "" {
			proxy, err = New(u, client)
		} else {
			proxy, err = NewWithPublicURL(u, publicURL, client)
		}
		if err != nil {
			return nil, err
		}
		p.targets = append(p.targets, &poolTarget{proxy: proxy})
	}
	return p, nil
}

// ServeHTTP forwards through a healthy endpoint, failing over on error.
//
// A 5xx from the control plane is NOT a failover trigger. It is an answer: the
// control plane considered the request and refused it, and retrying elsewhere
// would ask a second endpoint the same question and get the same refusal, while
// making a real error look like a flapping relay. Only a transport failure —
// nothing answered — moves to the next endpoint.
func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Proxied(r.URL.Path) {
		p.refused.Add(1)
		http.Error(w, "not an enrollment protocol path", http.StatusNotFound)
		return
	}
	for attempt := 0; attempt < len(p.targets); attempt++ {
		target := p.pick()
		if target == nil {
			break
		}
		rec := &failoverRecorder{ResponseWriter: w}
		target.proxy.ServeHTTP(rec, r)
		if !rec.transportFailed {
			if rec.upstreamResponded {
				p.markHealthy(target)
			}
			return
		}
		// Nothing answered. Take this endpoint out and try the next; the client
		// sees one response, from whichever endpoint produced one.
		p.markUnhealthy(target)
	}
	http.Error(w, "no control-plane endpoint is answering", http.StatusServiceUnavailable)
}

// pick returns the next endpoint that is not in cooldown.
func (p *Pool) pick() *poolTarget {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for i := 0; i < len(p.targets); i++ {
		t := p.targets[(p.next+i)%len(p.targets)]
		if t.unhealthy && now.Before(t.recoverAt) {
			continue
		}
		p.next = (p.next + i + 1) % len(p.targets)
		return t
	}
	return nil
}

func (p *Pool) markHealthy(t *poolTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t.unhealthy = false
	t.successes++
}

func (p *Pool) markUnhealthy(t *poolTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t.unhealthy = true
	t.failures++
	t.recoverAt = p.now().Add(p.cooldown)
	p.lastFailoverUnixNano = p.now().UTC().UnixNano()
}

// Health reports per-endpoint state for the agent's heartbeat.
type Health struct {
	Healthy         int
	Unhealthy       int
	Unknown         int
	Failures        int
	Forwarded       int64
	Refused         int64
	LastForwardedAt time.Time
	LastFailoverAt  time.Time
}

// Health snapshots the pool.
func (p *Pool) Health() Health {
	if p == nil {
		return Health{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var h Health
	h.Refused = p.refused.Load()
	for _, t := range p.targets {
		h.Failures += t.failures
		forwarded, refused := t.proxy.Stats()
		h.Forwarded += forwarded
		h.Refused += refused
		if at := t.proxy.LastForwardedAt(); at.After(h.LastForwardedAt) {
			h.LastForwardedAt = at
		}
		if t.successes == 0 && t.failures == 0 {
			h.Unknown++
			continue
		}
		// Cooldown expiry means "eligible for a probe", not "healthy". Only a
		// completed response can clear the unhealthy bit; otherwise the durable
		// topology would claim an endpoint answered when nobody had asked it.
		if t.unhealthy {
			h.Unhealthy++
			continue
		}
		h.Healthy++
	}
	if p.lastFailoverUnixNano != 0 {
		h.LastFailoverAt = time.Unix(0, p.lastFailoverUnixNano).UTC()
	}
	return h
}

// failoverRecorder notices whether the proxy produced a real response or a
// transport failure. Proxy marks the transport failure out of band, so a real
// HTTP 502 from the control plane remains an ordinary response.
type failoverRecorder struct {
	http.ResponseWriter
	wrote             bool
	transportFailed   bool
	upstreamResponded bool
}

func (f *failoverRecorder) WriteHeader(code int) {
	if !f.wrote {
		f.wrote = true
	}
	f.ResponseWriter.WriteHeader(code)
}

func (f *failoverRecorder) markTransportFailure() {
	f.transportFailed = true
}

func (f *failoverRecorder) markUpstreamResponse() {
	f.upstreamResponded = true
}

func (f *failoverRecorder) Write(b []byte) (int, error) {
	if f.transportFailed {
		// Swallow the proxy's own "could not reach" body: the client should see
		// the next endpoint's answer, not a message about an endpoint it never
		// asked for.
		return len(b), nil
	}
	return f.ResponseWriter.Write(b)
}
