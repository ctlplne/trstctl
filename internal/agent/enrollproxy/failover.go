// SPDX-License-Identifier: MPL-2.0

package enrollproxy

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// Surviving the loss of a relay (epic A4).
//
// One relay in a dark segment is a single point of failure for every enrolment
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

// Pool routes enrolment traffic across several control-plane endpoints.
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
	if len(upstreams) == 0 {
		return nil, errors.New("enrollproxy: a proxy pool needs at least one control-plane endpoint")
	}
	if cooldown <= 0 {
		cooldown = 15 * time.Second
	}
	p := &Pool{cooldown: cooldown, now: time.Now}
	for _, u := range upstreams {
		proxy, err := New(u, client)
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
		http.Error(w, "not an enrolment protocol path", http.StatusNotFound)
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
			p.markHealthy(target)
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
}

// Health reports per-endpoint state for the agent's heartbeat.
type Health struct {
	Healthy   int
	Unhealthy int
	Failures  int
}

// Health snapshots the pool.
func (p *Pool) Health() Health {
	if p == nil {
		return Health{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var h Health
	now := p.now()
	for _, t := range p.targets {
		h.Failures += t.failures
		if t.unhealthy && now.Before(t.recoverAt) {
			h.Unhealthy++
			continue
		}
		h.Healthy++
	}
	return h
}

// failoverRecorder notices whether the proxy produced a real response or a
// transport failure.
//
// It distinguishes them by the status the proxy writes on an unreachable
// upstream. A 502 that the proxy itself generated means nothing answered; a 502
// FROM the control plane would have a body it wrote, and is an answer. The two
// are told apart by whether the proxy short-circuited before any upstream bytes
// arrived, which is exactly what this records.
type failoverRecorder struct {
	http.ResponseWriter
	wrote           bool
	transportFailed bool
}

func (f *failoverRecorder) WriteHeader(code int) {
	if !f.wrote {
		f.wrote = true
		if code == http.StatusBadGateway {
			// The proxy writes 502 only when it could not reach upstream. Hold
			// the header back so a retry can still produce the real response.
			f.transportFailed = true
			return
		}
	}
	f.ResponseWriter.WriteHeader(code)
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
