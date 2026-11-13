// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Managed-key provider readiness (A169-L2). A provider whose credential comes
// from a workload identity exchanges the platform's token at its token
// endpoint; when that exchange cannot succeed, every managed-key request to
// the provider fails. The signer exchanges once as it starts, keeps
// retrying a failed exchange with backoff until one succeeds, and reports
// each provider's state in Health, so the control plane's readiness shows a
// provider that cannot authenticate before a request finds out.

// ManagedKeyReadinessProbe exchanges a provider's platform token once. It
// returns a *ManagedKeyReadinessError naming a closed reason, or nil.
type ManagedKeyReadinessProbe func(ctx context.Context) error

// ManagedKeyReadinessError carries a closed reason code; provider text never
// leaves the signer through it.
type ManagedKeyReadinessError struct{ Code string }

func (e *ManagedKeyReadinessError) Error() string { return "managed-key provider not ready: " + e.Code }

// The closed reason codes.
const (
	ReadinessPending             = "pending"
	ReadinessTokenUnreadable     = "federated_token_unreadable"
	ReadinessExchangeRefused     = "token_exchange_refused"
	ReadinessExchangeUnreachable = "token_exchange_unreachable"
	ReadinessExchangeFailed      = "token_exchange_failed"
)

var readinessCodes = map[string]bool{ReadinessTokenUnreadable: true, ReadinessExchangeRefused: true,
	ReadinessExchangeUnreachable: true, ReadinessExchangeFailed: true}

const (
	readinessProbeTimeout = 30 * time.Second
	readinessRetryMin     = 15 * time.Second
	readinessRetryMax     = 5 * time.Minute
)

// ManagedKeyProviderReadiness is one provider's reported state.
type ManagedKeyProviderReadiness struct {
	Provider string
	Ready    bool
	Reason   string
	Checked  time.Time
}

type managedKeyReadiness struct {
	mu       sync.Mutex
	state    map[string]ManagedKeyProviderReadiness
	probes   map[string]ManagedKeyReadinessProbe
	stop     chan struct{}
	stopOnce sync.Once
	retryMin time.Duration
	retryMax time.Duration
	now      func() time.Time
}

// WithManagedKeyReadinessProbes reports, in Health, whether each named
// provider's workload identity exchange has succeeded, probing once the server
// is built and retrying a failure with backoff until it succeeds. Shutdown
// stops the probes.
func WithManagedKeyReadinessProbes(probes map[string]ManagedKeyReadinessProbe) ServerOption {
	return func(s *Server) {
		r := s.ensureReadiness()
		for provider, probe := range probes {
			if probe == nil {
				continue
			}
			r.probes[provider] = probe
			r.state[provider] = ManagedKeyProviderReadiness{Provider: provider, Reason: ReadinessPending}
		}
	}
}

// WithManagedKeyReadinessBackoff sets the retry backoff for failed readiness
// probes (by default 15 seconds, doubling to 5 minutes).
func WithManagedKeyReadinessBackoff(min, max time.Duration) ServerOption {
	return func(s *Server) {
		r := s.ensureReadiness()
		if min > 0 {
			r.retryMin = min
		}
		if max >= r.retryMin {
			r.retryMax = max
		}
	}
}

func (s *Server) ensureReadiness() *managedKeyReadiness {
	if s.readiness == nil {
		s.readiness = &managedKeyReadiness{state: map[string]ManagedKeyProviderReadiness{}, probes: map[string]ManagedKeyReadinessProbe{},
			stop: make(chan struct{}), retryMin: readinessRetryMin, retryMax: readinessRetryMax, now: time.Now}
	}
	return s.readiness
}

// start launches the probes once every option has been applied.
func (r *managedKeyReadiness) start() {
	if r == nil {
		return
	}
	for provider, probe := range r.probes {
		go r.probeUntilReady(provider, probe)
	}
}

// CombineServerOptions applies several options as one.
func CombineServerOptions(opts ...ServerOption) ServerOption {
	return func(s *Server) {
		for _, opt := range opts {
			if opt != nil {
				opt(s)
			}
		}
	}
}

func (r *managedKeyReadiness) probeUntilReady(provider string, probe ManagedKeyReadinessProbe) {
	delay := r.retryMin
	for {
		ctx, cancel := context.WithTimeout(context.Background(), readinessProbeTimeout)
		err := probe(ctx)
		cancel()
		r.record(provider, err)
		if err == nil {
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-r.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay *= 2; delay > r.retryMax {
			delay = r.retryMax
		}
	}
}

func (r *managedKeyReadiness) record(provider string, err error) {
	state := ManagedKeyProviderReadiness{Provider: provider, Ready: err == nil, Checked: r.now().UTC()}
	if err != nil {
		state.Reason = ReadinessExchangeFailed
		var coded *ManagedKeyReadinessError
		if errors.As(err, &coded) && readinessCodes[coded.Code] {
			state.Reason = coded.Code
		}
	}
	r.mu.Lock()
	r.state[provider] = state
	r.mu.Unlock()
}

func (r *managedKeyReadiness) snapshot() []*signerpb.ManagedKeyProviderReadiness {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*signerpb.ManagedKeyProviderReadiness, 0, len(r.state))
	for _, st := range r.state {
		item := &signerpb.ManagedKeyProviderReadiness{Provider: st.Provider, Ready: st.Ready, Reason: st.Reason}
		if !st.Checked.IsZero() {
			item.CheckedUnix = st.Checked.Unix()
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

func (r *managedKeyReadiness) close() {
	if r != nil {
		r.stopOnce.Do(func() { close(r.stop) })
	}
}
