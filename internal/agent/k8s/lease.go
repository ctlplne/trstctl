// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Leader election for the cluster-scoped reconcilers. ELI5: the agent runs as
// a DaemonSet, so every node has a pod that could reconcile the SAME
// cluster-scoped Issuer/TrustBundle objects. Signing and status writes are
// idempotent, so concurrency is not a correctness bug — but N pods hammering
// the API server for one object's worth of work is wasteful and makes audit
// noisy. A coordination.k8s.io Lease elects one writer; the others idle and
// take over within one lease duration if the holder dies.
//
// This is a compare-and-swap over the raw API, matching the rest of this
// package (no controller-runtime dependency): renewals are conditional on the
// resourceVersion we last read, so two pods cannot both believe they hold it.

const (
	// LeaseDuration is how long a lease is honored without renewal. A
	// follower waits out this window before taking over, so a rolling
	// restart does not produce two active reconcilers.
	LeaseDuration = 30 * time.Second
	// LeaseRenewInterval is how often the holder refreshes; comfortably
	// inside LeaseDuration so a slow API call does not lose leadership.
	LeaseRenewInterval = 10 * time.Second
)

type leaseSpec struct {
	HolderIdentity       string `json:"holderIdentity"`
	LeaseDurationSeconds int    `json:"leaseDurationSeconds"`
	AcquireTime          string `json:"acquireTime,omitempty"`
	RenewTime            string `json:"renewTime,omitempty"`
}

type leaseObject struct {
	APIVersion string         `json:"apiVersion,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Spec       leaseSpec      `json:"spec"`
}

// Lease is a single named coordination.k8s.io/v1 Lease used to elect one
// reconciler among the DaemonSet's pods.
type Lease struct {
	client   *Client
	name     string
	identity string
	now      func() time.Time
}

// NewLease builds a lease handle in the client's namespace. identity should be
// unique per pod (the pod name; the downward API supplies it).
func NewLease(client *Client, name, identity string) *Lease {
	return &Lease{client: client, name: name, identity: identity, now: time.Now}
}

func (l *Lease) path() string {
	return fmt.Sprintf("/apis/coordination.k8s.io/v1/namespaces/%s/leases", l.client.Namespace())
}

// Acquire tries to become (or stay) the leader exactly once. It returns true
// when this identity holds the lease afterward. A lost race is an ordinary
// false, not an error: the other pod is doing the work.
func (l *Lease) Acquire(ctx context.Context) (bool, error) {
	st, body, err := l.client.request(ctx, http.MethodGet, l.path()+"/"+l.name, nil)
	if err != nil {
		return false, err
	}
	nowStr := l.now().UTC().Format(time.RFC3339)

	if st == http.StatusNotFound {
		created := leaseObject{
			APIVersion: "coordination.k8s.io/v1",
			Kind:       "Lease",
			Metadata:   map[string]any{"name": l.name, "namespace": l.client.Namespace()},
			Spec: leaseSpec{
				HolderIdentity:       l.identity,
				LeaseDurationSeconds: int(LeaseDuration / time.Second),
				AcquireTime:          nowStr,
				RenewTime:            nowStr,
			},
		}
		cst, _, cerr := l.client.request(ctx, http.MethodPost, l.path(), created)
		if cerr != nil {
			return false, cerr
		}
		// 409 means another pod created it first — it leads this round.
		return cst >= 200 && cst < 300, nil
	}
	if st < 200 || st >= 300 {
		return false, fmt.Errorf("k8s: read lease %s: status %d", l.name, st)
	}

	var current leaseObject
	if err := json.Unmarshal(body, &current); err != nil {
		return false, fmt.Errorf("k8s: decode lease %s: %w", l.name, err)
	}
	held := current.Spec.HolderIdentity == l.identity
	if !held && !l.expired(current.Spec) {
		return false, nil
	}

	current.Spec.HolderIdentity = l.identity
	current.Spec.LeaseDurationSeconds = int(LeaseDuration / time.Second)
	current.Spec.RenewTime = nowStr
	if !held {
		current.Spec.AcquireTime = nowStr
	}
	// The resourceVersion carried in metadata makes this a compare-and-swap:
	// a stale write loses with 409 rather than stomping the real holder.
	ust, _, uerr := l.client.request(ctx, http.MethodPut, l.path()+"/"+l.name, current)
	if uerr != nil {
		return false, uerr
	}
	return ust >= 200 && ust < 300, nil
}

// expired reports whether a lease's renewal window has elapsed, which is what
// lets a follower take over after the holder dies.
func (l *Lease) expired(spec leaseSpec) bool {
	if spec.HolderIdentity == "" {
		return true
	}
	renewed, err := time.Parse(time.RFC3339, spec.RenewTime)
	if err != nil {
		return true
	}
	duration := time.Duration(spec.LeaseDurationSeconds) * time.Second
	if duration <= 0 {
		duration = LeaseDuration
	}
	return l.now().After(renewed.Add(duration))
}
