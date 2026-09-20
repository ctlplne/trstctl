// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const coordinationLeasePlural = "leases"

type clockFunc func() time.Time

// LeaseElector coordinates multiple operator replicas through the Kubernetes
// coordination.k8s.io Lease API. It is deliberately small: one GET plus a
// create-or-patch attempt per campaign, with API conflicts treated as follower
// outcomes rather than fatal errors.
type LeaseElector struct {
	client       *Client
	namespace    string
	name         string
	identity     string
	duration     time.Duration
	now          clockFunc
	durationSecs int
}

func NewLeaseElector(client *Client, namespace, name, identity string, duration time.Duration, now clockFunc) *LeaseElector {
	if strings.TrimSpace(name) == "" {
		name = "trstctl-operator"
	}
	if strings.TrimSpace(identity) == "" {
		identity = "unknown"
	}
	if duration <= 0 {
		duration = 15 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	secs := int(duration.Seconds())
	if secs < 1 {
		secs = 1
	}
	return &LeaseElector{
		client:       client,
		namespace:    namespace,
		name:         name,
		identity:     identity,
		duration:     duration,
		now:          now,
		durationSecs: secs,
	}
}

func leaseItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/coordination.k8s.io/v1/namespaces/%s/%s/%s", ns, coordinationLeasePlural, name)
}

func leaseCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/coordination.k8s.io/v1/namespaces/%s/%s", ns, coordinationLeasePlural)
}

type leaseObject struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity"`
		LeaseDurationSeconds int    `json:"leaseDurationSeconds"`
		AcquireTime          string `json:"acquireTime"`
		RenewTime            string `json:"renewTime"`
	} `json:"spec"`
}

// TryAcquireOrRenew returns true only for the replica that currently owns or
// successfully acquires the Lease. Followers get false with nil error while the
// current lease is fresh.
func (e *LeaseElector) TryAcquireOrRenew(ctx context.Context) (bool, error) {
	st, body, err := e.client.do(ctx, http.MethodGet, leaseItemPath(e.namespace, e.name), "", nil)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		return e.createLease(ctx)
	}
	if st/100 != 2 {
		return false, fmt.Errorf("operator: get leader lease %s/%s: status %d: %s", e.namespace, e.name, st, string(body))
	}
	var lease leaseObject
	if err := json.Unmarshal(body, &lease); err != nil {
		return false, fmt.Errorf("operator: decode leader lease: %w", err)
	}
	holder := lease.Spec.HolderIdentity
	if holder != "" && holder != e.identity && !e.expired(lease) {
		return false, nil
	}
	return e.patchLease(ctx, holder != e.identity)
}

func (e *LeaseElector) createLease(ctx context.Context) (bool, error) {
	now := e.timestamp()
	obj := map[string]any{
		"apiVersion": "coordination.k8s.io/v1",
		"kind":       "Lease",
		"metadata": map[string]any{
			"name":      e.name,
			"namespace": e.namespace,
		},
		"spec": map[string]any{
			"holderIdentity":       e.identity,
			"leaseDurationSeconds": e.durationSecs,
			"acquireTime":          now,
			"renewTime":            now,
		},
	}
	st, body, err := e.client.do(ctx, http.MethodPost, leaseCollectionPath(e.namespace), "", obj)
	if err != nil {
		return false, err
	}
	if st == http.StatusConflict {
		return false, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("operator: create leader lease %s/%s: status %d: %s", e.namespace, e.name, st, string(body))
	}
	return true, nil
}

func (e *LeaseElector) patchLease(ctx context.Context, acquired bool) (bool, error) {
	now := e.timestamp()
	spec := map[string]any{
		"holderIdentity":       e.identity,
		"leaseDurationSeconds": e.durationSecs,
		"renewTime":            now,
	}
	if acquired {
		spec["acquireTime"] = now
	}
	patch := map[string]any{"spec": spec}
	st, body, err := e.client.do(ctx, http.MethodPatch, leaseItemPath(e.namespace, e.name), "application/merge-patch+json", patch)
	if err != nil {
		return false, err
	}
	if st == http.StatusConflict || st == http.StatusNotFound {
		return false, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("operator: patch leader lease %s/%s: status %d: %s", e.namespace, e.name, st, string(body))
	}
	return true, nil
}

func (e *LeaseElector) expired(lease leaseObject) bool {
	renew, err := time.Parse(time.RFC3339Nano, firstNonEmpty(lease.Spec.RenewTime, lease.Spec.AcquireTime))
	if err != nil {
		return true
	}
	duration := e.duration
	if lease.Spec.LeaseDurationSeconds > 0 {
		duration = time.Duration(lease.Spec.LeaseDurationSeconds) * time.Second
	}
	return !e.now().Before(renew.Add(duration))
}

func (e *LeaseElector) timestamp() string {
	return e.now().UTC().Format(time.RFC3339Nano)
}
