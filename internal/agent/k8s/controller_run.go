// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RunOptions configures the event-driven controller.
type RunOptions struct {
	// ClusterID identifies the cluster in posture reports.
	ClusterID string
	// Report receives each posture report: one once a burst of changes has
	// been processed, and a heartbeat every ReportEvery.
	Report func(context.Context, ControllerPostureReport)
	// ReportEvery is the posture heartbeat, and the reconcile interval the
	// control plane judges staleness by. Zero means thirty seconds.
	ReportEvery time.Duration
	// Resync re-queues every object this often, catching what no watch event
	// reports, such as a deleted certificate Secret. Zero means ten minutes.
	Resync time.Duration
	// Workers is how many objects are processed at once (never the same
	// object twice). Zero means two.
	Workers int
}

// permanentError marks a failure that retrying cannot fix (an invalid spec);
// the object is retried when it changes, not on a timer.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }

// Work-queue key prefixes. Kubernetes names cannot contain "/", so the text
// after the first "/" is the object's cache key.
const (
	keyIssuers     = "issuers"
	keyRequest     = "request/"
	keyCertificate = "certificate/"
	keyCSR         = "csr/"
	keyBundle      = "bundle/"
)

// Posture sections, as reported.
const (
	sectionCSR      = "csr"
	sectionRequests = "requests"
	sectionBundles  = "bundles"
)

// controllerRuntime is the informer/work-queue form of IssuerController: each
// resource's informer turns watch events into object keys, and workers
// converge one object per key with the same per-object functions the full
// Reconcile pass uses.
type controllerRuntime struct {
	c     *IssuerController
	opts  RunOptions
	queue *workQueue

	clusterIssuers, issuers, requests, certificates, csrs, bundles, configMaps *informer

	mu                            sync.Mutex
	clusterConfigs, issuerConfigs map[string]issuerConfig
	issuersSynced                 bool
	posture                       map[string]map[string]PostureResource
	failing                       map[string]map[string]bool
	changed                       bool
}

// Run converges trstctl issuers, cert-manager CertificateRequests, trstctl
// Certificates, native CertificateSigningRequests and TrustBundles as their
// watch events arrive, until ctx ends. It is the event-driven alternative to
// calling Reconcile on a timer.
func (c *IssuerController) Run(ctx context.Context, opts RunOptions) error {
	if opts.ReportEvery <= 0 {
		opts.ReportEvery = 30 * time.Second
	}
	if opts.Resync <= 0 {
		opts.Resync = 10 * time.Minute
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	rt := &controllerRuntime{
		c: c, opts: opts, queue: newWorkQueue(time.Second, 5*time.Minute),
		posture: map[string]map[string]PostureResource{sectionCSR: {}, sectionRequests: {}, sectionBundles: {}},
		failing: map[string]map[string]bool{sectionCSR: {}, sectionRequests: {}, sectionBundles: {}},
	}
	issuersChanged := func(string, map[string]any) { rt.queue.add(keyIssuers) }
	prefixed := func(prefix string) func(string, map[string]any) {
		return func(key string, _ map[string]any) { rt.queue.add(prefix + key) }
	}
	rt.clusterIssuers = newInformer(c.client, clusterIssuerCollectionPath(), "", issuersChanged)
	rt.issuers = newInformer(c.client, issuerCollectionPath(""), "", issuersChanged)
	rt.requests = newInformer(c.client, "/apis/cert-manager.io/v1/certificaterequests", "", prefixed(keyRequest))
	rt.certificates = newInformer(c.client, nativeCertificateCollectionPath(""), "", prefixed(keyCertificate))
	rt.csrs = newInformer(c.client, certificateSigningRequestsPath(), "", prefixed(keyCSR))
	rt.bundles = newInformer(c.client, trustBundleCollectionPath(), "", prefixed(keyBundle))
	// A distributed ConfigMap that is edited or deleted re-queues its bundle.
	rt.configMaps = newInformer(c.client, "/api/v1/configmaps", "app.kubernetes.io/managed-by=trstctl-agent",
		func(_ string, obj map[string]any) {
			meta, _ := obj["metadata"].(map[string]any)
			labels, _ := meta["labels"].(map[string]any)
			if bundle, _ := labels["trstctl.com/trust-bundle"].(string); bundle != "" {
				rt.queue.add(keyBundle + bundle)
			}
		})
	return rt.run(ctx)
}

func (rt *controllerRuntime) informers() []*informer {
	return []*informer{rt.clusterIssuers, rt.issuers, rt.requests, rt.certificates, rt.csrs, rt.bundles, rt.configMaps}
}

func (rt *controllerRuntime) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		rt.queue.shutDown()
		wg.Wait()
	}()
	for _, inf := range rt.informers() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inf.run(ctx)
		}()
	}
	rt.queue.add(keyIssuers)
	for range rt.opts.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				key, ok := rt.queue.get()
				if !ok {
					return
				}
				rt.process(ctx, key)
				rt.queue.done(key)
			}
		}()
	}

	resync := time.NewTicker(rt.opts.Resync)
	defer resync.Stop()
	heartbeat := time.NewTicker(rt.opts.ReportEvery)
	defer heartbeat.Stop()
	settle := time.NewTicker(time.Second)
	defer settle.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-resync.C:
			rt.enqueueAll()
		case <-heartbeat.C:
			rt.report(ctx)
		case <-settle.C:
			if rt.queue.idle() && rt.takeChanged() {
				rt.report(ctx)
			}
		}
	}
}

// enqueueAll queues every cached object.
func (rt *controllerRuntime) enqueueAll() {
	rt.queue.add(keyIssuers)
	rt.enqueueDependents()
	for _, key := range rt.bundles.keys() {
		rt.queue.add(keyBundle + key)
	}
}

// enqueueDependents queues everything whose issuer binding may have changed.
func (rt *controllerRuntime) enqueueDependents() {
	for _, pair := range []struct {
		prefix string
		inf    *informer
	}{{keyRequest, rt.requests}, {keyCertificate, rt.certificates}, {keyCSR, rt.csrs}} {
		for _, key := range pair.inf.keys() {
			rt.queue.add(pair.prefix + key)
		}
	}
}

func (rt *controllerRuntime) process(ctx context.Context, key string) {
	if key == keyIssuers {
		rt.processIssuers(ctx)
		return
	}
	rt.mu.Lock()
	ready := rt.issuersSynced
	clusterConfigs, issuerConfigs := rt.clusterConfigs, rt.issuerConfigs
	rt.mu.Unlock()
	if !ready {
		// Bindings are judged against issuers; wait for their first sync.
		rt.queue.addAfter(key, 200*time.Millisecond)
		return
	}
	switch {
	case strings.HasPrefix(key, keyBundle):
		name := strings.TrimPrefix(key, keyBundle)
		obj, ok := rt.bundles.get(name)
		if !ok {
			rt.forget(sectionBundles, key, name)
			return
		}
		_, posture, err := rt.c.syncTrustBundle(ctx, obj)
		rt.record(sectionBundles, key, name, posture, err)
	case strings.HasPrefix(key, keyCSR):
		name := strings.TrimPrefix(key, keyCSR)
		obj, ok := rt.csrs.get(name)
		if !ok {
			rt.forget(sectionCSR, key, name)
			return
		}
		_, posture, err := rt.c.syncKubernetesCSR(ctx, obj, issuerConfigs, clusterConfigs)
		rt.record(sectionCSR, key, name, posture, err)
	case strings.HasPrefix(key, keyRequest):
		name := strings.TrimPrefix(key, keyRequest)
		obj, ok := rt.requests.get(name)
		if !ok {
			rt.forget(sectionRequests, key, name)
			return
		}
		_, posture, err := rt.c.syncCertificateRequest(ctx, obj, issuerConfigs, clusterConfigs)
		if posture.Name == "" && err == nil {
			rt.forget(sectionRequests, key, name) // another issuer group's request
			return
		}
		rt.record(sectionRequests, key, name, posture, err)
	case strings.HasPrefix(key, keyCertificate):
		obj, ok := rt.certificates.get(strings.TrimPrefix(key, keyCertificate))
		if !ok {
			rt.queue.forget(key)
			return
		}
		now := time.Now()
		_, renewAt, err := rt.c.syncNativeCertificate(ctx, obj, issuerConfigs, clusterConfigs, now)
		if err != nil {
			rt.retry(key, err)
			return
		}
		rt.queue.forget(key)
		if !renewAt.IsZero() {
			rt.queue.addAfter(key, renewAt.Sub(now))
		}
	}
}

// processIssuers re-judges every issuer and, when the usable set changed,
// re-queues everything bound to one.
func (rt *controllerRuntime) processIssuers(ctx context.Context) {
	for _, inf := range []*informer{rt.clusterIssuers, rt.issuers} {
		if synced, _, _ := inf.state(); !synced {
			rt.queue.addAfter(keyIssuers, 200*time.Millisecond)
			return
		}
	}
	clusterConfigs, err := rt.c.syncIssuerResources(ctx, rt.clusterIssuers.snapshot(), clusterIssuerCollectionPath(), "ClusterIssuer")
	if err != nil {
		rt.retry(keyIssuers, err)
		return
	}
	issuerConfigs, err := rt.c.syncIssuerResources(ctx, rt.issuers.snapshot(), issuerCollectionPath(""), "Issuer")
	if err != nil {
		rt.retry(keyIssuers, err)
		return
	}
	rt.queue.forget(keyIssuers)
	rt.mu.Lock()
	changed := !rt.issuersSynced || !maps.Equal(rt.clusterConfigs, clusterConfigs) || !maps.Equal(rt.issuerConfigs, issuerConfigs)
	rt.clusterConfigs, rt.issuerConfigs, rt.issuersSynced = clusterConfigs, issuerConfigs, true
	rt.mu.Unlock()
	if changed {
		rt.enqueueDependents()
	}
}

// record keeps an object's posture and decides whether to retry it.
func (rt *controllerRuntime) record(section, key, name string, posture PostureResource, err error) {
	rt.mu.Lock()
	rt.posture[section][name] = posture
	if err != nil {
		rt.failing[section][name] = true
	} else {
		delete(rt.failing[section], name)
	}
	rt.changed = true
	rt.mu.Unlock()
	if err != nil {
		rt.retry(key, err)
		return
	}
	rt.queue.forget(key)
}

func (rt *controllerRuntime) forget(section, key, name string) {
	rt.mu.Lock()
	if _, ok := rt.posture[section][name]; ok {
		rt.changed = true
	}
	delete(rt.posture[section], name)
	delete(rt.failing[section], name)
	rt.mu.Unlock()
	rt.queue.forget(key)
}

func (rt *controllerRuntime) retry(key string, err error) {
	var invalid permanentError
	if errors.As(err, &invalid) {
		rt.queue.forget(key)
		return
	}
	rt.queue.retry(key)
}

func (rt *controllerRuntime) takeChanged() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	changed := rt.changed
	rt.changed = false
	return changed
}

func (rt *controllerRuntime) report(ctx context.Context) {
	if rt.opts.Report == nil {
		return
	}
	rt.opts.Report(ctx, rt.postureReport())
}

// postureReport describes what the controller holds now. A section is
// complete only when its informer has listed and no object in it is failing;
// cert-manager's section is complete and empty when cert-manager is not
// installed, as there is then nothing of it to sign.
func (rt *controllerRuntime) postureReport() ControllerPostureReport {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	section := func(name string, inf *informer, optional bool) PostureSection {
		resources := make([]PostureResource, 0, len(rt.posture[name]))
		for _, resource := range rt.posture[name] {
			resources = append(resources, resource)
		}
		sort.Slice(resources, func(i, j int) bool {
			if resources[i].Namespace != resources[j].Namespace {
				return resources[i].Namespace < resources[j].Namespace
			}
			return resources[i].Name < resources[j].Name
		})
		synced, installed, _ := inf.state()
		switch {
		case !synced || !rt.issuersSynced:
			return PostureSection{FailureCode: "not_reconciled", Resources: resources}
		case (!installed && !optional) || len(rt.failing[name]) > 0:
			return PostureSection{FailureCode: "reconcile_failed", Resources: resources}
		}
		return PostureSection{Complete: true, Resources: resources}
	}
	seconds := int(rt.opts.ReportEvery / time.Second)
	seconds = max(1, min(seconds, 86400))
	return ControllerPostureReport{
		ReportID: uuid.NewString(), ClusterID: rt.opts.ClusterID, ReconcileIntervalSeconds: seconds,
		CertificateSigning:  section(sectionCSR, rt.csrs, false),
		CertificateRequests: section(sectionRequests, rt.requests, true),
		TrustBundles:        section(sectionBundles, rt.bundles, false),
	}
}
