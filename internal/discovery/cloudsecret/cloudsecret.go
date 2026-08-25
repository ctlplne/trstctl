// SPDX-License-Identifier: MPL-2.0

// Package cloudsecret inventories metadata from managed secret stores. Content
// inspection is a separate explicit provider option: only then may an adapter
// fetch a value long enough to inspect it through internal/crypto/certinfo and
// wipe it. Both modes return non-secret metadata only. State changes happen
// later through the discovery orchestrator, preserving AN-2.
package cloudsecret

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const (
	// SourceKind is the served discovery source kind for cloud secret managers.
	SourceKind = "cloud_secret"
	// FindingKindCertificate is the discovery finding kind emitted for certificate
	// material imported from a secret manager.
	FindingKindCertificate = "x509_certificate"
	// FindingKindSecretResource is emitted for metadata-only inventory without
	// retrieving the resource value.
	FindingKindSecretResource = "cloud_secret_resource"
)

// Secret is one secret-manager value under inspection. Value may contain private
// material and must be wiped by the provider after InspectSecret returns.
type Secret struct {
	Name       string
	ResourceID string
	Location   string
	Provenance string
	Value      []byte
	Metadata   map[string]string
}

// Found is one certificate discovered inside a managed cloud secret.
type Found struct {
	Kind       string
	Provider   string
	ResourceID string
	SecretName string
	Location   string
	Provenance string
	Cert       certinfo.Info
	Metadata   map[string]string
}

// MetadataFound creates a value-free inventory record from a list or metadata
// response. It is safe to call regardless of content-inspection policy.
func MetadataFound(provider, resourceID, name, location, provenance string, metadata map[string]string) Found {
	return Found{
		Kind: FindingKindSecretResource, Provider: provider, ResourceID: nonempty(resourceID, name),
		SecretName: name, Location: location, Provenance: provenance, Metadata: cloneMap(metadata),
	}
}

// InspectSecret extracts certificate findings from one secret value. Non-certificate
// secrets return no findings and no error.
func InspectSecret(provider string, secret Secret) ([]Found, error) {
	infos, err := certinfo.InspectAll(secret.Value)
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return nil, nil
	}
	out := make([]Found, 0, len(infos))
	for i, info := range infos {
		meta := cloneMap(secret.Metadata)
		if len(infos) > 1 {
			meta["certificate_index"] = fmt.Sprint(i)
		}
		out = append(out, Found{
			Kind:       FindingKindCertificate,
			Provider:   provider,
			ResourceID: nonempty(secret.ResourceID, secret.Name),
			SecretName: secret.Name,
			Location:   secret.Location,
			Provenance: secret.Provenance,
			Cert:       info,
			Metadata:   meta,
		})
	}
	return out, nil
}

func cloneMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func nonempty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Sink receives discovered cloud-secret certificate findings.
type Sink interface {
	Record(ctx context.Context, f Found) error
}

// MemorySink collects discoveries in memory for tests.
type MemorySink struct {
	mu    sync.Mutex
	items []Found
}

// NewMemorySink returns an empty memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores one finding.
func (m *MemorySink) Record(_ context.Context, f Found) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, f)
	return nil
}

// All returns a snapshot of recorded findings.
func (m *MemorySink) All() []Found {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Found, len(m.items))
	copy(out, m.items)
	return out
}

// Provider enumerates certificate-bearing secrets from one cloud service.
type Provider interface {
	Name() string
	Enumerate(ctx context.Context) ([]Found, error)
}

// Report summarizes a cloud secret-manager discovery pass.
type Report struct {
	Providers  int
	Discovered int
	Failed     int
}

type config struct {
	workers int
	queue   int
	backoff time.Duration
}

// Option configures a Discoverer.
type Option func(*config)

// WithWorkers sets the maximum provider concurrency.
func WithWorkers(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.workers = n
		}
	}
}

// WithQueue sets the bounded provider queue.
func WithQueue(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.queue = n
		}
	}
}

// WithBackoff sets the retry wait for backpressure.
func WithBackoff(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// Discoverer enumerates providers on an isolated bounded worker pool.
type Discoverer struct {
	sink    Sink
	pool    *bulkhead.Pool
	backoff time.Duration
}

// NewDiscoverer builds a cloud secret-manager discoverer.
func NewDiscoverer(sink Sink, opts ...Option) *Discoverer {
	cfg := config{workers: 4, queue: 64, backoff: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	return &Discoverer{
		sink:    sink,
		pool:    bulkhead.New(bulkhead.Config{Name: "cloud-secret-discovery", Workers: cfg.workers, Queue: cfg.queue}),
		backoff: cfg.backoff,
	}
}

// Close shuts down the worker pool.
func (d *Discoverer) Close() { d.pool.Close() }

// Discover records every finding from every provider. A provider failure is counted
// and does not discard other providers' findings.
func (d *Discoverer) Discover(ctx context.Context, providers []Provider) Report {
	rep := Report{Providers: len(providers)}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, p := range providers {
		p := p
		wg.Add(1)
		task := func() {
			defer wg.Done()
			found, err := p.Enumerate(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				rep.Failed++
				return
			}
			for _, f := range found {
				if err := d.sink.Record(ctx, f); err != nil {
					rep.Failed++
					return
				}
				rep.Discovered++
			}
		}
		if err := d.submit(ctx, task); err != nil {
			wg.Done()
			mu.Lock()
			rep.Failed++
			mu.Unlock()
		}
	}
	wg.Wait()
	return rep
}

func (d *Discoverer) submit(ctx context.Context, task func()) error {
	for {
		err := d.pool.Submit(task)
		if err == nil {
			return nil
		}
		var rj *bulkhead.Rejected
		if !errors.As(err, &rj) || !rj.Retryable() {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.backoff):
		}
	}
}
