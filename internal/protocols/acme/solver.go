package acme

import (
	"context"
	"fmt"
	"sync"
)

// DNSProvider publishes and retracts the DNS-01 TXT records trstctl needs when it
// acts as an ACME *client* against an upstream CA (or drives a managed zone for
// its own DV). Real providers — Route53, Cloudflare, Google Cloud DNS, RFC 2136 —
// implement this interface and are hosted as capability-gated WASM connector
// plugins (F20); the interface is the plugin template. A provider does exactly
// two things and nothing else: it never reads private keys and never makes
// outbound calls beyond its zone API.
type DNSProvider interface {
	// PresentTXT publishes a TXT record `name` (an FQDN such as
	// "_acme-challenge.example.com") carrying `value`. Publishing the same
	// (name, value) twice is a no-op (idempotent).
	PresentTXT(ctx context.Context, name, value string) error
	// CleanupTXT removes a previously published (name, value). Removing an absent
	// record is a no-op.
	CleanupTXT(ctx context.Context, name, value string) error
}

// DNS01Solver answers a dns-01 challenge by publishing the required TXT record
// through a DNSProvider. It computes the record name and value exactly as the
// validator expects (DNS01RecordName / DNS01RecordValue), so the publish side and
// the verify side can never drift. When Resolver is set it self-checks that the
// record is visible before returning, so the CA is only asked to validate once
// propagation has happened.
type DNS01Solver struct {
	Provider DNSProvider
	Resolver Resolver // optional single self-check before the CA validates
	// Propagation, when set, waits for the record to be visible across every
	// authoritative view before returning (S8b.2); it supersedes Resolver.
	Propagation *PropagationChecker
}

// Present publishes the TXT record for (domain, keyAuth) and returns a cleanup
// function that retracts it. If a Resolver is configured it confirms the record
// is resolvable first, retracting and failing closed if not.
func (s DNS01Solver) Present(ctx context.Context, domain, keyAuth string) (cleanup func() error, err error) {
	if s.Provider == nil {
		return nil, fmt.Errorf("acme: DNS01Solver has no provider")
	}
	name := DNS01RecordName(domain)
	value := DNS01RecordValue(keyAuth)
	if err := s.Provider.PresentTXT(ctx, name, value); err != nil {
		return nil, fmt.Errorf("acme: dns-01 present %s: %w", name, err)
	}
	cleanup = func() error { return s.Provider.CleanupTXT(ctx, name, value) }
	// Wait for the record to be observable before the CA validates. A configured
	// PropagationChecker confirms visibility across every authoritative view
	// (S8b.2) and supersedes the single-Resolver self-check.
	switch {
	case s.Propagation != nil:
		if perr := s.Propagation.Wait(ctx, name, value); perr != nil {
			_ = cleanup()
			return nil, fmt.Errorf("acme: dns-01 propagation %s: %w", name, perr)
		}
	case s.Resolver != nil:
		records, lerr := s.Resolver.LookupTXT(ctx, name)
		if lerr != nil {
			_ = cleanup()
			return nil, fmt.Errorf("acme: dns-01 self-check %s: %w", name, lerr)
		}
		if !containsTXT(records, value) {
			_ = cleanup()
			return nil, fmt.Errorf("acme: dns-01 self-check %s: record not visible", name)
		}
	}
	return cleanup, nil
}

func containsTXT(records []string, want string) bool {
	for _, r := range records {
		if r == want {
			return true
		}
	}
	return false
}

// MemoryDNSProvider is an in-memory DNSProvider that also satisfies Resolver, so
// a solver can publish a record and a validator can read it straight back. It is
// the reference provider used by the conformance harness and is suitable for
// tests and single-node local development — not for serving real public DNS.
type MemoryDNSProvider struct {
	mu      sync.Mutex
	records map[string]map[string]bool // name -> set of values
}

// PresentTXT records (name, value) idempotently.
func (p *MemoryDNSProvider) PresentTXT(_ context.Context, name, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.records == nil {
		p.records = map[string]map[string]bool{}
	}
	if p.records[name] == nil {
		p.records[name] = map[string]bool{}
	}
	p.records[name][value] = true
	return nil
}

// CleanupTXT removes (name, value); removing an absent record is a no-op.
func (p *MemoryDNSProvider) CleanupTXT(_ context.Context, name, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if vs := p.records[name]; vs != nil {
		delete(vs, value)
		if len(vs) == 0 {
			delete(p.records, name)
		}
	}
	return nil
}

// LookupTXT returns the published values for name, satisfying Resolver.
func (p *MemoryDNSProvider) LookupTXT(_ context.Context, name string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for v := range p.records[name] {
		out = append(out, v)
	}
	return out, nil
}

// ConformDNSProvider exercises a DNSProvider through the full present → validate
// → cleanup cycle and asserts that what it publishes actually satisfies the real
// DNS01Validator, and that cleanup makes validation fail again. A provider plugin
// self-validates by passing this — the same role the connector conformance suite
// plays for deployment connectors. resolver reads the zone the provider writes to
// (for MemoryDNSProvider, pass the provider itself).
func ConformDNSProvider(ctx context.Context, p DNSProvider, resolver Resolver) error {
	const domain, keyAuth = "conformance.example", "conformance-token.account-thumbprint"
	solver := DNS01Solver{Provider: p, Resolver: resolver}
	cleanup, err := solver.Present(ctx, domain, keyAuth)
	if err != nil {
		return fmt.Errorf("conformance: present: %w", err)
	}

	v := DNS01Validator{Resolver: resolver}
	if err := v.Validate(ctx, ChallengeDNS01, domain, "conformance-token", keyAuth); err != nil {
		_ = cleanup()
		return fmt.Errorf("conformance: published record did not validate: %w", err)
	}

	if err := cleanup(); err != nil {
		return fmt.Errorf("conformance: cleanup: %w", err)
	}
	if err := v.Validate(ctx, ChallengeDNS01, domain, "conformance-token", keyAuth); err == nil {
		return fmt.Errorf("conformance: validation still succeeded after cleanup (record not retracted)")
	}
	return nil
}
