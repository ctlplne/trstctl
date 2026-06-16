// Package discovery inventories the certificates an agent can see locally (F3,
// S6.2): on the filesystem, in a PKCS#11 token, in the Windows certificate store,
// and in Kubernetes Secrets. Each source enumerates the certificates it holds;
// Discover runs a set of sources and reconciles every certificate it finds into
// the inventory through a Sink (an idempotent upsert by fingerprint, so a
// certificate seen in more than one place is one inventory row).
//
// Certificate metadata is extracted through the crypto boundary
// (internal/crypto/certinfo); this package parses no certificates itself and
// imports no crypto/*. Discovered certificates are opaque PEM bytes until they
// reach the boundary.
package discovery

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Source kinds recorded on each discovery.
const (
	SourceFilesystem  = "filesystem"
	SourcePKCS11      = "pkcs11"
	SourceWindowsCert = "windows-store"
	SourceKubernetes  = "k8s-secret"
)

// Found is a certificate discovered locally.
type Found struct {
	Source   string        // the discovery source kind
	Location string        // where it was found (a path, label, or secret name)
	Cert     certinfo.Info // its inventory metadata
}

// Source enumerates the certificates the agent can see in one place.
type Source interface {
	// Discover returns the certificates this source can see. A source-level
	// failure (an unreadable token, an unreachable API) is an error; individual
	// unparseable objects are skipped, not fatal.
	Discover(ctx context.Context) ([]Found, error)
	// Kind names the source for reports and errors.
	Kind() string
}

// Sink reconciles a discovered certificate into the inventory. Production wires
// StoreSink (upsert by fingerprint); tests use MemorySink.
type Sink interface {
	Record(ctx context.Context, f Found) error
}

// Report summarizes a discovery pass.
type Report struct {
	Sources    int
	Discovered int     // certificates recorded
	Errors     []error // non-fatal source/sink errors
}

// Discover runs every source and records each certificate it finds into sink.
// It is best-effort: a failing source or sink write is collected in the report,
// not fatal, so one broken source cannot hide the others.
func Discover(ctx context.Context, sources []Source, sink Sink) Report {
	rep := Report{Sources: len(sources)}
	for _, src := range sources {
		found, err := src.Discover(ctx)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("discovery: source %s: %w", src.Kind(), err))
			continue
		}
		for _, f := range found {
			if err := sink.Record(ctx, f); err != nil {
				rep.Errors = append(rep.Errors, fmt.Errorf("discovery: record %s %s: %w", f.Source, f.Location, err))
				continue
			}
			rep.Discovered++
		}
	}
	return rep
}

// CertEnumerator lists the certificates a local store holds, keyed by a
// store-specific label (a PKCS#11 object label, a Windows store entry name, a
// Kubernetes Secret name), each as PEM. The software token (softtoken), the
// Windows certificate store (certstore), and the Kubernetes client all implement
// it.
type CertEnumerator interface {
	EnumerateCertificates(ctx context.Context) (map[string][]byte, error)
}

// enumSource adapts a CertEnumerator into a Source.
type enumSource struct {
	kind  string
	scope string // a location prefix (token, store, or namespace)
	enum  CertEnumerator
}

// NewPKCS11Source discovers certificates on a PKCS#11 token.
func NewPKCS11Source(token string, enum CertEnumerator) Source {
	return &enumSource{kind: SourcePKCS11, scope: token, enum: enum}
}

// NewWindowsStoreSource discovers certificates in a Windows certificate store.
func NewWindowsStoreSource(storeName string, enum CertEnumerator) Source {
	return &enumSource{kind: SourceWindowsCert, scope: storeName, enum: enum}
}

// NewKubernetesSource discovers certificates in a namespace's TLS Secrets.
func NewKubernetesSource(namespace string, enum CertEnumerator) Source {
	return &enumSource{kind: SourceKubernetes, scope: namespace, enum: enum}
}

// Kind names the source.
func (s *enumSource) Kind() string { return s.kind }

// Discover enumerates the store and extracts each certificate's metadata,
// skipping any object that does not parse as a certificate.
func (s *enumSource) Discover(ctx context.Context) ([]Found, error) {
	certs, err := s.enum.EnumerateCertificates(ctx)
	if err != nil {
		return nil, err
	}
	var out []Found
	for label, pem := range certs {
		info, err := certinfo.Inspect(pem)
		if err != nil {
			continue // not a certificate; skip
		}
		out = append(out, Found{Source: s.kind, Location: location(s.scope, label), Cert: info})
	}
	return out, nil
}

func location(scope, label string) string {
	if scope == "" {
		return label
	}
	return scope + "/" + label
}

// MemorySink records discoveries in memory for tests.
type MemorySink struct {
	found []Found
}

var _ Sink = (*MemorySink)(nil)

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores the discovery.
func (m *MemorySink) Record(_ context.Context, f Found) error {
	m.found = append(m.found, f)
	return nil
}

// All returns the discoveries recorded so far.
func (m *MemorySink) All() []Found {
	out := make([]Found, len(m.found))
	copy(out, m.found)
	return out
}
