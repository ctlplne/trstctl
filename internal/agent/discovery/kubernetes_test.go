// SPDX-License-Identifier: MPL-2.0

package discovery_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/agent/discovery"
)

type stubK8sEnumerator struct {
	certs map[string][]byte
	err   error
	calls int
}

func (s *stubK8sEnumerator) EnumerateCertificates(context.Context) (map[string][]byte, error) {
	s.calls++
	return s.certs, s.err
}

func TestKubernetesSecretSourceReportsMetadataOnly(t *testing.T) {
	enum := &stubK8sEnumerator{certs: map[string][]byte{
		"payments-tls": []byte(cert1),
		"edge-tls":     []byte(cert1),
	}}
	source := discovery.NewKubernetesSecretSource("prod", enum)

	if source.Kind() != discovery.SourceKubernetes {
		t.Fatalf("Kind() = %q, want %q", source.Kind(), discovery.SourceKubernetes)
	}
	found, err := source.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d certificates, want 2: %+v", len(found), found)
	}
	// Stable order: a map iterates randomly, and an operator comparing two runs
	// should not see the inventory reshuffle for no reason.
	if found[0].Location != "prod/secret/edge-tls" || found[1].Location != "prod/secret/payments-tls" {
		t.Fatalf("locations are not namespace-qualified and sorted: %q, %q", found[0].Location, found[1].Location)
	}
	for _, f := range found {
		if f.Source != discovery.SourceKubernetes {
			t.Errorf("finding source = %q, want %q", f.Source, discovery.SourceKubernetes)
		}
		if f.Cert.SHA256Fingerprint == "" {
			t.Errorf("finding %q carries no inspected certificate metadata", f.Location)
		}
		if f.Metadata["namespace"] != "prod" || f.Metadata["key_bytes"] != "not_collected" {
			t.Errorf("finding %q metadata = %v", f.Location, f.Metadata)
		}
	}
}

// TestKubernetesSecretSourceSkipsUnparseableSecrets keeps one bad Secret from
// costing the operator the inventory of every other one in the namespace.
func TestKubernetesSecretSourceSkipsUnparseableSecrets(t *testing.T) {
	enum := &stubK8sEnumerator{certs: map[string][]byte{
		"good": []byte(cert1),
		"junk": []byte("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"),
	}}
	found, err := discovery.NewKubernetesSecretSource("default", enum).Discover(context.Background())
	if err != nil {
		t.Fatalf("one malformed Secret must not fail the pass: %v", err)
	}
	if len(found) != 1 || found[0].Location != "default/secret/good" {
		t.Fatalf("found = %+v, want only the parseable Secret", found)
	}
}

// TestKubernetesSecretSourceSurfacesAnUnreachableAPIServer is the other half:
// reporting an empty inventory for a cluster it could not reach would read as
// "no certificates here", which is worse than reporting nothing.
func TestKubernetesSecretSourceSurfacesAnUnreachableAPIServer(t *testing.T) {
	want := errors.New("dial tcp: connection refused")
	found, err := discovery.NewKubernetesSecretSource("prod", &stubK8sEnumerator{err: want}).Discover(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("Discover error = %v, want the underlying failure", err)
	}
	if len(found) != 0 {
		t.Fatalf("a failed enumeration must not report findings: %+v", found)
	}
}

func TestKubernetesSecretSourceLocationWithoutNamespace(t *testing.T) {
	enum := &stubK8sEnumerator{certs: map[string][]byte{"tls": []byte(cert1)}}
	found, err := discovery.NewKubernetesSecretSource("", enum).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 1 || found[0].Location != "secret/tls" {
		t.Fatalf("location = %+v", found)
	}
}

func TestKubernetesSecretSourceHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enum := &stubK8sEnumerator{certs: map[string][]byte{"a": []byte(cert1), "b": []byte(cert1)}}
	if _, err := discovery.NewKubernetesSecretSource("prod", enum).Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover error = %v, want context.Canceled", err)
	}
}
