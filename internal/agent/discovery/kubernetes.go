// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"sort"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Kubernetes TLS Secrets as a discovery source (epic C1).
//
// The collector boundary has declared a k8s-secret source kind since it was
// written, and the served API advertised it, but the agent binary built no
// enumerator: a cluster's TLS Secrets — often the largest single population of
// certificates an organization has, and the one nobody has an inventory of —
// were invisible.
//
// The read side already existed unwired (internal/agent/k8s EnumerateCertificates).
// This adapts it to the Source contract so the shipped agent can actually collect
// it, and so the served capability panel can advertise the kind because it is
// real rather than because it was declared.
//
// Metadata only, like every other agent source: the enumerator reads `tls.crt`,
// which is public certificate material. It never reads `tls.key`, and no key
// bytes cross the agent channel.

// KubernetesSecretEnumerator lists the certificates held in TLS Secrets, keyed by
// Secret name. It is the narrow slice of the Kubernetes client this source needs,
// declared here so the discovery package stays dependency-light and testable
// without a cluster.
type KubernetesSecretEnumerator interface {
	EnumerateCertificates(ctx context.Context) (map[string][]byte, error)
}

// KubernetesSecretSource inventories the TLS Secrets in one namespace.
type KubernetesSecretSource struct {
	namespace string
	enum      KubernetesSecretEnumerator
}

// NewKubernetesSecretSource returns a source over an enumerator. namespace is
// recorded on each finding's location so an operator can tell two identically
// named Secrets in different namespaces apart.
func NewKubernetesSecretSource(namespace string, enum KubernetesSecretEnumerator) *KubernetesSecretSource {
	return &KubernetesSecretSource{namespace: namespace, enum: enum}
}

// Kind names the source.
func (s *KubernetesSecretSource) Kind() string { return SourceKubernetes }

// Discover returns every certificate held in a TLS Secret the client can see.
//
// A Secret whose tls.crt does not parse is skipped rather than failing the pass:
// one malformed Secret in a namespace must not cost an operator the inventory of
// every other one. A failure to reach the API server is an error, because that is
// a source-level failure and reporting an empty inventory for an unreachable
// cluster would be worse than reporting nothing.
func (s *KubernetesSecretSource) Discover(ctx context.Context) ([]Found, error) {
	certs, err := s.enum.EnumerateCertificates(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(certs))
	for name := range certs {
		names = append(names, name)
	}
	// Map iteration order is random; a stable order keeps a re-run's report
	// comparable to the last one.
	sort.Strings(names)

	out := make([]Found, 0, len(names))
	for _, name := range names {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		for _, der := range certBlocks(certs[name]) {
			info, perr := certinfo.Inspect(der)
			if perr != nil {
				continue
			}
			out = append(out, Found{
				Source:   SourceKubernetes,
				Location: s.location(name),
				Cert:     info,
				Metadata: map[string]string{
					"namespace":   s.namespace,
					"secret_name": name, // #nosec G101 -- metadata key naming the Kubernetes Secret a public certificate was found in; no credential value present (CWE-798)
					"secret_type": "kubernetes.io/tls",
					"key_bytes":   "not_collected",
				},
			})
		}
	}
	return out, nil
}

func (s *KubernetesSecretSource) location(name string) string {
	if s.namespace == "" {
		return "secret/" + name
	}
	return s.namespace + "/secret/" + name
}
