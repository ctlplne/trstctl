// Package gcpcasfake is a faithful in-process double of the Google Cloud
// Certificate Authority Service (CAS) API the plugin uses, enough to exercise the
// plugin end-to-end in a Linux CI where the GCP SDK / OAuth transport cannot run.
// It implements gcpcas.API with the service's semantics — CreateCertificate
// synchronously returns the issued certificate (leaf + chain) for a known CA
// pool, and rejects an unknown pool — and signs submitted CSRs with a local
// software authority via the crypto boundary, so it holds no crypto/* itself.
package gcpcasfake

import (
	"context"
	"encoding/pem"
	"fmt"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca/gcpcas"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// caPool is the CA pool resource this double recognizes.
const caPool = "projects/trstctl-test/locations/us-central1/caPools/test-pool"

// API is an in-process CAS double backed by a software CA.
type API struct {
	authority *cryptoca.Authority

	mu  sync.Mutex
	seq int
}

var _ gcpcas.API = (*API)(nil)

// NewAPI starts a fake CAS backed by a fresh software CA.
func NewAPI() (*API, error) {
	authority, err := cryptoca.NewAuthority("GCP CAS Test Root")
	if err != nil {
		return nil, err
	}
	return &API{authority: authority}, nil
}

// CaPool is the CA pool resource the double recognizes.
func (a *API) CaPool() string { return caPool }

// CreateCertificate implements gcpcas.API: it signs synchronously and returns the
// certificate resource with its leaf and chain.
func (a *API) CreateCertificate(_ context.Context, in gcpcas.CreateCertificateInput) (gcpcas.Certificate, error) {
	if in.Parent != caPool {
		return gcpcas.Certificate{}, fmt.Errorf("NOT_FOUND: CA pool %q not found", in.Parent)
	}
	block, _ := pem.Decode(in.PemCSR)
	if block == nil {
		return gcpcas.Certificate{}, fmt.Errorf("INVALID_ARGUMENT: could not parse pemCsr")
	}
	ttl := in.Lifetime
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	issued, err := a.authority.IssueFromCSR(block.Bytes, ttl)
	if err != nil {
		return gcpcas.Certificate{}, fmt.Errorf("INTERNAL: %w", err)
	}
	leaf, chain := splitChain(issued.CertificatePEM)

	a.mu.Lock()
	a.seq++
	id := in.CertificateID
	if id == "" {
		id = "cert-" + strconv.Itoa(a.seq)
	}
	a.mu.Unlock()

	return gcpcas.Certificate{
		Name:                caPool + "/certificates/" + id,
		PemCertificate:      leaf,
		PemCertificateChain: chain,
	}, nil
}

// splitChain returns the first CERTIFICATE block (leaf) as PEM and the remaining
// blocks (the issuing chain) as a slice of PEM strings, as CAS does.
func splitChain(pemBytes []byte) (leaf string, chain []string) {
	rest := pemBytes
	first := true
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		enc := string(pem.EncodeToMemory(block))
		if first {
			leaf = enc
			first = false
		} else {
			chain = append(chain, enc)
		}
		rest = r
	}
	return leaf, chain
}
