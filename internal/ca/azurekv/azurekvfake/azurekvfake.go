// Package azurekvfake is a faithful in-process double of the Azure Key Vault
// certificates API the plugin uses, enough to exercise the plugin end-to-end in a
// Linux CI where the Azure SDK / AAD transport cannot run. It implements
// azurekv.API with the service's semantics — CreateCertificate starts a
// CertificateOperation (inProgress until completed), GetCertificateOperation is
// polled, GetCertificate returns the issued leaf and chain, and an unknown vault
// is rejected — and signs submitted CSRs with a local software authority via the
// crypto boundary, so it holds no crypto/* itself.
package azurekvfake

import (
	"context"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca/azurekv"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// vaultBaseURL is the vault this double recognizes.
const vaultBaseURL = "https://trstctl-test.vault.azure.net"

// API is an in-process Key Vault double backed by a software CA.
type API struct {
	authority *cryptoca.Authority

	mu           sync.Mutex
	certs        map[string][]byte // certName -> chain PEM
	remaining    map[string]int    // certName -> remaining inProgress poll calls
	pendingPolls int
}

var _ azurekv.API = (*API)(nil)

// NewAPI starts a fake Key Vault backed by a fresh software CA. By default the
// certificate operation completes immediately.
func NewAPI() (*API, error) {
	authority, err := cryptoca.NewAuthority("Azure Key Vault Test CA")
	if err != nil {
		return nil, err
	}
	return &API{authority: authority, certs: map[string][]byte{}, remaining: map[string]int{}}, nil
}

// VaultBaseURL is the vault the double recognizes.
func (a *API) VaultBaseURL() string { return vaultBaseURL }

// SetPendingPolls makes a created certificate's operation stay inProgress for the
// next n GetCertificateOperation calls before completing.
func (a *API) SetPendingPolls(n int) {
	a.mu.Lock()
	a.pendingPolls = n
	a.mu.Unlock()
}

// CreateCertificate implements azurekv.API.
func (a *API) CreateCertificate(_ context.Context, in azurekv.CreateCertificateInput) (azurekv.CertificateOperation, error) {
	if in.VaultBaseURL != vaultBaseURL {
		return azurekv.CertificateOperation{}, fmt.Errorf("vault %q not found", in.VaultBaseURL)
	}
	block, _ := pem.Decode(in.Csr)
	if block == nil {
		return azurekv.CertificateOperation{}, fmt.Errorf("could not parse CSR")
	}
	ttl := in.Lifetime
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	issued, err := a.authority.IssueFromCSR(block.Bytes, ttl)
	if err != nil {
		return azurekv.CertificateOperation{}, fmt.Errorf("issue: %w", err)
	}
	a.mu.Lock()
	a.certs[in.CertificateName] = issued.CertificatePEM
	status := azurekv.StatusCompleted
	if a.pendingPolls > 0 {
		a.remaining[in.CertificateName] = a.pendingPolls
		status = azurekv.StatusInProgress
	}
	a.mu.Unlock()
	return azurekv.CertificateOperation{Status: status}, nil
}

// GetCertificateOperation implements azurekv.API.
func (a *API) GetCertificateOperation(_ context.Context, gotVault, certName string) (azurekv.CertificateOperation, error) {
	if gotVault != vaultBaseURL {
		return azurekv.CertificateOperation{}, fmt.Errorf("vault %q not found", gotVault)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.certs[certName]; !ok {
		return azurekv.CertificateOperation{}, fmt.Errorf("certificate operation %q not found", certName)
	}
	if a.remaining[certName] > 0 {
		a.remaining[certName]--
		return azurekv.CertificateOperation{Status: azurekv.StatusInProgress}, nil
	}
	return azurekv.CertificateOperation{Status: azurekv.StatusCompleted}, nil
}

// GetCertificate implements azurekv.API.
func (a *API) GetCertificate(_ context.Context, gotVault, certName string) (azurekv.Certificate, error) {
	if gotVault != vaultBaseURL {
		return azurekv.Certificate{}, fmt.Errorf("vault %q not found", gotVault)
	}
	a.mu.Lock()
	chain, ok := a.certs[certName]
	a.mu.Unlock()
	if !ok {
		return azurekv.Certificate{}, fmt.Errorf("certificate %q not found", certName)
	}
	ders := derBlocks(chain)
	if len(ders) == 0 {
		return azurekv.Certificate{}, fmt.Errorf("certificate %q has no DER", certName)
	}
	return azurekv.Certificate{Cer: ders[0], Chain: ders[1:]}, nil
}

// derBlocks extracts the DER bytes of each CERTIFICATE block in a PEM chain.
func derBlocks(pemBytes []byte) [][]byte {
	var ders [][]byte
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
		rest = r
	}
	return ders
}
