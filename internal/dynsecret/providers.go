package dynsecret

import "context"

// This file is the dynamic-secret provider family (S17.2–S17.8): seven providers
// built from one template (BackendProvider) over the Backend seam, so each backend
// is a small, uniform instance that inherits the engine's AN-5/AN-6/AN-8
// guarantees. The realism of each lives in its Backend implementation (Postgres
// GRANT/REVOKE, AWS STS AssumeRole + revoke, an SSH cert from the S13.1 CA, …);
// the template handles the lease-facing contract identically for all.

// Backend is the per-target seam a provider drives: create a scoped credential and
// revoke it (idempotently). Real backends implement this against the live system;
// in-sandbox conformance uses in-memory doubles (live integration is the CI
// backstop, like the EST/SCEP differentials).
type Backend interface {
	Create(ctx context.Context, role string) (ref string, secret []byte, err error)
	Revoke(ctx context.Context, ref string) error
}

// BackendProvider adapts any Backend into a dynsecret.Provider (the S17.1a template).
type BackendProvider struct {
	name    string
	backend Backend
}

// NewProvider wraps a backend as a named provider.
func NewProvider(name string, b Backend) *BackendProvider {
	return &BackendProvider{name: name, backend: b}
}

// Name implements Provider.
func (p *BackendProvider) Name() string { return p.name }

// Generate implements Provider.
func (p *BackendProvider) Generate(ctx context.Context, req GenerateRequest) (Credential, error) {
	ref, secret, err := p.backend.Create(ctx, req.Role)
	if err != nil {
		return Credential{}, err
	}
	return Credential{BackendRef: ref, Secret: secret, Metadata: map[string]string{"role": req.Role}}, nil
}

// Revoke implements Provider.
func (p *BackendProvider) Revoke(ctx context.Context, backendRef string) error {
	return p.backend.Revoke(ctx, backendRef)
}

// The seven concrete providers (S17.2–S17.8). Each takes its backend client.
func NewPostgresProvider(b Backend) *BackendProvider { return NewProvider("postgresql", b) } // S17.2
func NewMySQLProvider(b Backend) *BackendProvider    { return NewProvider("mysql", b) }      // S17.3
func NewMongoProvider(b Backend) *BackendProvider    { return NewProvider("mongodb", b) }    // S17.4
func NewAWSSTSProvider(b Backend) *BackendProvider   { return NewProvider("aws-sts", b) }    // S17.5
func NewGCPIAMProvider(b Backend) *BackendProvider   { return NewProvider("gcp-iam", b) }    // S17.6
func NewAzureSPProvider(b Backend) *BackendProvider  { return NewProvider("azure-sp", b) }   // S17.7
func NewRedisSSHProvider(b Backend) *BackendProvider { return NewProvider("redis-ssh", b) }  // S17.8
