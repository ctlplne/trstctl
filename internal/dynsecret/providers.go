// SPDX-License-Identifier: MPL-2.0

package dynsecret

import "context"

// This file is the dynamic-secret provider family (S17.2–S17.8): the concrete
// database, cloud IAM, Kubernetes, and Redis providers
// built from one template (BackendProvider) over the Backend seam, so each backend
// is a small, uniform instance that inherits the engine's AN-5/AN-6/AN-8
// guarantees. The realism of each lives in its Backend implementation (Postgres
// GRANT/DROP ROLE, IAM access keys, Kubernetes TokenRequest, Redis ACL, …); the
// template handles the lease-facing contract identically for all.

// Backend is the per-target seam a provider drives: create a scoped credential and
// revoke it (idempotently). Real backends implement this against the live system;
// in-sandbox conformance uses in-memory doubles (live integration is the CI
// backstop, like the EST/SCEP differentials).
type Backend interface {
	Create(ctx context.Context, role string) (ref string, secret []byte, err error)
	Revoke(ctx context.Context, ref string) error
}

// RequestBackend is the richer production creation contract. It carries the
// stable lease id and requested validity into the target so retries converge on
// one external identity and native-expiry backends do not silently ignore TTL.
// The small Backend interface remains for third-party implementations.
type RequestBackend interface {
	CreateCredential(ctx context.Context, req GenerateRequest) (ref string, secret []byte, err error)
}

// PreparedRequestBackend applies a locally-prepared, durable credential identity
// during the external worker call. It is used by provider APIs that do not offer
// a request-id parameter but can idempotently upload/find the same public identity.
type PreparedRequestBackend interface {
	CreatePreparedCredential(ctx context.Context, req GenerateRequest, prepared []byte) (ref string, secret []byte, err error)
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
	var (
		ref    string
		secret []byte
		err    error
	)
	if backend, ok := p.backend.(RequestBackend); ok {
		ref, secret, err = backend.CreateCredential(ctx, req)
	} else {
		ref, secret, err = p.backend.Create(ctx, req.Role)
	}
	if err != nil {
		return Credential{}, err
	}
	return Credential{BackendRef: ref, Secret: secret, Metadata: map[string]string{"role": req.Role}}, nil
}

// Revoke implements Provider.
func (p *BackendProvider) Revoke(ctx context.Context, backendRef string) error {
	return p.backend.Revoke(ctx, backendRef)
}

// NewPostgresProvider builds the PostgreSQL dynamic-secret provider (S17.2).
func NewPostgresProvider(b Backend) *BackendProvider { return NewProvider("postgresql", b) }

// NewMySQLProvider builds the MySQL/MariaDB dynamic-secret provider (S17.3).
func NewMySQLProvider(b Backend) *BackendProvider { return NewProvider("mysql", b) }

// NewMongoProvider builds the MongoDB dynamic-secret provider (S17.4).
func NewMongoProvider(b Backend) *BackendProvider { return NewProvider("mongodb", b) }

// NewAWSIAMProvider builds the AWS IAM dynamic-secret provider (S17.5).
func NewAWSIAMProvider(b Backend) *BackendProvider { return NewProvider("aws-iam", b) }

// NewAWSSTSProvider builds the legacy AWS STS-named dynamic-secret provider alias.
func NewAWSSTSProvider(b Backend) *BackendProvider { return NewProvider("aws-sts", b) }

// NewGCPIAMProvider builds the GCP IAM dynamic-secret provider (S17.6).
func NewGCPIAMProvider(b Backend) *BackendProvider { return NewProvider("gcp-iam", b) }

// NewAzureEntraProvider builds the Azure Entra dynamic-secret provider (S17.7).
func NewAzureEntraProvider(b Backend) *BackendProvider { return NewProvider("azure-entra", b) }

// NewAzureSPProvider builds the legacy Azure service-principal provider alias.
func NewAzureSPProvider(b Backend) *BackendProvider { return NewProvider("azure-sp", b) }

// NewRedisProvider builds the Redis ACL dynamic-secret provider (S17.8).
func NewRedisProvider(b Backend) *BackendProvider { return NewProvider("redis", b) }

// NewRedisSSHProvider builds the legacy Redis/dynamic-SSH provider alias.
func NewRedisSSHProvider(b Backend) *BackendProvider { return NewProvider("redis-ssh", b) }

// NewKubernetesProvider builds the Kubernetes ServiceAccount token provider.
func NewKubernetesProvider(b Backend) *BackendProvider { return NewProvider("kubernetes", b) }
