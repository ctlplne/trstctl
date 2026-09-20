// SPDX-License-Identifier: BUSL-1.1

package rotation

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/secrettext"
)

var ErrCredentialNotFound = errors.New("rotation: credential not found")

// CredentialPublisher is the consumer-side pointer a static rotation cuts over.
// Implementations publish the new credential only to the target path (for example
// the served secret store, a deployment connector, or an operator-managed pointer)
// and can read the prior credential so Rollback can put it back.
type CredentialPublisher interface {
	ReadCredential(ctx context.Context, key string) (ref string, credential []byte, err error)
	PublishCredential(ctx context.Context, key, ref string, credential []byte) error
}

type publishedCredential struct {
	ref        string
	credential []byte
}

// MemoryCredentialPublisher is the in-process publisher used by conformance and
// served tests. It copies []byte material on both read and write so callers retain
// ownership of their buffers.
type MemoryCredentialPublisher struct {
	mu    sync.Mutex
	items map[string]publishedCredential
}

func NewMemoryCredentialPublisher() *MemoryCredentialPublisher {
	return &MemoryCredentialPublisher{items: map[string]publishedCredential{}}
}

func (p *MemoryCredentialPublisher) Put(key, ref string, credential []byte) {
	_ = p.PublishCredential(context.Background(), key, ref, credential)
}

func (p *MemoryCredentialPublisher) ReadCredential(_ context.Context, key string) (string, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item, ok := p.items[key]
	if !ok {
		return "", nil, ErrCredentialNotFound
	}
	return item.ref, secrettext.Clone(item.credential), nil
}

func (p *MemoryCredentialPublisher) PublishCredential(_ context.Context, key, ref string, credential []byte) error {
	if key == "" || ref == "" || len(credential) == 0 {
		return errors.New("rotation: key, ref, and credential are required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.items[key]; ok {
		secret.Wipe(old.credential)
	}
	p.items[key] = publishedCredential{ref: ref, credential: secrettext.Clone(credential)}
	return nil
}

// CredentialVerifier validates that a newly-published credential works for the
// consuming backend before the old credential is retired.
type CredentialVerifier interface {
	VerifyCredential(ctx context.Context, key, ref string, credential []byte) error
}

type CredentialVerifierFunc func(context.Context, string, string, []byte) error

func (f CredentialVerifierFunc) VerifyCredential(ctx context.Context, key, ref string, credential []byte) error {
	return f(ctx, key, ref, credential)
}

// BackendRotator adapts a create/revoke backend plus a publisher into rotation.Engine's
// Stage->Cutover->Verify->Retire->Rollback contract.
type BackendRotator struct {
	backend   dynsecret.Backend
	publisher CredentialPublisher
	verifier  CredentialVerifier

	mu     sync.Mutex
	staged map[string]*stagedCredential
}

type stagedCredential struct {
	ref           string
	credential    []byte
	oldRef        string
	oldCredential []byte
}

func NewBackendRotator(backend dynsecret.Backend, publisher CredentialPublisher, verifier CredentialVerifier) (*BackendRotator, error) {
	if backend == nil {
		return nil, errors.New("rotation: backend required")
	}
	if publisher == nil {
		return nil, errors.New("rotation: publisher required")
	}
	if verifier == nil {
		verifier = CredentialVerifierFunc(func(context.Context, string, string, []byte) error { return nil })
	}
	return &BackendRotator{backend: backend, publisher: publisher, verifier: verifier, staged: map[string]*stagedCredential{}}, nil
}

func (r *BackendRotator) Stage(ctx context.Context, key string) (string, error) {
	ref, credential, err := r.backend.Create(ctx, key)
	if err != nil {
		return "", fmt.Errorf("rotation: create staged credential: %w", err)
	}
	r.mu.Lock()
	if old := r.staged[key]; old != nil {
		old.destroy()
	}
	r.staged[key] = &stagedCredential{ref: ref, credential: credential}
	r.mu.Unlock()
	return ref, nil
}

func (r *BackendRotator) Cutover(ctx context.Context, key, newRef string) error {
	st := r.stagedFor(key, newRef)
	if st == nil {
		return ErrCredentialNotFound
	}
	oldRef, oldCredential, err := r.publisher.ReadCredential(ctx, key)
	if err != nil {
		return fmt.Errorf("rotation: read previous credential: %w", err)
	}
	r.mu.Lock()
	st.oldRef = oldRef
	if st.oldCredential != nil {
		secret.Wipe(st.oldCredential)
	}
	st.oldCredential = oldCredential
	r.mu.Unlock()
	if err := r.publisher.PublishCredential(ctx, key, newRef, st.credential); err != nil {
		return fmt.Errorf("rotation: publish staged credential: %w", err)
	}
	return nil
}

func (r *BackendRotator) Verify(ctx context.Context, key string) error {
	st := r.stagedFor(key, "")
	if st == nil {
		return ErrCredentialNotFound
	}
	if err := r.verifier.VerifyCredential(ctx, key, st.ref, st.credential); err != nil {
		return fmt.Errorf("rotation: verify staged credential: %w", err)
	}
	return nil
}

func (r *BackendRotator) Retire(ctx context.Context, key, oldRef string) error {
	if err := r.backend.Revoke(ctx, oldRef); err != nil {
		return fmt.Errorf("rotation: retire old credential: %w", err)
	}
	r.cleanup(key)
	return nil
}

func (r *BackendRotator) Rollback(ctx context.Context, key, oldRef string) error {
	st := r.stagedFor(key, "")
	if st == nil {
		return ErrCredentialNotFound
	}
	var restoreErr error
	if len(st.oldCredential) > 0 {
		restoreErr = r.publisher.PublishCredential(ctx, key, oldRef, st.oldCredential)
	}
	revokeErr := r.backend.Revoke(ctx, st.ref)
	r.cleanup(key)
	return errors.Join(restoreErr, revokeErr)
}

func (r *BackendRotator) stagedFor(key, ref string) *stagedCredential {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.staged[key]
	if st == nil {
		return nil
	}
	if ref != "" && st.ref != ref {
		return nil
	}
	return st
}

func (r *BackendRotator) cleanup(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.staged[key]; st != nil {
		st.destroy()
		delete(r.staged, key)
	}
}

func (s *stagedCredential) destroy() {
	secret.Wipe(s.credential)
	secret.Wipe(s.oldCredential)
	s.credential = nil
	s.oldCredential = nil
}

// PostgresConfig configures the concrete PostgreSQL static-credential rotator.
type PostgresConfig struct {
	DSN            []byte
	Database       string
	Schema         string
	UsernamePrefix string
	Publisher      CredentialPublisher
	VerifyQuery    string
}

func NewPostgresRotator(cfg PostgresConfig) (*BackendRotator, error) {
	backend, err := dynsecret.NewPostgresBackend(dynsecret.PostgresConfig{
		DSN: cfg.DSN, Database: cfg.Database, Schema: cfg.Schema, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return nil, err
	}
	verifyQuery := cfg.VerifyQuery
	if verifyQuery == "" {
		verifyQuery = "SELECT 1"
	}
	return NewBackendRotator(backend, cfg.Publisher, postgresVerifier{query: verifyQuery})
}

type postgresVerifier struct {
	query string
}

func (v postgresVerifier) VerifyCredential(ctx context.Context, _, _ string, credential []byte) error {
	conn, err := pgx.Connect(ctx, secrettext.String(credential))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, v.query)
	if err != nil {
		return err
	}
	rows.Close()
	return rows.Err()
}

// MySQLConfig configures the concrete MySQL static-credential rotator.
type MySQLConfig struct {
	Executor       dynsecret.SQLExecutor
	Database       string
	Host           string
	UsernamePrefix string
	Publisher      CredentialPublisher
	Verifier       CredentialVerifier
}

func NewMySQLRotator(cfg MySQLConfig) (*BackendRotator, error) {
	backend, err := dynsecret.NewMySQLBackend(cfg.Executor, dynsecret.MySQLConfig{
		Database: cfg.Database, Host: cfg.Host, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return nil, err
	}
	return NewBackendRotator(backend, cfg.Publisher, cfg.Verifier)
}

// AWSIAMConfig configures the concrete AWS IAM static-credential rotator.
type AWSIAMConfig struct {
	Endpoint        string
	HTTPClient      dynsecret.HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	UsernamePrefix  string
	Publisher       CredentialPublisher
	Verifier        CredentialVerifier
}

func NewAWSIAMRotator(cfg AWSIAMConfig) (*BackendRotator, error) {
	backend, err := dynsecret.NewAWSIAMBackend(dynsecret.AWSIAMConfig{
		Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, Region: cfg.Region, AccessKeyID: cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey, SessionToken: cfg.SessionToken, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return nil, err
	}
	return NewBackendRotator(backend, cfg.Publisher, cfg.Verifier)
}
