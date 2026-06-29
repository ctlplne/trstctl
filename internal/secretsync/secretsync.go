// Package secretsync pushes trstctl's secrets into external platforms (S19.4,
// F68): a sync template (push + drift detection) plus targets — Kubernetes,
// GitHub Actions, GitLab CI, Terraform/OpenTofu, Vercel/Netlify, AWS Parameter
// Store/Secrets Manager, and a generic webhook. Delivery is via the outbox so it
// is durable (AN-6) and idempotent / never half-writes (AN-5); syncs are audited
// (AN-2). (Read-only discovery of existing secrets is S20.1; this pushes outward.)
package secretsync

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Pusher delivers a key/value to one external platform.
type Pusher interface {
	Push(ctx context.Context, key string, value []byte) error
}

// Target is a named sync destination (a Pusher with a name).
type Target struct {
	name   string
	pusher Pusher
}

// NewTarget wraps a Pusher as a named target.
func NewTarget(name string, p Pusher) *Target { return &Target{name: name, pusher: p} }

// Name returns the target name.
func (t *Target) Name() string { return t.name }

// ProviderCatalogEntry describes one built-in sync integration. It is metadata only:
// credentials and endpoint URLs stay in operator configuration, not the catalog.
type ProviderCatalogEntry struct {
	ID           string
	Name         string
	Platform     string
	DeliveryMode string
	AuthMode     string
	WireFormat   string
	Capabilities []string
}

// SyncItem is a queued sync delivery.
type SyncItem struct {
	ID     string
	Key    string
	Target string
	Value  []byte
}

// Outbox is the durable delivery queue (AN-6).
type Outbox interface {
	Enqueue(ctx context.Context, item SyncItem) error
	Pending(ctx context.Context) ([]SyncItem, error)
	Done(ctx context.Context, id string) error
}

// Engine syncs secrets to one target via the outbox and tracks drift.
type Engine struct {
	tenantID string
	target   *Target
	outbox   Outbox
	audit    auditsink.Auditor
	mu       sync.Mutex
	desired  map[string]string // key -> hash of last synced value
	n        int
}

// New constructs a sync Engine.
func New(tenantID string, target *Target, outbox Outbox, audit auditsink.Auditor) *Engine {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Engine{tenantID: tenantID, target: target, outbox: outbox, audit: audit, desired: map[string]string{}}
}

// Sync records the desired value and durably enqueues a delivery to the target.
func (e *Engine) Sync(ctx context.Context, key string, value []byte) error {
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	id := "sync-" + hex.EncodeToString(nonce)
	secret.Wipe(nonce)
	e.mu.Lock()
	e.n++
	e.desired[key] = crypto.SHA256Hex(value)
	e.mu.Unlock()
	if err := e.outbox.Enqueue(ctx, SyncItem{ID: id, Key: key, Target: e.target.Name(), Value: value}); err != nil {
		return err
	}
	_ = auditsink.Emit(ctx, e.audit, nil, "secret.sync.enqueued", e.tenantID, []byte(fmt.Sprintf(`{"key":%q,"target":%q}`, key, e.target.Name())))
	return nil
}

// RunDeliveries drains the outbox, pushing each item to the target. A push failure
// leaves the item queued for retry (never a half-write); a success marks it done.
func (e *Engine) RunDeliveries(ctx context.Context) (int, error) {
	items, err := e.outbox.Pending(ctx)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, it := range items {
		err := e.target.pusher.Push(ctx, it.Key, it.Value)
		secret.Wipe(it.Value)
		if err != nil {
			continue // fail-safe: keep queued, retry later
		}
		if err := e.outbox.Done(ctx, it.ID); err != nil {
			return done, err
		}
		_ = auditsink.Emit(ctx, e.audit, nil, "secret.sync.delivered", e.tenantID, []byte(fmt.Sprintf(`{"key":%q,"target":%q}`, it.Key, it.Target)))
		done++
	}
	return done, nil
}

// Drift reports whether the current value of key differs from the last synced one.
func (e *Engine) Drift(key string, current []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	want, ok := e.desired[key]
	if !ok {
		return false
	}
	return want != crypto.SHA256Hex(current)
}

// NewKubernetesTarget syncs secrets to Kubernetes (native / External Secrets Operator).
func NewKubernetesTarget(p Pusher) *Target { return NewTarget("kubernetes", p) }

// NewGitHubActionsTarget syncs secrets to GitHub Actions.
func NewGitHubActionsTarget(p Pusher) *Target { return NewTarget("github-actions", p) }

// NewGitLabCITarget syncs secrets to GitLab CI.
func NewGitLabCITarget(p Pusher) *Target { return NewTarget("gitlab-ci", p) }

// NewTerraformTarget syncs secrets to Terraform/OpenTofu.
func NewTerraformTarget(p Pusher) *Target { return NewTarget("terraform", p) }

// NewTerraformCloudTarget syncs secrets to Terraform Cloud/OpenTofu.
func NewTerraformCloudTarget(p Pusher) *Target { return NewTarget("terraform-cloud", p) }

// NewVercelTarget syncs secrets to Vercel/Netlify.
func NewVercelTarget(p Pusher) *Target { return NewTarget("vercel-netlify", p) }

// NewAWSParamStoreTarget syncs secrets to AWS Parameter Store / Secrets Manager.
func NewAWSParamStoreTarget(p Pusher) *Target { return NewTarget("aws-parameter-store", p) }

// NewAWSSecretsManagerTarget syncs secrets to AWS Secrets Manager.
func NewAWSSecretsManagerTarget(p Pusher) *Target { return NewTarget("aws-secrets-manager", p) }

// NewGCPSecretManagerTarget syncs secrets to GCP Secret Manager.
func NewGCPSecretManagerTarget(p Pusher) *Target { return NewTarget("gcp-secret-manager", p) }

// NewAzureKeyVaultTarget syncs secrets to Azure Key Vault.
func NewAzureKeyVaultTarget(p Pusher) *Target { return NewTarget("azure-key-vault", p) }

// NewCITarget syncs secrets to a generic CI/CD secret endpoint.
func NewCITarget(p Pusher) *Target { return NewTarget("ci", p) }

// NewWebhookTarget syncs secrets to a generic signed webhook.
func NewWebhookTarget(p Pusher) *Target { return NewTarget("webhook", p) }

// ProviderCatalog returns the built-in sync provider catalog that the served API and
// UI expose. A provider is usable when the server wires a Target with the same ID.
func ProviderCatalog() []ProviderCatalogEntry {
	entries := []ProviderCatalogEntry{
		{
			ID:           "aws-secrets-manager",
			Name:         "AWS Secrets Manager",
			Platform:     "aws",
			DeliveryMode: "secretsmanager.PutSecretValue over HTTPS",
			AuthMode:     "AWS SigV4 access key, secret access key, optional session token",
			WireFormat:   "SecretBinary base64 payload",
			Capabilities: []string{"cloud-secret-manager", "binary-secret", "sigv4", "outbox-delivery"},
		},
		{
			ID:           "gcp-secret-manager",
			Name:         "GCP Secret Manager",
			Platform:     "gcp",
			DeliveryMode: "projects.secrets.addVersion over HTTPS",
			AuthMode:     "Bearer token or workload-federated access token supplied by operator config",
			WireFormat:   "payload.data base64 secret bytes",
			Capabilities: []string{"cloud-secret-manager", "versioned-secret", "outbox-delivery"},
		},
		{
			ID:           "azure-key-vault",
			Name:         "Azure Key Vault",
			Platform:     "azure",
			DeliveryMode: "secrets set over HTTPS",
			AuthMode:     "Bearer token supplied by operator config",
			WireFormat:   "base64 value with contentType application/octet-stream;base64",
			Capabilities: []string{"cloud-secret-manager", "versioned-secret", "outbox-delivery"},
		},
		{
			ID:           "github-actions",
			Name:         "GitHub Actions",
			Platform:     "github",
			DeliveryMode: "repository Actions secret upsert over HTTPS",
			AuthMode:     "Bearer token supplied by operator config",
			WireFormat:   "encoded_value payload accepted by the sync pusher boundary",
			Capabilities: []string{"ci-secret", "repository-secret", "outbox-delivery"},
		},
		{
			ID:           "gitlab-ci",
			Name:         "GitLab CI",
			Platform:     "gitlab",
			DeliveryMode: "project CI/CD variable upsert over HTTPS",
			AuthMode:     "PRIVATE-TOKEN supplied by operator config",
			WireFormat:   "masked project variable payload",
			Capabilities: []string{"ci-secret", "project-variable", "outbox-delivery"},
		},
		{
			ID:           "vercel-netlify",
			Name:         "Vercel",
			Platform:     "vercel",
			DeliveryMode: "project environment secret upsert over HTTPS",
			AuthMode:     "Bearer token supplied by operator config",
			WireFormat:   "encrypted environment variable payload",
			Capabilities: []string{"ci-secret", "deployment-env", "outbox-delivery"},
		},
		{
			ID:           "ci",
			Name:         "Generic CI secret endpoint",
			Platform:     "ci",
			DeliveryMode: "signed JSON secret push over HTTPS",
			AuthMode:     "Bearer token supplied by operator config",
			WireFormat:   "provider/key/encoded_value JSON envelope",
			Capabilities: []string{"ci-secret", "generic-json", "outbox-delivery"},
		},
		{
			ID:           "kubernetes",
			Name:         "Kubernetes Secret",
			Platform:     "kubernetes",
			DeliveryMode: "core v1 Secret upsert over HTTPS",
			AuthMode:     "Bearer token supplied by operator config",
			WireFormat:   "Opaque Secret data.value base64 payload",
			Capabilities: []string{"cluster-secret", "namespace-secret", "outbox-delivery"},
		},
	}
	for i := range entries {
		entries[i].Capabilities = append([]string(nil), entries[i].Capabilities...)
	}
	return entries
}

// MemoryOutbox is an in-process durable-semantics Outbox for single-node and tests.
type MemoryOutbox struct {
	mu      sync.Mutex
	pending map[string]SyncItem
}

// NewMemoryOutbox constructs a MemoryOutbox.
func NewMemoryOutbox() *MemoryOutbox { return &MemoryOutbox{pending: map[string]SyncItem{}} }

// Enqueue implements Outbox.
func (o *MemoryOutbox) Enqueue(_ context.Context, item SyncItem) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	item.Value = secrettext.Clone(item.Value)
	o.pending[item.ID] = item
	return nil
}

// Pending implements Outbox.
func (o *MemoryOutbox) Pending(_ context.Context) ([]SyncItem, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]SyncItem, 0, len(o.pending))
	for _, it := range o.pending {
		it.Value = secrettext.Clone(it.Value)
		out = append(out, it)
	}
	return out, nil
}

// Done implements Outbox.
func (o *MemoryOutbox) Done(_ context.Context, id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.pending, id)
	return nil
}
