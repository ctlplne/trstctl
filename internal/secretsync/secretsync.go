// Package secretsync pushes trstctl's secrets into external platforms (S19.4,
// F68): a sync template (push + drift detection) plus targets — Kubernetes,
// GitHub Actions, GitLab CI, Terraform/OpenTofu, Vercel/Netlify, AWS Parameter
// Store/Secrets Manager, and a generic webhook. Delivery is via the outbox so it
// is durable (AN-6) and idempotent / never half-writes (AN-5); syncs are audited
// (AN-2). (Read-only discovery of existing secrets is S20.1; this pushes outward.)
package secretsync

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
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
	e.mu.Lock()
	e.n++
	id := fmt.Sprintf("sync-%d", e.n)
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
		if err := e.target.pusher.Push(ctx, it.Key, it.Value); err != nil {
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

// NewVercelTarget syncs secrets to Vercel/Netlify.
func NewVercelTarget(p Pusher) *Target { return NewTarget("vercel-netlify", p) }

// NewAWSParamStoreTarget syncs secrets to AWS Parameter Store / Secrets Manager.
func NewAWSParamStoreTarget(p Pusher) *Target { return NewTarget("aws-parameter-store", p) }

// NewWebhookTarget syncs secrets to a generic signed webhook.
func NewWebhookTarget(p Pusher) *Target { return NewTarget("webhook", p) }

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
	o.pending[item.ID] = item
	return nil
}

// Pending implements Outbox.
func (o *MemoryOutbox) Pending(_ context.Context) ([]SyncItem, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]SyncItem, 0, len(o.pending))
	for _, it := range o.pending {
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
