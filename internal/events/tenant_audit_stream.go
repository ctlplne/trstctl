// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go/jetstream"
)

// A94: the per-tenant audit stream.
//
// A siloed tenant's events already land on its own subject lane
// (events.<lane>.>) inside the one source-of-truth stream. Sovereignty asks
// for more than a subject filter: the tenant's audit trail should exist as a
// stream of its own, with its own retention and its own name, that can be
// inspected, handed over, or deleted without touching a neighbour. A tenant
// audit stream is a JetStream stream that SOURCES the tenant's lane from the
// active events stream; it never accepts publishes of its own, so it cannot
// diverge from the log it mirrors.

const tenantAuditStreamPrefix = "TRSTCTL_AUDIT_"

// TenantAuditStream describes one tenant's audit stream.
type TenantAuditStream struct {
	Name         string
	Lane         string
	SourceStream string
	Messages     uint64
	Exists       bool
}

func tenantAuditStreamName(lane string) (string, error) {
	if lane == "" || strings.ContainsAny(lane, ".*>\t ") {
		return "", fmt.Errorf("events: invalid subject lane %q", lane)
	}
	var b strings.Builder
	for _, r := range lane {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return tenantAuditStreamPrefix + b.String(), nil
}

// EnsureTenantAuditStream creates or updates the tenant's audit stream so it
// sources exactly the tenant's lane from the active events stream. It is
// idempotent and safe to call from provisioning, the isolation drill, or a
// repair; it refuses on a read-only external source, where this process may
// not create streams.
func (l *Log) EnsureTenantAuditStream(ctx context.Context, lane string) (TenantAuditStream, error) {
	name, err := tenantAuditStreamName(lane)
	if err != nil {
		return TenantAuditStream{}, err
	}
	if l == nil || l.js == nil {
		return TenantAuditStream{}, errors.New("events: no JetStream context for the tenant audit stream")
	}
	if l.desiredReplicas < 1 {
		return TenantAuditStream{}, errors.New("events: tenant audit streams are unavailable on a read-only external source")
	}
	sourceName, _, err := l.resolveActiveStream(ctx)
	if err != nil {
		return TenantAuditStream{}, fmt.Errorf("events: resolve source stream for tenant audit stream: %w", err)
	}
	desired := jetstream.StreamConfig{
		Name:        name,
		Storage:     jetstream.FileStorage,
		Replicas:    l.desiredReplicas,
		Retention:   jetstream.LimitsPolicy,
		MaxMsgs:     -1,
		MaxBytes:    -1,
		AllowDirect: true,
		Sources: []*jetstream.StreamSource{{
			Name:          sourceName,
			FilterSubject: subjectPrefix + "." + lane + ".>",
		}},
		Metadata: map[string]string{
			"trstctl.tenant_lane": lane,
			"trstctl.source_name": sourceName,
		},
	}
	stream, err := l.js.CreateOrUpdateStream(ctx, desired)
	if err != nil {
		return TenantAuditStream{}, fmt.Errorf("events: ensure tenant audit stream %s: %w", name, err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return TenantAuditStream{}, fmt.Errorf("events: tenant audit stream %s info: %w", name, err)
	}
	return TenantAuditStream{Name: name, Lane: lane, SourceStream: sourceName, Messages: info.State.Msgs, Exists: true}, nil
}

// TenantAuditStreamInfo reports the tenant's audit stream as it is: absent is
// Exists=false, never an invented empty stream.
func (l *Log) TenantAuditStreamInfo(ctx context.Context, lane string) (TenantAuditStream, error) {
	name, err := tenantAuditStreamName(lane)
	if err != nil {
		return TenantAuditStream{}, err
	}
	if l == nil || l.js == nil {
		return TenantAuditStream{}, errors.New("events: no JetStream context for the tenant audit stream")
	}
	stream, err := l.js.Stream(ctx, name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return TenantAuditStream{Name: name, Lane: lane}, nil
	}
	if err != nil {
		return TenantAuditStream{}, fmt.Errorf("events: open tenant audit stream %s: %w", name, err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return TenantAuditStream{}, fmt.Errorf("events: tenant audit stream %s info: %w", name, err)
	}
	out := TenantAuditStream{Name: name, Lane: lane, Messages: info.State.Msgs, Exists: true}
	if len(info.Config.Sources) == 1 {
		out.SourceStream = info.Config.Sources[0].Name
	}
	return out, nil
}

// DeleteTenantAuditStream removes the tenant's audit stream. The source-of-truth
// events are untouched: this deletes the tenant's mirror, which teardown and
// the drill's cleanup own; an absent stream is not an error.
func (l *Log) DeleteTenantAuditStream(ctx context.Context, lane string) error {
	name, err := tenantAuditStreamName(lane)
	if err != nil {
		return err
	}
	if l == nil || l.js == nil {
		return errors.New("events: no JetStream context for the tenant audit stream")
	}
	err = l.js.DeleteStream(ctx, name)
	if err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
		return fmt.Errorf("events: delete tenant audit stream %s: %w", name, err)
	}
	return nil
}
