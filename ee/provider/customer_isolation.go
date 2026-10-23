// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenancy"
)

// A96: the Provider assurance console.
//
// An auditor asked "what isolation does customer X actually have?" could
// read the drill report, which proves the substrate, but nothing said what
// one customer's targets were. CustomerIsolation reads them from the live
// tenancy router, the same source every request's RLS schema, event lane and
// object prefix come from, plus the customer's audit stream as JetStream
// reports it. It is a delegated read: a customer's isolation is as much the
// customer's estate as its inventory.

// AuditStreamReader reports a tenant lane's audit stream (A94).
type AuditStreamReader interface {
	TenantAuditStreamInfo(ctx context.Context, lane string) (events.TenantAuditStream, error)
}

// CustomerIsolation is one customer's isolation as the deployment serves it.
type CustomerIsolation struct {
	TenantID             string `json:"tenant_id"`
	Model                string `json:"model"`
	PostgresSchema       string `json:"postgres_schema,omitempty"`
	JetStreamSubjectLane string `json:"jetstream_subject_lane,omitempty"`
	ObjectKeyPrefix      string `json:"object_key_prefix,omitempty"`
	AuditStream          struct {
		Name     string `json:"name,omitempty"`
		Exists   bool   `json:"exists"`
		Messages uint64 `json:"messages"`
	} `json:"audit_stream"`
	// Note explains a pooled customer or an unreadable audit stream in words.
	Note string `json:"note,omitempty"`
}

// CustomerIsolation reads the customer's isolation targets under its read
// delegation.
func (s *Service) CustomerIsolation(ctx context.Context, actor Operator, tenantID string) (CustomerIsolation, error) {
	if err := s.requireOperator(actor); err != nil {
		return CustomerIsolation{}, err
	}
	if err := s.authorize(ctx, actor, tenantID, OpRead); err != nil {
		return CustomerIsolation{}, err
	}
	if _, err := s.store.Tenant(ctx, tenantID); err != nil {
		return CustomerIsolation{}, err
	}
	targets, err := tenancy.CurrentRouter().TargetsFor(ctx, tenantID)
	if err != nil {
		return CustomerIsolation{}, fmt.Errorf("provider: resolve isolation targets: %w", err)
	}
	out := CustomerIsolation{TenantID: tenantID, Model: string(targets.Model), PostgresSchema: targets.PostgresSchema,
		JetStreamSubjectLane: targets.JetStreamSubjectLane, ObjectKeyPrefix: targets.ObjectKeyPrefix}
	if out.Model == "" {
		out.Model = string(tenancy.IsolationPooled)
	}
	if targets.JetStreamSubjectLane == "" {
		out.Note = "pooled: this customer shares the deployment's schema, event stream and object namespace, confined by row-level security, tenant subjects and key prefixes derived from its id"
		return out, nil
	}
	if s.auditStreams == nil {
		out.Note = "the audit stream reader is not attached; the lane is served but its audit stream cannot be reported"
		return out, nil
	}
	stream, err := s.auditStreams.TenantAuditStreamInfo(ctx, targets.JetStreamSubjectLane)
	if err != nil {
		out.Note = "the audit stream could not be read: " + err.Error()
		return out, nil
	}
	out.AuditStream.Name, out.AuditStream.Exists, out.AuditStream.Messages = stream.Name, stream.Exists, stream.Messages
	if !stream.Exists {
		out.Note = "the customer's lane has no audit stream yet; the isolation drill or provisioning ensures one"
	}
	return out, nil
}
