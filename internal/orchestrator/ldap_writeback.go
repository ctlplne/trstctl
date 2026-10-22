// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// DestinationLDAPWriteback is the outbox destination of an LDAP directory
// writeback (A83): a role change or offboarding an operator made in trstctl to
// a member the directory authenticated (a subject that is a DN under the
// tenant's writeback base), applied to the directory's role groups by the
// licensed worker. Control-plane work; no agent claims it.
const DestinationLDAPWriteback = "ldap.writeback"

// LDAPWritebackIntent names the member whose current state the worker writes
// back; it carries no member data, the worker reads the projected row.
type LDAPWritebackIntent struct {
	Subject       string `json:"subject"`
	Change        string `json:"change"`
	SourceEventID string `json:"source_event_id"`
}

// EnableLDAPWriteback names the tenants that write member changes back to
// their directory, each with the base DN its directory members live under.
// Set at composition, before any member command runs.
func (o *Orchestrator) EnableLDAPWriteback(baseDNByTenant map[string]string) {
	if o == nil {
		return
	}
	o.ldapWritebackBaseDNs = map[string]string{}
	for tenant, base := range baseDNByTenant {
		if tenant, base = strings.TrimSpace(tenant), normalizeDN(base); tenant != "" && base != "" {
			o.ldapWritebackBaseDNs[tenant] = base
		}
	}
}

// normalizeDN lowercases a DN and drops the spaces around its separators, the
// comparison form the suffix check uses.
func normalizeDN(dn string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(dn)), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}

// LDAPWritebackApplies reports whether subject is a directory DN under the
// tenant's writeback base.
func (o *Orchestrator) LDAPWritebackApplies(tenantID, subject string) bool {
	if o == nil {
		return false
	}
	base, ok := o.ldapWritebackBaseDNs[tenantID]
	if !ok {
		return false
	}
	dn := normalizeDN(subject)
	return strings.Contains(dn, "=") && (dn == base || strings.HasSuffix(dn, ","+base))
}

// enqueueLDAPWritebackTx queues the writeback for a member change inside the
// transaction that records it (AN-6), when the tenant writes back and the
// member is a directory DN under its base.
func (o *Orchestrator) enqueueLDAPWritebackTx(ctx context.Context, tx pgx.Tx, event events.Event, subject, change string) error {
	if o == nil || o.outbox == nil || !o.LDAPWritebackApplies(event.TenantID, subject) {
		return nil
	}
	payload, err := json.Marshal(LDAPWritebackIntent{Subject: subject, Change: change, SourceEventID: event.ID})
	if err != nil {
		return err
	}
	_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
		TenantID: event.TenantID, Destination: DestinationLDAPWriteback,
		IdempotencyKey: "ldap-writeback:" + event.ID, Payload: payload,
		EffectLane: "ldap-writeback:" + subject, RequiredAgentRole: "control_plane",
	})
	return err
}

// RecordLDAPWriteback appends the outcome of one writeback as audit evidence.
func (o *Orchestrator) RecordLDAPWriteback(ctx context.Context, tenantID string, recorded projections.LDAPWritebackRecorded) error {
	payload, err := json.Marshal(recorded)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventLDAPWritebackRecorded, tenantID, payload)
	return err
}
