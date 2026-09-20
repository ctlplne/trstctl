// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// outboxRecoveryRoutes is read-only. A reconciliation conflict is evidence of
// a refused command, not a mutable queue item an API caller may force through.
func (a *API) outboxRecoveryRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/incidents/outbox-reconciliation-conflicts", opID: "listOutboxReconciliationConflicts", summary: "List quarantined historical receiver-command conflicts without exposing executable payloads", handler: a.listOutboxReconciliationConflicts, resSchema: "OutboxReconciliationConflictList", successCode: "200", perm: authz.IncidentsRead},
	}
}
