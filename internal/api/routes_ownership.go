// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// The ownership data-quality routes (I1/I2), split out of the main route table.
//
// Not an arbitrary split: the served-file line budget objected, and this is the
// seam it asked for. These five answer one question the rest of the owners CRUD
// does not — is the ownership we hold actually TRUE — and they share a single
// rule: an external source may fill in what nobody recorded and may never
// overwrite what a human attested.
//
// There is deliberately no CMDB write route here. "No CMDB write unless
// explicitly configured" is held as the absence of such a route plus a ticket
// writer whose table allow-list rejects cmdb_ci, not as a flag.
func (a *API) ownershipDataQualityRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/owners/import", opID: "importOwnership", summary: "Import ownership from CSV: fills in what is unrecorded, refuses to overwrite what a human attested", handler: a.importOwnership, resSchema: "OwnershipImportResult", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners/ownership-conflicts", opID: "listOwnershipConflicts", summary: "List unresolved ownership disagreements between recorded owners and an external source", handler: a.listOwnershipConflicts, resSchema: "OwnershipConflictList", successCode: "200", perm: authz.OwnersRead},
		{method: "PUT", path: "/api/v1/owners/cmdb-schedule", opID: "putCMDBReconcileSchedule", summary: "Configure scheduled read-only reconciliation of ownership against a ServiceNow CMDB", handler: a.putCMDBSchedule, resSchema: "CMDBReconcileSchedule", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners/cmdb-schedule", opID: "getCMDBReconcileSchedule", summary: "Read the CMDB reconcile schedule, including when it last ran and why it last failed", handler: a.getCMDBSchedule, resSchema: "CMDBReconcileSchedule", successCode: "200", perm: authz.OwnersRead},
		{method: "GET", path: "/api/v1/owners/unowned", opID: "listUnownedIdentities", summary: "List managed identities whose ownership cannot answer an incident question", handler: a.listUnownedIdentities, resSchema: "UnownedQueue", successCode: "200", perm: authz.OwnersRead},
	}
}
