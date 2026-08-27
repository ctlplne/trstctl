// SPDX-License-Identifier: MPL-2.0

package api

import (
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/issuancerequest"
)

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
		{method: "POST", path: "/api/v1/owners/ownership-conflicts/{id}/resolve", opID: "resolveOwnershipConflict", summary: "Close an ownership disagreement with the reason it was decided", handler: a.resolveOwnershipConflict, pathParams: []param{pathUUID("id")}, reqSchema: "OwnershipResolveInput", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners/ownership-conflicts", opID: "listOwnershipConflicts", summary: "List unresolved ownership disagreements between recorded owners and an external source", handler: a.listOwnershipConflicts, resSchema: "OwnershipConflictList", successCode: "200", perm: authz.OwnersRead},
		{method: "PUT", path: "/api/v1/owners/cmdb-schedule", opID: "putCMDBReconcileSchedule", summary: "Configure scheduled read-only reconciliation of ownership against a ServiceNow CMDB", handler: a.putCMDBSchedule, resSchema: "CMDBReconcileSchedule", successCode: "200", mutation: true, perm: authz.OwnersWrite},
		{method: "GET", path: "/api/v1/owners/cmdb-schedule", opID: "getCMDBReconcileSchedule", summary: "Read the CMDB schedule, bounded-page coverage, retained cursor, terminal run, and last failure", handler: a.getCMDBSchedule, resSchema: "CMDBReconcileSchedule", successCode: "200", perm: authz.OwnersRead},
		{method: "GET", path: "/api/v1/owners/unowned", opID: "listUnownedIdentities", summary: "List managed identities whose ownership cannot answer an incident question", handler: a.listUnownedIdentities, resSchema: "UnownedQueue", successCode: "200", perm: authz.OwnersRead},
	}
}

// The I3 issuance-request lifecycle.
//
// Permissions reuse the EXISTING certs:request / certs:issue split, whose own
// doc comment says a requester cannot self-issue. Inventing a parallel
// certs:approve would give this surface a second separation-of-duties rule that
// could drift out of agreement with the one guarding direct issuance. Approve, deny, and cancel share one
// handler constructor so the transition and separation-of-duties rules cannot
// be enforced on one verb and forgotten on another.
func (a *API) issuanceRequestRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/issuance-requests", opID: "openIssuanceRequest", summary: "Open a first-class issuance request with a real lifecycle", handler: a.createIssuanceRequest, reqSchema: "IssuanceRequestInput", resSchema: "IssuanceRequest", successCode: "201", mutation: true, perm: authz.CertsRequest},
		{method: "POST", path: "/api/v1/issuance-requests/preview", opID: "previewIssuanceRequest", summary: "Validate and normalize an exact issuance request without writing state or contacting a certificate authority", handler: a.previewIssuanceRequest, reqSchema: "IssuanceRequestInput", resSchema: "IssuanceRequestPreview", successCode: "200", perm: authz.CertsRequest},
		{method: "GET", path: "/api/v1/issuance-requests", opID: "listIssuanceRequests", summary: "List issuance requests, including the denied and expired ones an audit needs", handler: a.listIssuanceRequests, resSchema: "IssuanceRequestList", successCode: "200", perm: authz.CertsRead},
		{method: "PUT", path: "/api/v1/issuance-requests/intake-schedule", opID: "putTicketIntakeSchedule", summary: "Configure bounded ServiceNow or Jira ticket intake with durable relay paging", handler: a.putTicketIntakeSchedule, reqSchema: "TicketIntakeInput", resSchema: "TicketIntakeSchedule", successCode: "200", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/issuance-requests/intake-schedule", opID: "getTicketIntakeSchedule", summary: "Read one provider's durable ticket-intake cursor, coverage, terminal run, and last failure", handler: a.getTicketIntakeSchedule, query: []param{{name: "system", typ: "string", desc: "provider schedule to read: servicenow (default) or jira"}}, resSchema: "TicketIntakeSchedule", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/issuance-requests/{id}/approve", opID: "approveIssuanceRequest", summary: "Approve a request; the requester can never approve their own", handler: a.decideIssuanceRequest(issuancerequest.StateApproved), pathParams: idPath, resSchema: "IssuanceRequest", successCode: "200", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/issuance-requests/{id}/deny", opID: "denyIssuanceRequest", summary: "Deny a request with a reason the requester can act on", handler: a.decideIssuanceRequest(issuancerequest.StateDenied), pathParams: idPath, reqSchema: "IssuanceDecisionInput", resSchema: "IssuanceRequest", successCode: "200", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/issuance-requests/{id}/cancel", opID: "cancelIssuanceRequest", summary: "Withdraw your own request; only the requester may", handler: a.decideIssuanceRequest(issuancerequest.StateCancelled), pathParams: idPath, resSchema: "IssuanceRequest", successCode: "200", mutation: true, perm: authz.CertsRequest},
		{method: "POST", path: "/api/v1/issuance-requests/{id}/prepare", opID: "prepareIssuanceRequest", summary: "Create or recover the exact requested identity and return its public CSR for guarded issuance", handler: a.prepareIssuanceRequest, pathParams: idPath, resSchema: "IssuanceRequestPreparation", successCode: "200", mutation: true, sensitiveResponse: true, perm: authz.IdentitiesWrite},
		{method: "POST", path: "/api/v1/issuance-requests/{id}/complete", opID: "completeIssuanceRequest", summary: "Mark a request issued only after its matching signer-backed certificate exists", handler: a.completeIssuanceRequest, pathParams: idPath, resSchema: "IssuanceRequest", successCode: "200", mutation: true, perm: authz.CertsIssue},
	}
}

// The I5 MDM device-correlation surface. READ ONLY, and deliberately so: there
// is no write route here, and internal/mdm has no request builder that can emit
// anything but a GET. A bad write to an MDM does not corrupt a record — it
// pushes a profile to real laptops.
func (a *API) mdmDeviceRoutes() []route {
	// The MDM's own device id is NOT a uuid — it is whatever Intune or Jamf
	// assigns, and that is precisely the identifier an admin can paste from
	// their console. Typing it as a uuid would reject every real Jamf id.
	devicePath := []param{
		pathString("mdm", "intune or jamf"),
		pathString("id", "the MDM's own device id, as shown in its console"),
	}
	return []route{
		{method: "GET", path: "/api/v1/mdm/devices", opID: "listMDMDevices", summary: "List MDM devices correlated to SCEP transactions, with unobserved counted apart from failed", handler: a.listMDMDevices, resSchema: "MDMDeviceList", successCode: "200", perm: authz.CertsRead},
		{method: "PUT", path: "/api/v1/mdm/poll-schedule", opID: "putMDMPollSchedule", summary: "Configure the per-MDM read schedule; relay execution requires a secret:// token reference", handler: a.putMDMPollSchedule, reqSchema: "MDMPollScheduleInput", resSchema: "MDMPollSchedule", successCode: "200", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/mdm/poll-schedule", opID: "listMDMPollSchedules", summary: "The configured MDM read schedules with their last outcome", handler: a.listMDMPollSchedules, resSchema: "MDMPollScheduleList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/mdm/{mdm}/devices/{id}/trace", opID: "getMDMDeviceTrace", summary: "Per-device enrollment trace showing which step an enrollment broke at", handler: a.getMDMDeviceTrace, pathParams: devicePath, resSchema: "MDMDeviceTrace", successCode: "200", perm: authz.CertsRead},
	}
}

// The A5 staged agent-upgrade surface. Pause and resume share one handler
// constructor so the state rules cannot be enforced on one verb and forgotten
// on the other.
func (a *API) agentUpgradeRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/agents/upgrade-campaign", opID: "getAgentUpgradeCampaign", summary: "Campaign state with the fleet's ring assignment and version histogram", handler: a.getUpgradeCampaign, resSchema: "AgentUpgradeCampaign", successCode: "200", perm: authz.AgentsRead},
		{method: "POST", path: "/api/v1/agents/upgrade-campaign", opID: "openAgentUpgradeCampaign", summary: "Start a staged rollout that halts automatically when a ring fails", handler: a.openUpgradeCampaign, reqSchema: "AgentUpgradeCampaignInput", resSchema: "AgentUpgradeCampaign", successCode: "201", mutation: true, perm: authz.AgentsWrite},
		{method: "POST", path: "/api/v1/agents/upgrade-campaign/pause", opID: "pauseAgentUpgradeCampaign", summary: "Pause a rollout; this gates dispatch, not just the button", handler: a.campaignControl("pause"), resSchema: "AgentUpgradeCampaign", successCode: "200", mutation: true, perm: authz.AgentsWrite},
		{method: "POST", path: "/api/v1/agents/upgrade-campaign/resume", opID: "resumeAgentUpgradeCampaign", summary: "Resume at the ring that halted, never past it", handler: a.campaignControl("resume"), resSchema: "AgentUpgradeCampaign", successCode: "200", mutation: true, perm: authz.AgentsWrite},
		{method: "POST", path: "/api/v1/agents/upgrade-ring", opID: "assignAgentUpgradeRing", summary: "Place an agent in a rollout ring; empty unassigns and is never read as broad", handler: a.assignAgentRing, reqSchema: "AgentRingInput", successCode: "200", mutation: true, perm: authz.AgentsWrite},
	}
}

// The white-label brand route (AUD-14). Unauthenticated by design: the brand
// decides what the LOGIN page looks like, and a surface requiring a session
// could never brand the one screen a customer sees before they have one. It
// carries presentation only.
func (a *API) brandingRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/brand", opID: "getBrand", summary: "Resolve the white-label brand for this host; presentation only, unauthenticated so the login screen can be branded", // perm is deliberately empty: "" means public on this table.
			handler: a.getBrand, resSchema: "Brand", successCode: "200"},
	}
}

// extractedRouteGroups is every route group split out of api.go, in one call so
// the main table's append block stays a single line as more groups arrive.
func (a *API) extractedRouteGroups() []route {
	var out []route
	out = append(out, a.ownershipDataQualityRoutes()...)
	out = append(out, a.issuanceRequestRoutes()...)
	out = append(out, a.mdmDeviceRoutes()...)
	out = append(out, a.agentUpgradeRoutes()...)
	out = append(out, a.brandingRoutes()...)
	out = append(out, a.outboxRecoveryRoutes()...)
	return out
}
