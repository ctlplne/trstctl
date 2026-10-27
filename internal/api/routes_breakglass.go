// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// breakglassRoutes is the emergency CA surface: ceremony-approved issuance,
// rotation and cross-signing under the signer-backed break-glass CA, the
// receipts that recover them, and the reconcile pass. Extracted from routes()
// so api.go stays inside the served-surface size budget.
func (a *API) breakglassRoutes(idPath []param) []route {
	return []route{
		{method: "POST", path: "/api/v1/breakglass/issue-ceremonies/preview", opID: "previewBreakglassIssue", summary: "Validate and explain an exact online break-glass request without opening a ceremony or calling the signer", handler: a.previewBreakglassIssue, reqSchema: "BreakglassIssueIntentRequest", resSchema: "BreakglassIssuePlanPreview", successCode: "200", perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/breakglass/issue-ceremonies", opID: "startBreakglassIssueCeremony", summary: "Start an exact-request-bound online break-glass ceremony", handler: a.startBreakglassIssueCeremony, reqSchema: "BreakglassIssueIntentRequest", resSchema: "BreakglassCeremony", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/breakglass/issue", opID: "issueBreakglass", summary: "Issue and audit a ceremony-approved online break-glass certificate", handler: a.issueBreakglass, reqSchema: "BreakglassIssueExecutionRequest", resSchema: "BreakglassIssueResponse", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "GET", path: "/api/v1/breakglass/issues", opID: "listBreakglassIssues", summary: "List bounded event-projected online emergency issue receipts without signed bundles", handler: a.listBreakglassIssues, query: []param{{name: "limit", typ: "integer", desc: "maximum receipts (1-100, default 20)"}, {name: "cursor", typ: "string", desc: "opaque source-sequence cursor from previous page"}}, resSchema: "BreakglassIssueReceiptList", successCode: "200", sensitiveResponse: true, perm: authz.CertsIssue},
		{method: "GET", path: "/api/v1/breakglass/issues/{id}", opID: "getBreakglassIssue", summary: "Recover the exact signed emergency bundle by ceremony ID after a lost response or restart", handler: a.getBreakglassIssue, pathParams: idPath, resSchema: "BreakglassIssueReceipt", successCode: "200", sensitiveResponse: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/breakglass/rotation-ceremonies", opID: "startBreakglassRotationCeremony", summary: "Start an exact-request-bound break-glass CA rotation ceremony", handler: a.startBreakglassRotationCeremony, reqSchema: "BreakglassRotationIntent", resSchema: "BreakglassCeremony", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/breakglass/rotate", opID: "rotateBreakglass", summary: "Rotate and bidirectionally cross-sign the signer-backed break-glass CA", handler: a.rotateBreakglass, reqSchema: "BreakglassRotationRequest", resSchema: "BreakglassRotation", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/breakglass/cross-sign-ceremonies", opID: "startBreakglassCrossSignCeremony", summary: "Start a target-certificate-bound break-glass cross-sign ceremony", handler: a.startBreakglassCrossSignCeremony, reqSchema: "BreakglassCrossSignRequest", resSchema: "BreakglassCeremony", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/breakglass/cross-sign", opID: "crossSignBreakglass", summary: "Cross-sign a CA certificate with the active break-glass signer", handler: a.crossSignBreakglass, reqSchema: "BreakglassCrossSignRequest", resSchema: "BreakglassCrossSign", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/breakglass/authority-receipts", opID: "listBreakglassAuthorityReceipts", summary: "List bounded event-projected emergency CA rotation and cross-sign receipts without certificate bodies", handler: a.listBreakglassAuthorityReceipts, query: []param{{name: "limit", typ: "integer", desc: "maximum receipts (1-100, default 20)"}, {name: "cursor", typ: "string", desc: "opaque source-sequence cursor from previous page"}}, resSchema: "BreakglassAuthorityReceiptList", successCode: "200", sensitiveResponse: true, perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/breakglass/authority-receipts/{id}", opID: "getBreakglassAuthorityReceipt", summary: "Recover the exact public rotation or cross-sign result by ceremony ID after a lost response or restart", handler: a.getBreakglassAuthorityReceipt, pathParams: idPath, resSchema: "BreakglassAuthorityReceipt", successCode: "200", sensitiveResponse: true, perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/breakglass/reconcile", opID: "reconcileBreakglass", summary: "Verify break-glass bundles and reconcile them into audit", handler: a.reconcileBreakglass, reqSchema: "BreakglassReconcileRequest", resSchema: "BreakglassReconcileResponse", successCode: "200", mutation: true, perm: authz.CertsIssue},
	}
}
