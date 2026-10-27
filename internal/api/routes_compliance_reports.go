// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// complianceReportRoutes are the scheduled compliance and inventory reports, their
// signed runs, and the cryptographic risk report an operator reads on demand.
func (a *API) complianceReportRoutes(idPath, page []param) []route {
	return []route{
		{method: "POST", path: "/api/v1/compliance/report-schedules/preview", opID: "previewComplianceReportSchedule", summary: "Review and fingerprint an exact compliance report schedule without writing state or generating a report", handler: a.previewComplianceReportSchedule, reqSchema: "ComplianceReportScheduleRequest", resSchema: "ComplianceReportSchedulePreview", successCode: "200", perm: authz.AuditWrite},
		{method: "POST", path: "/api/v1/compliance/report-schedules", opID: "createComplianceReportSchedule", summary: "Create a scheduled compliance or inventory report", handler: a.createComplianceReportSchedule, reqSchema: "ComplianceReportScheduleRequest", resSchema: "ComplianceReportSchedule", successCode: "201", mutation: true, perm: authz.AuditWrite},
		{method: "GET", path: "/api/v1/compliance/report-schedules", opID: "listComplianceReportSchedules", summary: "List scheduled compliance and inventory reports", handler: a.listComplianceReportSchedules, query: page, resSchema: "ComplianceReportScheduleList", successCode: "200", perm: authz.AuditRead},
		{method: "POST", path: "/api/v1/compliance/report-schedules/{id}/pause", opID: "pauseComplianceReportSchedule", summary: "Pause a compliance report schedule while retaining its definition and evidence", handler: a.pauseComplianceReportSchedule, pathParams: idPath, resSchema: "ComplianceReportSchedule", successCode: "200", mutation: true, perm: authz.AuditWrite},
		{method: "POST", path: "/api/v1/compliance/report-schedules/{id}/resume", opID: "resumeComplianceReportSchedule", summary: "Resume a compliance report schedule with a fresh full interval", handler: a.resumeComplianceReportSchedule, pathParams: idPath, resSchema: "ComplianceReportSchedule", successCode: "200", mutation: true, perm: authz.AuditWrite},
		{method: "GET", path: "/api/v1/compliance/report-schedules/{id}/runs", opID: "listComplianceReportRuns", summary: "List exact signed-report run receipts for one schedule, newest due edge first", handler: a.listComplianceReportRuns, pathParams: idPath, query: page, resSchema: "ComplianceReportRunList", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/compliance/report-runs/{id}", opID: "getComplianceReportRun", summary: "Read one event-backed scheduled-report run and recovery state", handler: a.getComplianceReportRun, pathParams: idPath, resSchema: "ComplianceReportRun", successCode: "200", perm: authz.AuditRead},
		{method: "GET", path: "/api/v1/compliance/report-runs/{id}/artifact", opID: "downloadComplianceReportArtifact", summary: "Download exact signed scheduled-report bytes after archive and signer verification", handler: a.downloadComplianceReportArtifact, pathParams: idPath, resSchema: "ScheduledComplianceArtifact", successCode: "200", perm: authz.AuditRead},
		{method: "POST", path: "/api/v1/compliance/report-runs/{id}/requeue", opID: "requeueComplianceReportRun", summary: "Requeue a failed scheduled report under the same exact due edge", handler: a.requeueComplianceReportRun, pathParams: idPath, resSchema: "ComplianceReportRun", successCode: "200", mutation: true, perm: authz.AuditWrite},
		{method: "GET", path: "/api/v1/reports/crypto-risk", opID: "getCryptoRiskReport", summary: "Report every weak, distrusted or quantum-vulnerable key with its dependents, its NIST IR 8547 deadline and its migration plan, in the order to act on, with changes since the last scheduled report", handler: a.getCryptoRiskReport, query: cryptoRiskQuery, resSchema: "CryptoRiskReport", successCode: "200", perm: authz.RiskRead},
		{method: "GET", path: "/api/v1/reports/crypto-risk/export", opID: "exportCryptoRiskReport", summary: "Export the cryptographic risk report as CSV, one row per key in priority order", handler: a.exportCryptoRiskReport, resSchema: "CryptoRiskExport", successCode: "200", perm: authz.RiskRead},
	}
}
