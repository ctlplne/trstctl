import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { ComplianceInventoryReportPanel, formatScheduleCadence, scheduleOverdueAtReportTime } from "@/pages/policy/ComplianceReportingPanels";
import { I18nProvider } from "@/i18n/I18nProvider";
import type { ComplianceInventoryReport, ComplianceReportSchedule } from "@/lib/api";

const hourly: ComplianceReportSchedule = {
  id: "0ea27bf9-3b11-484e-8dea-d96033e80a6b",
  tenant_id: "11111111-1111-4111-8111-111111111111",
  framework: "soc2",
  name: "Hourly signed pack",
  report_type: "framework_evidence_pack",
  interval_seconds: 3600,
  enabled: true,
  delivery: "audit_export",
  next_run_at: "2026-10-04T07:48:42Z",
  created_at: "2026-10-04T06:48:42Z",
  updated_at: "2026-10-04T06:48:42Z",
};

const report: ComplianceInventoryReport = {
  capability: "F62",
  evidence_refs: [],
  frameworks: ["soc2"],
  generated_at: "2026-10-04T06:50:00Z",
  report_types: ["framework_evidence_pack"],
  routes: [],
  schedules: [hourly],
  summary: {
    certificates: 0,
    crypto_assets: 0,
    discovery_schedules: 0,
    enabled_report_schedules: 1,
    frameworks_supported: 1,
    inventory_rows: 1,
    report_schedules: 1,
    report_types_supported: 1,
  },
};

describe("compliance report schedule cadence and due time", () => {
  it("shows the exact one-hour API schedule and its due time in the console", () => {
    render(
      <I18nProvider initialTimeZone="America/New_York">
        <ComplianceInventoryReportPanel report={report} schedules={[hourly]} scheduleAction={null} onToggleSchedule={() => {}} />
      </I18nProvider>,
    );
    const row = screen.getByText("Hourly signed pack").closest("tr");
    expect(row).not.toBeNull();
    const cells = within(row!).getAllByRole("cell");
    expect(cells[3]).toHaveTextContent("1h");
    expect(cells[4]).toHaveTextContent(/Oct 4, 2026.*3:48.*AM/);
  });

  it("preserves mixed day, hour, minute, and second cadences without rounding", () => {
    expect(formatScheduleCadence(86400)).toBe("1d");
    expect(formatScheduleCadence(90061)).toBe("1d 1h 1m 1s");
    expect(formatScheduleCadence(0)).toBe("-");
  });

  it("does not promise a next run while the schedule is paused", () => {
    const paused = { ...hourly, enabled: false };
    render(<ComplianceInventoryReportPanel report={report} schedules={[paused]} scheduleAction={null} onToggleSchedule={() => {}} />);
    const row = screen.getByText("Hourly signed pack").closest("tr");
    expect(row).not.toBeNull();
    const cells = within(row!).getAllByRole("cell");
    expect(cells[4]).toHaveTextContent("Paused — no run due");
    expect(cells[4]).not.toHaveTextContent(/Oct 4, 2026/);
  });

  it("labels a missed due time using the server report time, without trusting the browser clock", () => {
    const overdueReport = { ...report, generated_at: "2026-10-04T09:18:35Z" };
    render(<ComplianceInventoryReportPanel report={overdueReport} schedules={[hourly]} scheduleAction={null} onToggleSchedule={() => {}} />);
    const row = screen.getByText("Hourly signed pack").closest("tr");
    expect(within(row!).getAllByRole("cell")[4]).toHaveTextContent("Overdue — scheduled time passed");
    expect(scheduleOverdueAtReportTime(hourly, report.generated_at)).toBe(false);
    expect(scheduleOverdueAtReportTime(hourly, overdueReport.generated_at)).toBe(true);
    expect(scheduleOverdueAtReportTime({ ...hourly, enabled: false }, overdueReport.generated_at)).toBe(false);
    expect(scheduleOverdueAtReportTime({ ...hourly, next_run_at: "invalid" }, overdueReport.generated_at)).toBe(false);
  });
});
