import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RbacProvider } from "@/components/rbac";
import type { DiscoverySchedule } from "@/lib/api";
import { DiscoveryScheduleTable } from "./DiscoveryScheduleTableParts";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pauseDiscoverySchedule: vi.fn(),
    resumeDiscoverySchedule: vi.fn(),
    retireDiscoverySchedule: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const schedule: DiscoverySchedule = {
  id: "11111111-1111-4111-8111-111111111111",
  tenant_id: "22222222-2222-4222-8222-222222222222",
  source_id: "33333333-3333-4333-8333-333333333333",
  name: "Nightly SSH scan",
  interval_seconds: 3600,
  enabled: true,
  updated_at: "2026-10-13T14:00:00Z",
};

describe("discovery schedule lifecycle controls", () => {
  beforeEach(() => vi.clearAllMocks());

  it("pauses, resumes and requires a reviewed retirement", async () => {
    const user = userEvent.setup();
    const onUpdated = vi.fn();
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const onNotice = vi.fn();
    apiMock.pauseDiscoverySchedule.mockResolvedValue({ ...schedule, enabled: false });
    apiMock.resumeDiscoverySchedule.mockResolvedValue(schedule);
    apiMock.retireDiscoverySchedule.mockResolvedValue({ ...schedule, enabled: false, retired_at: "2026-10-13T15:00:00Z" });
    const { rerender } = render(
      <DiscoveryScheduleTable schedules={[schedule]} sourceByID={new Map()} onUpdated={onUpdated} onRefresh={onRefresh} onNotice={onNotice} />,
    );
    await user.click(screen.getByRole("button", { name: "Pause" }));
    expect(apiMock.pauseDiscoverySchedule).toHaveBeenCalledWith(schedule.id);
    expect(onUpdated).toHaveBeenCalledWith({ ...schedule, enabled: false });

    rerender(
      <DiscoveryScheduleTable
        schedules={[{ ...schedule, enabled: false }]}
        sourceByID={new Map()}
        onUpdated={onUpdated}
        onRefresh={onRefresh}
        onNotice={onNotice}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Resume" }));
    expect(apiMock.resumeDiscoverySchedule).toHaveBeenCalledWith(schedule.id);

    await user.click(screen.getByRole("button", { name: "Retire" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent("Its history stays visible, and it cannot run or be resumed.");
    expect(apiMock.retireDiscoverySchedule).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(apiMock.retireDiscoverySchedule).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Retire" }));
    await user.click(screen.getByRole("alertdialog").querySelector("button:last-child")!);
    expect(apiMock.retireDiscoverySchedule).toHaveBeenCalledWith(schedule.id);
    expect(onRefresh).toHaveBeenCalledTimes(3);
    expect(onNotice).toHaveBeenCalled();
  });

  it("shows retained retirement without offering another mutation", () => {
    render(
      <DiscoveryScheduleTable
        schedules={[{ ...schedule, enabled: false, retired_at: "2026-10-13T15:00:00Z" }]}
        sourceByID={new Map()}
        onUpdated={vi.fn()}
        onRefresh={vi.fn()}
        onNotice={vi.fn()}
      />,
    );
    expect(screen.getByText("Retired")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
  });

  it("does not offer lifecycle controls to a read-only operator", () => {
    render(
      <RbacProvider permissions={["discovery:read"]}>
        <DiscoveryScheduleTable schedules={[schedule]} sourceByID={new Map()} onUpdated={vi.fn()} onRefresh={vi.fn()} onNotice={vi.fn()} />
      </RbacProvider>,
    );
    expect(screen.getByText("Nightly SSH scan")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
  });
});
