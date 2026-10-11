import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretRotationScheduleTable } from "@/pages/secrets/SecretRotationScheduleTableParts";
import type { SecretRotationSchedule } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pauseSecretRotationSchedule: vi.fn(),
    resumeSecretRotationSchedule: vi.fn(),
    retireSecretRotationSchedule: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

function schedule(overrides: Partial<SecretRotationSchedule> = {}): SecretRotationSchedule {
  return {
    id: "25800000-0000-4000-8000-000000000001",
    tenant_id: "tenant-a",
    name: "daily database rotation",
    provider: "connector:ci",
    key: "database/password",
    old_ref: "version:3",
    interval_seconds: 86400,
    enabled: true,
    next_run_at: "2026-10-11T12:00:00Z",
    last_run_status: "completed",
    created_at: "2026-10-10T12:00:00Z",
    updated_at: "2026-10-10T12:00:00Z",
    ...overrides,
  };
}

describe("secret rotation schedule lifecycle controls", () => {
  it("uses exact schedule IDs for pause, resume and reviewed retirement", async () => {
    vi.clearAllMocks();
    const user = userEvent.setup();
    const initial = schedule();
    const paused = schedule({ enabled: false });
    const retired = schedule({ enabled: false, retired_at: "2026-10-11T13:00:00Z" });
    const onUpdated = vi.fn();
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    const onNotice = vi.fn();
    apiMock.pauseSecretRotationSchedule.mockResolvedValue(paused);
    apiMock.resumeSecretRotationSchedule.mockResolvedValue(initial);
    apiMock.retireSecretRotationSchedule.mockResolvedValue(retired);

    const props = { canWrite: true, onUpdated, onRefresh, onNotice };
    const view = render(<SecretRotationScheduleTable {...props} schedules={[initial]} />);
    const table = screen.getByRole("table", { name: "Scheduled secret rotations" });
    await user.click(within(table).getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(apiMock.pauseSecretRotationSchedule).toHaveBeenCalledWith(initial.id));
    expect(onUpdated).toHaveBeenLastCalledWith(paused);

    view.rerender(<SecretRotationScheduleTable {...props} schedules={[paused]} />);
    await user.click(within(table).getByRole("button", { name: "Resume" }));
    await waitFor(() => expect(apiMock.resumeSecretRotationSchedule).toHaveBeenCalledWith(initial.id));

    view.rerender(<SecretRotationScheduleTable {...props} schedules={[initial]} />);
    await user.click(within(table).getByRole("button", { name: "Retire" }));
    const review = screen.getByRole("alertdialog");
    expect(within(review).getByText(/daily database rotation/)).toBeInTheDocument();
    expect(apiMock.retireSecretRotationSchedule).not.toHaveBeenCalled();
    await user.click(within(review).getByRole("button", { name: "Retire" }));
    await waitFor(() => expect(apiMock.retireSecretRotationSchedule).toHaveBeenCalledWith(initial.id));
    expect(onUpdated).toHaveBeenLastCalledWith(retired);
    expect(onRefresh).toHaveBeenCalledTimes(3);
    expect(onNotice).toHaveBeenCalledTimes(3);

    view.rerender(<SecretRotationScheduleTable {...props} schedules={[retired]} />);
    expect(within(table).queryByRole("button", { name: "Resume" })).not.toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
  });

  it("does not offer write actions to a read-only operator", () => {
    render(<SecretRotationScheduleTable schedules={[schedule()]} canWrite={false} onUpdated={vi.fn()} onRefresh={vi.fn()} onNotice={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Pause" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Retire" })).toBeDisabled();
  });
});
