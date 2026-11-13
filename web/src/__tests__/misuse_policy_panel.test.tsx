// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { MisusePolicyPanel } from "@/components/risk/MisusePolicyPanel";
import { ApiError, api, type MisusePolicy } from "@/lib/api";

const defaults: MisusePolicy = { normal_days: 3, burst_floor: 64, burst_factor: 4, burst_lookback_days: 14, hourly_alert_cap: 20, custom: false };

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <MisusePolicyPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// M2-L2: the Risk page shows the thresholds misuse detection uses and lets a
// policy writer change them; a caller without policy:write is told so, and a
// server without misuse detection shows nothing.
describe("Misuse detection thresholds", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the defaults and saves the tenant's own thresholds", async () => {
    vi.spyOn(api, "misusePolicy").mockResolvedValue(defaults);
    const set = vi.spyOn(api, "setMisusePolicy").mockImplementation(async (input) => ({
      ...input,
      custom: true,
      set_by: "sec-admin",
      updated_at: "2026-11-13T10:00:00Z",
    }));
    const user = userEvent.setup();
    renderPanel();
    expect(await screen.findByText("The defaults apply.")).toBeInTheDocument();
    const floor = screen.getByLabelText("Secret reads in one hour before a burst is considered");
    expect(floor).toHaveValue(64);
    await user.clear(floor);
    await user.type(floor, "128");
    await user.click(screen.getByRole("button", { name: "Save thresholds" }));
    expect(await screen.findByText("Thresholds saved.")).toBeInTheDocument();
    expect(set).toHaveBeenCalledWith({ normal_days: 3, burst_floor: 128, burst_factor: 4, burst_lookback_days: 14, hourly_alert_cap: 20 });
    expect(await screen.findByText(/Set by sec-admin on/)).toBeInTheDocument();
  });

  it("says when the caller may not change them", async () => {
    vi.spyOn(api, "misusePolicy").mockResolvedValue(defaults);
    vi.spyOn(api, "setMisusePolicy").mockRejectedValue(new ApiError(403, '{"detail":"forbidden"}'));
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Save thresholds" }));
    expect(await screen.findByText("You can read these thresholds; changing them needs permission to write policy.")).toBeInTheDocument();
  });

  it("shows nothing when the server has no misuse detection", async () => {
    vi.spyOn(api, "misusePolicy").mockRejectedValue(new ApiError(404, '{"detail":"no such resource"}'));
    const { container } = renderPanel();
    await vi.waitFor(() => expect(container.querySelector("section")).toBeNull());
    expect(api.misusePolicy).toHaveBeenCalled();
  });
});
