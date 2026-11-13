// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { MisuseIncidentsPanel } from "@/components/risk/MisuseIncidentsPanel";
import { ApiError, api, type MisuseIncident } from "@/lib/api";

const reader: MisuseIncident = {
  id: "inc-1",
  credential_id: "reader",
  principal: "svc-reader",
  status: "open",
  opened_at: "2026-11-13T09:00:00Z",
  findings: 2,
};

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <MisuseIncidentsPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// M2-L3: the Risk page lists the open misuse incidents, one per flagged API
// token with its findings count, and closes one with the chosen resolution;
// a server without misuse detection shows nothing.
describe("Open misuse incidents", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists an open incident and closes it with the chosen resolution", async () => {
    const list = vi
      .spyOn(api, "misuseIncidents")
      .mockResolvedValueOnce({ items: [reader] })
      .mockResolvedValue({ items: [] });
    const close = vi.spyOn(api, "closeMisuseIncident").mockResolvedValue({ ...reader, status: "closed", resolution: "expected_use" });
    const user = userEvent.setup();
    renderPanel();
    const table = await screen.findByRole("table", { name: "Open misuse incidents, newest first" });
    const row = within(table).getAllByRole("row")[1];
    expect(row).toHaveTextContent("reader");
    expect(row).toHaveTextContent("svc-reader");
    expect(row).toHaveTextContent("2");
    await user.selectOptions(within(row).getByLabelText("Resolution for reader"), "expected_use");
    await user.click(within(row).getByRole("button", { name: "Close incident" }));
    expect(close).toHaveBeenCalledWith("inc-1", { resolution: "expected_use" });
    expect(await screen.findByText("No open misuse incidents.")).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith("open");
  });

  it("shows nothing when the server has no misuse detection", async () => {
    vi.spyOn(api, "misuseIncidents").mockRejectedValue(new ApiError(404, '{"detail":"no such resource"}'));
    const { container } = renderPanel();
    await vi.waitFor(() => expect(container.querySelector("section")).toBeNull());
  });
});
