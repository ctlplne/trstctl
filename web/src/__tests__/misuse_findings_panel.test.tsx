// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { MisuseFindingsPanel } from "@/components/risk/MisuseFindingsPanel";
import { ApiError, api, type MisuseFinding } from "@/lib/api";

const burst: MisuseFinding = {
  id: "f-2",
  rule: "secret_read_burst",
  credential_id: "reader",
  principal: "svc-reader",
  source: "127.0.0.0/24",
  window_start: "2026-11-10T10:00:00Z",
  observed_count: 64,
  baseline: 2,
  alerted: false,
  detected_at: "2026-11-10T10:05:00Z",
};

const lease: MisuseFinding = {
  id: "f-1",
  rule: "new_source_lease",
  credential_id: "deployer",
  principal: "svc-deployer",
  source: "10.20.30.0/24",
  window_start: "2026-11-10T09:00:00Z",
  observed_count: 1,
  baseline: 0,
  alerted: true,
  detected_at: "2026-11-10T09:05:00Z",
};

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <MisuseFindingsPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// M2-L1: the Risk page lists every misuse finding of the tenant's API tokens,
// including one whose alert the hourly budget held back, and pages to older
// ones; a server without misuse detection says so.
describe("Token misuse findings", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists findings newest first, says when an alert was held back, and pages to older ones", async () => {
    const spy = vi
      .spyOn(api, "misuseFindings")
      .mockImplementation(async (options) => (options?.cursor === "7" ? { items: [lease], next_cursor: "" } : { items: [burst], next_cursor: "7" }));
    const user = userEvent.setup();
    renderPanel();
    const table = await screen.findByRole("table", { name: "Misuse findings, newest first" });
    const first = within(table).getAllByRole("row")[1];
    expect(first).toHaveTextContent("reader");
    expect(first).toHaveTextContent("Read secrets 64 times from 127.0.0.0/24 in one hour; its largest earlier hour in 14 days was 2.");
    expect(first).toHaveTextContent("No alert: the hour's alert budget was spent");
    await user.click(screen.getByRole("button", { name: "Show older findings" }));
    expect(await within(table).findByText(/Requested a temporary credential from 10\.20\.30\.0\/24/)).toBeInTheDocument();
    expect(spy).toHaveBeenLastCalledWith({ cursor: "7" });
    expect(within(table).getAllByRole("row")[2]).toHaveTextContent("Alert sent");
    expect(screen.queryByRole("button", { name: "Show older findings" })).not.toBeInTheDocument();
  });

  it("says when the server has no misuse detection", async () => {
    vi.spyOn(api, "misuseFindings").mockRejectedValue(new ApiError(404, '{"detail":"no such resource"}'));
    renderPanel();
    expect(await screen.findByText("Misuse detection is not in this edition of the server.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("says when there are no findings", async () => {
    vi.spyOn(api, "misuseFindings").mockResolvedValue({ items: [], next_cursor: "" });
    renderPanel();
    expect(await screen.findByText("No misuse findings.")).toBeInTheDocument();
  });
});
