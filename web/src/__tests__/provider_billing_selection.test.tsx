// SPDX-License-Identifier: MPL-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ProviderBillingPanel } from "@/pages/provider/ProviderBillingPanel";
import { providerApi, type ProviderUsageEvidence } from "@/lib/providerApi";

const tenants = [
  { id: "alpha", slug: "alpha", name: "Alpha", status: "active" as const, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
  { id: "beta", slug: "beta", name: "Beta", status: "active" as const, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
];
function document(customer: string, digest: string): ProviderUsageEvidence {
  return {
    customer_id: customer,
    period_start: "2026-08-01T00:00:00Z",
    period_end: "2026-09-01T00:00:00Z",
    lines: [],
    signable: false,
    reason: "Incomplete period",
    digest,
    guidance: "Do not invoice",
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function renderPanel() {
  render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <ProviderBillingPanel tenants={tenants} onAuthError={vi.fn()} />
    </IntlProvider>,
  );
}

describe("Provider billing selection boundaries", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(providerApi, "customerHealth").mockImplementation(async (id) => ({
      tenant_id: id,
      health: "healthy",
      active_certificates: id === "alpha" ? 7 : 3,
    }));
    vi.spyOn(providerApi, "verifyUsageEvidence").mockResolvedValue({ verified: false });
  });

  it("discards an Alpha response delivered after the operator selects Beta", async () => {
    const alpha = deferred<ProviderUsageEvidence>();
    vi.spyOn(providerApi, "usageEvidence").mockReturnValueOnce(alpha.promise).mockResolvedValue(document("beta", "beta-digest"));
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Pull invoice evidence" }));
    await waitFor(() => expect(providerApi.usageEvidence).toHaveBeenCalledWith("alpha", expect.any(String), expect.any(String)));
    fireEvent.change(screen.getByLabelText("Billing customer"), { target: { value: "beta" } });
    await act(async () => {
      alpha.resolve(document("alpha", "alpha-digest"));
      await alpha.promise;
    });
    expect(screen.queryByText("alpha-digest")).not.toBeInTheDocument();
    expect(screen.queryByText("7")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));
    expect(await screen.findByText("beta-digest")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("clears completed evidence and download controls when the billing period changes", async () => {
    vi.spyOn(providerApi, "usageEvidence").mockResolvedValue(document("alpha", "old-period-digest"));
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Pull invoice evidence" }));
    await screen.findByText("old-period-digest");
    fireEvent.change(screen.getByLabelText("Billing period start"), { target: { value: "2026-07-01" } });
    expect(screen.queryByText("old-period-digest")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download finance CSV" })).not.toBeInTheDocument();
    expect(screen.getByText("Health unknown")).toBeInTheDocument();
  });

  it("does not apply an old customer's delayed signature verification to the next result", async () => {
    const verification = deferred<{ verified: boolean; keyId: string }>();
    vi.mocked(providerApi.verifyUsageEvidence).mockReturnValueOnce(verification.promise);
    vi.spyOn(providerApi, "usageEvidence")
      .mockResolvedValueOnce({ ...document("alpha", "alpha-signed"), signature: { alg: "RS256", key_id: "alpha-key", jws: "a.b.c" } })
      .mockResolvedValueOnce(document("beta", "beta-unsigned"));
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Pull invoice evidence" }));
    await screen.findByText("alpha-signed");
    fireEvent.change(screen.getByLabelText("Billing customer"), { target: { value: "beta" } });
    fireEvent.click(screen.getByRole("button", { name: "Pull invoice evidence" }));
    await screen.findByText("beta-unsigned");
    await act(async () => {
      verification.resolve({ verified: true, keyId: "alpha-key" });
      await verification.promise;
    });
    expect(screen.getByText("Unsigned")).not.toHaveClass("text-status-success");
    expect(screen.queryByText("alpha-signed")).not.toBeInTheDocument();
  });
});
