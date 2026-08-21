import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Privacy } from "@/pages/Privacy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    privacyCatalog: vi.fn(),
    privacySubjectErasures: vi.fn(),
    privacyRetentionRuns: vi.fn(),
    privacyArchiveAttestations: vi.fn(),
    erasePrivacySubject: vi.fn(),
    exportPrivacySubject: vi.fn(),
    enforcePrivacyRetention: vi.fn(),
    recordPrivacyArchiveAttestation: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPrivacy() {
  return render(
    <MemoryRouter initialEntries={["/privacy"]}>
      <ToastProvider>
        <main>
          <Privacy />
        </main>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("Route 036 evidence-privacy hierarchy", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.privacyCatalog.mockResolvedValue({
      items: [
        {
          id: "catalog-1",
          category: "audit subject",
          location: "events.Actor.Subject",
          owner: "platform",
          purpose: "audit attribution",
          retention_class: "audit",
          erasure: "pseudonymize",
        },
      ],
    });
    apiMock.privacySubjectErasures.mockResolvedValue({ items: [] });
    apiMock.privacyRetentionRuns.mockResolvedValue({
      items: [{ run_id: "run-1", enforced_at: "2026-08-21T10:00:00Z", requested_by_ref: "scheduler", counts: {}, cutoffs: {} }],
    });
    apiMock.privacyArchiveAttestations.mockResolvedValue({ items: [] });
  });

  it("answers the evidence boundary before loading or exposing exact controls", async () => {
    const user = userEvent.setup();
    renderPrivacy();

    expect(await screen.findByRole("heading", { level: 1, name: "Evidence privacy" })).toBeInTheDocument();
    expect(screen.getByText("Who can access evidence, how long it stays, and what is removed.", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Redaction, retention jobs, access logs, sanitized summaries.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Your evidence boundary" })).toBeInTheDocument();
    expect(screen.getByText("privacy:read", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Set per catalog entry", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Direct data, then archive proof", { exact: true })).toBeInTheDocument();

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    expect(within(actions).getByRole("button", { name: "Review policy" })).toBeEnabled();
    expect(document.querySelectorAll("main input, main select, main textarea, main table")).toHaveLength(0);

    for (const title of ["Policy and data map", "Subject rights", "Archive removal evidence", "Retention jobs"]) {
      expect(screen.getByText(title, { exact: true }).closest("details")).not.toHaveAttribute("open");
    }
    expect(apiMock.privacyCatalog).not.toHaveBeenCalled();
    expect(apiMock.privacySubjectErasures).not.toHaveBeenCalled();
    expect(apiMock.privacyArchiveAttestations).not.toHaveBeenCalled();
    expect(apiMock.privacyRetentionRuns).not.toHaveBeenCalled();

    await user.click(within(actions).getByRole("button", { name: "Review policy" }));
    await waitFor(() => expect(apiMock.privacyCatalog).toHaveBeenCalledTimes(1));
    expect(screen.getByText("Policy and data map", { exact: true }).closest("details")).toHaveAttribute("open");
    expect(await screen.findByRole("table", { name: "Personal-data catalog" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Personal-data catalog scroll area" })).toHaveAttribute("tabindex", "0");
  });

  it("loads each exact control only when its disclosure opens", async () => {
    const user = userEvent.setup();
    renderPrivacy();
    await screen.findByRole("heading", { level: 1, name: "Evidence privacy" });

    await user.click(screen.getByText("Subject rights", { exact: true }));
    await waitFor(() => expect(apiMock.privacySubjectErasures).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText("Data subject")).toBeInTheDocument();
    expect(screen.getByLabelText("Export data subject")).toBeInTheDocument();
    expect(apiMock.privacyArchiveAttestations).not.toHaveBeenCalled();
    expect(apiMock.privacyRetentionRuns).not.toHaveBeenCalled();

    await user.click(screen.getByText("Archive removal evidence", { exact: true }));
    await waitFor(() => expect(apiMock.privacyArchiveAttestations).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("button", { name: "Record attestation…" })).toBeInTheDocument();

    await user.click(screen.getByText("Retention jobs", { exact: true }));
    await waitFor(() => expect(apiMock.privacyRetentionRuns).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("table", { name: "Retention runs" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Retention runs scroll area" })).toHaveAttribute("tabindex", "0");
  });
});
