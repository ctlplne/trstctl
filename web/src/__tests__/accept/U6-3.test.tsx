import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Privacy } from "@/pages/Privacy";
import { ToastProvider } from "@/components/ToastProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    privacyCatalog: vi.fn(),
    privacySubjectErasures: vi.fn(),
    privacyRetentionRuns: vi.fn(),
    erasePrivacySubject: vi.fn(),
    enforcePrivacyRetention: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.privacyCatalog.mockReset().mockResolvedValue({
    items: [{ id: "cat-1", category: "owner-contact", location: "owners table", owner: "platform", purpose: "notifications", retention_class: "P-90d", erasure: "cascade" }],
  });
  apiMock.privacySubjectErasures.mockReset().mockResolvedValue({ items: [] });
  apiMock.privacyRetentionRuns.mockReset().mockResolvedValue({
    items: [{ run_id: "ret-1", enforced_at: "2026-06-20T10:00:00Z", requested_by_ref: "scheduler", counts: { certificates: 3 }, cutoffs: {} }],
  });
  apiMock.erasePrivacySubject.mockReset().mockResolvedValue({
    subject_ref: "owner-42",
    erased_at: "2026-06-21T09:00:00Z",
    reason: "GDPR Art.17",
    counts: { identities: 2 },
    selectors: {},
  });
  apiMock.enforcePrivacyRetention.mockReset().mockResolvedValue({ run_id: "ret-2", enforced_at: "2026-06-21T10:00:00Z", counts: {}, cutoffs: {} });
});

describe("U6-3 privacy / GDPR console", () => {
  it("renders served retention runs and files a subject-erasure request through the served endpoint", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <Privacy />
        </ToastProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.privacyRetentionRuns).toHaveBeenCalled());
    expect(await screen.findByRole("heading", { name: "Privacy & data governance" })).toBeInTheDocument();
    expect(await screen.findByText("ret-1")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Data subject"), "owner-42");
    await user.click(screen.getByRole("button", { name: "Erase subject" }));
    await waitFor(() => expect(apiMock.erasePrivacySubject).toHaveBeenCalledWith({ subject: "owner-42", reason: undefined }));
    expect(await screen.findByText("owner-42")).toBeInTheDocument();
  });
});
