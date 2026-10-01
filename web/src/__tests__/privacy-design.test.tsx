import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Privacy } from "@/pages/Privacy";
import { IntlProvider } from "@/i18n/I18nProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    privacyCatalog: vi.fn(),
    privacySubjectErasures: vi.fn(),
    privacyRetentionRuns: vi.fn(),
    privacyArchiveAttestations: vi.fn(),
    previewPrivacySubjectErasure: vi.fn(),
    previewPrivacyRetention: vi.fn(),
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

function renderPrivacy(initialTimeZone?: string) {
  const page = (
    <MemoryRouter initialEntries={["/privacy"]}>
      <ToastProvider>
        <main>
          <Privacy />
        </main>
      </ToastProvider>
    </MemoryRouter>
  );
  return render(initialTimeZone ? <IntlProvider initialTimeZone={initialTimeZone}>{page}</IntlProvider> : page);
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
    apiMock.previewPrivacySubjectErasure.mockResolvedValue({
      capability: "F79",
      operation: "erase_subject",
      ready: true,
      effect_free: true,
      request_fingerprint: "a".repeat(64),
      required_permission: "privacy:write",
      normalized_request: { subject: "alice@example.test", reason: "request" },
      subject_ref: "subject-ref-alice",
      counts: { owners: 1, api_tokens: 2 },
      total_records: 3,
      archive_attestations: 1,
      active_legal_holds: 1,
      prerequisites: ["Export required evidence before erasure."],
      blockers: [],
      warnings: ["Completed erasure is irreversible."],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["Pseudonymize direct operational rows."],
      execute_external_effects: [],
      recovery_steps: ["Retry the unchanged request with the same Idempotency-Key."],
      verification_steps: ["Export again and inspect erasure evidence."],
      secret_data_handling: "No secrets are returned.",
    });
    apiMock.previewPrivacyRetention.mockResolvedValue({
      capability: "F79",
      operation: "enforce_retention",
      ready: true,
      effect_free: true,
      request_fingerprint: "b".repeat(64),
      required_permission: "privacy:write",
      reviewed_at: "2026-09-04T10:00:00Z",
      cutoffs: { ssh_stale_before: "2026-03-08T10:00:00Z" },
      counts: { ssh_keys: 4 },
      total_records: 4,
      prerequisites: ["Review the effective tenant retention cutoffs."],
      blockers: [],
      warnings: ["Re-review if tenant data changes."],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["Append one retention event."],
      execute_external_effects: [],
      recovery_steps: ["Retry with the same Idempotency-Key."],
      verification_steps: ["List retention runs."],
      secret_data_handling: "Aggregate counts only.",
    });
    apiMock.erasePrivacySubject.mockResolvedValue({ subject_ref: "subject-ref-alice", counts: {}, selectors: {}, erased_at: "2026-09-04T10:01:00Z" });
    apiMock.enforcePrivacyRetention.mockResolvedValue({ run_id: "run-2", counts: {}, cutoffs: {}, enforced_at: "2026-09-04T10:02:00Z" });
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

  it("states the direct erasure boundary and offers a portable export in the selected time zone", async () => {
    const user = userEvent.setup();
    apiMock.exportPrivacySubject.mockResolvedValue({
      subject: "qa-viewer",
      subject_ref: "subject-ref-qa-viewer",
      tenant_id: "tenant-qa",
      generated_at: "2026-10-01T07:43:00Z",
      counts: { tenant_members: 1, api_tokens: 1 },
      tenant_members: [{ subject: "qa-viewer", status: "offboarded" }],
      api_tokens: [{ subject: "qa-viewer", scopes: ["access:read"] }],
    });
    renderPrivacy("America/New_York");
    await user.click(await screen.findByText("Subject rights", { exact: true }));
    expect(screen.getByText(/direct operational data.*archive evidence separately/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Export data subject"), "qa-viewer");
    await user.click(screen.getByRole("button", { name: "Export subject" }));
    expect(await screen.findByText("Oct 1, 2026, 3:43 AM")).toBeInTheDocument();
    const createObjectURL = vi.fn().mockReturnValue("blob:subject-export");
    const revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const previousCreate = URL.createObjectURL;
    const previousRevoke = URL.revokeObjectURL;
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    try {
      await user.click(screen.getByRole("button", { name: "Download export JSON" }));
      expect(click).toHaveBeenCalledTimes(1);
      expect(createObjectURL).toHaveBeenCalledTimes(1);
      const blob = createObjectURL.mock.calls[0][0] as Blob;
      const payload = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsText(blob);
      });
      const downloaded = JSON.parse(payload);
      expect(downloaded.tenant_members).toEqual([{ subject: "qa-viewer", status: "offboarded" }]);
      expect(downloaded.api_tokens).toEqual([{ subject: "qa-viewer", scopes: ["access:read"] }]);
      expect((click.mock.instances[0] as HTMLAnchorElement).download).toBe("trstctl-subject-export-subject-ref-qa-v.json");
      await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith("blob:subject-export"));
    } finally {
      click.mockRestore();
      if (previousCreate) Object.defineProperty(URL, "createObjectURL", { configurable: true, value: previousCreate });
      else Reflect.deleteProperty(URL, "createObjectURL");
      if (previousRevoke) Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: previousRevoke });
      else Reflect.deleteProperty(URL, "revokeObjectURL");
    }
  });

  it("contains long evidence fields inside each disclosure instead of widening the page", async () => {
    renderPrivacy();
    await screen.findByRole("heading", { level: 1, name: "Evidence privacy" });

    for (const title of ["Policy and data map", "Subject rights", "Archive removal evidence", "Retention jobs"]) {
      const disclosure = screen.getByText(title, { exact: true }).closest("details");
      expect(disclosure).toHaveClass("min-w-0");
    }
  });

  it("reviews destructive subject and retention effects before execution and exposes truthful recovery", async () => {
    const user = userEvent.setup();
    renderPrivacy();
    await user.click(await screen.findByText("Subject rights", { exact: true }));
    await user.type(screen.getByLabelText("Data subject"), "alice@example.test");
    await user.type(screen.getByLabelText("Reason"), "request");

    expect(apiMock.erasePrivacySubject).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review erasure" }));
    const erasureReview = await screen.findByRole("dialog", { name: "Review subject erasure" });
    expect(erasureReview).toHaveTextContent("No state changed");
    expect(erasureReview).toHaveTextContent("3 records matched");
    expect(erasureReview).toHaveTextContent("1 active legal hold");
    expect(erasureReview).toHaveTextContent("Completed erasure is irreversible");
    expect(erasureReview).toHaveTextContent("Retry the unchanged request with the same Idempotency-Key");
    await user.click(within(erasureReview).getByRole("button", { name: "Erase reviewed subject" }));
    await waitFor(() => expect(apiMock.erasePrivacySubject).toHaveBeenCalledWith({ subject: "alice@example.test", reason: "request" }));

    await user.click(screen.getByText("Retention jobs", { exact: true }));
    await waitFor(() => expect(apiMock.privacyRetentionRuns).toHaveBeenCalled());
    expect(apiMock.enforcePrivacyRetention).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review retention" }));
    const retentionReview = await screen.findByRole("dialog", { name: "Review retention enforcement" });
    expect(retentionReview).toHaveTextContent("4 records matched");
    expect(retentionReview).toHaveTextContent("ssh stale before");
    await user.click(within(retentionReview).getByRole("button", { name: "Enforce reviewed retention" }));
    await waitFor(() => expect(apiMock.enforcePrivacyRetention).toHaveBeenCalledTimes(1));
  });
});
