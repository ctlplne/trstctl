import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { IdentityRenewalHold } from "@/pages/identities/IdentityRenewalHold";
import type { Identity } from "@/lib/api";

const { resume } = vi.hoisted(() => ({ resume: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, resumeIdentityRenewal: resume } };
});

const identity = (pauses: Identity["renewal_paused"]): Identity =>
  ({
    id: "ident-1",
    kind: "x509_certificate",
    name: "svc.example.test",
    status: "deployed",
    owner_id: "owner-1",
    renewal_paused: pauses,
  }) as unknown as Identity;

function show(value: Identity) {
  return render(
    <MemoryRouter>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <AppQueryProvider>
          <IdentityRenewalHold identity={value} />
        </AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>,
  );
}

// B4-8: an operator rollback holds automatic renewal on that target; the
// identity view names each held target with the rollback reason and offers the
// audited resume. An identity with no hold shows nothing.
describe("renewal hold in identity detail", () => {
  beforeEach(() => {
    cleanup();
    resume.mockReset();
  });

  it("renders nothing without a hold", () => {
    show(identity([]));
    expect(screen.queryByRole("heading", { name: "Automatic renewal paused" })).toBeNull();
  });

  it("names the held target with its reason and resumes it through the audited route", async () => {
    resume.mockResolvedValue(identity([]));
    const user = userEvent.setup();
    show(identity([{ target_id: "target-a", paused_at: "2030-01-01T10:00:00Z", reason: "operator rollback: bad build" }]));
    expect(screen.getByRole("heading", { name: "Automatic renewal paused" })).toBeTruthy();
    expect(screen.getByText(/Expiry alerts keep firing, and its other targets keep renewing/)).toBeTruthy();
    expect(screen.getByText("target-a")).toBeTruthy();
    expect(screen.getByText(/operator rollback: bad build/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Resume renewal" }));
    await waitFor(() => expect(resume).toHaveBeenCalledWith("ident-1", { target_id: "target-a" }));
    expect(await screen.findByRole("status")).toHaveTextContent("The resume is in the audit log");
  });
});
