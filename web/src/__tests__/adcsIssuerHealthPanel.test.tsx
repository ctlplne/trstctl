import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ADCSIssuerHealthPanel } from "@/components/posture/ADCSIssuerHealthPanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({ apiMock: { adcsIssuerHealth: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("A161 AD CS issuer health", () => {
  beforeEach(() => {
    apiMock.adcsIssuerHealth.mockReset();
  });

  it("shows a failing issuer's classified refusal and what to do about it", async () => {
    apiMock.adcsIssuerHealth.mockResolvedValue({
      window_days: 7,
      guidance: "failing: the latest attempt through this issuer was refused",
      items: [
        {
          id: "corp-adcs-web",
          name: "Corp AD CS (WebServer template)",
          status: "failing",
          issued_in_window: 1,
          last_success_at: "2026-10-31T12:00:00Z",
          last_failure_at: "2026-10-31T12:05:00Z",
          last_failure_cause: "template_acl_denied",
          last_failure_summary: "The template's permissions do not allow this requester to enroll.",
          last_failure_remediation: "Grant the requesting account Enroll on the template.",
        },
      ],
    });
    render(
      <AppQueryProvider>
        <ADCSIssuerHealthPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("Corp AD CS (WebServer template)")).toBeInTheDocument();
    expect(screen.getByText("Failing")).toBeInTheDocument();
    expect(screen.getByText(/template_acl_denied/)).toBeInTheDocument();
    expect(screen.getByText("What to do: Grant the requesting account Enroll on the template.")).toBeInTheDocument();
  });

  it("says when no AD CS issuer is configured", async () => {
    apiMock.adcsIssuerHealth.mockResolvedValue({ window_days: 7, guidance: "", items: [] });
    render(
      <AppQueryProvider>
        <ADCSIssuerHealthPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("No AD CS issuer is configured for this tenant.")).toBeInTheDocument();
  });
});
