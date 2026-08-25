import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { CapabilityView } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { AuthorityAgreementPanel } from "@/components/AuthorityAgreementPanel";

const { authorityAgreement } = vi.hoisted(() => ({ authorityAgreement: vi.fn() }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, authorityAgreement } };
});

function runtime(operations: CapabilityView["operations"]): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks again at execution.",
    license: { tier: "community", state: "community" },
    operations,
    items: [],
  };
}

describe("AuthorityAgreementPanel runtime preflight", () => {
  beforeEach(() => {
    authorityAgreement.mockReset().mockResolvedValue({
      authorities: [],
      open_witnesses: 0,
      replay_watermark: 42,
      median_resolution_seconds: 0,
      resolved_in_window: 0,
      configured: true,
      collecting: true,
      detail: "The configured authorities agree at replay watermark 42.",
      guidance: "Keep reconciliation scheduled.",
    });
  });

  it("does not provoke a 404 when the licensed route is not attached", async () => {
    render(
      <CapabilityFixtureProvider view={runtime([])}>
        <AuthorityAgreementPanel />
      </CapabilityFixtureProvider>,
    );

    expect(
      await screen.findByText(/Cross-authority reconciliation is not available on this deployment/),
    ).toBeInTheDocument();
    expect(authorityAgreement).not.toHaveBeenCalled();
  });

  it("reads the report when the running process advertises the exact operation", async () => {
    render(
      <CapabilityFixtureProvider view={runtime([{ operation_id: "getAuthorityAgreement", state: "allowed" }])}>
        <AuthorityAgreementPanel />
      </CapabilityFixtureProvider>,
    );

    expect(await screen.findByText("The configured authorities agree at replay watermark 42.")).toBeInTheDocument();
    await waitFor(() => expect(authorityAgreement).toHaveBeenCalledTimes(1));
  });
});
