import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AgentJobLedgerPanel } from "@/pages/operations/AgentJobLedgerPanel";
import type { AgentJobPosture } from "@/lib/api";

// The receipt readout on Operations (epic A1).
//
// The signature gate is enforced in the binary whether or not anyone can see
// it, which is exactly why it needs a panel: a refused receipt means an agent
// believes it did work this control plane will not record, and that work is
// neither done nor requeued in anybody's understanding until someone notices.
// These assert the operator actually sees it, and — the part that is easy to
// get wrong — that they can tell the two causes apart.

const { apiMock } = vi.hoisted(() => ({ apiMock: { agentJobPosture: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function posture(overrides: Partial<AgentJobPosture> = {}): AgentJobPosture {
  return {
    served: true,
    claimable_kinds: ["connector.deploy"],
    generated_at: "2026-08-03T12:00:00Z",
    queues: [],
    redemptions: { live: 0, total: 0 },
    receipts: { verified: 0, rejected: 0 },
    ...overrides,
  } as AgentJobPosture;
}

// valueFor reads the <dd> beside a labelled <dt>. Matching on text alone would
// pick up the redemption counters, which are legitimately zero at the same time.
function valueFor(label: string): HTMLElement {
  const term = screen.getByText(label);
  const value = term.parentElement?.querySelector("dd");
  if (!value) throw new Error(`no value rendered for ${label}`);
  return value as HTMLElement;
}

function renderPanel() {
  return render(
    <MemoryRouter>
      <AgentJobLedgerPanel />
    </MemoryRouter>,
  );
}

describe("agent job receipt health", () => {
  beforeEach(() => {
    apiMock.agentJobPosture.mockReset();
  });

  it("names the cause of the most recent refusal, not just that one happened", async () => {
    apiMock.agentJobPosture.mockResolvedValue(
      posture({
        receipts: {
          verified: 41,
          rejected: 3,
          last_rejected_reason: "issued-at outside the accepted window",
          last_rejected_at: "2026-08-03T11:58:00Z",
        },
      }),
    );
    renderPanel();

    expect(await screen.findByText("Receipts verified")).toBeInTheDocument();
    expect(valueFor("Receipts verified")).toHaveTextContent("41");
    expect(valueFor("Receipts refused")).toHaveTextContent("3");
    // A drifting clock and a wrong signing key need opposite responses. A panel
    // that showed only "3 refused" would send an operator to check certificates
    // when the answer is NTP.
    expect(screen.getByText("issued-at outside the accepted window")).toBeInTheDocument();
  });

  it("marks refusals as needing attention, and leaves a clean fabric unmarked", async () => {
    apiMock.agentJobPosture.mockResolvedValue(
      posture({ receipts: { verified: 12, rejected: 1, last_rejected_reason: "unsigned" } }),
    );
    const { unmount } = renderPanel();
    await waitFor(() => expect(screen.getByText("Receipts refused")).toBeInTheDocument());
    expect(valueFor("Receipts refused")).toHaveClass("text-status-warning");
    unmount();

    apiMock.agentJobPosture.mockResolvedValue(posture({ receipts: { verified: 12, rejected: 0 } }));
    renderPanel();
    // Zero refusals is the normal state and must not be styled as a problem, or
    // the warning stops meaning anything on the day it is real.
    await waitFor(() => expect(screen.getByText("Most recent refusal")).toBeInTheDocument());
    expect(valueFor("Receipts refused")).toHaveTextContent("0");
    expect(valueFor("Receipts refused")).not.toHaveClass("text-status-warning");
    expect(valueFor("Most recent refusal")).toHaveTextContent("None");
  });
});
