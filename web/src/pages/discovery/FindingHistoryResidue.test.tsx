import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { DiscoveryFinding } from "@/lib/api";
import { FindingHistoryResidue } from "./FindingHistoryResidue";

function finding(kind: string): DiscoveryFinding {
  return {
    id: "residue-1",
    kind,
    ref: "slack-bot-token@app.env",
    metadata: {
      moved_finding_id: "df6ad016-2e35-5730-88ca-6d7b5538560d",
      secret_name: "billing/slack-bot-token",
      commit_count: 1,
      history_residue: [{ rule_id: "slack-bot-token", file: "app.env", line: 2, commit: "84be334d0a1b2c3d4e5f60718293a4b5c6d7e8f9" }],
    },
  } as unknown as DiscoveryFinding;
}

// P6-L6: a history-residue finding names the secret the value moved into,
// the moved finding it came from and the commits, and says what closes it.
describe("history that still holds a rotated leak", () => {
  it("lists the commits and what closes the finding", () => {
    render(<FindingHistoryResidue finding={finding("secret_history_residue")} />);
    expect(screen.getByRole("heading", { name: "History that still holds a rotated leak" })).toBeInTheDocument();
    expect(
      screen.getByText(
        "The value moved into billing/slack-bot-token and was rotated, closing finding df6ad016-2e35-5730-88ca-6d7b5538560d. These history commits still hold the old value:",
      ),
    ).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "History commits that still hold the value" });
    expect(within(list).getByText("84be334d0a1b app.env:2")).toBeInTheDocument();
    expect(screen.getByText(/A scan of the repository that finds no commit still holding the value closes this finding\./)).toBeInTheDocument();
  });

  it("shows nothing for another kind of finding", () => {
    const { container } = render(<FindingHistoryResidue finding={finding("leaked_secret")} />);
    expect(container).toBeEmptyDOMElement();
  });
});
