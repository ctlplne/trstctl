import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { DiscoveryFinding } from "@/lib/api";
import { FindingSecretMove } from "./FindingSecretMove";

function finding(move: Record<string, unknown> | undefined): DiscoveryFinding {
  return {
    id: "finding-1",
    kind: "leaked_secret",
    ref: "slack-bot-token@app.env",
    metadata: { rule_id: "slack-bot-token" },
    ...(move ? { secret_move: move } : {}),
  } as unknown as DiscoveryFinding;
}

const moved = {
  secret_name: "ledger/slack-bot-token",
  secret_version: 1,
  reference: "${secret.ledger/slack-bot-token}",
  moved_at: "2026-11-14T12:00:00Z",
  history_residue: [
    { rule_id: "slack-bot-token", file: "app.env", line: 2, commit: "54d80ce6a1b2c3d4e5f60718293a4b5c6d7e8f90" },
    { rule_id: "slack-bot-token", file: "copy.env", line: 1, commit: "8212c593e5b1e89c54e855626f7d1a003df02f18" },
  ],
};

// P6-L5: a moved finding names where the value now lives and the history
// commits that still hold it, and says when a later scan last re-checked
// that history and which run, or that none has since the move.
describe("a leaked secret moved into the vault", () => {
  it("lists the history commits and when a scan last re-checked them", () => {
    render(
      <FindingSecretMove
        finding={finding({ ...moved, history_residue_checked_at: "2026-11-14T13:30:00Z", history_residue_run_id: "bad43c12-26c2-4e79-bc53-49f92f75c924" })}
      />,
    );
    expect(screen.getByRole("heading", { name: "Moved into the vault" })).toBeInTheDocument();
    expect(screen.getByText("The value now lives in ${secret.ledger/slack-bot-token}, version 1.")).toBeInTheDocument();
    expect(screen.getByText("History commits that still hold the value: 2")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "History commits that still hold the value" });
    expect(within(list).getByText("54d80ce6a1b2 app.env:2")).toBeInTheDocument();
    expect(within(list).getByText("8212c593e5b1 copy.env:1")).toBeInTheDocument();
    expect(screen.getByText(/A scan last re-checked the history on .* \(run bad43c12-26c2-4e79-bc53-49f92f75c924\)\./)).toBeInTheDocument();
  });

  it("says no scan has looked again yet, and shows nothing for an unmoved finding", () => {
    const { container, rerender } = render(<FindingSecretMove finding={finding({ ...moved, history_residue: [] })} />);
    expect(screen.getByText("History commits that still hold the value: 0")).toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
    expect(screen.getByText("No scan has re-checked the history since the move; the commits are as the move found them.")).toBeInTheDocument();
    rerender(<FindingSecretMove finding={finding(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });
});
