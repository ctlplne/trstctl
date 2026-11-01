import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DiscoveryFinding } from "@/lib/api";
import { FindingAnnotation } from "./FindingAnnotation";

function finding(extra: Record<string, unknown> = {}): DiscoveryFinding {
  return {
    id: "finding-1",
    kind: "leaked_secret",
    ref: "generic-api-key@deploys/2026-10-30.json",
    metadata: { capability: "CAP-SCAN-04", rule_id: "generic-api-key", ...extra },
  } as unknown as DiscoveryFinding;
}

// A174: a third-party scan finding names where at the provider the
// credential was seen, annotates it there, and shows what the provider
// confirmed; a finding without a known place says why it cannot.
describe("finding annotation at the provider", () => {
  it("annotates a located finding and shows the provider's answer", async () => {
    const user = userEvent.setup();
    const onAnnotate = vi.fn().mockResolvedValue(undefined);
    render(
      <FindingAnnotation
        finding={finding({
          annotation_provider: "slack",
          provider_object: { channel: "deploys", channel_id: "C0DEPLOY", message_ts: "1730300050.000200" },
          provider_actions: { annotate: { status: "confirmed", detail: "Slack posted a reply in the thread." } },
        })}
        busy={false}
        onAnnotate={onAnnotate}
      />,
    );
    expect(screen.getByRole("heading", { name: "Tell the people where it leaked" })).toBeInTheDocument();
    expect(screen.getByText("At slack: deploys 1730300050.000200")).toBeInTheDocument();
    expect(screen.getByText("Annotation: confirmed. Slack posted a reply in the thread.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Annotate at slack" }));
    expect(onAnnotate).toHaveBeenCalledTimes(1);
  });

  it("explains a finding with no known place and ignores other findings", () => {
    const { rerender } = render(<FindingAnnotation finding={finding()} busy={false} onAnnotate={vi.fn()} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText(/no annotation connection/)).toBeInTheDocument();
    rerender(<FindingAnnotation finding={{ ...finding(), kind: "x509_certificate" } as DiscoveryFinding} busy={false} onAnnotate={vi.fn()} />);
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
  });
});
