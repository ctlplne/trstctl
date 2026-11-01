import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DiscoveryFinding } from "@/lib/api";
import { OAuthGrantProviderActions } from "./OAuthGrantProviderActions";

function finding(provider: string, extra: Record<string, unknown> = {}): DiscoveryFinding {
  return {
    id: "finding-1",
    kind: "oauth_grant_abuse",
    ref: "00u-alice",
    metadata: { provider, app_id: "0oa-exfil", principal: "00u-alice", ...extra },
  } as unknown as DiscoveryFinding;
}

// A170/A171: an OAuth grant finding offers revoking the grant and, where the
// provider's API can, blocking the app — each behind a confirmation — and
// shows what the provider confirmed.
describe("OAuth grant provider actions", () => {
  it("revokes after confirmation and shows the provider's answer", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn().mockResolvedValue(undefined);
    render(
      <OAuthGrantProviderActions
        finding={finding("okta", { provider_actions: { revoke_grant: { status: "confirmed", detail: "Okta revoked the user's grants." } } })}
        busy={false}
        onAction={onAction}
      />,
    );
    expect(screen.getByRole("heading", { name: "Act at okta" })).toBeInTheDocument();
    expect(screen.getByText("Grant revocation: confirmed. Okta revoked the user's grants.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke grant at provider" }));
    expect(onAction).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onAction).toHaveBeenCalledWith("revoke");
    await user.click(screen.getByRole("button", { name: "Block app at provider" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onAction).toHaveBeenLastCalledWith("block");
  });

  it("offers no block where the provider's API cannot, and nothing for other findings", () => {
    const { rerender } = render(<OAuthGrantProviderActions finding={finding("google")} busy={false} onAction={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Block app at provider" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot block an app/)).toBeInTheDocument();
    rerender(<OAuthGrantProviderActions finding={{ ...finding("okta"), kind: "certificate" } as DiscoveryFinding} busy={false} onAction={vi.fn()} />);
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
  });
});
