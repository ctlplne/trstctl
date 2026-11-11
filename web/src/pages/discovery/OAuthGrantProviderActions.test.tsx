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

  // A170-L1: Microsoft Graph's admin consent for every user names no user; the
  // panel offers revoking it as the tenant's consent, and a grant with no user
  // that is not such a consent still offers no revoke.
  it("revokes a Microsoft Graph admin consent for every user", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn().mockResolvedValue(undefined);
    const consent = finding("microsoft", { app_id: "sp-consented", principal: "", consent_type: "AllPrincipals" });
    const { rerender } = render(<OAuthGrantProviderActions finding={consent} busy={false} onAction={onAction} />);
    expect(screen.getByText(/consented to sp-consented for every user in the tenant/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke admin consent at provider" }));
    expect(
      screen.getByText("Revoke at the provider the admin consent that lets every user in the tenant use sp-consented? Each user's own grant stays."),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onAction).toHaveBeenCalledWith("revoke");
    rerender(<OAuthGrantProviderActions finding={finding("microsoft", { principal: "", consent_type: "Principal" })} busy={false} onAction={onAction} />);
    expect(screen.getByRole("button", { name: "Revoke grant at provider" })).toBeDisabled();
  });

  it("offers no block where the provider's API cannot, and nothing for other findings", () => {
    const { rerender } = render(<OAuthGrantProviderActions finding={finding("google")} busy={false} onAction={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Block app at provider" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot block an app/)).toBeInTheDocument();
    rerender(<OAuthGrantProviderActions finding={{ ...finding("okta"), kind: "certificate" } as DiscoveryFinding} busy={false} onAction={vi.fn()} />);
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
  });
});
