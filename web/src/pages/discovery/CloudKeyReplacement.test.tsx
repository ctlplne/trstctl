import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DiscoveryFinding, DynamicSecretConfiguredProvider } from "@/lib/api";
import { CloudKeyReplacement } from "./CloudKeyReplacement";

function finding(extra: Record<string, unknown> = {}): DiscoveryFinding {
  return {
    id: "finding-key",
    kind: "cloud_access_key",
    ref: "aws-iam:deploy-bot:AKIAEXAMPLEDEPLOY",
    metadata: { provider: "aws-iam", user: "deploy-bot", access_key_id: "AKIAEXAMPLEDEPLOY", status: "Active", stale: true, ...extra },
  } as unknown as DiscoveryFinding;
}

const providers = [
  { id: "aws-prod", type: "aws-sts", label: "AWS production", allowed_roles: ["deployer", "reader"], ready: true },
  { id: "pg-main", type: "postgresql", label: "Main database", allowed_roles: ["app"], ready: true },
] as unknown as DynamicSecretConfiguredProvider[];

// M3-L4: a stale AWS IAM user key is replaced from its finding by an AWS STS
// role, behind a confirmation, and the section shows what IAM confirmed.
describe("cloud key replacement", () => {
  it("replaces the key with an AWS role after confirmation", async () => {
    const user = userEvent.setup();
    const onReplace = vi.fn().mockResolvedValue(undefined);
    render(<CloudKeyReplacement finding={finding()} providers={providers} busy={false} onReplace={onReplace} />);
    expect(screen.getByRole("heading", { name: "Replace with short-lived credentials" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Main database" })).not.toBeInTheDocument();
    const replace = screen.getByRole("button", { name: "Replace key" });
    expect(replace).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Dynamic-secret provider"), "aws-prod");
    await user.selectOptions(screen.getByLabelText("Role"), "deployer");
    await user.click(replace);
    expect(onReplace).not.toHaveBeenCalled();
    expect(screen.getByText(/Set AKIAEXAMPLEDEPLOY of deploy-bot Inactive at AWS/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onReplace).toHaveBeenCalledWith("aws-prod", "deployer");
  });

  it("shows what IAM confirmed and offers nothing for an inactive key", () => {
    render(
      <CloudKeyReplacement
        finding={finding({
          status: "Inactive",
          replaced_by: "dynamic-secret:aws-prod/deployer",
          provider_actions: { deactivate_key: { status: "confirmed", detail: "IAM set the key Inactive." } },
        })}
        providers={providers}
        busy={false}
        onReplace={vi.fn()}
      />,
    );
    expect(screen.getByText("Key deactivation: confirmed. IAM set the key Inactive.")).toBeInTheDocument();
    expect(screen.getByText("Replaced by dynamic-secret:aws-prod/deployer.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Replace key" })).not.toBeInTheDocument();
  });

  it("names the missing provider and ignores other findings", () => {
    const { rerender } = render(<CloudKeyReplacement finding={finding()} providers={[]} busy={false} onReplace={vi.fn()} />);
    expect(screen.getByText(/No AWS STS dynamic-secret provider is configured/)).toBeInTheDocument();
    rerender(
      <CloudKeyReplacement
        finding={{ ...finding(), metadata: { provider: "gcp-iam" } } as unknown as DiscoveryFinding}
        providers={providers}
        busy={false}
        onReplace={vi.fn()}
      />,
    );
    expect(screen.queryByRole("heading", { name: "Replace with short-lived credentials" })).not.toBeInTheDocument();
  });
});
