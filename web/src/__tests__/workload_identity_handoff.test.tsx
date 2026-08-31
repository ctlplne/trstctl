import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkloadIdentityHandoff } from "@/components/WorkloadIdentityHandoff";
import { CredentialChip, middleTruncate } from "@/components/CredentialChip";

const identity = "spiffe://workloads.example.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/attested/method/k8s_sat/subject/ns/Payments/sa/API";

describe("signed workload identity handoff", () => {
  it("discloses and copies the entire server value without case changes, links or mutation", async () => {
    const user = userEvent.setup();
    const copy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    render(<WorkloadIdentityHandoff spiffeID={identity} />);
    expect(screen.getByText(identity)).not.toBeVisible();
    await user.tab();
    expect(screen.getByText("Signed workload ID")).toHaveFocus();
    await user.click(screen.getByText("Signed workload ID"));
    expect(screen.getByText(identity)).toBeVisible();
    expect(screen.getByText(identity)).toHaveClass("break-all", "whitespace-normal");
    expect(screen.getByText(/Trusting the CA alone does not authorize/)).toBeVisible();
    expect(screen.getByText(/does not change those rules or your trusted CA/)).toBeVisible();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy Signed workload ID" }));
    expect(copy).toHaveBeenCalledExactlyOnceWith(identity);
    expect(screen.getByRole("status")).toHaveTextContent("Copied to clipboard");
  });

  it.each([undefined, ""])("keeps unavailable identity explicit and has nothing invented to copy: %s", async (spiffeID) => {
    const user = userEvent.setup();
    render(<WorkloadIdentityHandoff spiffeID={spiffeID} />);
    await user.click(screen.getByText("Signed workload ID"));
    expect(screen.getByText(/does not include a canonical signed ID/)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("reveals the original complete chip value for manual copying if clipboard permission is denied", async () => {
    const user = userEvent.setup();
    const copy = vi.spyOn(navigator.clipboard, "writeText").mockRejectedValueOnce(new Error("denied")).mockResolvedValueOnce();
    const view = render(<CredentialChip value={identity} label="Signed workload ID" />);
    expect(screen.getByText(middleTruncate(identity))).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Copy Signed workload ID" }));
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed.");
    expect(screen.getByText(identity)).toBeVisible();
    expect(screen.queryByText("Copied to clipboard")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy Signed workload ID" }));
    expect(copy).toHaveBeenLastCalledWith(identity);
    expect(screen.getByRole("status")).toHaveTextContent("Copied to clipboard");
    view.rerender(<CredentialChip value="another-identity" label="Signed workload ID" />);
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
    expect(screen.queryByText(identity)).not.toBeInTheDocument();
  });
});
