import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RbacProvider, Can, useCan } from "@/components/rbac";

function Probe({ permission }: { permission: string }) {
  return <span>{useCan(permission) ? "yes" : "no"}</span>;
}

describe("U0-3 RBAC-aware UI primitive", () => {
  it("shows granted actions and hides the rest", () => {
    render(
      <RbacProvider permissions={["secrets:write"]}>
        <Can permission="secrets:write">
          <button type="button">Rotate</button>
        </Can>
        <Can permission="ca:admin" fallback={<span>no access</span>}>
          <button type="button">Run ceremony</button>
        </Can>
      </RbacProvider>,
    );
    expect(screen.getByRole("button", { name: "Rotate" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run ceremony" })).not.toBeInTheDocument();
    expect(screen.getByText("no access")).toBeInTheDocument();
  });

  it("is permissive when permissions are unknown (not yet loaded)", () => {
    render(<Probe permission="anything" />);
    expect(screen.getByText("yes")).toBeInTheDocument();
  });

  it("denies an ungranted permission within a loaded provider", () => {
    render(
      <RbacProvider permissions={[]}>
        <Probe permission="ca:admin" />
      </RbacProvider>,
    );
    expect(screen.getByText("no")).toBeInTheDocument();
  });
});
