import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Integrate } from "@/pages/Integrate";

describe("U8-5 integrate hub", () => {
  it("lists enrollment protocols, SDKs, and IaC artifacts with copyable references", () => {
    render(
      <MemoryRouter>
        <Integrate />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Integrate" })).toBeInTheDocument();
    expect(screen.getByText("ACME")).toBeInTheDocument();
    expect(screen.getByText("EST")).toBeInTheDocument();
    expect(screen.getByText("SCEP")).toBeInTheDocument();
    expect(screen.getByText("Python SDK")).toBeInTheDocument();
    expect(screen.getByText("Terraform provider")).toBeInTheDocument();
    expect(screen.getByText("SPIRE upstream authority")).toBeInTheDocument();
    // copyable references
    expect(screen.getAllByRole("button", { name: /^Copy / }).length).toBeGreaterThan(5);
  });
});
