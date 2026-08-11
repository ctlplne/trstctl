import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { SecretImport } from "@/components/secrets";

describe("U2-5 secret import", () => {
  it("discloses that bulk import is unavailable without rendering an active mutation", () => {
    render(<SecretImport />);
    expect(screen.getByText(/Bulk import is disabled/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import unavailable" })).toBeDisabled();
  });
});
