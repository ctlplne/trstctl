import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { SSHTrust } from "@/pages/SSHTrust";

function renderSSHTrust() {
  return render(
    <MemoryRouter>
      <SSHTrust />
    </MemoryRouter>,
  );
}

describe("SSH trust disclosure surface", () => {
  it("renders high-blast-radius SSH trust rollout without live mutation controls", () => {
    renderSSHTrust();

    expect(screen.getByRole("heading", { name: "SSH trust" })).toBeInTheDocument();
    expect(screen.getByText("High-blast-radius change")).toBeInTheDocument();
    expect(screen.getByText(/--ssh-trust-add-ca/)).toBeInTheDocument();
    expect(screen.getByText(/--ssh-trust-confirm/)).toBeInTheDocument();
    expect(screen.getByText("candidate CA")).toBeInTheDocument();
    expect(screen.getByText("sshd -t validation")).toBeInTheDocument();
    expect(screen.getByText("reload health failed")).toBeInTheDocument();
    expect(screen.getByText(/rollback trusted_ca_keys from backup/)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-CONNECTORS|BACKEND-DRIFT/).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /add ca|rewrite sshd|reload ssh|apply trust|rollback now/i })).not.toBeInTheDocument();
  });

  it("renders attestation-gated SSH user cert fixtures without issuing certs", () => {
    renderSSHTrust();

    expect(screen.getByRole("heading", { name: "Attestation-gated SSH user certs" })).toBeInTheDocument();
    expect(screen.getByText(/self-approval blocked/i)).toBeInTheDocument();
    expect(screen.getByText("principal: deployer")).toBeInTheDocument();
    expect(screen.getByText("TTL: 10 minutes")).toBeInTheDocument();
    expect(screen.getByText("source-address: 10.0.0.0/24")).toBeInTheDocument();
    expect(screen.getByText("force-command: /usr/local/bin/deploy")).toBeInTheDocument();
    expect(screen.getByText("attestation approved")).toBeInTheDocument();
    expect(screen.getByText("attestation denied")).toBeInTheDocument();
    expect(screen.getByText("attestation expired")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-ATTEST/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue ssh cert|approve self|mint ssh/i })).not.toBeInTheDocument();
  });
});
