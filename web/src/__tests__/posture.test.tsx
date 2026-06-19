import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Posture } from "@/pages/Posture";

function renderPosture() {
  return render(
    <MemoryRouter>
      <Posture />
    </MemoryRouter>,
  );
}

describe("posture collector disclosures", () => {
  it("renders CT monitoring as library-only with a non-interactive triage preview", () => {
    renderPosture();

    expect(screen.getByRole("heading", { name: "Posture" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Certificate Transparency monitoring" })).toBeInTheDocument();
    expect(screen.getByText("CT findings API not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-CT/).length).toBeGreaterThan(0);
    expect(screen.getByText("Unexpected SAN outside approved issuer profile")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add watchlist|poll ct|start monitoring/i })).not.toBeInTheDocument();
  });

  it("renders drift as an agent-only preview with disabled remediation and a reason", () => {
    renderPosture();

    expect(screen.getByRole("heading", { name: "Drift detection" })).toBeInTheDocument();
    expect(screen.getByText("Drift findings API not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-DRIFT/).length).toBeGreaterThan(0);

    for (const button of screen.getAllByRole("button", { name: /remediation blocked/i })) {
      expect(button).toBeDisabled();
    }
    expect(screen.getByText(/Restore from intended state or revoke the identity/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /remediate now|restore credential|re-issue now/i })).not.toBeInTheDocument();
  });

  it("renders CBOM crypto posture without a fake scan trigger and links weak crypto to risk", () => {
    renderPosture();

    expect(screen.getByRole("heading", { name: "CBOM and cryptographic observability" })).toBeInTheDocument();
    expect(screen.getByText("CBOM findings API not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-CBOM/).length).toBeGreaterThan(0);
    expect(screen.getByText(/RSA-2048, EC-256, and TLS 1.2/)).toBeInTheDocument();
    expect(screen.getByText(/3DES\/DES\/RC4\/NULL\/EXPORT\/MD5/)).toBeInTheDocument();
    expect(screen.getByText("ML-DSA, ML-KEM, SLH-DSA")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Link weak-crypto risk to the risk dashboard/i })).toHaveAttribute(
      "href",
      "/risk",
    );
    expect(screen.queryByRole("button", { name: /run cbom scan|scan now/i })).not.toBeInTheDocument();
  });

  it("renders crypto-agility and PQC readiness fixtures without claiming served inventory", () => {
    renderPosture();

    expect(screen.getByRole("heading", { name: "Crypto-agility and PQC readiness" })).toBeInTheDocument();
    expect(screen.getByText("Algorithm inventory not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-CBOM/).length).toBeGreaterThan(0);
    expect(screen.getByText("Weak legacy edge")).toBeInTheDocument();
    expect(screen.getByText("PQC-ready workload")).toBeInTheDocument();
    expect(screen.getByText("ML-DSA / ML-KEM / SLH-DSA")).toBeInTheDocument();
    expect(screen.getByText(/hybrid X25519\+ML-KEM policy/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run inventory|enable pqc|change algorithm/i })).not.toBeInTheDocument();
  });

  it("renders PQC migration waves as library-only with rollback and sign-off fixtures", () => {
    renderPosture();

    expect(screen.getByRole("heading", { name: "PQC migration orchestration" })).toBeInTheDocument();
    expect(screen.getByText("PQC migration orchestration is library-only")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PQC-MIGRATION/).length).toBeGreaterThan(0);
    expect(screen.getByText("Wave 0: inventory")).toBeInTheDocument();
    expect(screen.getByText("Wave 1: hybrid canary")).toBeInTheDocument();
    expect(screen.getByText("Wave 2: workload rotation")).toBeInTheDocument();
    expect(screen.getByText("rollback to classical profile")).toBeInTheDocument();
    expect(screen.getByText("policy sign-off required")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start migration|resume migration|dry run pqc/i })).not.toBeInTheDocument();
  });
});
