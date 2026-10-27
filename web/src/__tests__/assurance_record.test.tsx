import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AssuranceRecordPanel } from "@/components/certs";
import type { CertificateAssuranceRecord } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({ apiMock: { certificateAssuranceRecord: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const signed = {
  record: {
    format: "trstctl.credential-assurance-record/v1",
    tenant_id: "00000000-0000-4000-8000-000000000001",
    generated_at: "2026-10-26T12:00:00Z",
    credential: {
      certificate_id: "00000000-0000-4000-8000-0000000000c1",
      fingerprint: "fp",
      serial: "0a",
      subject: "CN=svc",
      sans: [],
      issuer: "CN=CA",
      status: "active",
      identity_ids: [],
    },
    discovery: [],
    issuance: { evidence_id: "event:e1", basis: "recorded", issued_by_trstctl: true, source: "issued", ca: "CN=CA" },
    deployments: [],
    verifications: [],
    renewals: { successors: [], runs: [] },
    audit: [],
    independently_observed: ["discovery", "deployment", "verification"],
    recorded_only: ["owner", "issuance", "renewal"],
    absent: ["revocation"],
    truncated: [],
  },
  signed_record: "a.b.c",
  record_sha256: "sha256:abcd",
  public_jwks: {},
  rendering: "# Credential assurance record",
} as unknown as CertificateAssuranceRecord;

afterEach(() => vi.restoreAllMocks());

describe("A179 certificate assurance record", () => {
  it("builds the signed record on request, names what was independently observed, and saves it", async () => {
    apiMock.certificateAssuranceRecord.mockResolvedValue(signed);
    const createObjectURL = vi.fn(() => "blob:record");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    let saved = "";
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      saved = this.download;
    });
    render(<AssuranceRecordPanel certificateId="00000000-0000-4000-8000-0000000000c1" />);

    expect(apiMock.certificateAssuranceRecord).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Build the signed assurance record" }));
    expect(apiMock.certificateAssuranceRecord).toHaveBeenCalledWith("00000000-0000-4000-8000-0000000000c1");
    expect(await screen.findByText("Independently observed: discovery, deployment, verification")).toBeInTheDocument();
    expect(screen.getByText("Recorded by trstctl only: owner, issuance, renewal")).toBeInTheDocument();
    expect(screen.getByText("No evidence: revocation")).toBeInTheDocument();
    expect(screen.getByText(/record sha256:abcd/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Download the signed record" }));
    expect(saved).toBe("assurance-record-00000000-0000-4000-8000-0000000000c1.json");
    expect(createObjectURL).toHaveBeenCalledTimes(1);
  });

  it("says so when the record cannot be built", async () => {
    apiMock.certificateAssuranceRecord.mockRejectedValue(new Error("503"));
    render(<AssuranceRecordPanel certificateId="c2" />);
    await userEvent.click(screen.getByRole("button", { name: "Build the signed assurance record" }));
    expect(await screen.findByText("The assurance record could not be built.")).toBeInTheDocument();
  });
});
