import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExternalCAHeldIssuesPanel } from "@/pages/cahierarchy/CAHierarchyHeldIssuesPart";
import { api, ApiError, type ExternalCA } from "@/lib/api";

// N1-L1: an issuance an AD CS template holds for a CA manager's approval is
// listed with the CA's request id, and Resume reads the request back by that
// id once a manager approved it. A request the CA still holds says so and
// changes nothing.

vi.mock("@/components/rbac", () => ({ useCan: () => true }));

const authorities = [
  { id: "corp-adcs-web", type: "adcs", name: "Corp AD CS (WebServer template)", status: "available" },
  { id: "public-acme", type: "letsencrypt", name: "Public ACME", status: "available" },
] as unknown as ExternalCA[];

const held = [
  { ca_request_id: 4101, dns_names: ["held.corp.example"], status: "held", held_at: "2026-11-12T08:00:00Z" },
  { ca_request_id: 4099, dns_names: ["done.corp.example"], status: "issued", serial: "6dfd3c34", held_at: "2026-11-11T08:00:00Z" },
];

describe("N1-L1 issuances held for CA approval", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "externalCAHeldIssues").mockResolvedValue(held as never);
  });

  it("lists each AD CS authority's held issuances with the CA's request id", async () => {
    render(<ExternalCAHeldIssuesPanel externalCAs={authorities} />);
    expect(await screen.findByRole("heading", { name: "Held for CA approval" })).toBeInTheDocument();
    expect(api.externalCAHeldIssues).toHaveBeenCalledTimes(1);
    expect(api.externalCAHeldIssues).toHaveBeenCalledWith("corp-adcs-web");
    const authority = screen.getByRole("region", { name: "Corp AD CS (WebServer template)" });
    const heldRow = (await within(authority).findByText("4101")).closest("tr") as HTMLTableRowElement;
    expect(within(heldRow).getByText("held.corp.example")).toBeInTheDocument();
    expect(within(heldRow).getByText("Held for approval")).toBeInTheDocument();
    expect(within(heldRow).getByRole("button", { name: "Resume the issuance held as CA request 4101" })).toBeInTheDocument();
    const doneRow = within(authority).getByText("4099").closest("tr") as HTMLTableRowElement;
    expect(within(doneRow).getByText("Issued (serial 6dfd3c34)")).toBeInTheDocument();
    expect(within(doneRow).queryByRole("button")).not.toBeInTheDocument();
  });

  it("says a request the CA still holds is still held, and finishes one a manager approved", async () => {
    const user = userEvent.setup();
    const resume = vi
      .spyOn(api, "resumeExternalCAHeldIssue")
      .mockRejectedValueOnce(new ApiError(409, JSON.stringify({ status: 409, detail: "the CA still holds the request for approval" })))
      .mockResolvedValueOnce({
        ca_request_id: 4101,
        dns_names: ["held.corp.example"],
        status: "issued",
        serial: "7a11",
        held_at: "2026-11-12T08:00:00Z",
      } as never);
    render(<ExternalCAHeldIssuesPanel externalCAs={authorities} />);
    const button = await screen.findByRole("button", { name: "Resume the issuance held as CA request 4101" });

    await user.click(button);
    expect(await screen.findByText("The CA still holds request 4101 for approval. Resume it once a CA manager approves it.")).toBeInTheDocument();
    expect(resume).toHaveBeenLastCalledWith("corp-adcs-web", 4101);

    await user.click(await screen.findByRole("button", { name: "Resume the issuance held as CA request 4101" }));
    expect(await screen.findByText("Request 4101 is issued (serial 7a11); its issuance has its certificate.")).toBeInTheDocument();
    await waitFor(() => expect(api.externalCAHeldIssues).toHaveBeenCalledTimes(3));
  });

  it("shows nothing without an AD CS authority", () => {
    const { container } = render(<ExternalCAHeldIssuesPanel externalCAs={[authorities[1]]} />);
    expect(container).toBeEmptyDOMElement();
    expect(api.externalCAHeldIssues).not.toHaveBeenCalled();
  });
});
