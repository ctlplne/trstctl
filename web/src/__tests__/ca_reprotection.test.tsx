import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CAReprotectionPanel } from "@/pages/cahierarchy/CAReprotectionPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    caAuthorities: vi.fn(),
    connectorTargets: vi.fn(),
    getCertificate: vi.fn(),
    previewCAKeyReprotectionPlan: vi.fn(),
    registerCAKeyReprotectionPlan: vi.fn(),
    caKeyReprotectionPlan: vi.fn(),
    startCAKeyReprotection: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), api: apiMock }));

const plan = {
  job_id: "job-1",
  identity_id: "identity-1",
  certificate_id: "cert-1",
  successor_authority_id: "ca-new",
  predecessor_fingerprint: "fingerprint-1",
  predecessor_spki_sha256: "spki-1",
  target_id: "target-1",
  target_revision_id: "revision-1",
  required_agent_id: "agent-1",
  connector: "apache",
  verify_address: "127.0.0.1:10443",
  verify_server_name: "ca.qa.invalid",
  ttl_seconds: 3600,
};

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.caAuthorities.mockResolvedValue({
    items: [
      { id: "ca-new", common_name: "QA successor", status: "active", replaces_id: "ca-old" },
      { id: "ca-unrelated", common_name: "Other CA", status: "active", replaces_id: "elsewhere" },
    ],
  });
  apiMock.connectorTargets.mockResolvedValue({ items: [{ id: "target-1", name: "QA Apache", connector: "apache", enabled: true, revision_id: "revision-1" }] });
  apiMock.getCertificate.mockResolvedValue({
    id: "cert-1",
    fingerprint: "fingerprint-1",
    subject: "CN=ca.qa.invalid",
    status: "active",
    key_origin: "host_agent",
    key_storage: "file",
  });
  apiMock.previewCAKeyReprotectionPlan.mockResolvedValue({ ...plan, ready: true, effect_free: true, recorded: false });
  apiMock.registerCAKeyReprotectionPlan.mockResolvedValue({ ...plan, recorded: true });
  apiMock.caKeyReprotectionPlan.mockResolvedValue({ ...plan, recorded: true });
  apiMock.startCAKeyReprotection.mockResolvedValue({
    key_id: "ca-old",
    planned: 1,
    enqueued: 1,
    jobs: [{ id: "job-1", kind: "reissue", dependent_class: "credential", dependent_ref: "cert-1", enqueued: true }],
  });
});

describe("CA re-protection console", () => {
  it("reviews exact server evidence, records and reads back the plan, then starts the same job", async () => {
    const user = userEvent.setup();
    const refresh = vi.fn().mockResolvedValue(undefined);
    render(<CAReprotectionPanel keyId="ca-old" certificateIDs={["cert-1"]} onRefresh={refresh} />);
    const panel = await screen.findByRole("region", { name: "Re-protect managed certificate" });
    await user.selectOptions(within(panel).getByLabelText("Successor CA"), "ca-new");
    await user.selectOptions(within(panel).getByLabelText("Host target"), "target-1");
    await user.clear(within(panel).getByLabelText("New certificate lifetime in seconds"));
    await user.type(within(panel).getByLabelText("New certificate lifetime in seconds"), "3600");
    await user.click(within(panel).getByRole("button", { name: "Review exact re-protection plan" }));
    expect(apiMock.previewCAKeyReprotectionPlan).toHaveBeenCalledWith("ca-old", {
      certificate_id: "cert-1",
      successor_authority_id: "ca-new",
      target_id: "target-1",
      expected_target_revision: "revision-1",
      expected_fingerprint: "fingerprint-1",
      ttl_seconds: 3600,
    });
    expect(await within(panel).findByText(/127\.0\.0\.1:10443/)).toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: "Record reviewed plan" }));
    await waitFor(() => expect(apiMock.caKeyReprotectionPlan).toHaveBeenCalledWith("ca-old", "job-1"));
    expect(within(panel).getByText("Plan recorded and read back")).toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: "Start re-protection" }));
    await waitFor(() => expect(apiMock.startCAKeyReprotection).toHaveBeenCalledWith("ca-old"));
    expect(await within(panel).findByText(/Queued 1 of 1/)).toBeInTheDocument();
    expect(refresh).toHaveBeenCalled();
  });

  it("refuses to record a changed preview and recovers a recorded plan by job ID", async () => {
    const user = userEvent.setup();
    apiMock.previewCAKeyReprotectionPlan.mockResolvedValueOnce({ ...plan, target_revision_id: "changed", ready: true, effect_free: true });
    render(<CAReprotectionPanel keyId="ca-old" certificateIDs={["cert-1"]} onRefresh={vi.fn()} />);
    const panel = await screen.findByRole("region", { name: "Re-protect managed certificate" });
    await user.selectOptions(within(panel).getByLabelText("Successor CA"), "ca-new");
    await user.selectOptions(within(panel).getByLabelText("Host target"), "target-1");
    await user.click(within(panel).getByRole("button", { name: "Review exact re-protection plan" }));
    expect(await within(panel).findByRole("alert")).toHaveTextContent("changed");
    expect(within(panel).queryByRole("button", { name: "Record reviewed plan" })).not.toBeInTheDocument();
    await user.type(within(panel).getByLabelText("Recover recorded job ID"), "job-1");
    await user.click(within(panel).getByRole("button", { name: "Load recorded plan" }));
    expect(await within(panel).findByText("Plan recorded and read back")).toBeInTheDocument();
    expect(apiMock.registerCAKeyReprotectionPlan).not.toHaveBeenCalled();
  });
});
