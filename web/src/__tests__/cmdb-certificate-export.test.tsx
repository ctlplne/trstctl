import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CMDBCertificateExportPanel } from "@/pages/integrate/CMDBCertificateExportPanel";
import { AppQueryProvider } from "@/lib/query";

const { mock } = vi.hoisted(() => ({ mock: { bindings: vi.fn(), queue: vi.fn(), status: vi.fn() } }));
vi.mock("@/lib/cmdbExportApi", () => ({ cmdbExportApi: mock }));

const certificate = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const operation = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

describe("Certificate export to the CMDB", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mock.bindings.mockResolvedValue({ items: [{ id: "certificate-writer", enabled: true, data_source: "trstctl" }] });
    mock.queue.mockResolvedValue({
      id: operation,
      status: "pending",
      certificate_id: certificate,
      binding_id: "certificate-writer",
      fingerprint: "ab",
      attempts: 0,
    });
    mock.status.mockResolvedValue({
      id: operation,
      status: "verified",
      certificate_id: certificate,
      binding_id: "certificate-writer",
      fingerprint: "ab",
      attempts: 1,
      receipt: { sys_id: "0123456789abcdef0123456789abcdef" },
    });
  });

  it("queues only a certificate and an operator binding, then reads the verified result", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <CMDBCertificateExportPanel />
      </AppQueryProvider>,
    );
    await user.selectOptions(await screen.findByLabelText("Certificate write binding"), "certificate-writer");
    await user.type(screen.getByLabelText("Certificate inventory ID"), certificate);
    await user.click(screen.getByRole("button", { name: "Export certificate" }));
    await waitFor(() => expect(mock.queue).toHaveBeenCalledWith({ binding_id: "certificate-writer", certificate_id: certificate }, expect.any(String)));
    expect(await screen.findByText("The CMDB record was independently verified.")).toBeInTheDocument();
    expect(screen.getByText("0123456789abcdef0123456789abcdef")).toBeInTheDocument();
    expect(mock.status).toHaveBeenCalledWith(operation, expect.anything());
  });

  it("explains the missing separate write authority without offering a credential field", async () => {
    mock.bindings.mockResolvedValue({ items: [] });
    render(
      <AppQueryProvider>
        <CMDBCertificateExportPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText(/No certificate write binding is enabled/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export certificate" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credential/i)).not.toBeInTheDocument();
  });

  it("rejects a malformed certificate ID before sending a mutation", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <CMDBCertificateExportPanel />
      </AppQueryProvider>,
    );
    await user.selectOptions(await screen.findByLabelText("Certificate write binding"), "certificate-writer");
    await user.type(screen.getByLabelText("Certificate inventory ID"), "not-a-certificate-id");
    await user.click(screen.getByRole("button", { name: "Export certificate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a write binding and enter a valid certificate UUID.");
    expect(mock.queue).not.toHaveBeenCalled();
  });
});
