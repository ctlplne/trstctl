import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IdentityCertificateEvidence } from "@/pages/identities/IdentityCertificateEvidence";
import { formatDateTime } from "@/i18n/format";
import { IntlProvider, useTranslation } from "@/i18n/I18nProvider";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, identityDeploymentEvidence: read } };
});
const fixture = () => ({
  identity_id: "selected",
  read_at: "2030-01-01T10:05:00Z",
  receipt: {
    id: "restored-receipt",
    identity_id: "selected",
    fingerprint: "exact-restored-leaf",
    status: "rolled_back",
    connector: "traefik",
    target: "same-endpoint",
    updated_at: "2030-01-01T10:00:00Z",
  },
  certificate: {
    id: "exact-certificate",
    fingerprint: "exact-restored-leaf",
    serial: "abcd",
    status: "superseded",
    not_before: "2030-01-01T09:00:00Z",
    not_after: "2030-01-02T09:00:00Z",
  },
});
function TimeZoneControl() {
  const { setTimeZone } = useTranslation();
  return <button onClick={() => setTimeZone("UTC")}>Use UTC for evidence</button>;
}
function show(timeZone = "UTC") {
  return render(
    <MemoryRouter>
      <IntlProvider initialLocale="en-US" initialTimeZone={timeZone}>
        <AppQueryProvider>
          <IdentityCertificateEvidence identityId="selected" />
          <TimeZoneControl />
        </AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>,
  );
}
describe("exact certificate evidence in identity detail", () => {
  beforeEach(() => {
    cleanup();
    read.mockReset();
  });
  it("uses the operator's time zone for all evidence dates and updates when the preference changes", async () => {
    read.mockResolvedValue(fixture());
    const user = userEvent.setup();
    show("America/New_York");
    await screen.findByRole("link", { name: "Review this certificate and revocation" });
    expect(screen.getByText(/Jan 1, 2030,\s4:00\sAM/)).toBeInTheDocument();
    expect(screen.getByText(/Jan 2, 2030,\s4:00\sAM/)).toBeInTheDocument();
    expect(screen.getByText(/same-endpoint/)).toHaveTextContent(/Jan 1, 2030,\s5:00\sAM/);
    await user.click(screen.getByRole("button", { name: "Use UTC for evidence" }));
    expect(screen.getByText(/Jan 1, 2030,\s9:00\sAM/)).toBeInTheDocument();
    expect(screen.getByText(/Jan 2, 2030,\s9:00\sAM/)).toBeInTheDocument();
    expect(screen.getByText(/same-endpoint/)).toHaveTextContent(/Jan 1, 2030,\s10:00\sAM/);
  });
  it.each(["superseded", "revoked"])("shows dates and exact certificate link without hiding a %s leaf or claiming current service", async (status) => {
    const data = fixture();
    data.certificate.status = status;
    read.mockResolvedValue(data);
    show();
    const link = await screen.findByRole("link", { name: "Review this certificate and revocation" });
    expect(link).toHaveAttribute("href", "/certificates?tab=crlct&certificate_id=exact-certificate");
    expect(read).toHaveBeenCalledWith("selected");
    expect(screen.getByText(formatDateTime(data.certificate.not_after))).toBeInTheDocument();
    expect(screen.getByText(formatDateTime(data.certificate.not_before))).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`^${status}$`, "i"))).toBeInTheDocument();
    expect(screen.getByText(/historical evidence; a replacement or target change/)).toBeInTheDocument();
    expect(screen.getByText(/same-endpoint/)).toHaveTextContent(formatDateTime(data.receipt.updated_at));
  });
  it("distinguishes missing deployment from missing certificate metadata", async () => {
    read.mockResolvedValue({ identity_id: "selected", read_at: fixture().read_at });
    const view = show();
    await screen.findByText("No completed certificate deployment is recorded for this identity.");
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    view.unmount();
    read.mockResolvedValue({ ...fixture(), certificate: undefined });
    show();
    await screen.findByText("The completed receipt has no matching certificate metadata.");
    expect(screen.getByText(/same-endpoint/)).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
  it.each(["identity", "receipt", "fingerprint"])("refuses mismatched %s evidence", async (field) => {
    const data = fixture();
    if (field === "identity") data.identity_id = "other";
    if (field === "receipt") data.receipt.identity_id = "other";
    if (field === "fingerprint") data.certificate.fingerprint = "other";
    read.mockResolvedValue(data);
    show();
    await screen.findByRole("alert");
    expect(screen.getByText("Certificate evidence does not match this identity and deployment receipt.")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
  it("retries a failed read without turning failure into empty evidence", async () => {
    read.mockRejectedValueOnce(new Error("Access denied")).mockResolvedValueOnce(fixture());
    const user = userEvent.setup();
    show();
    await screen.findByText("Access denied");
    expect(screen.queryByText(/No completed certificate deployment/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reload certificate evidence" }));
    await screen.findByRole("link", { name: "Review this certificate and revocation" });
    expect(read).toHaveBeenCalledTimes(2);
  });
});
