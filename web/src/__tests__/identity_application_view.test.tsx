import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import type { IdentityApplicationView } from "@/lib/api";
import { endpointBindingDefaultsFromSearch } from "@/lib/endpointBindingDefaults";
import { IdentityApplicationPanel } from "@/pages/identities/IdentityApplicationPanel";

const { read, approvalsPage, alertsPage } = vi.hoisted(() => ({ read: vi.fn(), approvalsPage: vi.fn(), alertsPage: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, identityApplication: read, identityApplicationApprovals: approvalsPage, identityApplicationAlerts: alertsPage } };
});

type StepPreview = IdentityApplicationView["review_plan"][number]["preview"];
const stepPreview = (preview: Partial<StepPreview> & Pick<StepPreview, "state">): StepPreview => ({
  ready: true,
  refusals: [],
  warnings: [],
  policy: [],
  readback: [],
  ...preview,
});
const renewal = stepPreview({ state: "previewed", from: "deployed", to: "renewing", event_type: "identity.renewing" });

const fixture = (): IdentityApplicationView => ({
  identity: {
    id: "app-1",
    tenant_id: "t1",
    owner_id: "owner-1",
    kind: "x509_certificate",
    name: "orders.example.test",
    status: "deployed",
  } as IdentityApplicationView["identity"],
  inventory_state: "served",
  owner: { id: "owner-1", name: "orders-app", kind: "workload" },
  issuer: { source: "external", id: "corp-digicert", name: "Corporate DigiCert", certificate_issuer: "CN=DigiCert Test Issuing CA" },
  profile: { name: "orders-tls", version: 4, spec_digest: "digest", requires_approval: true, enrollment_methods: ["acme", "api"] },
  certificate: { id: "cert-2", fingerprint: "fp-2", serial: "0a0b", status: "active", not_after: "2030-02-01T00:00:00Z" },
  destination: {
    target_id: "target-1",
    name: "arn:aws:acm:us-east-1:123456789012:certificate/orders",
    connector: "aws-acm",
    revision: "rev-1",
    enabled: true,
    last_delivery_status: "delivered",
    last_delivery_fingerprint: "fp-2",
    last_delivery_at: "2030-01-01T10:00:00Z",
  },
  served: { fingerprint: "fp-2", vantage: "relay", at: "2030-01-01T11:00:00Z", matches_current: true },
  approvals: [],
  renewal: { due: false, next_action: "renew before expiry", blockers: [], source: "profile" },
  alerts: [],
  actions: [
    { action: "recover", available: false, method: "POST", path: "/x", reason: "nothing to recover: renewal has not failed and no rollback holds it" },
    { action: "revoke", available: true, method: "POST", path: "/x" },
    { action: "retire", available: false, method: "POST", path: "/x", reason: "a certificate is retired after it is revoked" },
  ],
  defaults: { owner_id: "owner-1", profile_name: "orders-tls", issuer_source: "external", issuer_id: "corp-digicert", connector: "aws-acm" },
  review_plan: [
    { action: "approve", subject: "orders-tls", preview: renewal },
    { action: "issue", subject: "external:corp-digicert", preview: renewal },
    {
      action: "deploy",
      subject: "arn:aws:acm:us-east-1:123456789012:certificate/orders (aws-acm)",
      preview: stepPreview({ state: "later", from: "renewing", to: "deployed", event_type: "identity.renewed" }),
    },
    { action: "verify", subject: "relay", preview: stepPreview({ state: "later" }) },
  ],
});

function show() {
  return render(
    <MemoryRouter>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <AppQueryProvider>
          <IdentityApplicationPanel identityId="app-1" />
        </AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>,
  );
}

describe("certificate application view (A244)", () => {
  beforeEach(() => {
    cleanup();
    read.mockReset();
    approvalsPage.mockReset();
    alertsPage.mockReset();
  });

  it("shows the exact CA, destination, what was seen and from where, the next action and the actions", async () => {
    read.mockResolvedValue(fixture());
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    await section.findByText("Seen in use");
    expect(read).toHaveBeenCalledWith("app-1");
    expect(section.getByText("An endpoint was seen presenting the active certificate.")).toBeInTheDocument();
    expect(section.getByText("External CA: Corporate DigiCert")).toBeInTheDocument();
    expect(section.getByText("CN=DigiCert Test Issuing CA")).toBeInTheDocument();
    expect(section.getByText(/orders-tls, version 4/)).toBeInTheDocument();
    expect(section.getByText("Issuance needs approval.")).toBeInTheDocument();
    expect(section.getByText(/through aws-acm/)).toBeInTheDocument();
    expect(section.getByText(/Seen by a network agent, as a client sees it at/)).toBeInTheDocument();
    expect(section.queryByText("That sighting is of an earlier certificate, not the active one.")).not.toBeInTheDocument();
    expect(section.getByText("Renew before it expires")).toBeInTheDocument();
    expect(section.getByText("Permitted enrollment methods: acme, api")).toBeInTheDocument();
    const steps = section.getAllByRole("listitem").map((item) => item.firstChild?.textContent);
    expect(steps.slice(0, 4)).toEqual([
      "An approver signs off under profile orders-tls",
      "Issue from external:corp-digicert",
      "Deploy to arn:aws:acm:us-east-1:123456789012:certificate/orders (aws-acm)",
      "Confirm it from the network with a network agent",
    ]);
    expect(section.getByText("a certificate is retired after it is revoked")).toBeInTheDocument();
    expect(section.getByText("Available now")).toBeInTheDocument();
    const reuse = section.getByRole("link", { name: "Use these defaults for another certificate" });
    const href = reuse.getAttribute("href") ?? "";
    expect(href.startsWith("/connectors?")).toBe(true);
    expect(endpointBindingDefaultsFromSearch(new URLSearchParams(href.split("?")[1]))).toEqual({
      owner_id: "owner-1",
      profile_name: "orders-tls",
      issuer_key: "external:corp-digicert",
    });
  });

  it("names the method that enrolled the active certificate and the first one, apart from the profile's permitted methods (A244-L4)", async () => {
    const view = fixture();
    view.enrollment = { first_method: "est", first_certificate_id: "cert-1", current_method: "acme" };
    read.mockResolvedValue(view);
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    await section.findByText("Enrolled by: acme");
    expect(section.getByText("First certificate enrolled by: est")).toBeInTheDocument();
    expect(section.getByText("Permitted enrollment methods: acme, api")).toBeInTheDocument();
  });

  it("says a renewal's certificate is only delivered and names what changed under an approval", async () => {
    const view = fixture();
    view.inventory_state = "delivered";
    view.served = { fingerprint: "fp-1", vantage: "local", at: "2030-01-01T09:00:00Z", matches_current: false };
    view.approvals = [
      {
        id: "ap-1",
        status: "pending",
        action: "issue",
        created_at: "2030-01-01T08:00:00Z",
        expires_at: "2030-01-02T08:00:00Z",
        changed: ["destination", "issuer"],
      },
    ];
    view.renewal = { due: false, next_action: "blocked", blockers: ["destination disabled"] };
    view.review_plan = [
      { action: "issue", subject: "external:corp-digicert", preview: renewal },
      { action: "verify", subject: "", preview: stepPreview({ state: "later" }) },
    ];
    read.mockResolvedValue(view);
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    await section.findByText("Delivered");
    expect(section.getByText("The destination accepted the active certificate. Nothing has seen an endpoint present it yet.")).toBeInTheDocument();
    expect(section.getByText("That sighting is of an earlier certificate, not the active one.")).toBeInTheDocument();
    expect(section.getByText(/Changed since it was asked: destination, issuing CA\./)).toBeInTheDocument();
    expect(section.getByText("Blocked until the failed prerequisites below are fixed")).toBeInTheDocument();
    expect(section.getByText(/destination disabled/)).toBeInTheDocument();
    expect(section.getByText("Nothing observes this destination yet, so the new certificate will read as delivered, not seen in use")).toBeInTheDocument();
  });

  it("shows what the transition preview refuses in a plan step and which step the later ones wait on (A244-L2)", async () => {
    const view = fixture();
    view.identity.status = "requested";
    const refusal = "control-plane key generation is off for this tenant; attach subject_csr_pem";
    const issuance = stepPreview({
      state: "previewed",
      from: "requested",
      to: "issued",
      event_type: "identity.issued",
      ready: false,
      refusals: [refusal],
      warnings: ["No issuing authority is pinned on this identity."],
      policy: ["Certificate profile, quota, approval, CSR, and signer checks run again at execution."],
      readback: ["Read /api/v1/identities/app-1 and confirm status is issued."],
    });
    view.review_plan = [
      { action: "issue", subject: "platform:trstctl-issuing-ca", preview: issuance },
      {
        action: "deploy",
        subject: "orders (nginx)",
        preview: stepPreview({ state: "later", from: "issued", to: "deployed", event_type: "identity.deployed", ready: false, waits_on: "issue" }),
      },
      { action: "verify", subject: "", preview: stepPreview({ state: "later", ready: false, waits_on: "issue" }) },
    ];
    read.mockResolvedValue(view);
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    await section.findByText("Previewed now (requested → issued). Nothing was written or sent.");
    expect(section.getByText(`Refused now: ${refusal}`)).toHaveClass("text-destructive");
    expect(section.getAllByText("Waits on the issue step, which would be refused now.")).toHaveLength(2);
    expect(section.getByText("Runs later (issued → deployed).")).toBeInTheDocument();
    expect(section.getByText("Read once the delivery is done.")).toBeInTheDocument();
    expect(section.getByText("Warnings: No issuing authority is pinned on this identity.")).toBeInTheDocument();
    expect(section.getByText("What execution checks and how to confirm it")).toBeInTheDocument();
    expect(section.getByText("Certificate profile, quota, approval, CSR, and signer checks run again at execution.")).toBeInTheDocument();
    expect(section.getByText("Read /api/v1/identities/app-1 and confirm status is issued.")).toBeInTheDocument();
  });

  it("shows older approvals and alerts from the view's cursors (A244-L3)", async () => {
    const view = fixture();
    const approval = (id: string, action: string, at: string) => ({ id, status: "approved", action, created_at: at, expires_at: at, changed: [] });
    view.approvals = [approval("ap-new", "renew", "2030-01-03T00:00:00Z")];
    view.approvals_next_cursor = "ap-cursor-1";
    view.alerts = [];
    view.alerts_next_cursor = "al-cursor-1";
    approvalsPage.mockResolvedValueOnce({ items: [approval("ap-old", "issue", "2029-06-01T00:00:00Z"), approval("ap-new", "renew", "2030-01-03T00:00:00Z")] });
    alertsPage.mockResolvedValueOnce({ items: [], next_cursor: "al-cursor-2" }).mockResolvedValueOnce({
      items: [{ id: "77", kind: "renewal_failed", destination: "notification.webhook", status: "sent", created_at: "2029-05-01T00:00:00Z" }],
    });
    read.mockResolvedValue(view);
    const user = userEvent.setup();
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    await user.click(await section.findByRole("button", { name: "Show older approvals" }));
    expect(approvalsPage).toHaveBeenCalledWith("app-1", "ap-cursor-1");
    expect(await section.findByText(/^issue/)).toBeInTheDocument();
    expect(section.getAllByText(/^renew/)).toHaveLength(1);
    expect(section.queryByRole("button", { name: "Show older approvals" })).not.toBeInTheDocument();

    await user.click(section.getByRole("button", { name: "Show older alerts" }));
    expect(alertsPage).toHaveBeenCalledWith("app-1", "al-cursor-1");
    expect(
      await section.findByText("No alerts for this certificate in that stretch of notifications. Show older alerts reads further back."),
    ).toBeInTheDocument();
    await user.click(section.getByRole("button", { name: "Show older alerts" }));
    expect(alertsPage).toHaveBeenLastCalledWith("app-1", "al-cursor-2");
    expect(await section.findByText(/renewal_failed/)).toBeInTheDocument();
    expect(section.queryByRole("button", { name: "Show older alerts" })).not.toBeInTheDocument();
  });

  it("says whether anything checks the destination's endpoint (A244-L1)", async () => {
    const checked = fixture();
    checked.destination = { ...checked.destination!, verify_address: "orders.example.test:443" };
    read.mockResolvedValue(checked);
    show();
    let section = within(await screen.findByRole("region", { name: "Application view" }));
    expect(await section.findByText("Its endpoint orders.example.test:443 is checked every interval for the delivered certificate.")).toBeInTheDocument();
    cleanup();

    const unchecked = fixture();
    unchecked.inventory_state = "delivered";
    unchecked.served = undefined;
    read.mockResolvedValue(unchecked);
    show();
    section = within(await screen.findByRole("region", { name: "Application view" }));
    expect(
      await section.findByText("Nothing checks this destination's endpoint. Set verify_address on its deployment target to have it checked every interval."),
    ).toBeInTheDocument();
  });

  it("names the identity's own certificate details when they changed under an approval (A245-L5)", async () => {
    const view = fixture();
    view.approvals = [
      {
        id: "ap-2",
        status: "superseded",
        action: "issue",
        created_at: "2030-01-01T08:00:00Z",
        expires_at: "2030-01-02T08:00:00Z",
        changed: ["identity"],
      },
    ];
    read.mockResolvedValue(view);
    show();
    const section = within(await screen.findByRole("region", { name: "Application view" }));
    expect(await section.findByText(/Changed since it was asked: certificate details \(names, key algorithm or request\)\./)).toBeInTheDocument();
  });

  it("refuses an answer for a different identity", async () => {
    const view = fixture();
    view.identity = { ...view.identity, id: "someone-else" };
    read.mockResolvedValue(view);
    show();
    expect(await screen.findByText("Couldn't load the application view.")).toBeInTheDocument();
    expect(screen.queryByText("Seen in use")).not.toBeInTheDocument();
  });
});
