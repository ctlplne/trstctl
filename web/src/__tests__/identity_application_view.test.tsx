import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import type { IdentityApplicationView } from "@/lib/api";
import { endpointBindingDefaultsFromSearch } from "@/lib/endpointBindingDefaults";
import { IdentityApplicationPanel } from "@/pages/identities/IdentityApplicationPanel";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, identityApplication: read } };
});

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
    { action: "approve", subject: "orders-tls" },
    { action: "issue", subject: "external:corp-digicert" },
    { action: "deploy", subject: "arn:aws:acm:us-east-1:123456789012:certificate/orders (aws-acm)" },
    { action: "verify", subject: "relay" },
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
    expect(section.getByText("Enrollment methods: acme, api")).toBeInTheDocument();
    const steps = section.getAllByRole("listitem").map((item) => item.textContent);
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
      { action: "issue", subject: "external:corp-digicert" },
      { action: "verify", subject: "" },
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

  it("refuses an answer for a different identity", async () => {
    const view = fixture();
    view.identity = { ...view.identity, id: "someone-else" };
    read.mockResolvedValue(view);
    show();
    expect(await screen.findByText("Couldn't load the application view.")).toBeInTheDocument();
    expect(screen.queryByText("Seen in use")).not.toBeInTheDocument();
  });
});
