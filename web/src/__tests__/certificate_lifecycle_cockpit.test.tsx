import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ToastProvider } from "@/components/ToastProvider";
import { Certificates } from "@/pages/Certificates";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    certificateHealth: vi.fn(),
    crlDistributions: vi.fn(),
    revocationHealth: vi.fn(),
    rogueCertificates: vi.fn(),
    risk: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    owners: vi.fn(),
    identities: vi.fn(),
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderPage(timeZone = "UTC") {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone={timeZone}>
          <Certificates />
        </IntlProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("Certificate Lifecycle cockpit", () => {
  it("routes a newly issued certificate to its exact identity and exposes revocation without offering renewal", async () => {
    const certificate = {
      id: "fresh-leaf",
      tenant_id: "tenant-1",
      subject: "CN=fresh.example",
      owner_id: "team-platform",
      fingerprint: "fresh-fp",
      status: "active",
      not_after: "2026-08-30T12:00:00Z",
      identity_ids: ["fresh-identity"],
    };
    apiMock.certificatePage.mockResolvedValue({ items: [certificate] });
    apiMock.getCertificate.mockResolvedValue(certificate);
    apiMock.identities.mockResolvedValue([
      { id: "wrong-identity", kind: "x509_certificate", name: "fresh.example", owner_id: "team-platform", status: "deployed" },
      { id: "fresh-identity", kind: "x509_certificate", name: "fresh.example", owner_id: "team-platform", status: "issued" },
    ]);
    renderPage();
    const queue = await screen.findByRole("table", { name: "Certificate action queue" });
    expect(await within(queue).findByRole("link", { name: "Review identity lifecycle" })).toHaveAttribute("href", "/identities?identity=fresh-identity");
    expect(within(queue).queryByRole("link", { name: "Start renewal" })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Review" }));
    const detail = await screen.findByRole("dialog", { name: "Certificate details" });
    expect(await within(detail).findByRole("link", { name: "Review identity lifecycle" })).toHaveAttribute("href", "/identities?identity=fresh-identity");
    expect(within(detail).queryByRole("button", { name: /Renew/ })).not.toBeInTheDocument();
    expect(within(detail).getByRole("link", { name: "Start incident response" })).toHaveAttribute("href", "/incidents?identity=fresh-identity");
    expect(within(detail).getByRole("link", { name: "View in credential graph" })).toHaveAttribute("href", "/graph?node=cert%3Afresh-leaf");
    expect(within(detail).getByRole("link", { name: "Review revocation" })).toHaveAttribute("href", "/certificates?tab=crlct&certificate_id=fresh-leaf");
    fireEvent.click(within(detail).getByRole("link", { name: "Review revocation" }));
    const center = await screen.findByRole("region", { name: "Revocation center" });
    expect(await within(center).findByRole("combobox", { name: "Managed certificate" })).toHaveValue("certificate:fresh-leaf");
    expect(screen.getByRole("tab", { name: "Revocation & CT" })).toHaveAttribute("aria-selected", "true");
  });
  it("observes publication that completes after the initial revocation read", async () => {
    const distribution = {
      tenant_id: "tenant-1",
      ca_id: "issuer-1",
      full_number: 2,
      full_url: "/crl/tenant-1",
      revoked_count: 1,
      shard_count: 0,
      shards: [],
      this_update: "2026-08-24T12:00:00Z",
      next_update: "2026-08-25T12:00:00Z",
    };
    apiMock.crlDistributions.mockResolvedValue({ items: [distribution] });
    renderPage();
    fireEvent.click(await screen.findByRole("tab", { name: "Revocation & CT" }));
    expect(await screen.findByText("CAs: 1; shards: 0; revoked serials: 1.")).toBeInTheDocument();
    apiMock.crlDistributions.mockResolvedValue({ items: [{ ...distribution, full_number: 3, revoked_count: 2 }] });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_500);
    });
    expect(await screen.findByText("CAs: 1; shards: 0; revoked serials: 2.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "#3" })).toHaveAttribute("href", "/crl/tenant-1");
  });

  it("hides a refused publication snapshot, stops polling, and permits explicit read recovery", async () => {
    const distribution = {
      tenant_id: "tenant-1",
      ca_id: "issuer-1",
      full_number: 2,
      full_url: "/crl/tenant-1",
      revoked_count: 1,
      shard_count: 0,
      shards: [],
      this_update: "2026-08-24T12:00:00Z",
      next_update: "2026-08-25T12:00:00Z",
    };
    apiMock.crlDistributions.mockResolvedValue({ items: [distribution] });
    renderPage();
    fireEvent.click(await screen.findByRole("tab", { name: "Revocation & CT" }));
    expect(await screen.findByText("CAs: 1; shards: 0; revoked serials: 1.")).toBeInTheDocument();
    apiMock.crlDistributions.mockRejectedValue(new ApiError(403, '{"detail":"Certificate evidence permission removed"}'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_500);
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("No published CRL was loaded. Publication is not proven.");
    expect(screen.queryByText("CAs: 1; shards: 0; revoked serials: 1.")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "#2" })).not.toBeInTheDocument();
    const callsAfterDenial = apiMock.crlDistributions.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(apiMock.crlDistributions).toHaveBeenCalledTimes(callsAfterDenial);
    apiMock.crlDistributions.mockResolvedValue({ items: [{ ...distribution, full_number: 3, revoked_count: 2 }] });
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("CAs: 1; shards: 0; revoked serials: 2.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(new Date("2026-08-24T12:00:00Z"));
    localStorage.clear();

    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-expired",
          tenant_id: "tenant-1",
          subject: "CN=checkout.prod.example",
          issuer: "CN=Production CA",
          status: "active",
          fingerprint: "fp-expired",
          not_after: "2026-08-23T12:00:00Z",
          deployment_location: "production / ingress / checkout",
          attributes: { environment: "production", team_name: "Payments" },
        },
        {
          id: "cert-renewal-failed",
          identity_ids: ["identity-api"],
          tenant_id: "tenant-1",
          subject: "CN=api.prod.example",
          issuer: "CN=Production CA",
          status: "active",
          fingerprint: "fp-api",
          not_after: "2026-08-27T12:00:00Z",
          owner_id: "team-platform",
          deployment_location: "connector.deploy",
          attributes: { team_id: "team-platform" },
        },
        {
          id: "cert-planned",
          identity_ids: ["identity-jobs"],
          tenant_id: "tenant-1",
          subject: "CN=jobs.stage.example",
          issuer: "CN=Issuing CA",
          status: "active",
          fingerprint: "fp-jobs",
          not_after: "2026-09-13T12:00:00Z",
          owner_id: "team-platform",
          deployment_location: "staging / worker / jobs",
          attributes: { environment: "staging", team_id: "team-platform" },
        },
      ],
    });
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      inventory_path: "/api/v1/certificates",
      expiring_path: "/api/v1/certificates?expiring_before=2026-09-23T12:00:00Z",
      expiry_buckets: [],
      source_breakdown: [],
      expiring: [],
      summary: {
        total: 3,
        active: 3,
        expired: 1,
        expiring_7d: 2,
        expiring_30d: 3,
        expiring_90d: 3,
        revoked: 0,
        superseded: 0,
        external_source_count: 0,
        imported_count: 0,
        discovered_count: 0,
        unknown_expiry_count: 0,
        health: "critical",
      },
    });
    apiMock.getCertificate.mockResolvedValue({
      id: "cert-renewal-failed",
      identity_ids: ["identity-api"],
      tenant_id: "tenant-1",
      subject: "CN=api.prod.example",
      issuer: "CN=Production CA",
      status: "active",
      fingerprint: "fp-api",
      not_after: "2026-08-27T12:00:00Z",
      owner_id: "team-platform",
      deployment_location: "production / load balancer / api",
    });
    apiMock.crlDistributions.mockResolvedValue({ items: [] });
    apiMock.revocationHealth.mockResolvedValue(undefined);
    apiMock.rogueCertificates.mockResolvedValue(undefined);
    apiMock.risk.mockResolvedValue([]);
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rotation-failed",
          tenant_id: "tenant-1",
          identity_id: "identity-api",
          predecessor_fingerprint: "fp-api",
          status: "failed",
          trigger: "scheduled",
          error: "upstream CA timed out",
          created_at: "2026-08-24T10:00:00Z",
          updated_at: "2026-08-24T10:05:00Z",
        },
        {
          id: "rotation-ok",
          tenant_id: "tenant-1",
          identity_id: "identity-jobs",
          predecessor_fingerprint: "fp-old-jobs",
          successor_fingerprint: "fp-jobs",
          status: "succeeded",
          trigger: "scheduled",
          created_at: "2026-08-20T10:00:00Z",
          updated_at: "2026-08-20T10:05:00Z",
          completed_at: "2026-08-20T10:05:00Z",
        },
        {
          id: "unrelated-secret-rotation",
          tenant_id: "tenant-1",
          identity_id: "identity-secret",
          predecessor_fingerprint: "secret-version-1",
          status: "failed",
          trigger: "scheduled",
          created_at: "2026-08-24T10:00:00Z",
          updated_at: "2026-08-24T10:05:00Z",
        },
        {
          id: "cancelled-certificate-rotation",
          tenant_id: "tenant-1",
          identity_id: "identity-jobs",
          status: "cancelled",
          trigger: "scheduled",
          created_at: "2026-08-18T10:00:00Z",
          updated_at: "2026-08-18T10:05:00Z",
          completed_at: "2026-08-18T10:05:00Z",
        },
      ],
    });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-failed",
          tenant_id: "tenant-1",
          identity_id: "identity-api",
          fingerprint: "fp-api",
          connector: "f5",
          target: "api-load-balancer",
          destination: "production / load balancer / api",
          status: "verify_failed",
          attempts: 3,
          detail: "new certificate was not observed",
          rollback: "available",
          created_at: "2026-08-24T10:06:00Z",
          updated_at: "2026-08-24T10:12:00Z",
        },
        {
          id: "delivery-ok",
          tenant_id: "tenant-1",
          identity_id: "identity-jobs",
          fingerprint: "fp-jobs",
          connector: "kubernetes",
          target: "jobs-worker",
          destination: "staging / worker / jobs",
          status: "verified",
          attempts: 1,
          rollback: "available",
          created_at: "2026-08-20T10:06:00Z",
          updated_at: "2026-08-20T10:08:00Z",
        },
        {
          id: "unrelated-secret-delivery",
          tenant_id: "tenant-1",
          identity_id: "identity-secret",
          fingerprint: "secret-version-2",
          connector: "vault",
          target: "payment-secret",
          destination: "secret/production/payment",
          status: "failed",
          attempts: 2,
          detail: "secret target rejected the update",
          rollback: "available",
          created_at: "2026-08-24T10:06:00Z",
          updated_at: "2026-08-24T10:08:00Z",
        },
      ],
    });
    apiMock.owners.mockResolvedValue([
      {
        id: "team-platform",
        tenant_id: "tenant-1",
        kind: "team",
        name: "Platform Trust",
        email: "platform@example.test",
        environment: "production",
        escalation_chain: ["oncall@example.test"],
        ownership_attested: true,
        ownership_complete: true,
        ownership_current: true,
      },
    ]);
    apiMock.identities.mockResolvedValue([
      { id: "identity-api", kind: "x509_certificate", name: "api.prod.example", owner_id: "team-platform", status: "renewal_failed" },
      { id: "identity-jobs", kind: "x509_certificate", name: "jobs.stage.example", owner_id: "team-platform", status: "deployed" },
    ]);
    apiMock.notifications.mockResolvedValue({
      items: [
        {
          id: "notification-dead",
          tenant_id: "tenant-1",
          certificate_id: "cert-expired",
          destination: "payments-oncall@example.test",
          status: "dead",
          attempts: 4,
          severity: "critical",
          subject: "CN=checkout.prod.example",
          last_error: "mailbox rejected the message",
          created_at: "2026-08-24T09:00:00Z",
        },
      ],
    });
    apiMock.notificationChannels.mockResolvedValue({
      items: [{ id: "email", label: "Email", category: "email", delivery: "outbox", configured: true, enabled: true }],
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "urgent-certificates",
          tenant_id: "tenant-1",
          name: "Urgent certificates",
          default_channels: ["email"],
          channels_by_severity: { critical: ["email"] },
          digest_interval_seconds: 0,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 0, next_run_at: "2026-08-24T12:00:00Z", timezone: "UTC" },
          created_at: "2026-08-01T00:00:00Z",
          updated_at: "2026-08-01T00:00:00Z",
        },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps inventory and certificate details on the selected local calendar day", async () => {
    const certificate = {
      id: "midnight-cert",
      tenant_id: "tenant-1",
      subject: "CN=midnight.example.test",
      status: "active",
      fingerprint: "midnight-fp",
      not_before: "2026-08-30T23:24:48Z",
      not_after: "2026-08-31T00:24:48Z",
    };
    apiMock.certificatePage.mockResolvedValue({ items: [certificate] });
    apiMock.getCertificate.mockResolvedValue(certificate);
    renderPage("America/New_York");
    const inventory = await screen.findByRole("table", { name: "Inventoried certificates" });
    const row = within(inventory).getByRole("row", { name: /midnight.example.test/ });
    expect(within(row).getByText("Aug 30, 2026")).toBeInTheDocument();
    expect(within(row).queryByText("Aug 31, 2026")).not.toBeInTheDocument();
    fireEvent.click(within(row).getByRole("button", { name: "Review" }));
    const detail = await screen.findByRole("dialog", { name: "Certificate details" });
    expect(within(detail).getByText("Aug 30, 2026, 8:24 PM")).toBeInTheDocument();
    expect(detail.querySelector('time[datetime="2026-08-31T00:24:48Z"]')).not.toBeNull();
  });

  it("puts the whole urgent answer, evidence, and next actions in the default first view", async () => {
    const view = renderPage();

    const cockpit = await screen.findByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(within(cockpit).getByText("1", { selector: "[data-metric='expired']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("2", { selector: "[data-metric='expiring-7d']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("3", { selector: "[data-metric='expiring-30d']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("1", { selector: "[data-metric='owner-gaps']" })).toBeInTheDocument();
    expect(within(cockpit).getByText(/1 renewal failed/i)).toBeInTheDocument();
    expect(within(cockpit).getByText(/1 deployment failed verification/i)).toBeInTheDocument();

    expect(within(cockpit).getByRole("img", { name: "Certificate work arriving over the next 90 days" })).toBeInTheDocument();
    expect(within(cockpit).getByRole("table", { name: "Certificate work arrival data" })).toBeInTheDocument();
    expect(within(cockpit).getByRole("img", { name: "Renewal and deployment outcomes by week" })).toBeInTheDocument();
    const outcomeTable = within(cockpit).getByRole("table", { name: "Renewal and deployment outcome data" });
    expect(outcomeTable).toBeInTheDocument();
    const outcomeTotals = within(outcomeTable)
      .getAllByRole("row")
      .slice(1)
      .reduce(
        (totals, row) => {
          const cells = within(row).getAllByRole("cell");
          return { succeeded: totals.succeeded + Number(cells[0]?.textContent ?? 0), failed: totals.failed + Number(cells[1]?.textContent ?? 0) };
        },
        { succeeded: 0, failed: 0 },
      );
    // An intentional stop is neither a successful renewal nor a failure.
    expect(outcomeTotals).toEqual({ succeeded: 2, failed: 2 });

    const queue = within(cockpit).getByRole("table", { name: "Certificate action queue" });
    const expiredRow = within(queue).getByRole("row", { name: /checkout\.prod\.example/i });
    expect(within(expiredRow).getByText("production")).toBeInTheDocument();
    expect(within(expiredRow).getByText("Expired 1 day ago")).toBeInTheDocument();
    expect(within(expiredRow).getByText("Manual renewal")).toBeInTheDocument();
    expect(within(expiredRow).getByText("No accountable owner")).toBeInTheDocument();
    expect(within(expiredRow).getByRole("link", { name: "Assign owner" })).toHaveAttribute("href", "/owners?status=orphaned");

    const failedRow = within(queue).getByRole("row", { name: /api\.prod\.example/i });
    expect(within(failedRow).getByText("production")).toBeInTheDocument();
    expect(within(failedRow).getByText("Renewal failed")).toBeInTheDocument();
    expect(within(failedRow).getByText("Platform Trust")).toBeInTheDocument();
    expect(within(failedRow).getByText(/deployment verification failed/i)).toBeInTheDocument();
    expect(within(failedRow).getByRole("link", { name: "Retry renewal" })).toHaveAttribute("href", "/identities?identity=identity-api");

    const alertSafety = within(cockpit).getByRole("region", { name: "Urgent alert delivery safety" });
    expect(within(alertSafety).getByText(/route is configured/i)).toBeInTheDocument();
    expect(within(alertSafety).getByText(/1 urgent alert is dead/i)).toBeInTheDocument();
    expect(within(alertSafety).getByText(/does not prove a human received it/i)).toBeInTheDocument();
    expect(within(alertSafety).getByRole("link", { name: "Repair alert delivery" })).toHaveAttribute("href", "/notifications?status=dead");

    const inventory = screen.getByRole("table", { name: "Inventoried certificates" });
    const inventoryRow = within(inventory).getByRole("row", { name: /api\.prod\.example/i });
    fireEvent.click(within(inventoryRow).getByRole("button", { name: /review/i }));
    const detail = await screen.findByRole("dialog", { name: /certificate details/i });
    expect(within(detail).getByText("Effective ownership")).toBeInTheDocument();
    expect(within(detail).getByRole("link", { name: "Platform Trust" })).toHaveAttribute("href", "/owners?owner=team-platform");
    expect(within(detail).getByText(/Current ownership · Alert contact reachable/)).toBeInTheDocument();

    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("identifies SPIFFE certificates and routes fresh attestation without inventing key custody", async () => {
    const certificate = {
      id: "workload-cert",
      tenant_id: "tenant-1",
      subject: "",
      sans: ["spiffe://prod/payments"],
      issuer: "CN=Issuing CA",
      status: "active",
      fingerprint: "fp-workload",
      source: "attested:k8s_sat",
      not_before: "2026-08-24T11:59:00Z",
      not_after: "2026-08-24T12:45:00Z",
      custody_summary: "Key custody was not recorded for this credential.",
    };
    apiMock.certificatePage.mockResolvedValue({ items: [certificate] });
    apiMock.getCertificate.mockResolvedValue(certificate);
    renderPage();
    const queue = await screen.findByRole("table", { name: "Certificate action queue" });
    expect(within(queue).getByRole("row", { name: /spiffe:\/\/prod\/payments/ })).toHaveTextContent("Expires in 45 min");
    const inventory = screen.getByRole("table", { name: "Inventoried certificates" });
    const row = within(inventory).getByRole("row", { name: /spiffe:\/\/prod\/payments/ });
    fireEvent.click(within(row).getByRole("button", { name: "Review" }));
    const detail = await screen.findByRole("dialog", { name: "Certificate details" });
    expect(within(detail).getByRole("link", { name: "Replace with fresh workload proof" })).toHaveAttribute("href", "/workloads?workflow=attested");
    expect(within(detail).getByText(/cannot establish where the private key was created or how it is protected/i)).toBeInTheDocument();
    expect(within(detail).queryByText(/predates custody|found by discovery/)).not.toBeInTheDocument();
    expect(detail.querySelector('time[datetime="2026-08-24T12:45:00Z"]')).not.toBeNull();
  });

  it("updates a short-lived deadline when expiry passes while the page stays open", async () => {
    // This test owns the clock: coverage/instrumentation latency must not
    // advance a 500 ms lifetime before the initial assertion observes it.
    vi.useFakeTimers({ shouldAdvanceTime: false });
    vi.setSystemTime(new Date("2026-08-24T12:00:00Z"));
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "brief-cert",
          tenant_id: "tenant-1",
          subject: "CN=brief.test",
          status: "active",
          fingerprint: "brief-fp",
          not_after: "2026-08-24T12:00:00.500Z",
        },
      ],
    });
    await act(async () => {
      renderPage();
    });
    const queue = screen.getByRole("table", { name: "Certificate action queue" });
    expect(within(queue).getByText("Expires in under 1 min")).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(1000);
    });
    expect(within(queue).getByText("Already expired")).toBeInTheDocument();
    expect(within(queue).queryByText("Expires today")).not.toBeInTheDocument();
  });

  it("refreshes server totals at expiry without counting only the loaded certificate page", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    vi.setSystemTime(new Date("2026-08-24T12:00:00Z"));
    const initial = await apiMock.certificateHealth();
    apiMock.certificateHealth
      .mockClear()
      .mockResolvedValueOnce({ ...initial, summary: { ...initial.summary, total: 100, expired: 0 } })
      .mockImplementation(async () => ({ ...initial, generated_at: new Date().toISOString(), summary: { ...initial.summary, total: 100, expired: 38 } }));
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "brief", subject: "CN=brief.test", status: "active", fingerprint: "brief-fp", not_after: "2026-08-24T12:00:00.500Z" }],
      next_cursor: "more-pages",
    });
    await act(async () => {
      renderPage();
      await vi.advanceTimersByTimeAsync(25);
    });
    const cockpit = screen.getByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(cockpit.querySelector('[data-metric="expired"]')).toHaveTextContent("0");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100);
    });
    expect(within(cockpit).getByText("Already expired")).toBeInTheDocument();
    expect(apiMock.certificateHealth).toHaveBeenCalledTimes(2);
    // React commits the clock effect at the end of act; deliver the query
    // notification scheduled by that effect in a separate timer turn.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(25);
    });
    expect(cockpit.querySelector('[data-metric="expired"]')).toHaveTextContent("38");
    expect(apiMock.certificateHealth).toHaveBeenCalledTimes(2);
    expect(apiMock.owners).toHaveBeenCalledTimes(1);
    expect(apiMock.notificationChannels).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000);
    });
    expect(apiMock.certificateHealth).toHaveBeenCalledTimes(3);
    expect(apiMock.certificatePage).toHaveBeenCalledTimes(1);
  });

  it("makes failed expiry refresh unavailable instead of presenting a stale safe zero", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    const initial = await apiMock.certificateHealth();
    apiMock.certificateHealth
      .mockClear()
      .mockResolvedValueOnce({ ...initial, summary: { ...initial.summary, expired: 0 } })
      .mockRejectedValue(new Error("dependency unavailable"));
    await act(async () => {
      renderPage();
      await vi.advanceTimersByTimeAsync(25);
    });
    const cockpit = screen.getByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(cockpit.querySelector('[data-metric="expired"]')).toHaveTextContent("0");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(32_000);
    });
    expect(within(cockpit).getByText(/Expiry totals are unavailable/)).toBeInTheDocument();
    expect(cockpit.querySelector('[data-metric="expired"]')).not.toHaveTextContent(/^0$/);
    expect(screen.getByRole("table", { name: "Inventoried certificates" })).toBeInTheDocument();
  });

  it("counts the complete owner-gap population while keeping the visible work queue bounded", async () => {
    const certificates = Array.from({ length: 12 }, (_, index) => ({
      id: `cert-unowned-${index}`,
      tenant_id: "tenant-1",
      subject: `CN=service-${index}.prod.example`,
      issuer: "CN=Production CA",
      status: "active",
      fingerprint: `fp-unowned-${index}`,
      not_after: "2026-08-30T12:00:00Z",
      deployment_location: "production",
    }));
    apiMock.certificatePage.mockResolvedValue({ items: certificates });
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      inventory_path: "/api/v1/certificates",
      expiring_path: "/api/v1/certificates?expiring_before=2026-09-23T12:00:00Z",
      expiry_buckets: [],
      source_breakdown: [],
      expiring: [],
      summary: {
        total: 12,
        active: 12,
        expired: 0,
        expiring_7d: 12,
        expiring_30d: 12,
        expiring_90d: 12,
        revoked: 0,
        superseded: 0,
        external_source_count: 0,
        imported_count: 0,
        discovered_count: 0,
        unknown_expiry_count: 0,
        health: "critical",
      },
    });

    renderPage();
    const cockpit = await screen.findByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(within(cockpit).getByText(/12 certificates need action/i)).toBeInTheDocument();
    expect(within(cockpit).getByText("12", { selector: "[data-metric='owner-gaps']" })).toBeInTheDocument();
    expect(within(within(cockpit).getByRole("table", { name: "Certificate action queue" })).getAllByRole("row")).toHaveLength(11);
  });

  it("labels owner coverage as not checked when its tenant evidence API is unavailable", async () => {
    apiMock.owners.mockRejectedValue(new Error("owner projection unavailable"));
    renderPage();
    const cockpit = await screen.findByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(within(cockpit).getByText("Not checked", { selector: "[data-metric='owner-gaps']" })).toBeInTheDocument();
  });
  it("keeps a superseded discovery baseline out of the work queue and the arrival bins (DP2-030)", async () => {
    vi.setSystemTime(new Date("2026-08-24T12:00:00Z"));
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-baseline",
          tenant_id: "tenant-1",
          subject: "CN=superseded.partner-lab.example",
          issuer: "CN=Old Vendor CA",
          // The listener now verifiably serves its managed certificate; this observed
          // baseline is retired, so its missing owner and its expiry tomorrow are not work.
          status: "superseded",
          fingerprint: "fp-baseline",
          not_after: "2026-08-25T12:00:00Z",
          deployment_location: "127.0.0.1:10443",
          attributes: {},
        },
      ],
    });
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      inventory_path: "/api/v1/certificates",
      expiring_path: "/api/v1/certificates?expiring_before=2026-09-23T12:00:00Z",
      expiry_buckets: [],
      source_breakdown: [],
      expiring: [],
      summary: {
        total: 1,
        active: 0,
        expired: 0,
        expiring_7d: 0,
        expiring_30d: 0,
        expiring_90d: 0,
        revoked: 0,
        superseded: 1,
        external_source_count: 1,
        imported_count: 0,
        discovered_count: 1,
        unknown_expiry_count: 0,
        health: "ok",
      },
    });
    renderPage();
    const cockpit = await screen.findByRole("region", { name: "Certificate Lifecycle cockpit" });
    const arrival = within(cockpit).getByRole("table", { name: "Certificate work arrival data" });
    expect(within(arrival).getByRole("row", { name: /^0–14 days/ })).toHaveTextContent(/0–14 days\s*0$/);
    expect(within(cockpit).queryByText(/superseded\.partner-lab\.example/)).toBeNull();
  });
  it("counts a certificate in its 30th day once: within 30 days and in the 15–29 bin, never under 30–44 (DP2-012)", async () => {
    vi.setSystemTime(new Date("2026-08-24T12:00:00Z"));
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-day30",
          tenant_id: "tenant-1",
          subject: "CN=edge.partner-lab.example",
          issuer: "CN=Issuing CA",
          status: "active",
          fingerprint: "fp-day30",
          // 29 days 23 hours out: within 30 days by the served half-open rule, and
          // "30 days" once rounded up for display. It must be counted exactly once.
          not_after: "2026-09-23T11:00:00Z",
          owner_id: "team-platform",
          deployment_location: "127.0.0.1:10443",
          attributes: { team_id: "team-platform" },
        },
      ],
    });
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      inventory_path: "/api/v1/certificates",
      expiring_path: "/api/v1/certificates?expiring_before=2026-09-23T12:00:00Z",
      expiry_buckets: [],
      source_breakdown: [],
      expiring: [],
      summary: {
        total: 1,
        active: 1,
        expired: 0,
        expiring_7d: 0,
        expiring_30d: 1,
        expiring_90d: 1,
        revoked: 0,
        superseded: 0,
        external_source_count: 0,
        imported_count: 0,
        discovered_count: 0,
        unknown_expiry_count: 0,
        health: "critical",
      },
    });
    renderPage();
    const cockpit = await screen.findByRole("region", { name: "Certificate Lifecycle cockpit" });
    expect(within(cockpit).getByText("1", { selector: "[data-metric='expiring-30d']" })).toBeInTheDocument();
    const arrival = within(cockpit).getByRole("table", { name: "Certificate work arrival data" });
    expect(within(arrival).getByRole("row", { name: /^15–29 days/ })).toHaveTextContent(/15–29 days\s*1$/);
    expect(within(arrival).getByRole("row", { name: /^30–44 days/ })).toHaveTextContent(/30–44 days\s*0$/);
  });
});
