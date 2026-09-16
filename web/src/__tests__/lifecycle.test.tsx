import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities, graphNodeIdForIdentity } from "@/pages/Identities";
// The real ApiError class (the vi.mock below spreads the real module and only
// replaces `api`), used to simulate a 429 with a Retry-After hint (SURFACE-007).
import { ApiError } from "@/lib/api";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    issuers: vi.fn(),
    owners: vi.fn(),
    getIdentity: vi.fn(),
    identityDeploymentEvidence: vi.fn(),
    issueCertificate: vi.fn(),
    previewIdentityTransition: vi.fn(),
    transitionIdentity: vi.fn(),
    decommissionNHI: vi.fn(),
    approveIdentityAction: vi.fn(),
    graphBlastRadius: vi.fn(),
    connectorDeliveries: vi.fn(),
    rotationRuns: vi.fn(),
    lifecycleAutomationPlan: vi.fn(),
    bulkRevokeIdentities: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderIdentities(path = "/identities", timeZone = "UTC") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <IntlProvider initialLocale="en-US" initialTimeZone={timeZone}>
        <AppQueryProvider>
          <Identities />
        </AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>,
  );
}

async function openIdentityDetails(user: ReturnType<typeof userEvent.setup>, name: string) {
  const row = (await screen.findByText(name)).closest("tr")!;
  await user.click(within(row).getByRole("button", { name: /view details/i }));
  return screen.findByRole("dialog", { name: "Identity detail" });
}

function transitionPlanFor(id: string, to: string) {
  const fromByTarget: Record<string, string> = {
    issued: "requested",
    deployed: "issued",
    renewing: "deployed",
    revoked: "deployed",
    retired: "revoked",
  };
  const destinationByTarget: Record<string, string> = {
    issued: "ca.issue",
    deployed: "connector.deploy",
    renewing: "ca.renew",
    revoked: "revocation.publish",
  };
  const from = fromByTarget[to] ?? "requested";
  const destination = destinationByTarget[to];
  return {
    capability: "nhi_lifecycle_transition",
    ready: true,
    identity_id: id,
    identity_name: id,
    identity_kind: "x509_certificate",
    owner_id: "own-1",
    owner_name: "team",
    from,
    to,
    expected_version: 2,
    event_type: `identity.${to}`,
    side_effect: Boolean(destination),
    side_effect_destination: destination,
    request_fingerprint: `sha256:${id}:${to}`,
    required_permission: "identities:write",
    prerequisites: [`The identity is still ${from}.`, "An accountable owner is assigned.", "The operator can write identities."],
    preview_writes: [],
    preview_external_effects: [],
    execution_writes: [`Append identity.${to}.`, `Project the identity to ${to}.`],
    execution_external_effects: destination ? [`Queue one ${destination} intent through the outbox.`] : [],
    verification_steps: [`Read the identity and confirm ${to}.`, "Follow the durable receipt."],
    warnings: [],
    guidance: "This preview performed no write and contacted no external system.",
  };
}

async function confirmReviewedAction(user: ReturnType<typeof userEvent.setup>) {
  const review = await screen.findByRole("dialog", { name: /^Review /i });
  expect(await within(review).findByText("No changes made by preview")).toBeInTheDocument();
  await user.click(within(review).getByRole("button", { name: "Run reviewed action" }));
}

describe("lifecycle actions from the UI", () => {
  it("keeps identity validity and rotation history in the operator's selected time zone", async () => {
    const identity = {
      id: "timezone-identity",
      name: "timezone.example.test",
      kind: "x509_certificate",
      status: "deployed",
      not_before: "2030-01-01T00:30:00Z",
      not_after: "2030-01-02T00:30:00Z",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.rotationRuns.mockResolvedValue({
      items: [{ id: "zone-run", identity_id: identity.id, status: "succeeded", trigger: "scheduler", completed_at: "2030-01-01T00:35:00Z" }],
    });
    const user = userEvent.setup();
    renderIdentities("/identities", "America/New_York");
    const row = (await screen.findByText(identity.name, { selector: "span" })).closest("tr")!;
    await user.click(screen.getByText("Delivery and rotation evidence", { selector: "summary" }));
    const history = await screen.findByRole("table", { name: "Loaded lifecycle rotation runs" });
    expect(await within(history).findByText(/Dec 31, 2029,\s7:35\sPM/)).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: /view details/i }));
    const detail = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(detail).getByText(/Dec 31, 2029,\s7:30\sPM/)).toBeInTheDocument();
    expect(within(detail).getByText(/Jan 1, 2030,\s7:30\sPM/)).toBeInTheDocument();
  });
  it.each([
    ["revoked", "Revoked; evidence is retained.", "running"],
    ["retired", "Retired; no further action is available.", "running"],
    ["revoked", "Revoked; evidence is retained.", "cancelled"],
    ["retired", "Retired; no further action is available.", "cancelled"],
  ])("keeps a %s identity terminal with summary %s and %s rotation evidence", async (status, summary, runStatus) => {
    apiMock.identities.mockResolvedValue([{ id: "stopped-mail", name: "stopped-mail.example.test", kind: "x509_certificate", status }]);
    apiMock.rotationRuns.mockResolvedValue({
      items: [{ id: "unfinished-renewal", identity_id: "stopped-mail", status: runStatus, trigger: "scheduler", updated_at: "2026-09-12T23:14:00Z" }],
    });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [{ id: "prior-delivery", identity_id: "stopped-mail", status: "verified", updated_at: "2026-09-12T23:11:00Z" }],
    });
    renderIdentities();
    const row = (await screen.findByText("stopped-mail.example.test", { selector: "span" })).closest("tr")!;
    await userEvent.setup().click(screen.getByText("Delivery and rotation evidence", { selector: "summary" }));
    const history = await screen.findByRole("table", { name: "Loaded lifecycle rotation runs" });
    expect(await within(history).findByText("scheduler")).toBeInTheDocument();
    if (runStatus === "cancelled") {
      const badge = await within(history).findByText("Cancelled");
      expect(badge).toHaveAttribute("data-status-value", "cancelled");
      expect(badge.querySelector("[data-status-dot]")).toHaveAttribute("data-status-dot", "neutral");
    }
    await waitFor(() => expect(row).toHaveTextContent(summary));
    expect(row).not.toHaveTextContent("Rotation is in progress.");
    expect(row).not.toHaveTextContent("Delivered successfully.");
  });

  it.each([
    ["verified", "Delivered successfully."],
    ["verify_failed", "Delivery needs attention."],
  ])("uses the latest %s probe receipt in the identity row", async (status, summary) => {
    apiMock.identities.mockResolvedValue([{ id: "mail-1", name: "mail.example.test", kind: "x509_certificate", status: "deployed" }]);
    const receipt = { identity_id: "mail-1", connector: "postfix", target: "mail", attempts: 1 };
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        { ...receipt, id: "probe", status, updated_at: "2026-09-12T23:11:26.399Z" },
        { ...receipt, id: "deploy", status: "delivered", updated_at: "2026-09-12T23:11:26.384Z" },
      ],
    });
    renderIdentities();
    const row = (await screen.findByText("mail.example.test")).closest("tr")!;
    await waitFor(() => expect(row).toHaveTextContent(summary));
    expect(row).not.toHaveTextContent("Waiting for delivery.");
  });

  it.each([
    ["external", "External CA"],
    ["private", "Private CA"],
    ["platform", "trstctl platform CA"],
  ])("shows the selected %s CA without treating it as historical issuance proof", async (source, label) => {
    const identity = {
      id: "endpoint-ca",
      name: "endpoint.example",
      kind: "x509_certificate",
      owner_id: "own-1",
      status: "deployed",
      issuer_id: null,
      attributes: { issuing_authority_source: source, issuing_authority_id: "ca-exact", issuing_authority_name: "Selected authority" },
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    renderIdentities("/identities?identity=endpoint-ca");
    const drawer = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(await within(drawer).findByText(`${label}: Selected authority`)).toBeInTheDocument();
    expect(within(drawer).getByText("Selected issuance CA")).toBeInTheDocument();
    expect(within(drawer).getByText(/Check each certificate's issuance evidence/)).toBeInTheDocument();
    expect(within(drawer).queryByText("No issuer bound")).not.toBeInTheDocument();
  });

  it.each([
    { issuing_authority_source: "external", issuing_authority_name: "Incomplete" },
    { issuing_authority_source: "unknown", issuing_authority_id: "not-a-default" },
  ])("does not infer a CA from an incomplete selection %j", async (attributes) => {
    const identity = { id: "endpoint-ca", name: "endpoint.example", kind: "x509_certificate", owner_id: "own-1", status: "deployed", attributes };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    renderIdentities("/identities?identity=endpoint-ca");
    const drawer = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(await within(drawer).findByText("CA selection is incomplete or unsupported")).toBeInTheDocument();
    expect(within(drawer).queryByText("No issuer bound")).not.toBeInTheDocument();
  });

  it("explains that retirement preserves history and does not revoke a certificate", async () => {
    const identity = { id: "retire-exact", name: "retirement.example", kind: "x509_certificate", owner_id: "own-1", status: "revoked" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities("/identities?identity=retire-exact");
    const drawer = await screen.findByRole("dialog", { name: "Identity detail" });
    await user.click(await within(drawer).findByRole("button", { name: "Retire" }));
    await screen.findByText(/retains its record and audit history/);
    const review = screen.getByRole("alertdialog", { name: /^Review Retire for retirement.example$/ });
    expect(within(review).getByText(/retains its record and audit history/)).toBeInTheDocument();
    expect(within(review).getByText(/Retirement does not revoke a certificate/)).toBeInTheDocument();
    expect(within(review).queryByText(/discards the credential record/)).not.toBeInTheDocument();
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
  });

  it("opens and closes the exact identity named by a certificate lifecycle link", async () => {
    const identity = { id: "linked-identity", name: "same.example", kind: "x509_certificate", owner_id: "own-1", status: "issued" };
    apiMock.identities.mockResolvedValue([{ ...identity, id: "same-name-other", status: "deployed" }, identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    renderIdentities("/identities?identity=linked-identity");
    const drawer = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(await within(drawer).findByText("linked-identity")).toBeInTheDocument();
    expect(apiMock.getIdentity).toHaveBeenCalledWith("linked-identity");
    expect(within(drawer).getByRole("button", { name: "Deploy" })).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: "Renew" })).not.toBeInTheDocument();
    await userEvent.setup().click(within(drawer).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog", { name: "Identity detail" })).not.toBeInTheDocument();
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
  });
  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
  });

  it.each(["pending", "refused"])("does not turn a %s global stream into absent receipts", async (state) => {
    apiMock.connectorDeliveries.mockResolvedValue({ items: [], next_cursor: "" });
    apiMock.rotationRuns.mockImplementation(() =>
      state === "pending" ? new Promise(() => {}) : Promise.reject(new ApiError(403, JSON.stringify({ detail: "rotation read refused" }))),
    );
    const user = userEvent.setup();
    renderIdentities();
    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    await waitFor(() => expect(apiMock.connectorDeliveries).toHaveBeenCalled());
    expect(screen.queryByText("No delivery or rotation receipts yet")).not.toBeInTheDocument();
    expect(screen.queryByText("No rotation runs")).not.toBeInTheDocument();
    if (state === "refused") {
      expect((await screen.findAllByText(/rotation read refused/)).length).toBeGreaterThan(0);
      expect(screen.queryByText("No delivery or rotation receipts yet")).not.toBeInTheDocument();
    }
  });

  it("reads selected-identity history beyond a partial tenant page", async () => {
    const identity = { id: "dep-1", name: "scoped-history", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.rotationRuns.mockImplementation(async (options) =>
      options?.identityId
        ? {
            items: [
              {
                id: "scoped-run",
                identity_id: identity.id,
                status: "succeeded",
                trigger: "manual",
                successor_fingerprint: "actual-scoped-successor",
                updated_at: "2026-09-10T17:26:45Z",
              },
            ],
            next_cursor: "",
          }
        : { items: [], next_cursor: "tenant-next" },
    );
    apiMock.connectorDeliveries.mockImplementation(async (options) =>
      options?.identityId ? { items: [], next_cursor: "" } : { items: [], next_cursor: "tenant-next" },
    );
    const user = userEvent.setup();
    renderIdentities();
    const drawer = await openIdentityDetails(user, identity.name);
    expect(await within(drawer).findByText(/succeeded via manual; successor actual-scope/)).toBeInTheDocument();
    expect(within(drawer).queryByText("no lifecycle rotation run yet")).not.toBeInTheDocument();
    expect(apiMock.rotationRuns).toHaveBeenCalledWith(expect.objectContaining({ identityId: identity.id, limit: 50 }));
    const row = screen
      .getAllByText(identity.name)
      .find((e) => e.closest("tr"))!
      .closest("tr")!;
    expect(row).toHaveTextContent("History is partial. Open details.");
  });

  it("keeps scoped history partial until the operator loads the remaining page", async () => {
    const identity = { id: "dep-1", name: "paged-history", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.rotationRuns.mockImplementation(async (options) => {
      if (!options?.identityId) return { items: [], next_cursor: "tenant-next" };
      return options.cursor
        ? {
            items: [
              {
                id: "last-id",
                identity_id: identity.id,
                status: "succeeded",
                trigger: "manual",
                successor_fingerprint: "newer-scoped-successor",
                updated_at: "2026-09-10T17:26:45Z",
              },
            ],
            next_cursor: "",
          }
        : {
            items: [{ id: "first-id", identity_id: identity.id, status: "failed", trigger: "manual", updated_at: "2026-09-09T17:26:45Z" }],
            next_cursor: "scoped-next",
          };
    });
    const user = userEvent.setup();
    renderIdentities();
    const drawer = await openIdentityDetails(user, identity.name);
    const more = await within(drawer).findByRole("button", { name: "Load more rotation records" });
    expect(within(drawer).queryByText("no lifecycle rotation run yet")).not.toBeInTheDocument();
    expect(within(drawer).queryByText(/failed via manual/)).not.toBeInTheDocument();
    expect(apiMock.rotationRuns.mock.calls.some(([options]) => options?.cursor === "scoped-next")).toBe(false);
    await user.click(more);
    expect(await within(drawer).findByText(/succeeded via manual; successor newer-scoped/)).toBeInTheDocument();
    expect(apiMock.rotationRuns).toHaveBeenCalledWith({ identityId: identity.id, limit: 50, cursor: "scoped-next" });
  });

  it("does not describe a refused scoped receipt read as no history", async () => {
    const identity = { id: "dep-1", name: "unavailable-history", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.rotationRuns.mockImplementation(async (options) => {
      if (options?.identityId) throw new ApiError(403, JSON.stringify({ detail: "receipt access refused" }));
      return { items: [], next_cursor: "" };
    });
    const user = userEvent.setup();
    renderIdentities();
    const drawer = await openIdentityDetails(user, identity.name);
    expect(await within(drawer).findByText(/receipt access refused/)).toBeInTheDocument();
    expect(within(drawer).queryByText("no lifecycle rotation run yet")).not.toBeInTheDocument();
    expect(within(drawer).queryByText("no rollback reference recorded yet")).not.toBeInTheDocument();
  });

  it.each(["succeeded", "failed"])("refreshes an asynchronously %s renewal without reloading the page", async (outcome) => {
    const identity = { id: "dep-1", name: "live-renewal", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    let current = identity;
    apiMock.identities.mockImplementation(async () => [current]);
    apiMock.getIdentity.mockImplementation(async () => current);
    apiMock.transitionIdentity.mockImplementation(async () => {
      current = { ...identity, status: "renewing" };
      return current;
    });
    const user = userEvent.setup();
    renderIdentities();
    const drawer = await openIdentityDetails(user, identity.name);
    await user.click(within(drawer).getByRole("button", { name: /^renew$/i }));
    await confirmReviewedAction(user);
    await screen.findByText(/Request accepted for live-renewal: renewing/i);
    expect(within(drawer).queryByRole("button", { name: /^renew$/i })).not.toBeInTheDocument();

    vi.useFakeTimers();
    current = { ...identity, status: outcome === "succeeded" ? "deployed" : "renewal_failed" };
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "completed-live-renewal",
          identity_id: identity.id,
          status: outcome,
          trigger: "manual",
          successor_fingerprint: outcome === "succeeded" ? "actual-test-successor" : "",
          error: outcome === "failed" ? "signer refused" : "",
          created_at: "2026-09-10T15:28:24Z",
          completed_at: "2026-09-10T15:28:26Z",
        },
      ],
    });
    // This is a source-only asynchronous API fixture. Product runtime evidence
    // is the retained campaign observation, not these fixture values.
    const initialReads = apiMock.identities.mock.calls.length;
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(apiMock.identities).toHaveBeenCalledTimes(initialReads);
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(50);
    });
    expect(apiMock.identities.mock.calls.length).toBeGreaterThan(initialReads);
    const row = screen
      .getAllByText(identity.name)
      .find((e) => e.closest("tr"))!
      .closest("tr")!;
    expect(within(row).getByText(outcome === "succeeded" ? "deployed" : "Renewal Failed")).toBeInTheDocument();
    expect(within(drawer).getByText(new RegExp(`${outcome} via manual; successor`))).toBeInTheDocument();
    // Both successful completion and the served renewal_failed retry edge allow renewal.
    expect(within(drawer).getByRole("button", { name: /^renew$/i })).toBeEnabled();
    const visibleReads = apiMock.identities.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_050);
    });
    expect(apiMock.identities.mock.calls.length).toBeGreaterThan(visibleReads);
    expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(1);
  });

  it("discards inventory and drawer reads started before an accepted renewal", async () => {
    const before = { id: "dep-1", name: "late-read-renewal", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    let current = before;
    let holdInventory = false;
    let holdDetail = false;
    let finishInventory!: (value: (typeof before)[]) => void;
    let finishDetail!: (value: typeof before) => void;
    apiMock.identities.mockImplementation(() => {
      if (!holdInventory) return Promise.resolve([current]);
      holdInventory = false;
      return new Promise<(typeof before)[]>((resolve) => {
        finishInventory = resolve;
      });
    });
    apiMock.getIdentity.mockImplementation(() => {
      if (!holdDetail) return Promise.resolve(current);
      holdDetail = false;
      return new Promise<typeof before>((resolve) => {
        finishDetail = resolve;
      });
    });
    apiMock.transitionIdentity.mockImplementation(async () => {
      current = { ...before, status: "renewing" };
      return current;
    });
    const user = userEvent.setup();
    renderIdentities();
    const drawer = await openIdentityDetails(user, before.name);
    await within(drawer).findByRole("button", { name: /^renew$/i });
    holdInventory = true;
    holdDetail = true;
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await waitFor(() => expect(finishInventory).toBeTypeOf("function"));
    await waitFor(() => expect(finishDetail).toBeTypeOf("function"));
    await user.click(within(drawer).getByRole("button", { name: /^renew$/i }));
    await confirmReviewedAction(user);
    await screen.findByText(/Request accepted for late-read-renewal: renewing/i);
    await act(async () => {
      finishInventory([before]);
      finishDetail(before);
    });
    const row = screen
      .getAllByText(before.name)
      .find((e) => e.closest("tr"))!
      .closest("tr")!;
    expect(within(row).getByText("renewing")).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: /^renew$/i })).not.toBeInTheDocument();
    expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(1);
  });

  it("keeps the selected identity when a previous drawer response arrives late", async () => {
    const a = { id: "dep-a", name: "slow-drawer-a", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    const b = { ...a, id: "dep-b", name: "current-drawer-b", status: "revoked" };
    let finishA!: (value: typeof a) => void;
    apiMock.identities.mockResolvedValue([a, b]);
    apiMock.getIdentity.mockImplementation((id) =>
      id === a.id
        ? new Promise<typeof a>((resolve) => {
            finishA = resolve;
          })
        : Promise.resolve(b),
    );
    const user = userEvent.setup();
    renderIdentities();
    const first = await openIdentityDetails(user, a.name);
    await waitFor(() => expect(finishA).toBeTypeOf("function"));
    await user.click(within(first).getByRole("button", { name: "Close" }));
    const second = await openIdentityDetails(user, b.name);
    await within(second).findByRole("button", { name: /^retire$/i });
    await act(async () => {
      finishA(a);
    });
    expect(within(second).getByText(b.name)).toBeInTheDocument();
    expect(within(second).queryByText(a.name)).not.toBeInTheDocument();
    expect(within(second).getByRole("button", { name: /^retire$/i })).toBeEnabled();
    expect(within(second).queryByRole("button", { name: /^renew$/i })).not.toBeInTheDocument();
  });

  beforeEach(() => {
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", kind: "x509_ca", name: "LE" }]);
    apiMock.owners.mockReset().mockResolvedValue([
      {
        id: "own-1",
        kind: "workload",
        name: "team",
        application_id: "APP-TEAM",
        environment: "production",
        ownership_complete: true,
        ownership_attested: true,
        ownership_current: true,
      },
    ]);
    // Fixtures use `status` — the field the SERVED Identity contract (OpenAPI) carries
    // and that identityState() reads (SURFACE-005: the FE no longer guesses `state`).
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "new-1", name: "svc", status: "issued" });
    apiMock.getIdentity.mockReset();
    apiMock.previewIdentityTransition.mockReset().mockImplementation(async (id: string, to: string) => transitionPlanFor(id, to));
    apiMock.transitionIdentity.mockReset().mockImplementation(async (id: string, to: string) => ({ id, name: id, status: to }));
    apiMock.decommissionNHI.mockReset().mockResolvedValue({
      capability: "CAP-GOV-04",
      coverage: ["departure", "vendor_term", "inactivity", "revoke", "retire"],
      reason: "departure decommission via UI",
      summary: { total_matched: 1, revoked: 1, retired: 0, skipped: 0, failed: 0 },
      items: [
        {
          identity_id: "dep-1",
          name: "payments-api",
          kind: "api_key",
          owner_id: "own-1",
          signal_type: "departure",
          action: "revoked",
          from: "deployed",
          to: "revoked",
        },
      ],
    });
    apiMock.approveIdentityAction.mockReset().mockResolvedValue({ resource: "req-1", action: "issue", approver: "ra", approvals: 1 });
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: "cert:demo", kind: "credential", name: "demo" },
      affected: [],
      by_kind: {},
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({ items: [] });
    apiMock.identityDeploymentEvidence.mockReset().mockImplementation(async (identity_id) => ({ identity_id, read_at: "2030-01-01T00:00:00Z" }));
    apiMock.rotationRuns.mockReset().mockResolvedValue({ items: [] });
    apiMock.lifecycleAutomationPlan.mockReset().mockResolvedValue({
      capability: "lifecycle_automation",
      ready: true,
      generated_at: "2026-06-20T00:00:00Z",
      scheduler: {
        status: "running",
        renew_before: "720h0m0s",
        alert_before: "168h0m0s",
        interval: "1m0s",
        ari_first: true,
        maintenance_window_status: "open",
      },
      summary: {
        monitored: 0,
        due_now: 0,
        renewal_failed: 0,
        outbox_pending: 0,
        outbox_processing: 0,
        outbox_failed: 0,
      },
      items: [],
      controls: [
        { action: "start", state: "available", detail: "Review and queue one due renewal." },
        { action: "pause", state: "configuration_only", detail: "Maintenance windows pause new starts." },
        { action: "resume", state: "automatic", detail: "New starts resume when the window opens." },
        { action: "retry", state: "conditional", detail: "A failed renewal can be reviewed as a new attempt." },
        { action: "cancel", state: "unavailable_after_enqueue", detail: "Queued work may already be leased." },
        { action: "rollback", state: "conditional", detail: "Use predecessor evidence after delivery." },
      ],
      preview_writes: [],
      preview_external_effects: [],
      execution_writes: ["Append one lifecycle transition event.", "Queue ca.renew through the outbox."],
      execution_external_effects: ["The signer issues a successor and the connector deploys it."],
      verification_steps: ["Confirm the rotation run and connector delivery receipts."],
    });
    apiMock.identities.mockReset();
  });

  it("keeps each identity row to one review action and moves lifecycle choices into detail", async () => {
    const identity = { id: "dep-quiet", name: "quiet-row", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("quiet-row")).closest("tr")!;
    expect(within(row).getAllByRole("button")).toHaveLength(1);
    expect(within(row).getByRole("button", { name: "View details" })).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Renew" })).not.toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: "View details" }));
    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(dialog).getByRole("button", { name: "Renew" })).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("maps served identity data to graph node IDs conservatively", () => {
    expect(
      graphNodeIdForIdentity({
        id: "dep-1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBe("id:dep-1");
    expect(
      graphNodeIdForIdentity({
        id: "dep-2",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
        attributes: { graph_node_id: "credential:dep-2" },
      }),
    ).toBe("credential:dep-2");
    expect(
      graphNodeIdForIdentity({
        id: "api-1",
        name: "api-key",
        kind: "api_key",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBeNull();
  });

  it("offers the state-appropriate action and calls the transition endpoint", async () => {
    const identities = [
      { id: "req-1", name: "requested-svc", status: "requested" },
      { id: "iss-1", name: "issued-svc", status: "issued" },
      { id: "dep-1", name: "deployed-svc", status: "deployed" },
    ];
    apiMock.identities.mockResolvedValue(identities);
    apiMock.getIdentity.mockImplementation(async (id: string) => identities.find((identity) => identity.id === id)!);
    const user = userEvent.setup();
    renderIdentities();

    // A requested identity can be issued.
    let dialog = await openIdentityDetails(user, "requested-svc");
    await user.click(within(dialog).getByRole("button", { name: /^issue$/i }));
    await confirmReviewedAction(user);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything(), undefined, expect.any(String), 2));
    await user.click(within(dialog).getByRole("button", { name: "Close" }));

    // An issued identity can be deployed or revoked.
    dialog = await openIdentityDetails(user, "issued-svc");
    await user.click(within(dialog).getByRole("button", { name: /^deploy$/i }));
    await confirmReviewedAction(user);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("iss-1", "deployed", expect.anything(), undefined, expect.any(String), 2));
    await user.click(within(dialog).getByRole("button", { name: "Close" }));

    // A deployed identity can be renewed.
    dialog = await openIdentityDetails(user, "deployed-svc");
    await user.click(within(dialog).getByRole("button", { name: /^renew$/i }));
    await confirmReviewedAction(user);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "renewing", expect.anything(), undefined, expect.any(String), 2));
  });

  it("reviews an exact server-owned lifecycle plan before execution and verifies the returned state", async () => {
    const identity = { id: "dep-1", name: "deployed-svc", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.transitionIdentity.mockResolvedValue({ ...identity, status: "renewing" });
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "deployed-svc");
    await user.type(within(detail).getByLabelText("Transition reason"), "rotate before maintenance");
    await user.click(within(detail).getByRole("button", { name: /^renew$/i }));

    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    await waitFor(() => expect(apiMock.previewIdentityTransition).toHaveBeenCalledWith("dep-1", "renewing", "rotate before maintenance"));
    const review = await screen.findByRole("dialog", { name: /Review Renew for deployed-svc/i });
    expect(within(review).getByText("No changes made by preview")).toBeInTheDocument();
    expect(within(review).getByText(/deployed → renewing/)).toBeInTheDocument();
    expect(within(review).getAllByText(/ca.renew/).length).toBeGreaterThan(0);
    expect(within(review).getByText(/Append identity.renewing/)).toBeInTheDocument();
    expect(within(review).getByText(/Read the identity and confirm renewing/)).toBeInTheDocument();

    await user.click(within(review).getByRole("button", { name: "Run reviewed action" }));
    await waitFor(() =>
      expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "renewing", "rotate before maintenance", undefined, expect.any(String), 2),
    );
    expect(await screen.findByText(/Request accepted for deployed-svc: renewing/i)).toBeInTheDocument();
  });

  it("renders identities on the shared DataGrid with lifecycle badges and all six kind filters", async () => {
    const fixtures = [
      { id: "x509-1", name: "tls-api", kind: "x509_certificate", owner_id: "owner-x", status: "issued" },
      { id: "ssh-cert-1", name: "ssh-user", kind: "ssh_certificate", owner_id: "owner-sshc", status: "requested" },
      { id: "ssh-key-1", name: "deploy-key", kind: "ssh_key", owner_id: "owner-ssh", status: "deployed" },
      { id: "secret-1", name: "db-password", kind: "secret", owner_id: "owner-sec", status: "revoked" },
      { id: "api-key-1", name: "stripe-token", kind: "api_key", owner_id: "owner-api", status: "retired" },
      { id: "workload-1", name: "payments-worker", kind: "workload_identity", owner_id: "owner-work", status: "renewing" },
    ];
    apiMock.identities.mockResolvedValue(fixtures);
    const user = userEvent.setup();
    renderIdentities();

    const table = await screen.findByRole("table", { name: /credential identities/i });
    expect(table).toBeInTheDocument();
    expect(within(table).getAllByRole("columnheader")).toHaveLength(6);
    expect(within(table).queryByRole("columnheader", { name: "Credential type" })).not.toBeInTheDocument();
    expect(screen.getByText("issued")).toHaveAttribute("data-status-badge", "lifecycle");
    expect(screen.getAllByText("Owner record unavailable").length).toBeGreaterThan(0);

    for (const identity of fixtures) {
      await user.selectOptions(screen.getByLabelText("Credential type"), identity.kind);
      expect(await screen.findByText(identity.name)).toBeInTheDocument();
      for (const other of fixtures.filter((fixture) => fixture.id !== identity.id)) {
        expect(screen.queryByText(other.name)).not.toBeInTheDocument();
      }
    }

    await user.selectOptions(screen.getByLabelText("Credential type"), "all");
    expect(await screen.findByText("tls-api")).toBeInTheDocument();
    expect(screen.getByText("payments-worker")).toBeInTheDocument();
  });

  it("makes the identity journey search-first and translates owner, kind, and delivery internals into operator language", async () => {
    apiMock.owners.mockResolvedValue([
      {
        id: "owner-payments",
        tenant_id: "tenant-1",
        kind: "team",
        name: "Payments API",
        environment: "production",
        escalation_chain: [],
        ownership_attested: true,
        ownership_complete: true,
        ownership_current: true,
      },
    ]);
    apiMock.identities.mockResolvedValue([
      { id: "payments-1", name: "payments-api", kind: "x509_certificate", owner_id: "owner-payments", status: "deployed" },
      { id: "deploy-1", name: "release-deploy", kind: "ssh_key", owner_id: "owner-missing", status: "deployed" },
    ]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-1",
          identity_id: "payments-1",
          connector: "api-token",
          target: "github-actions/release",
          status: "failed",
          reason: "plugin_surface_unconfigured",
          fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          created_at: "2026-08-20T00:00:00Z",
          updated_at: "2026-08-20T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();

    renderIdentities();

    expect(await screen.findByRole("heading", { name: "Machine identities" })).toBeInTheDocument();
    expect(screen.getByText("Which machines and services have identities, and whether they are healthy.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Find identities" })).toHaveAttribute("href", "#identity-search");
    expect(screen.getByRole("button", { name: "Add identity" })).toBeInTheDocument();

    const paymentsRow = (await screen.findByText("payments-api")).closest("tr")!;
    expect(paymentsRow).toHaveTextContent("TLS certificate");
    expect(paymentsRow).toHaveTextContent("Payments API");
    expect(paymentsRow).toHaveTextContent("Production");
    expect(paymentsRow).toHaveTextContent("Not delivered yet — this connector still needs setup.");
    expect(paymentsRow).not.toHaveTextContent("owner-payments");
    expect(paymentsRow).not.toHaveTextContent("plugin_surface_unconfigured");

    await user.type(screen.getByRole("searchbox", { name: "Find identities" }), "release");
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
    const releaseRow = screen.getByText("release-deploy").closest("tr")!;
    expect(within(releaseRow).getByText("SSH key")).toBeInTheDocument();
    expect(within(releaseRow).getByText("Owner record unavailable")).toBeInTheDocument();
  });

  it("loads kind-specific identity details and links owner plus issuer", async () => {
    const details = {
      "x509/1": {
        id: "x509/1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-x",
        issuer_id: "issuer-x",
        status: "issued",
        not_after: "2026-07-01T00:00:00Z",
        attributes: { dns_names: ["api.example.test"] },
      },
      "ssh-key-1": {
        id: "ssh-key-1",
        name: "deploy-key",
        kind: "ssh_key",
        owner_id: "owner-ssh",
        status: "deployed",
        attributes: { fingerprint: "SHA256:abc" },
      },
      "workload-1": {
        id: "workload-1",
        name: "payments-worker",
        kind: "workload_identity",
        owner_id: "owner-workload",
        issuer_id: "issuer-workload",
        status: "requested",
        attributes: { spiffe_id: "spiffe://example.test/payments" },
      },
    };
    apiMock.identities.mockResolvedValue(Object.values(details));
    apiMock.getIdentity.mockImplementation(async (id: keyof typeof details) => details[id]);
    const user = userEvent.setup();
    renderIdentities();

    const x509Row = (await screen.findByText("tls-api")).closest("tr")!;
    await user.click(within(x509Row).getByRole("button", { name: /view details/i }));

    await waitFor(() => expect(apiMock.getIdentity).toHaveBeenCalledWith("x509/1"));
    expect(await screen.findByRole("dialog", { name: "Identity detail" })).toBeInTheDocument();
    expect(await screen.findByText("X.509 certificate identity")).toBeInTheDocument();
    expect(screen.getByText("Not after")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Owner record unavailable" })).toHaveAttribute("href", "/owners?owner=owner-x");
    await user.click(screen.getByText("Show owner ID"));
    expect(screen.getByText("owner-x")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Issuer issuer-x" })).toHaveAttribute("href", "/protocols?issuer=issuer-x");
    expect(screen.getByText(/api.example.test/)).toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const sshRow = screen.getByText("deploy-key").closest("tr")!;
    await user.click(within(sshRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText("SSH key identity")).toBeInTheDocument();
    expect(screen.getByText("No issuer bound")).toBeInTheDocument();
    expect(screen.getByText(/SHA256:abc/)).toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const workloadRow = screen.getByText("payments-worker").closest("tr")!;
    await user.click(within(workloadRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByRole("heading", { name: "Workload identity" })).toBeInTheDocument();
    expect(screen.getByText(/spiffe:\/\/example.test\/payments/)).toBeInTheDocument();
  });

  it("traps focus in the identity detail drawer and returns focus to the opener", async () => {
    const identity = {
      id: "x509/1",
      name: "tls-api",
      kind: "x509_certificate",
      owner_id: "owner-x",
      issuer_id: "issuer-x",
      status: "issued",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("tls-api")).closest("tr")!;
    const opener = within(row).getByRole("button", { name: /view details/i });
    await user.click(opener);

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    const close = within(dialog).getByRole("button", { name: "Close" });
    const lastAction = within(dialog).getByRole("button", { name: "Move to revoked" });

    expect(close).toHaveFocus();

    await user.tab({ shift: true });
    expect(lastAction).toHaveFocus();

    await user.tab();
    expect(close).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Identity detail" })).not.toBeInTheDocument();
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("renders the per-credential activity timeline disclosure in the identity drawer (FE-022)", async () => {
    const identity = {
      id: "dep-1",
      name: "timeline-svc",
      kind: "x509_certificate",
      owner_id: "owner-1",
      status: "deployed",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("timeline-svc")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(dialog).getByText("Credential activity timeline")).toBeInTheDocument();
    expect(within(dialog).getByText(/projected connector and rotation evidence/i)).toBeInTheDocument();
    for (const state of ["Lifecycle accepted", "Connector delivery", "Rotation run", "Rollback evidence"]) {
      expect(within(dialog).getByText(state)).toBeInTheDocument();
    }
    expect(within(dialog).getByText("no connector delivery receipt yet")).toBeInTheDocument();
    expect(within(dialog).getByText("no lifecycle rotation run yet")).toBeInTheDocument();
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 });
  });

  it("disables invalid state-machine targets and sends the captured transition reason", async () => {
    const identity = { id: "req-1", name: "request-state-machine", kind: "x509_certificate", owner_id: "owner-1", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("request-state-machine")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    expect(await screen.findByText("Next valid actions")).toBeInTheDocument();
    await user.click(screen.getByText("Show all lifecycle rules"));
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Move to deployed" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeDisabled();

    await user.type(screen.getByLabelText("Transition reason"), "approved in CAB-1234");
    await user.click(screen.getByRole("button", { name: "Move to issued" }));
    await confirmReviewedAction(user);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", "approved in CAB-1234", undefined, expect.any(String), 2));
  });

  it("shows revoked and retired terminal handling in the state machine", async () => {
    const revoked = { id: "rev-1", name: "revoked-svc", kind: "api_key", owner_id: "owner-r", status: "revoked" };
    const retired = { id: "ret-1", name: "retired-svc", kind: "secret", owner_id: "owner-t", status: "retired" };
    apiMock.identities.mockResolvedValue([revoked, retired]);
    apiMock.getIdentity.mockImplementation(async (id: string) => (id === "rev-1" ? revoked : retired));
    const user = userEvent.setup();
    renderIdentities();

    const revokedRow = (await screen.findByText("revoked-svc")).closest("tr")!;
    await user.click(within(revokedRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Revocation requested.*client enforcement/)).toBeInTheDocument();
    await user.click(screen.getByText("Show all lifecycle rules"));
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeEnabled();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const retiredRow = screen.getByText("retired-svc").closest("tr")!;
    await user.click(within(retiredRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Terminal state: retired identities/i)).toBeInTheDocument();
    await user.click(screen.getByText("Show all lifecycle rules"));
    for (const target of ["issued", "deployed", "renewing", "revoked", "retired"]) {
      expect(screen.getByRole("button", { name: `Move to ${target}` })).toBeDisabled();
    }
  });

  it("revokes an identity only after the user confirms (SURFACE-007)", async () => {
    const identity = { id: "dep-9", name: "to-revoke", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "to-revoke");
    // Clicking Revoke must NOT immediately call the destructive transition — it opens
    // a confirmation dialog that names the credential.
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/queues revocation at the issuing system.*clients enforce it/)).toBeInTheDocument();
    // The dialog names the credential (it appears in both the heading and the body).
    expect(within(dialog).getAllByText(/to-revoke/).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole("heading", { level: 2, name: /review revoke for to-revoke/i })).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /yes, revoke/i })).toBeDisabled();
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();

    await user.tab({ shift: true });
    expect(within(dialog).getByRole("button", { name: /cancel/i })).toHaveFocus();

    await user.tab();
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();

    // Confirming requires the credential name and sends the operator reason.
    await user.type(within(dialog).getByLabelText(/type credential name/i), "to-revoke");
    const reason = within(dialog).getByLabelText(/revocation reason/i);
    await user.selectOptions(reason, "keyCompromise");
    expect(within(dialog).getByRole("button", { name: /yes, revoke/i })).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Review updated action" }));
    await waitFor(() => expect(apiMock.previewIdentityTransition).toHaveBeenLastCalledWith("dep-9", "revoked", "keyCompromise"));
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-9", "revoked", "keyCompromise", undefined, expect.any(String), 2));
  });

  it("keeps the reviewed command across approval refusal and a fresh page mount", async () => {
    const identity = { id: "governed-revoke", name: "governed.example.test", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.transitionIdentity
      .mockRejectedValueOnce(
        new ApiError(
          403,
          JSON.stringify({
            code: "identity_approval_required",
            approval_request_id: "1ca14715-666f-5ed8-bd88-7b262fe543f5",
            approval_status: "pending",
            detail: "awaits two independent approvals",
          }),
        ),
      )
      .mockResolvedValue({ ...identity, status: "revoked" });
    const user = userEvent.setup();
    const firstPage = renderIdentities();
    let detail = await openIdentityDetails(user, identity.name);
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));
    let dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByLabelText(/type credential name/i), identity.name);
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(1));
    expect(apiMock.transitionIdentity.mock.calls[0]?.[4]).toEqual(expect.any(String));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("awaits two independent approvals");
    expect(within(dialog).getByRole("link", { name: "Open approval requests" })).toHaveAttribute("href", "/approvals");
    firstPage.unmount();
    renderIdentities();
    detail = await openIdentityDetails(user, identity.name);
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));
    dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByLabelText(/type credential name/i), identity.name);
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity.mock.calls[1]).toEqual(apiMock.transitionIdentity.mock.calls[0]);
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
  });

  it.each(["denied", "expired", "superseded"])("starts a distinct command only after explicit recovery from %s approval", async (status) => {
    const identity = { id: "closed-command", name: "closed.example.test", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    const requestId = "1ca14715-666f-5ed8-bd88-7b262fe543f5";
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const refusal = new ApiError(
      403,
      JSON.stringify({ code: "identity_approval_required", approval_request_id: requestId, approval_status: status, detail: "approval request is closed" }),
    );
    apiMock.transitionIdentity
      .mockRejectedValueOnce(refusal)
      .mockRejectedValueOnce(refusal)
      .mockResolvedValue({ ...identity, status: "revoked" });
    const user = userEvent.setup();
    renderIdentities();
    const detail = await openIdentityDetails(user, identity.name);
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByLabelText(/type credential name/i), identity.name);
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await within(dialog).findByRole("button", { name: "Review a new request" });
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity.mock.calls[0]).toEqual(apiMock.transitionIdentity.mock.calls[1]);
    await user.click(await within(dialog).findByRole("button", { name: "Review a new request" }));
    await waitFor(() => expect(apiMock.previewIdentityTransition).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2);
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(3));
    expect(apiMock.transitionIdentity.mock.calls[2]?.[4]).toBe(`${apiMock.transitionIdentity.mock.calls[0]?.[4]}:${requestId}`);
  });

  it("keeps an uncertain network retry bound and gives a changed reviewed reason a new command", async () => {
    const identity = { id: "uncertain-command", name: "uncertain.example.test", kind: "x509_certificate", owner_id: "own-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.previewIdentityTransition.mockImplementation(async (id: string, to: string, reason: string) => ({
      ...transitionPlanFor(id, to),
      request_fingerprint: `sha256:${id}:${to}:${reason}`,
    }));
    apiMock.transitionIdentity.mockRejectedValue(new TypeError("connection lost before response"));
    const user = userEvent.setup();
    renderIdentities();
    const detail = await openIdentityDetails(user, identity.name);
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByLabelText(/type credential name/i), identity.name);
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await within(dialog).findByRole("alert");
    expect(within(dialog).queryByRole("button", { name: "Review a new request" })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity.mock.calls[0]?.[4]).toEqual(expect.any(String));
    expect(apiMock.transitionIdentity.mock.calls[0]).toEqual(apiMock.transitionIdentity.mock.calls[1]);
    await user.selectOptions(within(dialog).getByLabelText(/revocation reason/i), "keyCompromise");
    expect(within(dialog).getByRole("button", { name: /yes, revoke/i })).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Review updated action" }));
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(3));
    expect(apiMock.transitionIdentity.mock.calls[2]?.[2]).toBe("keyCompromise");
    expect(apiMock.transitionIdentity.mock.calls[2]?.[4]).not.toBe(apiMock.transitionIdentity.mock.calls[0]?.[4]);
  });

  it("shows served blast-radius impact before destructive confirmation (FE-083)", async () => {
    const identity = { id: "dep-9", name: "to-revoke", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "id:dep-9", kind: "credential", name: "to-revoke certificate" },
      affected: [
        { id: "workload:api", kind: "workload", name: "payments-api" },
        { id: "workload:worker", kind: "workload", name: "payments-worker" },
        { id: "resource:db", kind: "resource", name: "payments-db" },
      ],
      by_kind: { workload: 2, resource: 1 },
    });
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "to-revoke");
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("id:dep-9"));
    const dialog = await screen.findByRole("alertdialog");
    const impactHeading = await within(dialog).findByRole("heading", { name: "Blast-radius impact" });
    const impact = impactHeading.closest("section")!;
    expect(within(impact).getByText(/id:dep-9/)).toBeInTheDocument();
    expect(within(impact).getByText(/3 downstream affected nodes/i)).toBeInTheDocument();
    expect(within(impact).getByText("workload")).toBeInTheDocument();
    expect(within(impact).getByText("2")).toBeInTheDocument();
    expect(within(impact).getByText("resource")).toBeInTheDocument();
    expect(within(impact).getByText("1")).toBeInTheDocument();
  });

  it("does not invent blast-radius impact when no graph node mapping exists (FE-083)", async () => {
    const identity = { id: "api-9", name: "api-key", kind: "api_key", owner_id: "owner-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "api-key");
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));

    expect(apiMock.graphBlastRadius).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/no graph node mapping/i)).toBeInTheDocument();
  });

  it("degrades blast-radius impact when the graph request fails (FE-083)", async () => {
    const identity = { id: "dep-404", name: "missing-graph-node", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.graphBlastRadius.mockRejectedValue(new ApiError(404, JSON.stringify({ detail: "graph node not found" })));
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "missing-graph-node");
    await user.click(within(detail).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("id:dep-404"));
    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText(/Blast-radius impact unavailable: graph node not found/i)).toBeInTheDocument();
  });

  it("cancelling the confirmation does not revoke (SURFACE-007)", async () => {
    const identity = { id: "dep-9", name: "keep-me", status: "deployed" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "keep-me");
    const opener = within(detail).getByRole("button", { name: /^revoke$/i });
    await user.click(opener);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("bulk revokes selected identities with one transactional request and a server-reported summary", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "dep-1", name: "bulk-ok", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" },
      { id: "dep-2", name: "bulk-fail", kind: "x509_certificate", owner_id: "owner-2", status: "deployed" },
      { id: "req-1", name: "not-selected", kind: "x509_certificate", owner_id: "owner-3", status: "requested" },
    ]);
    // One transactional call; the server reports per-item outcomes (no client fan-out).
    apiMock.bulkRevokeIdentities.mockResolvedValue({
      total_matched: 2,
      total_revoked: 1,
      total_skipped: 0,
      total_failed: 1,
      items: [
        { id: "dep-1", status: "revoked" },
        { id: "dep-2", status: "failed", error: "connector queue unavailable" },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByLabelText("Select bulk-ok"));
    await user.click(screen.getByLabelText("Select bulk-fail"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Bulk revoke selected" }));

    const dialog = await screen.findByRole("alertdialog", { name: /Revoke 2 selected identities/i });
    expect(within(dialog).getByText(/single bulk revocation request/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Confirm bulk revoke" })).toHaveFocus();

    // Pick an explicit RFC 5280 reason before confirming.
    await user.selectOptions(within(dialog).getByLabelText("Revocation reason"), "keyCompromise");
    await user.click(within(dialog).getByRole("button", { name: "Confirm bulk revoke" }));

    await waitFor(() => expect(apiMock.bulkRevokeIdentities).toHaveBeenCalledTimes(1));
    expect(apiMock.bulkRevokeIdentities).toHaveBeenCalledWith({ identity_ids: ["dep-1", "dep-2"], reason: "keyCompromise" });
    // No client-side fan-out through single-item transitions.
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(await screen.findByText(/Revoked 1 of 2 \(skipped 0, failed 1\)/i)).toBeInTheDocument();
    expect(screen.getByText(/bulk-fail failed: connector queue unavailable/)).toBeInTheDocument();
  });

  it("runs NHI decommission from a served governance signal", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-1", name: "payments-api", kind: "api_key", owner_id: "owner-1", status: "deployed" }]);
    apiMock.decommissionNHI.mockResolvedValueOnce({
      capability: "CAP-GOV-04",
      coverage: ["departure", "vendor_term", "inactivity", "revoke", "retire"],
      reason: "vendor termination CAB-22",
      summary: { total_matched: 1, revoked: 1, retired: 0, skipped: 0, failed: 0 },
      items: [
        {
          identity_id: "dep-1",
          name: "payments-api",
          kind: "api_key",
          owner_id: "owner-1",
          signal_type: "vendor_term",
          action: "revoked",
          from: "deployed",
          to: "revoked",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    await user.click(screen.getByText("Open decommission controls"));
    const form = screen.getByRole("form", { name: "NHI decommission" });
    await user.selectOptions(within(form).getByLabelText("Signal"), "vendor_term");
    await user.type(within(form).getByLabelText("Vendor"), "Acme SaaS");
    await user.type(within(form).getByLabelText("Reason"), "vendor termination CAB-22");
    await user.click(within(form).getByRole("button", { name: "Decommission" }));

    await waitFor(() => expect(apiMock.decommissionNHI).toHaveBeenCalledTimes(1));
    expect(apiMock.decommissionNHI).toHaveBeenCalledWith({
      reason: "vendor termination CAB-22",
      signals: [{ type: "vendor_term", vendor_name: "Acme SaaS", evidence_refs: ["ui:identities/decommission"] }],
    });
    expect(await screen.findByText(/CAP-GOV-04: matched 1; revoked 1; retired 0; failed 0/)).toBeInTheDocument();
    expect(screen.getByText("payments-api revoked via vendor_term")).toBeInTheDocument();
  });

  it("removes static revocation endpoint prose from the identities page", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "revocation-docs", status: "deployed" }]);

    renderIdentities();

    expect(await screen.findByText("revocation-docs")).toBeInTheDocument();
    expect(screen.queryByText("Revocation publication")).not.toBeInTheDocument();
    expect(screen.queryByText(/public OCSP and CRL responders/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Responder paths are tenant-scoped/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/live propagation health/i)).not.toBeInTheDocument();
  });

  it("surfaces a 429 rate-limit with a Retry-After hint (SURFACE-007)", async () => {
    const identity = { id: "req-1", name: "svc", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(new ApiError(429, "rate limited", 12));
    const user = userEvent.setup();
    renderIdentities();

    // The reviewed action reaches the mutation and keeps the Retry-After detail.
    const detail = await openIdentityDetails(user, "svc");
    await user.click(within(detail).getByRole("button", { name: /^issue$/i }));
    await confirmReviewedAction(user);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/rate limited/i);
    expect(alert).toHaveTextContent(/12s/);
  });

  it("shows served problem details for denied issue", async () => {
    const identity = { id: "req-1", name: "request-only-svc", kind: "x509_certificate", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(
      new ApiError(
        403,
        JSON.stringify({
          detail: "certs:request principals cannot self-issue; a distinct approver is required",
        }),
      ),
    );
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "request-only-svc");
    const issue = within(detail).getByRole("button", { name: /^issue$/i });
    await user.click(issue);
    await confirmReviewedAction(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/certs:request principals cannot self-issue/i);
    expect(alert).toHaveTextContent(/distinct approver/i);
    expect(issue).toBeDisabled();
    expect(detail).toHaveTextContent(/certs:request principals cannot self-issue/i);
  });

  it("moves dual-control approval decisions out of identity rows", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "self-approval-svc", kind: "x509_certificate", status: "requested" }]);
    renderIdentities();

    const row = (await screen.findByText("self-approval-svc")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.queryByText("JIT approvals moved to the inbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /review in approvals|open approvals inbox/i })).not.toBeInTheDocument();
  });

  it("keeps the dedicated approvals inbox out of the identities page", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        status: "requested",
        attributes: {
          requester: "alice",
          approvals: "1/2",
          grant_expires_at: "2026-06-19T18:00:00Z",
        },
      },
    ]);
    renderIdentities();

    expect(await screen.findByText("jit-db")).toBeInTheDocument();
    expect(screen.queryByText("JIT approvals moved to the inbox")).not.toBeInTheDocument();
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
    expect(screen.queryByText("1/2")).not.toBeInTheDocument();
    expect(screen.queryByText("2026-06-19T18:00:00Z")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /open approvals inbox/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve issue for jit-db/i })).not.toBeInTheDocument();
  });

  it("summarizes connector failures for operators and preserves exact receipt evidence behind disclosure", async () => {
    apiMock.identities.mockResolvedValue([{ id: "iss-1", name: "issued-svc", kind: "x509_certificate", status: "issued" }]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "receipt-1",
          tenant_id: "tenant-1",
          identity_id: "iss-1",
          destination: "connector.deploy",
          connector: "nginx",
          target: "edge-1",
          fingerprint: "abc123",
          status: "failed",
          attempts: 1,
          reason: "plugin_not_loaded",
          detail: "connector is not owned by a loaded signed plugin",
          rollback_ref: "",
          idempotency_key: "event-1",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    await user.click(screen.getByText("Show exact reason"));
    expect(screen.getByText("plugin_not_loaded")).toBeInTheDocument();
    const row = screen.getByText("issued-svc").closest("tr")!;
    expect(row).toHaveTextContent("Delivery needs attention.");
    expect(row).not.toHaveTextContent("plugin_not_loaded");
  });

  it("renders the server-owned lifecycle automation plan with safe controls, scheduler evidence, and narrow-screen containment", async () => {
    const longIdentityName = "checkout-39e37caa-8171-426c-a311-5b7c9fd87bb7.qa.trstctl.test";
    apiMock.identities.mockResolvedValue([{ id: "ren-1", name: longIdentityName, kind: "x509_certificate", status: "deployed" }]);
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "run-1",
          tenant_id: "tenant-1",
          identity_id: "ren-1",
          status: "succeeded",
          trigger: "scheduler",
          reason: "scheduled renewal before expiry",
          predecessor_fingerprint: "old",
          successor_fingerprint: "new",
          rollback_ref: "restore certificate fingerprint old",
          idempotency_key: "event-2",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:01:00Z",
          completed_at: "2026-06-20T00:01:00Z",
        },
      ],
    });
    apiMock.lifecycleAutomationPlan.mockResolvedValue({
      capability: "lifecycle_automation",
      ready: true,
      generated_at: "2026-06-20T00:00:00Z",
      scheduler: {
        status: "running",
        renew_before: "720h0m0s",
        alert_before: "168h0m0s",
        interval: "1m0s",
        ari_first: true,
        maintenance_window_status: "open",
      },
      summary: { monitored: 1, due_now: 1, renewal_failed: 0, outbox_pending: 0, outbox_processing: 0, outbox_failed: 0 },
      items: [
        {
          identity_id: "ren-1",
          identity_name: longIdentityName,
          identity_status: "deployed",
          owner_id: "own-1",
          owner_name: "team",
          certificate_id: "cert-1",
          not_after: "2026-06-25T00:00:00Z",
          due: true,
          renewal_source: "ari",
          reason: "The CA renewal window is open.",
          latest_run_id: "run-1",
          latest_run_status: "succeeded",
          rollback_ref: "restore certificate fingerprint old",
          blockers: [],
        },
      ],
      controls: [
        { action: "start", state: "available", detail: "Review and queue one due renewal." },
        { action: "pause", state: "configuration_only", detail: "Maintenance windows pause new starts." },
        { action: "resume", state: "automatic", detail: "New starts resume when the window opens." },
        { action: "retry", state: "conditional", detail: "A failed renewal can be reviewed as a new attempt." },
        { action: "cancel", state: "unavailable_after_enqueue", detail: "Queued work may already be leased." },
        { action: "rollback", state: "conditional", detail: "Use predecessor evidence after delivery." },
      ],
      preview_writes: [],
      preview_external_effects: [],
      execution_writes: ["Append identity.renewing and queue ca.renew."],
      execution_external_effects: ["Issue and deploy the successor asynchronously."],
      verification_steps: ["Confirm rotation and connector receipts."],
    });
    const user = userEvent.setup();
    renderIdentities();

    const heading = await screen.findByRole("heading", { name: "Lifecycle automation" });
    const panel = heading.closest("section");
    expect(panel).toHaveClass("min-w-0", "max-w-full");
    expect(await within(panel!).findByTestId("lifecycle-automation-body")).toHaveClass("min-w-0", "grid-cols-[minmax(0,1fr)]");
    expect(within(panel!).getByText(longIdentityName)).toHaveClass("break-all");
    expect(screen.getByText("Automatic renewals are running")).toBeInTheDocument();
    expect(screen.getByText(/Renew 30 days before expiry/)).toBeInTheDocument();
    expect(screen.getByText(/ARI window opens first/)).toBeInTheDocument();
    expect(screen.getByText(/Maintenance windows pause new starts/)).toBeInTheDocument();
    expect(screen.getByText(/Revocation or retirement cancels queued issuance and renewal retries/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review renewal now" })).toBeInTheDocument();
    expect(apiMock.lifecycleAutomationPlan).toHaveBeenCalled();

    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    expect(screen.getByText("Succeeded", { selector: "[data-status-value='succeeded']" })).toBeInTheDocument();
    expect(screen.getAllByText("scheduler").length).toBeGreaterThan(0);
    expect(screen.getByText("restore certificate fingerprint old")).toBeInTheDocument();
  });

  it.each([
    ["5m0s", 300],
    ["36h0m0s", 129_600],
    ["168h30m0s", undefined],
    ["24h0m1s", undefined],
  ])("preserves exact renewal lead %s instead of rounding to days", async (duration, seconds) => {
    const plan = await apiMock.lifecycleAutomationPlan();
    apiMock.identities.mockResolvedValue([]);
    apiMock.lifecycleAutomationPlan.mockResolvedValue({
      ...plan,
      scheduler: {
        ...plan.scheduler,
        renew_before: duration,
        renew_before_seconds: seconds,
        alert_before: "2161h0m0s",
        alert_before_seconds: 7_779_600,
      },
    });
    renderIdentities();
    expect(await screen.findByText(`Renewal lead time: ${duration}. Alert lead time: 2161h0m0s.`)).toBeInTheDocument();
  });

  it("fails closed instead of crashing when lifecycle automation evidence is malformed", async () => {
    apiMock.identities.mockResolvedValue([]);
    apiMock.lifecycleAutomationPlan.mockResolvedValue({ capability: "lifecycle_automation", ready: true });

    renderIdentities();

    expect(await screen.findByText("Automation details are unavailable")).toBeInTheDocument();
    expect(screen.getByText(/Could not load the lifecycle automation plan/)).toBeInTheDocument();
    expect(screen.queryByText("Automatic renewals are running")).not.toBeInTheDocument();
  });

  it("reports idempotency protection after a successful lifecycle transition", async () => {
    const identity = { id: "req-1", name: "idempotent-svc", kind: "x509_certificate", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const detail = await openIdentityDetails(user, "idempotent-svc");
    await user.click(within(detail).getByRole("button", { name: /^issue$/i }));
    await confirmReviewedAction(user);

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything(), undefined, expect.any(String), 2));
    expect(await screen.findByRole("status")).toHaveTextContent(/Idempotency-Key protects/i);
    expect(screen.getByRole("status")).toHaveTextContent(/duplicate execution/i);
  });

  it("creates (issues) a new identity from the page", async () => {
    apiMock.identities.mockResolvedValue([]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "svc");
    await user.selectOptions(screen.getByLabelText("Ready owner"), "own-1");
    await user.click(screen.getByRole("button", { name: /create|issue/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith(expect.objectContaining({ name: "svc", ownerId: "own-1" })));
  });

  it("refuses to issue into an owner record that cannot pass deployment readiness", async () => {
    apiMock.identities.mockResolvedValue([]);
    apiMock.owners.mockResolvedValue([
      { id: "incomplete", kind: "workload", name: "Missing application", ownership_complete: false, ownership_current: false },
      {
        id: "stale",
        kind: "workload",
        name: "Stale attestation",
        application_id: "APP-STALE",
        environment: "production",
        ownership_complete: true,
        ownership_attested: true,
        ownership_current: false,
      },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "svc");

    expect(screen.getByRole("combobox", { name: "Ready owner" })).toHaveValue("");
    expect(screen.getByRole("button", { name: /create|issue/i })).toBeDisabled();
    expect(screen.getByText("No deployment-ready owner is available.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create or attest an owner" })).toHaveAttribute("href", "/owners");
    expect(apiMock.issueCertificate).not.toHaveBeenCalled();
  });

  it("requires explicit acknowledgement before issuing a wildcard identity", async () => {
    apiMock.identities.mockResolvedValue([]);
    const issued = {
      id: "wildcard-1",
      name: "*.payments.example",
      kind: "x509_certificate",
      owner_id: "own-1",
      status: "issued",
      attributes: { validation_method: "dns-01", wildcard_blast_radius_acknowledged: true },
    };
    apiMock.issueCertificate.mockResolvedValue(issued);
    apiMock.getIdentity.mockResolvedValue(issued);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "*.payments.example");
    await user.selectOptions(screen.getByLabelText("Ready owner"), "own-1");
    expect(screen.getByRole("heading", { name: "Wildcard safety check" })).toBeInTheDocument();
    expect(screen.getByText("Automatic ACME requests can prove wildcard control only with DNS-01.")).toBeInTheDocument();
    expect(screen.getByText("Before ACME use, verify that the zone’s DNS provider policy allows wildcards.")).toBeInTheDocument();
    expect(screen.getByText("After deployment, the lifecycle scheduler watches and renews it.")).toBeInTheDocument();
    const issue = screen.getByRole("button", { name: /create|issue/i });
    expect(issue).toBeDisabled();
    expect(screen.getByText(/does not weaken ACME validation/i)).toBeInTheDocument();

    await user.click(screen.getByLabelText(/Acknowledge wildcard blast radius/i));
    expect(issue).toBeEnabled();
    await user.click(issue);
    await waitFor(() =>
      expect(apiMock.issueCertificate).toHaveBeenCalledWith({
        name: "*.payments.example",
        ownerId: "own-1",
        wildcardBlastRadiusAcknowledged: true,
      }),
    );
    expect(await screen.findByText(/Wildcard issued: \*\.payments\.example/i)).toBeInTheDocument();
    expect(screen.getByText(/Deploy it to enter automatic renewal monitoring/i)).toBeInTheDocument();
    const detail = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(detail).getByText("*.payments.example")).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: /^deploy$/i })).toBeInTheDocument();
  });

  it("fails wildcard issuance closed with a direct DNS-policy recovery path", async () => {
    apiMock.identities.mockResolvedValue([]);
    apiMock.issueCertificate.mockRejectedValue(new ApiError(400, "wildcard policy does not allow this zone"));
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "*.blocked.example");
    await user.selectOptions(screen.getByLabelText("Ready owner"), "own-1");
    await user.click(screen.getByLabelText(/Acknowledge wildcard blast radius/i));
    await user.click(screen.getByRole("button", { name: /create|issue/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No wildcard certificate was issued");
    expect(alert).toHaveTextContent("wildcard policy does not allow this zone");
    expect(within(alert).getByRole("link", { name: "Check DNS-01 setup" })).toHaveAttribute("href", "/protocols#dns-config-heading");
    expect(alert).toHaveTextContent("Do not weaken validation to make the request pass");
  });

  it("ties a wildcard renewal action to recovery links and identity-named rotation proof", async () => {
    const wildcard = {
      id: "wildcard-deployed-1",
      name: "*.renew.example",
      kind: "x509_certificate",
      owner_id: "own-1",
      status: "deployed",
      attributes: { validation_method: "dns-01", wildcard_blast_radius_acknowledged: true },
    };
    apiMock.identities.mockResolvedValue([wildcard]);
    apiMock.getIdentity.mockResolvedValue(wildcard);
    apiMock.transitionIdentity.mockResolvedValue({ ...wildcard, status: "renewing" });
    apiMock.lifecycleAutomationPlan.mockResolvedValue({
      capability: "lifecycle_automation",
      ready: true,
      generated_at: "2026-08-30T00:00:00Z",
      scheduler: {
        status: "running",
        renew_before: "720h0m0s",
        alert_before: "336h0m0s",
        interval: "1m0s",
        ari_first: true,
        maintenance_window_status: "open",
      },
      summary: { monitored: 1, due_now: 1, renewal_failed: 0, outbox_pending: 0, outbox_processing: 0, outbox_failed: 0 },
      items: [
        {
          identity_id: wildcard.id,
          identity_name: wildcard.name,
          identity_status: "deployed",
          owner_id: "own-1",
          owner_name: "team",
          certificate_id: "cert-wildcard-1",
          not_after: "2026-08-31T00:00:00Z",
          due: true,
          renewal_source: "ari",
          reason: "The CA renewal window is open.",
          blockers: [],
        },
      ],
      controls: [],
      preview_writes: [],
      preview_external_effects: [],
      execution_writes: ["Append identity.renewing and queue ca.renew."],
      execution_external_effects: ["Issue and deploy the successor asynchronously."],
      verification_steps: ["Confirm rotation and connector receipts."],
    });
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rotation-wildcard-1",
          identity_id: wildcard.id,
          status: "succeeded",
          trigger: "scheduler",
          predecessor_fingerprint: "sha256:old",
          successor_fingerprint: "sha256:new",
          rollback_ref: "restore sha256:old",
          updated_at: "2026-08-30T00:01:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    expect(await screen.findByText("Wildcard renewal · verify the successor and rollback receipt")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review renewal now" }));
    await confirmReviewedAction(user);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith(wildcard.id, "renewing", expect.anything(), undefined, expect.any(String), 2));

    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByText("Delivery and rotation evidence", { selector: "summary" }));
    const rotationTable = screen.getByRole("table", { name: "Loaded lifecycle rotation runs" });
    expect(within(rotationTable).getByText("*.renew.example")).toBeInTheDocument();
    expect(within(rotationTable).getByText("scheduler")).toBeInTheDocument();
    expect(within(rotationTable).getByText("restore sha256:old")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open rotation runs" })).toHaveAttribute("href", "/operations");
    expect(screen.getByRole("link", { name: "Open connectors and rollback" })).toHaveAttribute("href", "/connectors");
  });

  it("does not record dual-control approval from the identity row", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "needs-approval", status: "requested" }]);
    renderIdentities();

    const row = (await screen.findByText("needs-approval")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /review in approvals|open approvals inbox/i })).not.toBeInTheDocument();
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });
});
