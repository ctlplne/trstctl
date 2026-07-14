import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import { messages, type MessageKey } from "@/i18n/messages";
import { navGroups, primaryNavItems } from "@/lib/navigation";

/** naming_parity (S-A2, guards DA-07): every rail destination must present ONE
 * name — the nav label, the page H1, and the document.title prefix must match.
 * The three-way drift the 2026-07-13 live pass caught (Risk/Posture/Graph nav
 * vs H1 vs title) becomes impossible to reintroduce silently once this holds
 * in CI. */

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  // Resolve every api call to a benign empty shape; pages render their chrome
  // (header + H1) regardless of data. Permissions listed inline because the
  // vi.mock factory is hoisted above module-scope consts.
  const permissions = [
    "access:read",
    "agents:read",
    "agents:write",
    "audit:read",
    "certs:issue",
    "certs:read",
    "certs:request",
    "connectors:read",
    "discovery:read",
    "graph:read",
    "identities:read",
    "incidents:read",
    "issuers:read",
    "keys:write",
    "lifecycle:read",
    "notifications:read",
    "owners:read",
    "policy:read",
    "privacy:read",
    "profiles:read",
    "risk:read",
    "secrets:read",
    "secrets:write",
  ];
  // A value that satisfies BOTH array-returning api methods (.filter/.map) and
  // paged/object-returning ones (.items/.events/…): an array with the common
  // container fields attached.
  const dual = () =>
    Object.assign([] as unknown[], {
      items: [],
      events: [],
      summary: {},
      coverage: [],
      targets: [],
      sources: [],
      findings: [],
      logs: [],
      nodes: [],
      edges: [],
      features: [],
      tools: [],
      report_types: [],
      routes: [],
      residuals: [],
      schedules: [],
      controls: [],
      frameworks: [],
      telemetry: { allowed: 0, denied: 0, replay_rejected: 0 },
      signed_export: { manifest: { controls: [] } },
      public_key_der: "",
      next_cursor: undefined,
    });
  const base: Record<string, unknown> = {};
  for (const key of Object.keys(actual.api)) {
    base[key] = vi.fn().mockResolvedValue(dual());
  }
  base.me = vi.fn().mockResolvedValue({ subject: "np", tenant_id: "t1", email: "np@example.test", permissions });
  return { ...actual, api: base };
});

function railTargets(): Array<{ to: string; labelKey: MessageKey }> {
  const items: Array<{ to: string; labelKey: MessageKey }> = [];
  for (const item of primaryNavItems) items.push({ to: item.to, labelKey: item.labelKey });
  for (const group of navGroups) for (const item of group.items) items.push({ to: item.to, labelKey: item.labelKey });
  return items;
}

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <MemoryRouter initialEntries={[path]}>
            <AppRoutes />
          </MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("naming parity (S-A2)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  for (const target of railTargets()) {
    const expected = messages[target.labelKey].defaultMessage;
    it(`nav label, H1, and title agree for ${target.to} ("${expected}")`, async () => {
      const view = renderAt(target.to);
      const heading = await screen.findByRole("heading", { level: 1 });
      await waitFor(() => expect(heading).toHaveTextContent(expected));
      await waitFor(() => expect(document.title.startsWith(expected)).toBe(true));
      view.unmount();
    });
  }
});
