import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import { messages, type MessageKey } from "@/i18n/messages";
import { navGroups, primaryNavItems } from "@/lib/navigation";
import type { NHIShadowPosture } from "@/lib/api";

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
      providers: [],
      configured_targets: [],
      configured_providers: [],
      configured_sync_targets: [],
      detection_sources: [],
      vault_providers: [],
      webhook_paths: [],
      event_flow: [],
      release_gates: [],
      ingest_paths: [],
      architecture_controls: [],
      evidence_refs: [],
      recommended_next_actions: [],
      operator_actions: [],
      crds: [],
      crd: { kind: "", status: "" },
      modes: [],
      workload_kinds: [],
      reload_workloads: [],
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
      custody: {
        total: 0,
        recorded: 0,
        unrecorded: 0,
        origins: { requester: 0, host_agent: 0, device: 0, control_plane: 0, signer: 0 },
        storage: { locked_memory: 0, file: 0, os_store: 0, pkcs11: 0, device_bound: 0, service: 0 },
        exportability: { exportable: 0, non_exportable: 0 },
        unrecorded_certificates: [],
      },
      next_cursor: undefined,
    });
  const base: Record<string, unknown> = {};
  for (const key of Object.keys(actual.api)) {
    base[key] = vi.fn().mockResolvedValue(dual());
  }
  const emptyShadowPosture = {
    capability: "nhi-shadow-posture",
    generated_at: "2026-07-27T00:00:00Z",
    coverage: [],
    summary: {
      total_analyzed: 0,
      findings: 0,
      unmanaged: 0,
      investigating: 0,
      unregistered: 0,
      ownerless: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      kind_counts: {},
      surface_counts: {},
    },
    findings: [],
    recommended_actions: [],
    evidence_refs: [],
  } satisfies NHIShadowPosture;
  base.nhiShadowPosture = vi.fn().mockResolvedValue(emptyShadowPosture);
  base.me = vi.fn().mockResolvedValue({ subject: "np", tenant_id: "t1", email: "np@example.test", permissions });
  return { ...actual, api: base };
});

function railTargets(): Array<{ to: string; labelKey: MessageKey }> {
  const items: Array<{ to: string; labelKey: MessageKey }> = [];
  for (const item of primaryNavItems) items.push({ to: item.to, labelKey: item.labelKey });
  for (const group of navGroups) for (const item of group.items) items.push({ to: item.to, labelKey: item.labelKey });
  return items;
}

const standaloneTargets: Array<{ to: string; labelKey: MessageKey }> = [{ to: "/wizard", labelKey: "source.set.up.trstctl.b56c208e41" }];

const certificateDesignTargets = [
  {
    to: "/certificates",
    answer: /healthy.*expire soon.*needs action/i,
    proof: /subject.*serial.*issuer chain.*renewal job.*revocation/i,
    primary: "Add certificate",
  },
  {
    to: "/profiles",
    answer: /control what machines may request.*key strength.*lifetime/i,
    proof: /versioned JSON spec.*minimum strengths.*policy binding/i,
    primary: "Create rule",
  },
  {
    to: "/request",
    answer: /choose a rule.*name the machine.*submit for approval/i,
    proof: /profile version.*requester subject.*idempotency.*issuance event/i,
    primary: "Next: name it",
  },
  {
    to: "/ca-hierarchy",
    answer: /who signs each certificate.*trust chain.*multiple people/i,
    proof: /root.*intermediate lineage.*signer custody.*ceremony quorum.*rollover/i,
    primary: "Add authority",
  },
  {
    to: "/protocols",
    answer: /safe doorway.*request and renew.*ACME.*EST.*SCEP.*CMP/i,
    proof: /public endpoints.*responder health.*tenant.*profile binding.*diagnostics/i,
    primary: "Set up next method",
  },
  {
    to: "/codesign",
    answer: /release digests.*where the keys stay.*verifies each signature.*software and private key never enter this browser/i,
    proof: /artifact digest.*signing mode.*policy.*signature receipt.*audit/i,
    primary: "Sign artifact",
  },
] as const;

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

  for (const target of [...railTargets(), ...standaloneTargets]) {
    const expected = messages[target.labelKey].defaultMessage;
    it(`nav label, H1, and title agree for ${target.to} ("${expected}")`, async () => {
      const view = renderAt(target.to);
      const heading = await screen.findByRole("heading", { level: 1 });
      await waitFor(() => expect(heading).toHaveTextContent(expected));
      await waitFor(() => expect(document.title.startsWith(expected)).toBe(true));
      view.unmount();
    });
  }

  it('names the dev-only /styleguide route "Design system" in its H1 and document title', async () => {
    const view = renderAt("/styleguide");
    const heading = await screen.findByRole("heading", { level: 1, name: "Design system" });
    expect(heading).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Design system · trstctl"));
    view.unmount();
  });

  for (const target of certificateDesignTargets) {
    it(`opens ${target.to} with a plain answer, exact proof, and one obvious next action`, async () => {
      const view = renderAt(target.to);
      try {
        const answer = await screen.findByTestId("page-depth-answer");
        const proof = await screen.findByTestId("page-depth-prove");
        expect(answer).toHaveTextContent(target.answer);
        expect(proof).toHaveTextContent(target.proof);
        expect(await screen.findByRole(target.to === "/protocols" ? "link" : "button", { name: target.primary })).toBeInTheDocument();
      } finally {
        view.unmount();
      }
    });
  }

  it("renders the Discovery shadow-posture fixture without a NaN warning", async () => {
    const consoleError = vi.spyOn(console, "error");
    const view = renderAt("/discovery");
    try {
      await screen.findByRole("heading", { name: messages["discovery.shadow.heading"].defaultMessage });
      const errors = consoleError.mock.calls.flat().map(String).join("\n");
      expect(errors).not.toContain("Received NaN");
    } finally {
      view.unmount();
      consoleError.mockRestore();
    }
  });
});
