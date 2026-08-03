import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { ThemeProvider } from "@/components/ThemeProvider";
import { IntlProvider, directionForLocale, formatMessage, negotiateLocale, useTranslation } from "@/i18n/I18nProvider";
import { formatDate, formatNumber, formatPlural } from "@/i18n/format";
import extractedDebtBudget from "@/i18n/extractedMessages.budget.json";
import { extractedMessages } from "@/i18n/extractedMessages.gen";
import { defaultLocale, defaultTimeZone, eagerCatalogs, messages, productionLocales, pseudoLocalize, type MessageKey } from "@/i18n/messages";

// S-C10: es/de are lazy per-locale modules now. The guards below still audit
// the FULL catalogs (parity, placeholders, digests), so load them explicitly —
// the digest pins must not move on a split, only on reviewed string changes.
const catalogs = {
  ...eagerCatalogs,
  "es-ES": (await import("@/i18n/catalog.es-ES")).default,
  "de-DE": (await import("@/i18n/catalog.de-DE")).default,
} as const;
import { contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

function DemoFormats() {
  const { formatDate: localizedDate, formatNumber: localizedNumber, formatPlural: localizedPlural, t } = useTranslation();
  return (
    <dl>
      <dt>{t("nav.section.needsAction")}</dt>
      <dd>{localizedDate("2026-06-20T12:00:00Z")}</dd>
      <dt>number</dt>
      <dd>{localizedNumber(123456)}</dd>
      <dt>plural</dt>
      <dd>{localizedPlural(2, { one: "node", other: "nodes" })}</dd>
    </dl>
  );
}

function LocaleProbe() {
  const { locale, setLocale, t, timeZone } = useTranslation();
  return (
    <section>
      <p data-testid="locale-probe">
        {locale}|{timeZone}|{t("nav.section.needsAction")}
      </p>
      <button type="button" onClick={() => setLocale("en-US")}>
        choose English
      </button>
    </section>
  );
}

describe("i18n boundary", () => {
  function setViewportWidth(width: number) {
    act(() => {
      Object.defineProperty(window, "innerWidth", {
        configurable: true,
        value: width,
        writable: true,
      });
      window.dispatchEvent(new Event("resize"));
    });
  }

  it("resolves shell navigation through the pseudo-locale catalog", () => {
    render(
      <IntlProvider initialLocale="en-XA" initialTimeZone="UTC">
        <ThemeProvider>
          <MemoryRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>main</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ThemeProvider>
      </IntlProvider>,
    );

    const nav = screen.getByRole("navigation", { name: pseudoLocalize("Primary") });
    expect(nav).toBeInTheDocument();
    expect(screen.getByText(pseudoLocalize("Needs action"))).toBeInTheDocument();
    expect(within(nav).getByText(pseudoLocalize("Dashboard"))).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "?" });
    // The shortcuts dialog title went through the DA-14 sweep, so under the
    // pseudo-locale its accessible name is pseudo-localized like all shell copy.
    expect(screen.getByRole("dialog", { name: pseudoLocalize("Keyboard shortcuts") })).toBeInTheDocument();
  });

  it("renders real Spanish page chrome and lets the operator switch locale in memory", async () => {
    render(
      <IntlProvider initialLocale="es-ES" initialTimeZone="UTC">
        <ThemeProvider>
          <MemoryRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>main</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ThemeProvider>
      </IntlProvider>,
    );

    // S-C10: the es catalog is a lazy module — copy is English until it
    // resolves (never raw keys), then swaps in place.
    const nav = await screen.findByRole("navigation", { name: "Principal" });
    expect(await screen.findByText("Acción requerida")).toBeInTheDocument();
    expect(within(nav).getByText("Panel")).toBeInTheDocument();
    const selector = screen.getByRole("combobox", { name: "Idioma" });
    expect(selector).toHaveValue("es-ES");

    fireEvent.change(selector, { target: { value: "en-US" } });
    expect(screen.getByText("Needs action")).toBeInTheDocument();
  });

  it("swaps English fallback for the lazy catalog after an in-session locale switch (S-C10)", async () => {
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <ThemeProvider>
          <MemoryRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>main</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ThemeProvider>
      </IntlProvider>,
    );

    expect(await screen.findByText("Needs action")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Language" }), { target: { value: "de-DE" } });
    // English serves until the de catalog module resolves; then the tree
    // re-renders translated.
    expect(await screen.findByText("Aktion erforderlich")).toBeInTheDocument();
    expect(screen.queryByText("Needs action")).not.toBeInTheDocument();
  });

  it("closes the localized mobile navigation after route selection", () => {
    setViewportWidth(380);
    render(
      <IntlProvider initialLocale="en-XA" initialTimeZone="UTC">
        <ThemeProvider>
          <MemoryRouter initialEntries={["/certificates"]}>
            <Routes>
              <Route element={<AppShell />}>
                <Route path="certificates" element={<h1>certificates</h1>} />
                <Route index element={<h1>main</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ThemeProvider>
      </IntlProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: pseudoLocalize("Open primary navigation") }));
    const drawer = screen.getByRole("dialog", { name: pseudoLocalize("Primary navigation") });
    // S-C1: at /certificates the drawer shows the Certificates & PKI space's
    // rows (Dashboard lives on the Home plane), so select the space's own row.
    fireEvent.click(within(drawer).getByRole("link", { name: new RegExp(pseudoLocalize("Certificates").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }));

    expect(screen.queryByRole("dialog", { name: pseudoLocalize("Primary navigation") })).not.toBeInTheDocument();
    setViewportWidth(1024);
  });

  it("sets document locale, direction, and timezone from the provider policy", () => {
    render(
      <IntlProvider initialLocale="ar-XB" initialTimeZone="Asia/Tokyo">
        <DemoFormats />
      </IntlProvider>,
    );

    expect(document.documentElement.lang).toBe("ar-XB");
    expect(document.documentElement.dir).toBe("rtl");
    expect(document.documentElement.dataset.timeZone).toBe("Asia/Tokyo");
    expect(screen.getByText(pseudoLocalize("Needs action"))).toBeInTheDocument();
    expect(screen.getByText("nodes")).toBeInTheDocument();
  });

  it("applies server-provided locale and timezone preferences", async () => {
    render(
      <IntlProvider serverLocale="es-ES" serverTimeZone="Europe/Madrid">
        <LocaleProbe />
      </IntlProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("locale-probe")).toHaveTextContent("es-ES|Europe/Madrid|Acción requerida"));
    fireEvent.click(screen.getByRole("button", { name: "choose English" }));
    expect(screen.getByTestId("locale-probe")).toHaveTextContent("en-US|Europe/Madrid|Needs action");
  });

  it("keeps every served navigation key present in the typed message catalog", () => {
    const keys = new Set<MessageKey>();
    for (const item of taskNavItems) {
      keys.add(item.labelKey);
      keys.add(item.descriptionKey);
    }
    for (const group of navGroups) {
      keys.add(group.labelKey);
      for (const item of group.items) keys.add(item.labelKey);
    }
    for (const item of contextualRouteItems) {
      keys.add(item.groupKey);
      keys.add(item.labelKey);
    }

    for (const key of keys) {
      expect(messages[key]?.defaultMessage, key).toBeTruthy();
    }
  });

  it("provides deterministic locale negotiation and formatting helpers", () => {
    expect(negotiateLocale(["fr-CA", "en-GB"])).toBe(defaultLocale);
    expect(negotiateLocale(["es-MX"])).toBe("es-ES");
    expect(negotiateLocale(["de-AT"])).toBe("de-DE");
    expect(negotiateLocale(["de"])).toBe("de-DE");
    expect(negotiateLocale(["ar-SA"])).toBe("ar-XB");
    expect(directionForLocale("he-IL")).toBe("rtl");
    expect(formatMessage("command.routeDescription", { group: "Platform" })).toBe("Route · Platform");
    expect(formatMessage("command.routeDescription", { group: "Plataforma" }, "es-ES")).toBe("Ruta · Plataforma");
    expect(formatDate("2026-06-20T12:00:00Z", { locale: "en-US", timeZone: defaultTimeZone })).toMatch(/Jun/);
    expect(formatNumber(1234, { locale: "en-US", timeZone: defaultTimeZone })).toBe("1,234");
    expect(formatPlural(1, { one: "node", other: "nodes" })).toBe("node");
  });

  it("ships real non-English production catalogs rather than pseudo-only locale coverage", () => {
    const realNonEnglishLocales = productionLocales.filter((locale) => locale !== defaultLocale);
    expect(realNonEnglishLocales).toContain("es-ES");
    expect(realNonEnglishLocales).toContain("de-DE");
    // Each production catalog contains reviewed production copy for the anchor
    // key, not the English default and not a pseudo-localized transform (C-L1).
    const expectedNeedsAction: Record<string, string> = { "es-ES": "Acción requerida", "de-DE": "Aktion erforderlich" };
    for (const locale of realNonEnglishLocales) {
      const translatedKeys = (Object.keys(messages) as MessageKey[]).filter((key) => catalogs[locale][key] !== catalogs[defaultLocale][key]);
      expect(translatedKeys.length).toBeGreaterThan(50);
      expect(catalogs[locale]["nav.section.needsAction"]).toBe(expectedNeedsAction[locale]);
      expect(catalogs[locale]["nav.section.needsAction"]).not.toBe(pseudoLocalize(messages["nav.section.needsAction"].defaultMessage));
    }
  });

  it("preserves every interpolation placeholder in each production translation", () => {
    const placeholders = (message: string) => Array.from(message.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g), (match) => match[1]).sort();

    for (const locale of productionLocales.filter((candidate) => candidate !== defaultLocale)) {
      for (const key of Object.keys(messages) as MessageKey[]) {
        expect(placeholders(catalogs[locale][key]), `${locale}:${key}`).toEqual(placeholders(catalogs[defaultLocale][key]));
      }
    }
  });

  it("pins the reviewed production catalogs against English-fallback regressions", () => {
    const digest = (locale: (typeof productionLocales)[number]) => {
      const payload = (Object.keys(messages) as MessageKey[]).map((key) => `${key}\0${catalogs[locale][key]}`).join("\0");
      return createHash("sha256").update(payload).digest("hex");
    };

    // Updating either digest is a deliberate translation-review decision. The
    // ratchet catches a long-tail value being reset to its English seed just as
    // it catches any other unreviewed production-catalog edit.
    expect({
      "es-ES": digest("es-ES"),
      "de-DE": digest("de-DE"),
    }).toEqual({
      // B5 custody re-pin: two source.custody.* keys add the per-certificate key
      // custody line, including the sentence that says unrecorded is not the
      // same as safe. Machine-authored es/de - FLAGGED FOR HUMAN REVIEW.
      // F3 evidence re-pin: one source.adcs.evidence key renders the attributes
      // and values a finding was derived from, so an operator can check it
      // against the template's own property page instead of taking it on faith.
      // Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // F1 AD CS re-pin: twenty-two source.adcs.* keys add the certificate
      // template posture panel — the risk verdict, what each template permits
      // and the fix, whether a CA publishes it, and the empty state that
      // distinguishes "no AD CS estate" from "nobody has looked". Machine-
      // authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // D5 dry-run re-pin: three source.dry.run.* keys label the relay-executed
      // target test. dry_run_planned is the first status on this surface that
      // reads as success and it earns it — a relay reached the target and
      // resolved every credential — while still saying "would" rather than
      // "did". Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // A3 relay-executor re-pin: four source.relay.* keys add the relay
      // capability panel to the Agents detail pane — what this build executes
      // as a relay, which connectors it carries, and the flag that turns it on.
      // Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // A3 redemption re-pin: five operations.jobs.redemptions.* keys add the
      // credential-custody readout to the Operations job ledger — how much
      // material relays hold outside the seal right now, how long the oldest
      // has been held, and what a count that does not fall means. Machine-
      // authored es/de translations - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // A3 vantage re-pin: four source.*.a3vant* keys add the connector
      // registry's "Executes on" column — host agent / network relay / control
      // plane — read from the live vantage census. Machine-authored es/de
      // translations - FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // A2 agent-roles re-pin: ten source.agent.role.* keys add the enrollment
      // role selector (host / network relay with per-role help), the relay
      // credential-custody warning, the empty-selection note, the fleet role
      // badges, and the not-yet-reported label that distinguishes an agent with
      // no grant from one that has not heartbeated since the upgrade. Machine-
      // authored es/de translations - FLAGGED FOR HUMAN TRANSLATION REVIEW
      // before release; "agents:relay.grant" stays byte-identical as a
      // technical identifier in every locale.
      // I18N-ca357ca0 re-pin: 223 source keys move strings, conditional
      // fallbacks, interpolated accessibility labels, and warning copy from
      // renderable JSX expressions into the typed catalog. Technical
      // identifiers and punctuation-only format templates stay byte-identical;
      // all natural-language values carry placeholder-safe es/de translations.
      // UX-04 follow-up: the intermediate-CA description now uses customer
      // language in every locale instead of the internal "served" status.
      // Posture follow-up: the localized crypto inventory separator preserves
      // its leading space so adjacent algorithm and transport text stays clear.
      // Discovery-coverage re-pin: eight discovery.coverage.* keys (panel
      // heading, caption, three-bucket summary, table headers, observed-by and
      // unavailable copy) land with machine-authored es/de translations -
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // D-7806a198 adds the isolated-preview banner and sample-playbook copy,
      // and removes "served" implementation jargon from CA health copy.
      // I-60770d64 adds the reviewed core PQC campaign workflow copy while
      // preserving placeholders and technical identifiers in every locale.
      // I-093b9270 adds the AWS workload-identity source wizard, honest
      // air-gap/failure state, validation, and status copy in both catalogs.
      // The independently shippable GCP and Azure stages extend that same
      // wizard with provider-specific validation and status copy. Every added
      // value is present in es/de and preserves the English placeholders.
      // P-5da72dc3 adds the read-only ARI publication/window/scheduler panel
      // and its honest loading, empty, permission, unavailable, and error
      // states in both production catalogs.
      // I-aa8623a3 adds the tenant key-domain migration, seal, failure,
      // recovery, and unseal workflow in both production catalogs while
      // preserving the completed/total progress placeholders.
      // K2 truth-integrity sweep re-pin: three delivery-status labels move the
      // console off wording that read stronger than the served claim —
      // config_validated ("target not contacted"), its legacy spelling for
      // receipts stored before the rename, and rollback_recorded ("attested,
      // not executed"). Reviewed for meaning in all three locales: each label
      // has to carry the negation, because dropping it is exactly the defect
      // being fixed. No placeholders and no technical identifiers involved.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW alongside
      // the outstanding translation review sheet.
      // H5 CA-calendar re-pin: six keys give CA authorities a year-scale expiry
      // horizon in the console — the band label, the renew/re-key-by date and the
      // leaf validity it assumes, the "beyond planning horizon" and "no recorded
      // expiry" states, and the warning that leaves are already being truncated.
      // Reviewed for meaning in all three locales; the truncation warning and the
      // "no recorded expiry" state must keep their negation, since a missing
      // expiry rendered as healthy is the defect being fixed. One interpolated
      // message ({value1}-day leaves) preserves its placeholder in every locale.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // C1a truth-integrity re-pin: one key for the agent endpoint-discovery
      // panel's honest empty state. The console previously fell back to a
      // hardcoded capability list naming PKCS#11, the Windows certificate store,
      // and Kubernetes Secrets — none of which the agent binary can collect — so
      // an agent advertising nothing still rendered as covering a Windows estate.
      // The fallback is deleted; the panel now says nothing is advertised.
      // Reviewed for meaning in all three locales.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // B4 re-pin: eighteen protocols.eab.* keys for the ACME external-account-
      // binding operator panel — scope, quota, usage counters, the disable/enable
      // verbs, the two distinct empty states (ACME not mounted vs no credentials
      // configured), and the sentence stating that rotation stays a configuration
      // operation because trstctl will not return a shared MAC secret over the
      // API. Reviewed for meaning in all three locales; the count placeholders in
      // the quota and usage strings are preserved.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // C5 re-pin: seventeen keys give certificate-transparency monitoring its own
      // headline surface on Discovery instead of one number in a tile shared with
      // drift — the watchlist, per-log checkpoint state, unexpected-issuance
      // findings with a hand-off to remediation, and the coverage-honesty
      // sentence stating that only the configured domains and logs are covered.
      // The drift panel keeps its own title now that CT is unbundled from it.
      // Reviewed for meaning in all three locales; the coverage-honesty and
      // empty-state strings must keep their negation, and the {count}/{value}
      // placeholders are preserved.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // B1 re-pin: seven keys for the CSR-first request form — the field label,
      // the help text stating that pasting a CSR is the fallback for a host with
      // no agent (where an agent is enrolled it generates the key and submits the
      // request itself), the openssl command that produces one, the sentence
      // naming what happens if you leave it empty, and the invalid-paste hint.
      // Reviewed for meaning in all three locales; the help and "omitted" strings
      // must keep their qualifications, and the openssl command plus the PEM
      // header stay byte-identical everywhere because they are protocol literals.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // A1 re-pin: nine keys for the agent job ledger panel on Operations —
      // per-kind waiting/held counts, the oldest-wait column that distinguishes a
      // drained queue from a stalled one, and the two distinct empty states
      // (channel not mounted vs no kind enabled) so zeros are never ambiguous.
      // Reviewed for meaning in all three locales; both empty-state strings must
      // keep their explanation of which case the operator is looking at.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      "es-ES": "bd84ad5c1ba5bb620ce61da4bf1954e041777d117646f09ca91e326f15853388",
      "de-DE": "9fca96232243704b878a4a30f0fb5fe5f6a895e9b037f9625ffb282a3dd2fe72",
    });
  });

  it("blocks new hard-coded UI strings outside the extracted catalog", () => {
    // DA-14 is closed as a CLASS, not a count: the AST ratchet found zero
    // hardcoded user-facing strings, and the budget is pinned there forever.
    expect(extractedDebtBudget.maxExtractedMessages).toBe(0);
    expect(extractedMessages.length).toBe(0);
    expect(extractedDebtBudget.maxExtractedMessages).toBe(extractedMessages.length);
    expect(extractedDebtBudget.maxExtractedMessages).toBeLessThan(1273);
    expect(extractedDebtBudget.maxExtractedMessages).toBeLessThanOrEqual(1300);
    execFileSync(process.execPath, [path.resolve(process.cwd(), "scripts/extract-i18n-messages.mjs"), "--check"], {
      cwd: process.cwd(),
      stdio: "pipe",
    });
  });
});
