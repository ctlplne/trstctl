import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { ThemeProvider } from "@/components/ThemeProvider";
import { IntlProvider, directionForLocale, formatMessage, negotiateLocale, useTranslation } from "@/i18n/I18nProvider";
import { formatDate, formatNumber, formatPlural } from "@/i18n/format";
import extractedDebtBudget from "@/i18n/extractedMessages.budget.json";
import { extractedMessages } from "@/i18n/extractedMessages.gen";
import {
  buildTranslatedCatalog,
  defaultLocale,
  defaultTimeZone,
  eagerCatalogs,
  lazyCatalogLoaders,
  messages,
  productionLocales,
  pseudoLocalize,
  type MessageKey,
} from "@/i18n/messages";
import esESRuntimeValues from "@/i18n/catalog.es-ES.runtime.gen.json";
import deDERuntimeValues from "@/i18n/catalog.de-DE.runtime.gen.json";

// S-C10: es/de are lazy per-locale modules now. The guards below still audit
// the FULL catalogs (parity, placeholders, digests), so load them explicitly —
// the digest pins must not move on a split, only on reviewed string changes.
const catalogs = {
  ...eagerCatalogs,
  "es-ES": (await import("@/i18n/catalog.es-ES")).default,
  "de-DE": (await import("@/i18n/catalog.de-DE")).default,
} as const;
const runtimeCatalogs = {
  "es-ES": buildTranslatedCatalog(esESRuntimeValues),
  "de-DE": buildTranslatedCatalog(deDERuntimeValues),
} as const;
import { contextualRouteItems, navGroups, taskNavItems } from "@/lib/navigation";

// These tests render shell chrome without an AuthProvider, so useAuth falls back
// to the null-user default context. They previously depended on hasPermission
// failing open to render the permission-gated navigation they inspect; that
// fail-open is fixed, so the fully-permitted operator these tests always meant to
// exercise is now stated explicitly. ("*" is how unrestricted is expressed.)
vi.mock("@/auth/AuthProvider", async (orig) => {
  const actual = await orig<typeof import("@/auth/AuthProvider")>();
  return {
    ...actual,
    useAuth: () => ({
      user: {
        subject: "test-operator",
        tenant_id: "t1",
        email: "operator@example.test",
        roles: ["admin"],
        permissions: ["*"],
      },
      loading: false,
      error: null,
      preview: false,
      previewAvailable: false,
      startPreview: () => {},
      logout: async () => {},
    }),
  };
});

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

function stubRuntimeCatalogFetch(): () => void {
  const originalFetch = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const values = String(input).includes("de-DE") ? deDERuntimeValues : esESRuntimeValues;
      return new Response(JSON.stringify(values), { status: 200, headers: { "content-type": "application/json" } });
    }),
  );
  return () => vi.stubGlobal("fetch", originalFetch);
}

describe("i18n boundary", () => {
  it("generates byte-identical compact runtime catalogs from the reviewed keyed sources", () => {
    expect(runtimeCatalogs["es-ES"]).toEqual(catalogs["es-ES"]);
    expect(runtimeCatalogs["de-DE"]).toEqual(catalogs["de-DE"]);
  });

  it("fails closed when a runtime catalog is unavailable or structurally stale", async () => {
    const originalFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("unavailable", { status: 503 })),
    );
    await expect(lazyCatalogLoaders["es-ES"]()).rejects.toThrow("HTTP 503");

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify([null]), { status: 200, headers: { "content-type": "application/json" } })),
    );
    await expect(lazyCatalogLoaders["de-DE"]()).rejects.toThrow("translated catalog has 1 values");
    vi.stubGlobal("fetch", originalFetch);
  });

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
    expect(within(nav).getByText(pseudoLocalize("Home"))).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "?" });
    // The shortcuts dialog title went through the DA-14 sweep, so under the
    // pseudo-locale its accessible name is pseudo-localized like all shell copy.
    expect(screen.getByRole("dialog", { name: pseudoLocalize("Keyboard shortcuts") })).toBeInTheDocument();
  });

  it("renders real Spanish page chrome and lets the operator switch locale in memory", async () => {
    const restoreFetch = stubRuntimeCatalogFetch();
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
    expect(within(nav).getByText("Inicio")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cuenta y preferencias" }));
    const selector = screen.getByRole("combobox", { name: "Idioma" });
    expect(selector).toHaveValue("es-ES");
    restoreFetch();

    fireEvent.change(selector, { target: { value: "en-US" } });
    expect(screen.getByText("Needs action")).toBeInTheDocument();
  });

  it("swaps English fallback for the lazy catalog after an in-session locale switch (S-C10)", async () => {
    const restoreFetch = stubRuntimeCatalogFetch();
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
    fireEvent.click(screen.getByRole("button", { name: "Account and preferences" }));
    fireEvent.change(screen.getByRole("combobox", { name: "Language" }), { target: { value: "de-DE" } });
    // English serves until the de catalog module resolves; then the tree
    // re-renders translated.
    expect(await screen.findByText("Aktion erforderlich")).toBeInTheDocument();
    expect(screen.queryByText("Needs action")).not.toBeInTheDocument();
    restoreFetch();
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
    expect(formatMessage("command.routeDescription", { group: "Platform" })).toBe("Page · Platform");
    expect(formatMessage("command.routeDescription", { group: "Plataforma" }, "es-ES")).toBe("Página · Plataforma");
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
      // QA design g15 re-pin: the machine-identity journey now uses a
      // search-first operator answer, translated human credential and owner
      // labels, calm delivery summaries, and progressive exact evidence.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // F37 re-pin: the effect-free rotation review, stale-plan warning,
      // execution boundary, recovery explanation, and exact plan labels are
      // translated. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // QA product g13 re-pin: the Spanish tool-health explanation now says
      // "the system" instead of the ordinary Spanish word that the source-debt
      // oracle reads as an English marker. Meaning and fail-honest tone reviewed.
      // QA design g16 re-pin: the discovery journey now names the operator goal,
      // puts findings before scan machinery, translates human credential kinds,
      // and keeps raw monitoring and finding evidence behind named disclosures.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g17 re-pin: the risk journey now leads with the translated
      // What-to-fix-first decision, human credential and reason labels, one
      // review action, and separate exact/supporting evidence disclosures.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // F65 re-pin: the dynamic-secret journey replaces the retired free-text
      // form with translated choose/review/use-and-retire steps, exact effect
      // and recovery copy, and reveal-once custody warnings. Retired source.*
      // strings were removed. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA product g40 re-pin: cross-system discovery now explains the complete
      // six-surface evidence rule, progress, valid sample, and all missing
      // surfaces in one response. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA design g17 live-polish re-pin: operator-facing impact language now
      // uses a simple known-item count, moves the exact component breakdown
      // behind the evidence disclosure, and removes blast-radius jargon from
      // the screen-reader caption. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA design g26 re-pin: the cryptography route now leads with the
      // upgrade decision, uses a plain-language worklist, and moves scanner,
      // compatibility, PQC, authority, and drift machinery behind three named
      // disclosures. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // AUD-58 Provider workforce re-pin: twenty-two keys label SAML sign-in,
      // SCIM lifecycle, exact customer/operation grants, expiry, last use, and
      // retained revocation evidence. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // AUD-59 Provider billing re-pin: twenty-one keys label customer/period
      // selection, billable and reconciliation truth, independent signature
      // verification, digest, and signed-JSON/finance-CSV downloads. The
      // negation in not-billable, verification-failed, unsigned, and
      // unreconciled must survive translation. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // AUD-60 Provider health re-pin: ten keys label loading, unknown,
      // unavailable, lifecycle-derived health, and tenant-confined active
      // certificate counts. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA design g27 re-pin: SSH and Secrets now expose one operational task
      // at a time, while exact SSH state and every previously served workflow
      // remain reachable. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA design g28 re-pin: the CA overview now uses a compact status strip,
      // keeps discovery and issuance evidence collapsed, and treats a disabled
      // optional external registry as expected absence. Machine-authored es/de
      // — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // QA design g28 cleanup: three source-extracted strings retired with the
      // old SSH authority label and two always-visible CA row actions were
      // removed from all catalogs after the unused-message oracle proved that
      // no rendered surface still references them.
      // AUD-37 AD CS evidence re-pin: twenty-three keys expose configured IIS
      // probes, CA restriction unknown-state honesty, exact endpoint evidence,
      // signed compliance references, and an explicit private-CIDR SSRF
      // boundary. Technical endpoint-kind tokens, CIDRs, and HTTP stay
      // byte-identical. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // AUD-41 incident-wave re-pin: reviewed keys explain the retired direct
      // mutation, plan-first order, and separately authorized game-day boundary.
      // B5 custody re-pin: two source.custody.* keys add the per-certificate key
      // custody line, including the sentence that says unrecorded is not the
      // same as safe. Machine-authored es/de - FLAGGED FOR HUMAN REVIEW.
      // F3 evidence re-pin: one source.adcs.evidence key renders the attributes
      // and values a finding was derived from, so an operator can check it
      // against the template's own property page instead of taking it on faith.
      // Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // D3 re-pin: six source.*.d3tri* keys add the deployment-truth panel —
      // delivered, verified serving, serving something else, and not checked.
      // The last one is the honest middle and had to be named rather than
      // folded into either side. Machine-authored es/de - FLAGGED FOR HUMAN
      // TRANSLATION REVIEW.
      // D2 re-pin: eighteen source.*.d2ver* keys add the endpoint verification
      // section — what each listener is actually SERVING, per vantage, with the
      // comparisons that actually ran and a "never verified" that reads as the
      // strong statement it is. Machine-authored es/de - FLAGGED FOR HUMAN
      // TRANSLATION REVIEW.
      // QA product g50 re-pin: twenty-six ACME operator-plan keys explain
      // readiness, the effect-free preview, the one safe next action, and
      // recovery. Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // B7 second-pass re-pin: three findings the refuters had dismissed turned
      // out to be right — a failed freshness read rendered identically to a
      // healthy deployment, timestamps bypassed the locale/timezone policy every
      // other panel in that file uses, and the docs overstated the publish
      // bound. The two new keys are the failed-read state, which has to say
      // plainly that it is not evidence of health. Machine-authored es/de -
      // FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // B7 review re-pin: the adversarial pass found the never-validated count
      // had no singular form ("1 identifiers"), the DNS-01 consent flag was not
      // in the edit dialog at all (a PUT silently revoked it), and the
      // capability columns rendered "matrix unavailable" for every authority
      // because they keyed on Issuer.kind. Fixing those added a one/many pair,
      // the consent toggle and its explanation, and the internal-authority
      // answers. Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // B7 staleness re-pin: ten protocols.dns01.upstream* keys add the
      // upstream authorization freshness panel — when each identifier last
      // actually proved control, as against when it last rode a reuse the
      // install did not earn. Machine-authored es/de - FLAGGED FOR HUMAN
      // TRANSLATION REVIEW.
      // B7 upstream DV re-pin: three source.*.b7dv* keys add the issuer
      // domain-validation column — whether trstctl can satisfy this authority's
      // DCV challenge with nobody in the loop, which is the question the
      // shrinking CA/Browser Forum reuse window turns into an operational one.
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
      // AUD-180 target-timeline re-pin: deploy, listener verification, and
      // rollback evidence keep their order and target placeholder while the
      // Spanish and German copy drops the internal served-API phrase.
      // Posture follow-up: the localized crypto inventory separator preserves
      // its leading space so adjacent algorithm and transport text stays clear.
      // Discovery-coverage re-pin: eight discovery.coverage.* keys (panel
      // heading, caption, three-bucket summary, table headers, observed-by and
      // unavailable copy) land with machine-authored es/de translations -
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // D-7806a198 adds the isolated-preview banner and sample-playbook copy,
      // and removes "served" implementation jargon from CA health copy.
      // F26 custody re-pin: the reviewed three-step HSM/KMS journey now names
      // all six providers, startup-only secret-reference requirements, the
      // zero-effect preview, exact blockers, execution effects, and proof.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW.
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
      // F9 audit-feed review re-pin: the new copy distinguishes a zero-effect
      // preview from the later durable write and still-later collector call,
      // invalidates stale reviews after an edit, and explains automatic retry
      // without cursor advancement. Machine-authored es/de translations —
      // FLAG FOR HUMAN TRANSLATION REVIEW before release.
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
      // J1 audit-export re-pin: six source.export.format.* / source.format.*
      // keys name the export encodings. Format names (NDJSON, CSV, Splunk HEC,
      // Microsoft Sentinel) are product nouns and stay untranslated in all three
      // locales on purpose — a localized "NDJSON" would not match what the
      // operator's ingest pipeline calls it.
      // H1 trust re-pin: three source.trusted.by.* keys carry the "N stores
      // across M hosts" headline and the empty state. The empty state's meaning
      // is load-bearing and must survive translation: it says no scanned store
      // carries this anchor, NOT that nothing trusts the CA.
      // H2 migration re-pin: twelve source.migration.* keys. The read-only
      // sentence must keep saying that nothing is distributed, issued or
      // deployed, and the counts line must stay a count rather than becoming a
      // readiness percentage in any locale.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // I1 ownership re-pin: two source.unowned.* keys. The counts string must
      // keep its three separate numbers in every locale — collapsing them into a
      // total would lose the only information that makes the queue actionable.
      // H4 retirement re-pin: fourteen source.retirement.* keys. The cleared
      // state must keep saying the SIGNER mints the record, the unavailable
      // state must forbid a destruction decision, and the confirmation must say
      // the signer-held key is permanently destroyed. Machine-authored es/de —
      // FLAG FOR HUMAN TRANSLATION REVIEW.
      // I2 ownership-provenance re-pin: eleven keys. Five say whether ownership
      // is actually being re-read from the CMDB, including the two states that
      // otherwise look exactly like a healthy sync — paused, and failing. Four
      // carry the disagreement queue and say for each row whether the change was
      // REFUSED or APPLIED, because a list whose entries all read like completed
      // work is worse than no list. Two render where an ownership claim came
      // from, and an owner with no recorded origin says "not recorded" rather
      // than "manual" in every locale — absence of provenance is not evidence a
      // human said so, and a translation that blurred that would undo the point
      // of the column. One M2 key was folded in at the same time: "via" was a
      // hardcoded literal the extractor caught.
      // I3 issuance-request re-pin: four keys for the request queue. Every state
      // is named rather than folded into open/closed, and "expired" says
      // "nobody decided" in all three locales — an expiry is the ABSENCE of a
      // decision, and a translation that rendered it as a decision would put a
      // judgement in the record that no human made.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // I5 MDM re-pin: three keys. The load-bearing one says an unobserved
      // device is NOT a failed one, in every locale — a translation that
      // rendered "unknown" as a failure would send an admin to re-push a
      // profile that is already installed, and the counts are deliberately
      // separate for the same reason.
      // A5 rollout re-pin: four keys. HALTED and PAUSED must read differently in
      // every locale — one is the machine's finding that a build is bad, the
      // other a person stopping deliberately, and an operator resuming a pause
      // they made must not silently resume a halt they never saw. The halted
      // string also says a resume restarts AT that ring, not past it.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // I2 conflict-resolution re-pin: two keys for the resolve control. The
      // reason field's label says REQUIRED in every locale, because a
      // resolution with no explanation tells the next reader nothing about
      // which side was right — and a translation that dropped the requirement
      // would let an operator try, be refused by the route, and learn the rule
      // from an error instead of the form.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // L2 invoice-evidence re-pin: fourteen platform.usageEvidence.* keys for
      // the usage panel. The two that carry weight are the billable /
      // not-billable badge labels: a locale that rendered an unsignable period
      // as billable would hand a finance team an invoice figure the system
      // itself refuses to stand behind, and the panel's whole design is that
      // the verdict is read before the numbers. The description says a period
      // the metering store could not cover end to end is a partial view rather
      // than an invoice, in every locale.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // A5 dispatch re-pin: two source.fleet.upgrade.* keys separate an
      // observe-only campaign from a dispatching one. The distinction is the
      // point: a gating campaign that reads as a pushing one looks like a
      // rollout that hangs, and an operator would "fix" it by pushing builds
      // around the rings the campaign exists to run.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // L2 attestation re-pin: five platform.usageEvidence.* keys for the
      // reconciliation lines and the signature state. The two that carry
      // weight are `diverged` (both numbers named, so an operator can chase
      // the gap) and `unsigned` (an unsigned document must not read as
      // attested — the absence is itself information).
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // I2 relay-vantage re-pin: one source.cmdb.sync.relay key saying which
      // machine performed the read — an operator debugging a relay-mode sync
      // against firewall logs needs to know the request never left the
      // segment.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // I5 offline-renewal re-pin: one source.mdm.devices.renewalrisk key.
      // The sentence has to say NOTHING HAS FAILED YET in every locale — the
      // whole hazard is a green dashboard over a certificate expiring in a
      // drawer, and a translation that reads as a failure alert would send
      // operators hunting for an error that does not exist.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // L3 provider-console re-pin: twenty-one source.provider.* keys for the
      // operator-authenticated provider console (customer list, provision, suspend,
      // offboard). The suspend/offboard confirmations carry the safety story: one
      // click changes a whole customer's world, so each is a confirmed action.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // F4 AD CS certificate-database re-pin: thirteen source.adcs.* keys for the
      // certificate-database panel. Two sentences carry the safety story: PENDING is
      // not FAILED (approval, not resubmission), and 'gaps' count rows the ingest could
      // not fully read so a collection problem never reads as an empty or healthy CA.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // B6 edge-delegation re-pin: fifteen source.edge.* keys for the
      // delegated edge sub-CA panel. Two sentences carry the safety story and
      // must survive review intact in every locale: default-OFF as the healthy
      // baseline (an empty list is the design, not a gap), and the journal
      // honesty rule — an air-gapped host's silence is absence of evidence,
      // never evidence of inactivity.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // L3 isolation-drill re-pin: five source.provider.drill.* keys add the
      // provider console's on-demand tenant-isolation drill — its heading and
      // admin-only description, the run action, and the pass/fail results. The
      // fail line reads as the imperative it is ("investigate immediately")
      // rather than a neutral status. Machine-authored es/de — FLAG FOR HUMAN
      // TRANSLATION REVIEW.
      // AUD-33 E1 status re-pin: the existing source.cp.retained.* key now labels
      // the three open architecture exceptions as warnings, not terminal design
      // choices. The six unimplemented accepted rows use source.not.migrated.*.
      // Machine-authored es/de —
      // FLAG FOR HUMAN TRANSLATION REVIEW.
      // I5 trace-detail re-pin: one punctuation-format key keeps the durable
      // step detail inside the typed catalog. The em dash and placeholder are
      // intentionally byte-identical in every locale; no prose was translated.
      // AUD-76 compliance-evidence re-pin: eight policy.compliance.* keys name
      // the tenant/window binding, exact immutable refs, and missing evidence.
      // “Unbound” and “Unknown” must retain their absence semantics so a legacy
      // pack cannot render as tenant-bound or complete. Machine-authored es/de
      // translations — FLAG FOR HUMAN TRANSLATION REVIEW.
      // AUD-77 import-unavailable re-pin: four secrets.import.* keys explain
      // why bulk import stays fail-closed and direct operators to individually
      // idempotent creates. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-106/AUD-107 scheduler-truth re-pin: the rotation scope, schedule
      // limits, queued/completed/failed outcomes, and exact deferred-edge
      // reasons now stay distinct in every locale. In particular, queued must
      // not read as completed, and approval-pending/claimed work must not read
      // as a failed rotation. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-115 client-boundary re-pin: one deferred-reason key names the
      // pre-evidence schedule state that requires an operator to re-save its
      // configuration. The translations preserve that required action and do
      // not describe the row as failed. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-28 relay-discovery re-pin: ten discovery.source/run keys name
      // the declared segment, optional exact relay selector, execution binding,
      // and verified terminal executor. “Unbound” must remain an absence state,
      // and control-plane execution must not translate as relay execution.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-35 AD CS inventory re-pin: source creation, exact network-relay
      // selection, reference-only bind credentials, source lifecycle, and the
      // enrollment-principal SID column are named in every locale. The console
      // stays TLS-verifying; the lab-only API override remains documented.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-40 executable-migration re-pin: the manifest now names one exact
      // signer-backed authority instead of accepting pasted certificate text,
      // the review labels that authority, and each wave names its signed
      // trust-plus-live verification denominator. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-44 ownership-readiness re-pin: the owner-depth fields, attributed
      // attestation state, stale-owner queue, and temporary exception workflow
      // now have reviewed catalog entries. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-51 audit-export re-pin: eight audit.export.* keys name the saved
      // RFC 3161 proof status, authority time, chain head, and honest offline
      // verification guidance. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-54 signed-drill-history re-pin: six platform.dr.history.* keys name
      // durable evidence, completion time, exact signer, signature state, and
      // download action. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW BEFORE RELEASE.
      // AUD-25 custody-evidence re-pin: seven policy.compliance.custody* keys
      // name complete versus incomplete custody and the exact missing fields.
      // The es/de wording preserves that incomplete means missing evidence,
      // never a safe or inferred custody state. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-26/AUD-123 edge-custody re-pin: eight source.edge.* keys name
      // TPM-backed, PKCS#11-backed, and deliberately exceptional software
      // custody. The wording must not translate a host-attested PKCS#11
      // operator claim into TPM same-key proof, or an exportable software key
      // into hardware custody. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-34 relay-plugin-census re-pin: fifteen connectors.relayPlugins.*
      // keys name certificate-verified evidence, metadata-only handling,
      // effective grants, and the explicit no-loaded-plugins state. The es/de
      // wording keeps "signed" distinct from merely reported and never calls
      // module bytes catalog data. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-36 AD CS semantic-drift re-pin: nine source.adcs.drift.* keys
      // name immutable before/after history, dangerous lifecycle facts, and
      // say explicitly that only a worsening change creates a notification.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-39 revocation-cache re-pin: twenty-eight keys name per-segment
      // CRL/OCSP freshness, issuer-signature evidence, traffic, and the honest
      // unobserved state. “No report” must not become “healthy,” and stale must
      // remain distinct from empty in every locale. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-46 CMDB pagination re-pin: four keys name the read/expected/page
      // denominator, distinguish an unavailable total, reserve “complete” for
      // the terminal page, and say that an incomplete cursor survives for the
      // next relay page. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-52 native collector-feed re-pin: fifty-four keys explain exact
      // Splunk/Sentinel batches, durable cursor/lag/retry/failure receipts,
      // credential references, private-egress controls, and every form state.
      // Product names, example URLs, env references, IDs, and numeric bounds
      // stay byte-identical. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-56 pricing-entitlement re-pin: fifteen platform.editions.* keys
      // name the five published price bands, the signed deployment environment,
      // production-unit consumption, and remaining bundled non-production slots.
      // Currency, counts, and placeholders stay exact. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-65 crypto-readiness re-pin: thirteen keys name the canonical
      // dataset digest, graph-bound actions, stale-topology refusal, and signed
      // CSV/NDJSON exports. The translations keep unknown distinct from safe
      // and stale distinct from completed. Machine-authored es/de — FLAGGED
      // FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-67 canonical urgent-risk re-pin: fifteen keys distinguish the
      // all-projection count, its two named sources, loading, and unavailable
      // authority. "Unavailable" must never collapse to a translated zero.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-69 safe Explorer re-pin: thirty-eight keys label editable path,
      // query, header, and JSON inputs; exact-request review; validation;
      // cancellation; and expired/revoked token truth. Protocol tokens such
      // as UUID, RFC3339, JSON, OpenAPI, and Idempotency-Key stay exact.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // AUD-70 CT replacement re-pin: five keys distinguish per-log success,
      // per-log failure, bounded diagnostic detail, and retired audit history
      // that is explicitly not polled. Machine-authored es/de; human review is
      // required before release.
      // AUD-78 owner-selector re-pin: eight keys replace the false session-
      // principal prefill with explicit tenant-owner selection, unavailable
      // and empty roster states, searchable name/kind/email/UUID filtering,
      // and actionable recovery. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // QA g35 login-truth re-pin: two keys replace the broken SSO action on
      // OIDC-disabled installs with explicit setup/API-token guidance.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // QA g57 unavailable-state re-pin: three strings that were previously
      // hard-coded now use typed keys for privileged access, MCP tools, and
      // the external-CA registry. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // Quiet-confidence foundation re-pin: the seven shared page-depth keys
      // label Answer, Do next, and Technical details without hiding exact
      // evidence; the account key groups mobile identity and preferences.
      // The Home/first-run extension adds an honest attention sentence,
      // inline estate summary, optional metrics depth, selected-journey proof,
      // and simpler first-run outcome. The operator-facing Dashboard and
      // Journeys labels are now the plainer Home and Guided setup. Placeholders
      // and negations are retained.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // Checkpoint 5 certificate-language re-pin: the certificate workspace now
      // names request methods, rules, authorities, and software signing in
      // task-first language. Four new primary actions and the reviewed label
      // changes are mirrored in es/de. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release. The live-browser follow-up
      // also distinguishes an empty DNS-01 or MDM policy list from a failed
      // load and gives the operator the next safe setup step.
      // Checkpoint 7 issuance-decision re-pin: seventeen keys turn the visible
      // request queue into an actionable, permission-aware approval, denial,
      // and withdrawal workflow. Every locale preserves the load-bearing
      // distinction that an approval has been recorded but no certificate has
      // been minted yet. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // Checkpoint 9 issuance-fulfillment re-pin: five keys explain the secure
      // approved-to-issued bridge, its required permissions, signer-backed
      // evidence, and a retryable not-ready state without claiming that an
      // approval itself minted a certificate. Machine-authored es/de — FLAGGED
      // FOR HUMAN TRANSLATION REVIEW before release.
      // Secrets quiet-confidence re-pin: the six workspaces now ask one plain
      // operator question, name one next action, and describe accurate reveal,
      // destination, scanner, and lifecycle boundaries. Machine-authored es/de
      // translations — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Workload/SSH quiet-confidence re-pin: twenty-four keys state the setup
      // prerequisite, distinguish ready from disabled, name the safe next
      // action, disclose exact evidence progressively, and make clear that an
      // SSH rollout form records evidence rather than running host commands.
      // The full vocabulary oracle then replaced the internal "served
      // workflow" phrase with the customer-facing "workspace" in all locales.
      // The docs debt-marker oracle also required the Spanish dashboard copy
      // to avoid an ordinary word that is byte-identical to a debt marker.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g18 Security-incidents re-pin: new keys name the
      // responder's three immediate questions, distinguish loading, failed,
      // empty, individual, and fleet evidence without guessing, pluralize
      // affected credentials and failed targets, and focus the translated
      // Continue-response action. The navigation label changes with the route.
      // A collapsed exact-state proof now names the event timeline, missing
      // approval record, idempotency key, evidence bundle, replacement,
      // revocation, delivery, failed targets, and rollback references without
      // turning absent evidence into a success claim.
      // The live visual follow-up replaces the owner-remediation API status
      // "served" with the plain Queue-loaded evidence state in every locale.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g20 Jobs-and-queues re-pin: the route now leads with failed
      // and waiting work, one translated review action, responsive job cards,
      // and three named evidence disclosures. Exact attempts, queue limits,
      // payload IDs, failure reasons, rollback references, and event-log links
      // stay available without exposing raw identifiers in the decision path.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g23 Jobs-and-queues evidence re-pin: an absent rollback
      // reference now says Not recorded instead of silently removing the
      // field. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW
      // before release.
      // QA design g25 Jobs-and-queues live-polish re-pin: the visible action is
      // the short Review/Prüfen/Revisar inside a card that already names the
      // job; its accessible name still includes the exact human job label.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g27 re-pin: the credential-graph journey now starts with the
      // affected-systems answer, keeps relationship evidence behind named
      // disclosures, and names source, confidence, coverage limits, and export.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g28 re-pin: the migration journey now names cutover
      // readiness, incomplete-plan rejection, source mappings, dual-run trust
      // evidence, retained wave evidence, and explicit rollback confirmation.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g29 re-pin: the Ownership journey now starts with the
      // accountable-team answer and exact live coverage counts, exposes one
      // assign action, and keeps records, bounded exceptions, provenance,
      // disagreements, and review history behind three named disclosures. A
      // genuinely empty inventory stays distinct from complete ownership.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g30 re-pin: the Agents journey now answers online,
      // certificate-bound trust, and current heartbeat/version evidence before
      // exposing enrollment, revocation, offboarding, upgrade, queue, Workload
      // API, enrollment-proxy, and endpoint-discovery machinery. Unknown trust
      // or service reports remain unknown rather than reading as healthy.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g31 re-pin: the deployment-destination journey now answers
      // configured and verified coverage first, names the one safe add action,
      // and keeps target mutation, health/retry/rollback, and connector/plugin
      // evidence behind three translated disclosures. Unconfigured endpoints
      // and unused connector capabilities cannot inflate the opening claim.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g32 re-pin: Rules and approvals now answers verified
      // fail-closed protection, custom-rule state, recorded changes, and
      // pending access decisions before exposing rule history, safe testing,
      // framework evidence, and review machinery. Failed opening APIs render
      // unknown rather than healthy. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // QA design g33 re-pin: Requests waiting for approval now leads with the
      // requested change, reason, and consequence; keeps immutable evidence,
      // policy result, dual-control history, and specialized tools behind
      // named disclosures; and gives wide data-grid viewports their own
      // localized keyboard-scroll label. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // QA design g34 re-pin: Alerts and delivery now explains the
      // event-to-recipient path, safe channel boundary, routing/outbox model,
      // dead-letter evidence, and the honest fixed-template limitation in
      // every production locale. Machine-authored Spanish and German remain
      // flagged for human language review.
      // QA design g34.1 live-polish re-pin: the empty routing form no longer
      // presents invented channels or ownership as saved-looking defaults;
      // every locale names the no-ready-channel boundary and the exact safe
      // next step. Machine-authored Spanish and German remain flagged for
      // human language review.
      // QA design g35 re-pin: Change history now answers who changed what,
      // when, and whether the last event shown records an outcome; it keeps
      // the explicit not-newest/not-complete bounded-window warning, search,
      // immutable signatures/exports, retention boundary, and collector
      // delivery explicit in every locale.
      // Machine-authored Spanish and German remain flagged for human language
      // review.
      // QA design g36 re-pin: Evidence privacy now names the exact read/write
      // permission boundary, per-entry retention, direct-data removal and
      // archive proof before exposing the policy map, subject rights, archive
      // attestations, or retention jobs. Its sidebar label and keyboard-scroll
      // regions use the same reviewed language. Machine-authored Spanish and
      // German remain flagged for human language review.
      // QA design g37 re-pin: Connect other tools now explains inbound,
      // outbound, and repeatable automation paths before exposing enrollment,
      // SDK, IaC, GitOps, permission, plugin, webhook, and durable-delivery
      // evidence. The real-workflow chooser and route label use the same
      // production-locale language. Machine-authored Spanish and German remain
      // flagged for human language review.
      // QA design g38 re-pin: API playground now explains a safe request,
      // temporary least-privilege access, result-first responses, recovery,
      // and progressive exact request/schema evidence in all production
      // locales. The full-suite vocabulary follow-up replaces the internal
      // "served contract" phrase with an available-request explanation.
      // Machine-authored Spanish and German remain flagged for human language
      // review before release.
      // QA design g39 re-pin: Product help now opens with one plain-language
      // question action, names its source/permission/privacy/reference
      // boundaries, and loads runtime or MCP expert detail only on demand.
      // Spanish and German preserve the read-only and tenant-role negations.
      // Machine-authored translations remain flagged for human language review.
      // QA design g40 re-pin: People and roles now leads with the plain answer,
      // reads only the required roster and role catalog by default, and keeps
      // exact SSO, permission, access-key, privileged-session, certification,
      // destructive-confirmation, and durable-readback language behind named
      // disclosures or focused dialogs. PostgreSQL, SSH, tenant_id, RLS, and
      // base64 remain byte-identical technical nouns. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // QA design g40 vocabulary re-pin: customer copy now says available or
      // configured and confirms changes in the current roster; internal
      // served/not-served API language remains outside the rendered journey.
      // Machine-authored translations remain flagged for human review.
      // QA design g40 role-choice re-pin: Add person now offers explicit
      // catalog-backed choices and fails closed with a refresh instruction
      // when no current role exists; nobody must type internal role syntax.
      // Machine-authored translations remain flagged for human review.
      // QA design g40 live-security re-pin: the optional privileged-access
      // failure now uses static ELI5 guidance instead of rendering an
      // unrestricted backend 503 detail. People, roles, and key metadata are
      // explicitly named as still working. Machine-authored translations
      // remain flagged for human review.
      // QA design g41 re-pin: System health now states whether the control
      // plane is securely configured, names unknown and attention states,
      // keeps configuration/dependency/exception evidence intentional, and
      // never turns a failed read into a readiness claim. Machine-authored
      // translations remain flagged for human language review.
      // QA design g41 privacy re-pin: request failures in the lazy custody and
      // usage-evidence panels now give generic next steps without echoing
      // backend paths, traces, credentials, or connection strings. Genuine
      // served lifecycle evidence remains exact. Machine-authored translations
      // remain flagged for human language review.
      // QA design g42 re-pin: Plan and license now gives the current plan,
      // enabled-feature count, signature state, and expiry before exact
      // feature and entitlement evidence; safe installation, fail-closed
      // recovery, and lazy architecture proof keep their security qualifiers.
      // Machine-authored translations remain flagged for human language review.
      // QA design g42 size re-pin: repeated labels reuse the existing reviewed
      // vocabulary, while concise install and evidence copy keeps every
      // signature, custody, binding, process-agreement, and recovery boundary.
      // The same repair removes 111 source-unreferenced historical messages;
      // the permanent source-reference gate proves no reachable value dropped.
      // QA design g42 protected-journey re-pin: the regional-issuance evidence
      // again says that follower regions serve projected reads while exactly
      // one region may write for a tenant. Machine-authored es/de — FLAGGED
      // FOR HUMAN TRANSLATION REVIEW before release.
      // QA design g43 Route 003 re-pin: the API-free Platform setup doorway
      // names the three production-readiness boundaries and sends operators
      // to the separately scoped access, health, and signed-license pages.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA design g43 final-language re-pin: Home and guided setup now name the
      // actual next action, Workloads and SSH explain who or what receives a
      // short-lived identity, and the protocol/SSH page names stay identical in
      // the rail, H1, and browser title. Every safety qualifier remains intact.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // Quiet-confidence shell re-pin: each product space now asks its plain-
      // language operator question, and wizard progress offers the nearby
      // steps first while preserving the complete sequence on request.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // Quiet-confidence working-view re-pin: task search uses outcome-first
      // verbs, and the certificate inventory gives a one-sentence weekly
      // answer before progressive table controls. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Quiet-confidence live-interaction re-pin: an empty incident history
      // now says Start response; a recorded history still says Continue
      // response. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // Quiet-confidence v3 re-pin: setup paints only three recommended paths,
      // secret metadata/actions use translated progressive disclosure, and
      // incident evidence leads with a plain tamper-evidence promise. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Quiet-confidence v4 re-pin: advanced secret administration closes by
      // default while remaining one click away. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Quiet-confidence v5 re-pin: identity lifecycle and fleet-wide
      // decommission controls now disclose progressively, while the one-click
      // valid next actions stay translated. The retired internal "state
      // machine" heading is removed. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // Quiet-confidence v6 re-pin: the two secondary administration links
      // are named by one quiet More disclosure, and the first-use journey says
      // plainly that integrations and an agent can be deferred. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Quiet-confidence protocol re-pin: the default protocol journey now
      // explains which method fits each machine, while responder paths and
      // exact setup evidence stay available in the operations disclosure.
      // Dashboard risk reasons and task-list descriptions use plain language.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // Quiet-confidence cold-evaluator re-pin: page recovery, optional
      // integration availability, protocol readiness, capacity references,
      // ownership evidence, and renewal models now say exactly what the
      // system knows without implying success. Machine-authored es/de
      // translations — FLAG FOR HUMAN REVIEW.
      // Certctl-informed product carve: reviewed space labels and the new
      // Trust Operations cockpit keep urgency, ownership, alert delivery, and
      // unknown-state language explicit. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // Certificate Lifecycle cockpit re-pin: expiry, renewal, deployment,
      // ownership, alert-route, action-queue, and chart-table copy is present
      // in all production catalogs. Negations around unavailable evidence and
      // human receipt remain explicit. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // Runtime-asset re-pin: reviewed es/de values now load as same-origin
      // JSON only when selected, so translated copy no longer consumes the
      // JavaScript parse/compile budget. Six superseded certificate-strip keys
      // and duplicate cockpit labels were retired after source search and the
      // catalog parity oracle proved them unreachable.
      // Work-arrival range re-pin: the inclusive day-window label is now
      // explicit production copy rather than an ad-hoc English abbreviation.
      // Placeholders and meaning were reviewed in all three catalogs.
      // Ownership-operations re-pin: hierarchy, incident routes, gap reasons,
      // asset/owner filters, assignment, reassignment, and success copy are
      // present with placeholder parity in both production catalogs. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Alert Center G5 re-pin: the five operator views, truthful delivery
      // semantics, routing inheritance/preview, global urgency indicator, and
      // no-deadline state are translated in both production catalogs. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Workload and Secrets G6 re-pin: the two workspace roots now explain
      // tenant-served urgency, ownership, expiry, delivery, and access risk in
      // plain language. The workspace names also match their rail labels and
      // document titles. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // Missing-evidence G6R1 re-pin: Secrets and Workloads now say urgency is
      // unknown when a required check cannot be read. Available Workloads
      // counts remain visible, but every missing check says unavailable rather
      // than presenting a safe zero. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // Software Trust and Trust Operations G7 re-pin: both roots now expose
      // served outcomes, approvals, operational infrastructure, and explicit
      // unknown states. The managed-key read-model gap remains named instead
      // of becoming a fabricated health claim. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Home G7 re-pin: each urgent row names the affected workspace,
      // consequence, deadline, automation uncertainty, owner, and safest next
      // action. The six-tool strip labels missing reads unavailable.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // Live G7R1 truthfulness re-pin: Home and Trust Operations now name the
      // current effective owner and say unavailable when ownership cannot be
      // verified. These strings preserve the distinction between missing and
      // unreadable evidence. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // Product-overhaul g5 re-pin: reviewed the complete guided discovery
      // source workflow in Spanish and German, including field-level errors,
      // least-privilege and secret-handling boundaries, normalized-plan proof,
      // and recovery copy. Technical examples (CIDRs, env: references, ports,
      // DNs, and URLs) remain byte-identical. Machine-authored es/de — FLAGGED
      // FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul discovery parity re-pin: the typed source wizard now
      // names its capability-contract failure, AD CS enrollment/private-CIDR
      // boundary, and AWS/GCP metadata filters. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul discovery live-parity re-pin: the new-scope action,
      // existing-scope chooser, exact boundary, fail-closed degraded state,
      // and the fact that declaration does not start a scan are now explicit.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // Product-overhaul relay-readiness re-pin: preview, saved-source
      // preflight, and source rows distinguish ready from blocked and explain
      // that saving does not queue an impossible scan. Machine-authored es/de
      // — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul access-service re-pin: the degraded Secrets state now
      // explains that temporary API keys remain independently available and
      // still require access:write. The permission token stays byte-identical.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // Product-overhaul Transit readiness re-pin: the degraded Secrets state
      // now explains that Transit uses its independent encryption service and
      // names the five operations that remain available. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul Transit key-prerequisite re-pin: the console now
      // distinguishes AEAD, HMAC, and signing keys, explains metadata-only
      // readback, gives exact keys:read/keys:write recovery, and reports
      // durable create/rotate versions. Cryptographic type names, permission
      // tokens, and ECDSA P-256 stay byte-identical. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul runtime-truth re-pin: twenty-six keys explain what the
      // running server actually attached, what the current role may do, why a
      // route or exact action is limited, and how to recover without asking for
      // a broader role. Negations in unknown/unavailable states and technical
      // capability/permission identifiers keep their meaning. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Product-overhaul journey-truth re-pin: six keys distinguish pending,
      // runtime-unavailable, and failed detector checks and label progress as
      // evidence rather than navigation position. The unavailable and failed
      // meanings remain distinct in every locale. The failed-check recovery
      // copy intentionally says what is available, without leaking internal
      // server/served-state vocabulary. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // QA g21 re-pin: the known native-store-off state now explains the
      // live independent checks and configuration remedy instead of retrying.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA g26 Provider preflight re-pin: four keys distinguish checking,
      // unattached, and unknown attachment truth, then send the operator to
      // the unaffected tenant console. The translations preserve the
      // fail-closed meaning and never imply that a missing Provider plane is a
      // tenant-console failure. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // QA g28 Discovery recovery re-pin: eight keys label retry eligibility,
      // durable replacement lineage, blocked prerequisites, pending state, and
      // the explicit promise that the original failure remains unchanged as
      // evidence. Run IDs stay byte-identical. Machine-authored es/de — FLAGGED
      // FOR HUMAN TRANSLATION REVIEW before release.
      // QA g31 Agent presence cleanup: three obsolete browser-derived
      // heartbeat phrases were removed after the server became the sole owner
      // of online/stale/clock-skew meaning. The unused-message oracle proves no
      // rendered surface still references them; no remaining translation was
      // changed or replaced by an English fallback.
      // Home truth re-pin: the cockpit now distinguishes durable source
      // records from unique credentials, names every source-count denominator,
      // counts X.509 identities as managed identities, and stops calling every
      // tracked agent online. Placeholders and the non-unique warning were
      // reviewed in both catalogs. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // Discovery identity-picker re-pin: the claim journey now searches and
      // selects human identity and owner labels, explains the selected record,
      // and creates a managed identity inline without exposing an editable raw
      // UUID. The now-unreachable raw-ID placeholder was retired from every
      // catalog. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW
      // before release.
      // Product Help availability-first re-pin: twenty-two keys disclose a
      // disabled, unreadable, or role-blocked help backend before input; route
      // ordinary defects and suspected vulnerabilities separately; warn that
      // operators own the final evidence handoff; and show licensed support
      // only from served entitlement data. Negations, credentials/private-key
      // exclusions, and contract ownership were reviewed for meaning. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // API-key discovery-plan re-pin: twelve keys explain that the server
      // validates the exact metadata-only draft before any source is saved or
      // scan runs, and that token values are rejected. Negations and the
      // no-write/no-scan boundary were reviewed for meaning. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // Agent-enrollment plan re-pin: eighteen keys name the review-before-mint
      // boundary, exact identity/role/mTLS destination, no-token/no-contact
      // guarantee, direct discovery evidence links, and stale-agent recovery.
      // Security negations and technical meaning were reviewed in both catalogs.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // F18 drift-recovery re-pin: thirty-three keys explain effect-free exact
      // plan review, non-secret watched paths, execution/permission boundaries,
      // blocked recovery, and the distinct replacement/original run receipt.
      // Negations and lineage meaning were reviewed in both catalogs. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F4 request-preview re-pin: the review explains no-write/no-CA preview,
      // requester-held key custody, independent approval, exact submission
      // effects, prerequisite recovery, and deterministic retry. Negations and
      // security meaning were reviewed in both catalogs. Machine-authored es/de
      // — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F48 review re-pin: twelve reviewed keys name the effect-free CA
      // rotation receipt, predecessor/successor, risks, and exact confirmation.
      // Machine-authored es/de - FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // F53 recovery re-pin: the certificate-profile journey now names the
      // effect-free preview, active/source/next versions, stale-review failure,
      // dual-control wait state, risks, and verification steps. Negations and
      // security meaning were reviewed in both catalogs. Machine-authored es/de
      // - FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F22 EST qualification re-pin: thirty keys explain the credential-free
      // CA-chain, CSR-rule, and authentication-wall checks, their exact
      // no-issuance boundary, and the safe repair-and-retry loop. The Bearer,
      // CSR, PKCS#7, HTTP, EST, and trstctl identifiers remain byte-identical.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // F23 SCEP qualification re-pin: thirty keys explain the no-body,
      // credential-free capabilities, CA/RA-material, and empty-message checks,
      // their exact no-issuance boundary, and strict repair-and-retry loop.
      // CMS, CSR, MDM, CA/RA, SHA-256, HTTP, SCEP, and trstctl remain
      // byte-identical. Machine-authored es/de translations — FLAG FOR HUMAN
      // REVIEW.
      // F59 lifecycle-review re-pin: nineteen keys explain the effect-free
      // preview, exact owner/effect/version/permission, changed-plan boundary,
      // durable writes, and fail-closed verification result. Placeholders and
      // security meaning were reviewed in both catalogs. Machine-authored es/de
      // translations — FLAG FOR HUMAN TRANSLATION REVIEW before release.
      // F21 graph-path re-pin: seven keys explain server-confirmed shortest
      // relationship chains, evidence provenance, and direct risk, lifecycle,
      // and audit handoffs. Placeholders and fail-honest path meaning were
      // reviewed. Machine-authored es/de translations — FLAG FOR HUMAN
      // TRANSLATION REVIEW before release.
      // F47 revocation-center re-pin: translated effect-free review, reason,
      // impact, propagation, irreversible confirmation, and proof copy. The
      // unknown-state negations and placeholders remain intact. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F55 CMP qualification re-pin: translated preview, exact live gates,
      // zero-effect boundary, bounded refusal receipts, repair-and-rerun, and
      // real-client handoff. Names such as CMP, PKIMessage, CSR, and RA remain
      // byte-identical. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION
      // REVIEW before release.
      // F54 enrollment re-pin: seven reviewed keys name renewal readiness,
      // the dedicated path and current-certificate mTLS boundary, plus the
      // exact replacement/revoke/offboard recovery. The unavailable state and
      // unrecoverable-token warning must preserve their negation. Machine-
      // authored es/de translations — FLAG FOR HUMAN TRANSLATION REVIEW.
      // F56 MDM policy re-pin: translated first-policy setup, exact effect-free
      // preview, reference-name-only boundary, challenge rotation, and retry
      // recovery. The zero-effect and no-secret claims must keep their
      // negation. Machine-authored es/de translations — FLAG FOR HUMAN
      // TRANSLATION REVIEW before release.
      // F52 CBOM re-pin: translated scope, effect-free plan, exact limits,
      // partial-failure recovery, and durable inventory proof. Technical
      // identifiers and the zero-effect boundary remain unchanged. Machine-
      // authored es/de translations — FLAG FOR HUMAN TRANSLATION REVIEW.
      // F24 SPIFFE re-pin: translated trust-domain, owner-only UDS, isolated
      // signer, bounded-capacity, host migration, effect-free review, and
      // repair-and-rerun copy. SPIFFE, X.509, JWT, UDS, and Unix remain product
      // or protocol nouns. Seven superseded CBOM source-extraction keys were
      // removed after the unused-message oracle proved no rendered surface
      // references them. Machine-authored es/de translations — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW before release.
      // F25 re-pin: dedicated temporary-credential workflow plus exact
      // preview, approval, recovery, and private-key boundary. Machine-
      // authored es/de translations — FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // F43 direct SSH issuance re-pin: the three-step host/user workflow now
      // names exact preview effects, TTL clamps, key boundaries, signer calls,
      // certificate disclosure, and KRL recovery. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F43 live-browser polish re-pin: the SSH readiness line now uses
      // label-first counts so zero and one cannot produce broken grammar.
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW.
      // F69 provider-qualification re-pin: the add, effect-free review, real
      // publish/verify/cleanup, sanitized history, and cleanup-retry journey is
      // translated without translating protocol identifiers or the example
      // DNS name. Machine-authored es/de — FLAG FOR HUMAN REVIEW.
      // F70 signed-plugin qualification re-pin: seventeen keys explain the
      // exact running package, Ed25519 provenance, startup admission, DNS
      // publish/cleanup contract, capability grants, and the fail-honest
      // unavailable-plugin recovery state. A missing plugin must remain
      // unavailable in every locale; it must never read as admitted or built
      // in. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW
      // BEFORE RELEASE.
      // F71 CNAME-isolation re-pin: the exact production name, required
      // delegation target, fail-closed behavior, and pending/failed/proved
      // states are now named in all three locales. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F72 CAA-policy re-pin: the five live policy states, governing name,
      // exact public records, allowed issuers, fail-closed boundary, and safe
      // recovery are named in all three locales. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F72 live-browser follow-up: three CAA empty states now distinguish an
      // unrestricted policy, an unverified DNS answer, and missing issuer
      // configuration from a real deny-all record. The negation and unknown
      // state were reviewed for meaning in all three locales. Machine-authored
      // es/de translations — FLAGGED FOR HUMAN TRANSLATION REVIEW.
      // F6 lifecycle-automation re-pin: renewal and alert timing, ARI priority,
      // maintenance-window deferral, safe controls, durable queue state, and
      // recovery links are now named in all production catalogs. Machine-
      // authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F73 domain-validation activity re-pin: real order state, offered
      // challenge methods, the method that proved control, pending state, and
      // the challenge/account non-disclosure boundary are now named in all
      // production catalogs. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW before release.
      // F74 wildcard-lifecycle re-pin: the DNS-01-only proof boundary,
      // blast-radius acknowledgement, fail-closed recovery, exact issued-name
      // receipt, renewal handoff, and predecessor/successor evidence label are
      // now named in all production catalogs. The negation that operator issue
      // does not weaken ACME validation was reviewed in both translations.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA F74 g96 re-pin: identity issuance now names a deployment-ready
      // owner, and first-run setup records a complete, current ownership
      // attestation before creating a certificate. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // QA F75 g97 re-pin: the optional-agent step now names the honest
      // pre-token state without claiming the server omitted its endpoint. The
      // exact endpoint warning remains reserved for an unusable token response.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW before
      // release.
      // QA F51 g98 re-pin: the timestamp workflow now names the effect-free
      // readiness check, isolated signer/certificate/audit gates, safe repairs,
      // and the separate OpenSSL wire-proof boundary. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // F30 exact-preview re-pin: request/review/result copy, deferred proof
      // verification, stable retry keys, and operator-managed trust guidance.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F30 live-baseline correction: tenant trust configuration is not proof
      // that issuance will succeed; server preview also resolves operator trust.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // Proof-handling correction: the form sends proof to the server and clears
      // it after success; only the public certificate remains for deliberate copy.
      // g102 live-QA repairs: neutral unsuccessful-attempt labels, accurate
      // registered-identity counts, minute/hour deadlines, attested replacement,
      // and custody unknowns without invented explanations. Machine-authored
      // es/de remain FLAGGED FOR HUMAN TRANSLATION REVIEW before release.
      // g103 live-QA repair: three expiry snapshot messages distinguish observed,
      // refreshing and unavailable totals; audit explains server-owned tool scope
      // and preserved filters, with explicit feature/action/supporting-area labels.
      // Placeholders and the 30-second cadence remain exact. Machine-authored
      // es/de are FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F61 g104: reviewed explicit preview-versus-authorization language,
      // unknown history/freshness, same-key retries and new-request warning;
      // removed eight obsolete session-only broker messages from every locale.
      // Machine-authored es/de translations require human review before release.
      // G111 signed-ID handoff: reviewed exact whole-ID authorization, missing
      // legacy evidence, explicit trust cutover, unknown issuance and clipboard
      // failure copy in both catalogs. Machine-authored es/de — FLAGGED FOR
      // HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // G122 connector-readiness re-pin: prepared destinations remain disabled,
      // the console names the explicit enable boundary, enrollment selects a
      // verified destination, and identity/connector mismatches explain the
      // refusal without implying any work was queued. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F61 g124 recovery re-pin: the revocation center distinguishes managed
      // lifecycle identities from exact certificate records, preserves the
      // deep-linked certificate ID, and explains live-state re-checks and
      // durable verification without internal "served" jargon. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F61 g125 fail-closed confirmation re-pin: destructive confirmation now
      // asks for the exact displayed credential label, because subjectless
      // broker records deliberately fall back to their non-empty certificate
      // ID. Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW
      // BEFORE RELEASE.
      // F16 g138 durable-readback re-pin: the scan result now explains that a
      // separate inventory read, rather than the mutation response, proves the
      // saved tenant records and migration guidance. The error copy must retain
      // the explicit no-success-claim boundary. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F63 create-preview re-pin: the two-step create journey, zero-effect
      // review, stale-plan warning, separate execution action, and progress
      // labels preserve their safety meaning and placeholders in both locales.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F64 developer-access re-pin: a separate workspace now explains review,
      // exact plan inputs, no-effect preview, least privilege, execution, retry,
      // stale-version refusal, value-free verification, and snippet copy recovery.
      // Nine obsolete strings from the invalid old snippet panel were removed.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F64 live-UX re-pin: the route summary now counts capabilities with
      // usable authorized actions instead of saying zero are ready because a
      // separately named operation is unavailable. Machine-authored es/de —
      // FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F60 re-pin: the share workflow now explains effect-free review,
      // ambiguous-response recovery, bearer custody, expiry, and redemption
      // failure in each production locale. The F58 method helper also replaces
      // internal "served" language with operator-facing "ready" language.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F38 re-pin: the complete temporary API-key journey now explains exact
      // review binding, caller-scope attenuation, one-time bearer custody,
      // stable retry, verification without the human session, revocation, and
      // automatic expiry. Twelve obsolete extracted strings from the retired
      // direct-mint panel were removed. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // F39 re-pin: the secret-scanning journey now distinguishes effect-free
      // review, reviewed execution, stale-plan refusal, same-key retry, and
      // redacted durable proof. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // F39 live-browser repair re-pin: the Discovery handoff now says when
      // results are scoped to one exact run and names the action that returns
      // to the full finding list. Machine-authored es/de — FLAGGED FOR HUMAN
      // TRANSLATION REVIEW BEFORE RELEASE.
      // F65 live-browser repair re-pin: renewal headroom now names the exact
      // remaining seconds and the no-time-left recovery action. Machine-authored
      // es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      // F66 re-pin: the Transit recovery and proof surfaces now explain sealed
      // startup restore, KMIP runtime state, no-auto-retry recovery, complete
      // version history, filtered audit receipts, and real signature verification.
      // Machine-authored es/de — FLAGGED FOR HUMAN TRANSLATION REVIEW BEFORE RELEASE.
      "es-ES": "8aade4ab3d046fb4cf33953eec9177a8ec92b21a825eaf6f9a8ce1f6e1ca39a9",
      "de-DE": "40cb2407f3913eaf6a380144a90a5322d6f8f345f04fa03c19c114947ea14cbf",
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
