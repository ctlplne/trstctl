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
import { defaultLocale, defaultTimeZone, eagerCatalogs, messages, productionLocales, pseudoLocalize, type MessageKey } from "@/i18n/messages";

// S-C10: es/de are lazy per-locale modules now. The guards below still audit
// the FULL catalogs (parity, placeholders, digests), so load them explicitly —
// the digest pins must not move on a split, only on reviewed string changes.
const catalogs = {
  ...eagerCatalogs,
  "es-ES": (await import("@/i18n/catalog.es-ES")).default,
  "de-DE": (await import("@/i18n/catalog.de-DE")).default,
} as const;
const runtimeCatalogs = {
  "es-ES": (await import("@/i18n/catalog.es-ES.runtime.gen")).default,
  "de-DE": (await import("@/i18n/catalog.de-DE.runtime.gen")).default,
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

describe("i18n boundary", () => {
  it("generates byte-identical compact runtime catalogs from the reviewed keyed sources", () => {
    expect(runtimeCatalogs["es-ES"]).toEqual(catalogs["es-ES"]);
    expect(runtimeCatalogs["de-DE"]).toEqual(catalogs["de-DE"]);
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
      "es-ES": "80886255dfedbe9e107f38884ff96481ffc319c0456ff399f289b31321dba7e2",
      "de-DE": "42cb0f0fe0a6b750a42e5431e177dc1793593c4ea032a5279c2ee9767a078e55",
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
