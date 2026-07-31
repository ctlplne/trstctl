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
      // I18N-ca357ca0 re-pin: 223 source keys move strings, conditional
      // fallbacks, interpolated accessibility labels, and warning copy from
      // renderable JSX expressions into the typed catalog. Technical
      // identifiers and punctuation-only format templates stay byte-identical;
      // all natural-language values carry placeholder-safe es/de translations.
      // UX-04 follow-up: the intermediate-CA description now uses customer
      // language in every locale instead of the internal "served" status.
      // Posture follow-up: the localized crypto inventory separator preserves
      // its leading space so adjacent algorithm and transport text stays clear.
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
      // Machine-authored es/de translations — FLAG FOR HUMAN REVIEW alongside
      // the outstanding translation review sheet.
      "es-ES": "9727aefe950fe2c05ba27c26804a3bae162a3f8074e16f79e0457874015f6018",
      "de-DE": "bfc25eb1f7c725c09b44cead42f5be4fae4b3828da5a57c95698e7f75bce0690",
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
