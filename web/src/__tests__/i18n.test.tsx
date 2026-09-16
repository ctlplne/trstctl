import { execFileSync } from "node:child_process";
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
  it("ships only English in production and keeps the generated English values exact", () => {
    expect(productionLocales).toEqual(["en-US"]);
    expect(Object.keys(eagerCatalogs[defaultLocale]).sort()).toEqual(Object.keys(messages).sort());
    for (const key of Object.keys(messages) as MessageKey[]) {
      expect(eagerCatalogs[defaultLocale][key], key).toBe(messages[key].defaultMessage);
    }
  });

  it("renders English chrome and never offers removed production languages", async () => {
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
    const selector = screen.getByRole("combobox", { name: "Language" });
    expect(selector).toHaveValue("en-US");
    const values = within(selector)
      .getAllByRole("option")
      .map((option) => (option as HTMLOptionElement).value);
    expect(values).toContain("en-US");
    expect(values).not.toContain("es-ES");
    expect(values).not.toContain("de-DE");
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

  it("resolves shell navigation through the pseudo-locale catalog", async () => {
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
    expect(await screen.findByRole("dialog", { name: pseudoLocalize("Keyboard shortcuts") })).toBeInTheDocument();
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
      <IntlProvider serverLocale="en-US" serverTimeZone="Europe/Madrid">
        <LocaleProbe />
      </IntlProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("locale-probe")).toHaveTextContent("en-US|Europe/Madrid|Needs action"));
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
    expect(negotiateLocale(["es-MX"])).toBe(defaultLocale);
    expect(negotiateLocale(["de-AT"])).toBe(defaultLocale);
    expect(negotiateLocale(["de"])).toBe(defaultLocale);
    expect(negotiateLocale(["ar-SA"])).toBe(defaultLocale);
    expect(negotiateLocale(["en-XA", "ar-XB"])).toBe(defaultLocale);
    expect(directionForLocale("he-IL")).toBe("rtl");
    expect(formatMessage("command.routeDescription", { group: "Platform" })).toBe("Page · Platform");
    expect(formatDate("2026-06-20T12:00:00Z", { locale: "en-US", timeZone: defaultTimeZone })).toMatch(/Jun/);
    expect(formatNumber(1234, { locale: "en-US", timeZone: defaultTimeZone })).toBe("1,234");
    expect(formatPlural(1, { one: "node", other: "nodes" })).toBe("node");
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
