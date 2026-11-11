import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppShell } from "@/components/AppShell";
import { Login } from "@/pages/Login";
import { PoweredByTrstctl } from "@/components/PoweredByTrstctl";
import { brandTokenOverrides, resetPublicBrand } from "@/lib/usePublicBrand";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    logout: vi.fn(),
    getPublicBrand: vi.fn(),
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

// A white-labeled tenant whose token overrides try to blank the page.
const hostileBrand = {
  product_name: "Northwind Managed PKI",
  custom: true,
  login_message: "Northwind customers sign in with their Northwind account.",
  logo_data_uri: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=",
  token_overrides: {
    "--background": "0 0% 100%",
    "--foreground": "0 0% 100%",
    "--font-size-caption": "0px",
    "--primary": "url(https://attacker.example/x)",
    "not-a-token": "red",
    "--x; color": "red",
  },
};

function luminance(hex: string): number {
  const channel = (i: number) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function renderShell() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <ThemeProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={["/"]}>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>Overview</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ThemeProvider>
    </IntlProvider>,
  );
}

function renderLogin() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <ThemeProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={["/login"]}>
            <Routes>
              <Route path="/login" element={<Login />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ThemeProvider>
    </IntlProvider>,
  );
}

describe("MSP-1 Powered by trstctl", () => {
  beforeEach(() => {
    resetPublicBrand();
    document.documentElement.removeAttribute("style");
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.logout.mockResolvedValue(undefined);
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1440, writable: true });
  });

  it("renders with fixed trstctl styling that no stylesheet can override, at over 4.5:1 contrast", () => {
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PoweredByTrstctl />
      </IntlProvider>,
    );
    const mark = screen.getByTestId("powered-by-trstctl");
    expect(mark).toHaveTextContent("Powered by trstctl");
    for (const property of ["display", "visibility", "opacity", "color", "background-color", "font-size", "min-height"]) {
      expect(mark.style.getPropertyPriority(property)).toBe("important");
    }
    expect(mark.style.getPropertyValue("font-size")).toBe("12px");
    const ratio = (luminance("#ffffff") + 0.05) / (luminance("#0b2e24") + 0.05);
    expect(ratio).toBeGreaterThanOrEqual(4.5);
    expect(mark.getAttribute("style")).not.toContain("var(");
  });

  it("shows a white-labeled tenant's brand beside the mark in the header, applying only safe token overrides", async () => {
    apiMock.getPublicBrand.mockResolvedValue(hostileBrand);
    renderShell();
    expect(await screen.findByText("Northwind Managed PKI")).toBeInTheDocument();
    expect(screen.getByTestId("powered-by-trstctl")).toBeInTheDocument();
    expect(screen.getByTestId("tenant-brand-logo")).toHaveAttribute("src", hostileBrand.logo_data_uri);
    const root = document.documentElement.style;
    expect(root.getPropertyValue("--foreground")).toBe("0 0% 100%");
    expect(root.getPropertyValue("--primary")).toBe("");
    expect(brandTokenOverrides(hostileBrand).map(([name]) => name)).toEqual(["--background", "--foreground", "--font-size-caption"]);
  });

  it("puts the mark above the fold on a white-labeled sign-in page", async () => {
    apiMock.getPublicBrand.mockResolvedValue(hostileBrand);
    renderLogin();
    expect(await screen.findByRole("heading", { level: 1, name: "Northwind Managed PKI" })).toBeInTheDocument();
    expect(screen.getByText(hostileBrand.login_message)).toBeInTheDocument();
    const mark = screen.getByTestId("powered-by-trstctl");
    // The mark precedes the sign-in card: it is the first thing on the page.
    expect(mark.compareDocumentPosition(screen.getByRole("heading", { level: 1 })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("shows trstctl's own brand and no extra mark when nothing is white-labeled", async () => {
    apiMock.getPublicBrand.mockResolvedValue({ product_name: "trstctl", custom: false });
    renderShell();
    await screen.findByText("u@example.test");
    expect(screen.queryByTestId("powered-by-trstctl")).not.toBeInTheDocument();
    expect(screen.getByTestId("brand-mark")).toBeInTheDocument();
  });
});
