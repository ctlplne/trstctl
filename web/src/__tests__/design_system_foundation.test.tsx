import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataGrid, type DataGridSort } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { StatusBadge } from "@/components/StatusBadge";
import { describeStatus, expiryBandForDate, riskBand } from "@/lib/statusVocab";

const webRoot = process.cwd();
const css = readFileSync(path.join(webRoot, "src/index.css"), "utf8");
const tailwind = readFileSync(path.join(webRoot, "tailwind.config.js"), "utf8");
const agentsSource = readFileSync(path.join(webRoot, "src/pages/Agents.tsx"), "utf8");
const certsSource = readFileSync(path.join(webRoot, "src/pages/Certificates.tsx"), "utf8");
const riskSource = readFileSync(path.join(webRoot, "src/pages/Risk.tsx"), "utf8");
const buttonSource = readFileSync(path.join(webRoot, "src/components/ui/button.tsx"), "utf8");
const cardSource = readFileSync(path.join(webRoot, "src/components/ui/card.tsx"), "utf8");
const pageHeaderSource = readFileSync(path.join(webRoot, "src/components/PageHeader.tsx"), "utf8");
const themeProviderSource = readFileSync(path.join(webRoot, "src/components/ThemeProvider.tsx"), "utf8");
const appShellSource = readFileSync(path.join(webRoot, "src/components/AppShell.tsx"), "utf8");

type Row = { id: string; name: string; status: string; owner: string };
type HslToken = { h: number; s: number; l: number };

const rows: Row[] = [
  { id: "r1", name: "payments-api", status: "active", owner: "platform" },
  { id: "r2", name: "worker", status: "revoked", owner: "security" },
];

const columns = [
  { id: "name", header: "Name", sortable: true, cell: (row: Row) => row.name },
  {
    id: "status",
    header: "Status",
    cell: (row: Row) => <StatusBadge vocabulary="certificate" value={row.status} />,
  },
  { id: "owner", header: "Owner", hiddenByDefault: true, cell: (row: Row) => row.owner },
];

function parseThemeTokens(selector: ":root" | ".dark") {
  const blockStart = css.indexOf(`${selector} {`);
  expect(blockStart, `missing ${selector} token block`).toBeGreaterThanOrEqual(0);
  const openBrace = css.indexOf("{", blockStart);
  const closeBrace = css.indexOf("\n  }", openBrace);
  expect(closeBrace, `missing ${selector} token block close`).toBeGreaterThan(openBrace);

  const tokens: Record<string, HslToken> = {};
  const tokenPattern = /--([a-z0-9-]+):\s*([0-9.]+)\s+([0-9.]+)%\s+([0-9.]+)%\s*;/g;
  for (const match of css.slice(openBrace + 1, closeBrace).matchAll(tokenPattern)) {
    tokens[match[1]] = { h: Number(match[2]), s: Number(match[3]), l: Number(match[4]) };
  }
  return tokens;
}

function requireToken(tokens: Record<string, HslToken>, name: string) {
  const token = tokens[name];
  expect(token, `missing --${name}`).toBeDefined();
  return token;
}

function hslToRgb({ h, s, l }: HslToken) {
  const saturation = s / 100;
  const lightness = l / 100;
  const chroma = (1 - Math.abs(2 * lightness - 1)) * saturation;
  const secondary = chroma * (1 - Math.abs(((h / 60) % 2) - 1));
  const match = lightness - chroma / 2;
  let red = 0;
  let green = 0;
  let blue = 0;

  if (h < 60) {
    red = chroma;
    green = secondary;
  } else if (h < 120) {
    red = secondary;
    green = chroma;
  } else if (h < 180) {
    green = chroma;
    blue = secondary;
  } else if (h < 240) {
    green = secondary;
    blue = chroma;
  } else if (h < 300) {
    red = secondary;
    blue = chroma;
  } else {
    red = chroma;
    blue = secondary;
  }

  return [red, green, blue].map((channel) => channel + match);
}

function relativeLuminanceRgb(rgb: number[]) {
  const [red, green, blue] = rgb.map((channel) => {
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return red * 0.2126 + green * 0.7152 + blue * 0.0722;
}

function relativeLuminance(hsl: HslToken) {
  return relativeLuminanceRgb(hslToRgb(hsl));
}

function contrastRatio(foreground: HslToken, background: HslToken) {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
}

function contrastRatioOnTint(foreground: HslToken, underlay: HslToken, alpha: number) {
  const foregroundRgb = hslToRgb(foreground);
  const underlayRgb = hslToRgb(underlay);
  const tintedBackground = foregroundRgb.map((channel, index) => channel * alpha + underlayRgb[index] * (1 - alpha));
  const foregroundLuminance = relativeLuminanceRgb(foregroundRgb);
  const backgroundLuminance = relativeLuminanceRgb(tintedBackground);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
}

function contrastRatioOnLayeredTints(foreground: HslToken, base: HslToken, layers: Array<{ color: HslToken; alpha: number }>) {
  const foregroundRgb = hslToRgb(foreground);
  const backgroundRgb = layers.reduce(
    (underlay, layer) => hslToRgb(layer.color).map((channel, index) => channel * layer.alpha + underlay[index] * (1 - layer.alpha)),
    hslToRgb(base),
  );
  const foregroundLuminance = relativeLuminanceRgb(foregroundRgb);
  const backgroundLuminance = relativeLuminanceRgb(backgroundRgb);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
}

describe("Clarity/Console design-system foundation", () => {
  it("exposes brand, honesty, risk, density, type, and elevation tokens", () => {
    for (const token of [
      "--brand-accent",
      "--operate",
      "--observe",
      "--disclose",
      "--risk-critical",
      "--risk-high",
      "--risk-medium",
      "--risk-low",
      "--density-comfortable",
      "--font-size-heading",
      "--elevation-2",
    ]) {
      expect(css).toContain(token);
    }

    for (const themeKey of ["brand", "operate", "observe", "disclose", "risk", "fontSize", "elevation2"]) {
      expect(tailwind).toContain(themeKey);
    }
  });

  it("pins the quiet-confidence attention hierarchy instead of marketing chrome", () => {
    expect(pageHeaderSource).toContain('data-testid="page-depth-answer"');
    expect(pageHeaderSource).toContain('data-testid="page-depth-operate"');
    expect(pageHeaderSource).toContain('data-testid="page-depth-prove"');
    expect(buttonSource).toContain("rounded-control");
    expect(buttonSource).not.toContain("gap-2 rounded-full text-sm");
    expect(buttonSource).not.toContain("translate-y");
    expect(cardSource).toContain("shadow-none");
    expect(themeProviderSource).toContain('stored ?? "light"');
  });

  it("defines every ui-* component class that source references (R-01 guard)", () => {
    // .ui-input was referenced by ~145 call sites for months while defined
    // nowhere — every form control rendered as raw native chrome, and no test
    // could see it because this suite guarded tokens, not classes. Any ui-*
    // class a component wears must have a rule in index.css.
    const referenced = new Set<string>();
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          walk(path.join(dir, entry.name));
          continue;
        }
        if (!/\.(ts|tsx)$/.test(entry.name)) continue;
        const source = readFileSync(path.join(dir, entry.name), "utf8");
        for (const match of source.matchAll(/\bui-[a-z][a-z0-9-]*/g)) {
          referenced.add(match[0]);
        }
      }
    };
    walk(path.join(webRoot, "src"));
    const defined = new Set([...css.matchAll(/\.(ui-[a-z][a-z0-9-]*)/g)].map((m) => m[1]));
    const missing = [...referenced].filter((name) => !defined.has(name)).sort();
    expect(referenced.size).toBeGreaterThanOrEqual(3); // ui-input, ui-panel, ui-table
    expect(missing).toEqual([]);

    // Same failure class, Tailwind flavor: shadcn-derived markup carries an
    // `input` COLOR (border-input etc.) that this config never defined — the
    // class silently emitted nothing and the global border-color rule hid it
    // at 78 call sites. The token is `border`; keep the synonym out.
    const phantomColor = /\b(?:border|bg|ring|text)-input\b/;
    const phantoms: string[] = [];
    const walkPhantom = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          walkPhantom(path.join(dir, entry.name));
          continue;
        }
        if (!entry.name.endsWith(".tsx") || entry.name.includes(".test.")) continue;
        const source = readFileSync(path.join(dir, entry.name), "utf8");
        if (phantomColor.test(source)) phantoms.push(path.join(dir, entry.name).slice(webRoot.length + 1));
      }
    };
    walkPhantom(path.join(webRoot, "src"));
    expect(phantoms).toEqual([]);
  });

  it("ratchets raw form controls in pages toward the rule-14 primitives (R-02)", () => {
    // Form controls are primitives (DESIGN.md rule 14): new fields use
    // Input/Select/Textarea inside <Field>, and existing raw tags migrate when
    // their page is next touched — the same migrate-when-touched policy as
    // useResource. This budget only goes DOWN. If this fails with a HIGHER
    // count, a new raw control was added: use the primitives. If it fails
    // with a LOWER count, you migrated some — lower the budget in this change.
    const budget = { input: 244, select: 62, textarea: 67 };
    const counts = { input: 0, select: 0, textarea: 0 };
    const walkPages = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          walkPages(path.join(dir, entry.name));
          continue;
        }
        if (!entry.name.endsWith(".tsx") || entry.name.includes(".test.") || entry.name.includes(".stories.")) continue;
        const source = readFileSync(path.join(dir, entry.name), "utf8");
        counts.input += (source.match(/<input\b/g) ?? []).length;
        counts.select += (source.match(/<select\b/g) ?? []).length;
        counts.textarea += (source.match(/<textarea\b/g) ?? []).length;
      }
    };
    walkPages(path.join(webRoot, "src/pages"));
    for (const kind of ["input", "select", "textarea"] as const) {
      expect(counts[kind], `raw <${kind}> count in src/pages`).toBeLessThanOrEqual(budget[kind]);
    }
  });

  it("keeps tracked-uppercase micro-labels inside the Eyebrow primitive (R-04 ratchet)", () => {
    // Eyebrow is THE tracked-uppercase micro-label (S-C9); PageHeader's accent
    // eyebrow is the one sanctioned brand-flavored variant. Hand-rolled
    // uppercase+tracking clusters drift into "four slightly different
    // versions" — Secrets had eight with a different tracking value. Any
    // className combining uppercase with a tracking- utility outside the two
    // primitive files fails here: use <Eyebrow> (overrides via className).
    const sanctioned = new Set(["typography.tsx", "PageHeader.tsx"]);
    const offenders: string[] = [];
    const walkAll = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          walkAll(path.join(dir, entry.name));
          continue;
        }
        if (!entry.name.endsWith(".tsx") || entry.name.includes(".test.") || sanctioned.has(entry.name)) continue;
        const source = readFileSync(path.join(dir, entry.name), "utf8");
        for (const match of source.matchAll(/className="[^"]*"/g)) {
          if (match[0].includes("uppercase") && match[0].includes("tracking-")) {
            offenders.push(`${path.join(dir, entry.name).slice(webRoot.length + 1)}: ${match[0]}`);
          }
        }
      }
    };
    walkAll(path.join(webRoot, "src"));
    expect(offenders).toEqual([]);
  });

  it("keeps text-bearing control token pairs at WCAG AA contrast", () => {
    const tokenPairs = [
      { background: "primary", foreground: "primary-foreground", label: "primary button" },
      { background: "destructive", foreground: "destructive-foreground", label: "destructive button" },
      { background: "background", foreground: "muted-foreground", label: "muted body text" },
    ] as const;

    for (const [themeName, selector] of [
      ["light", ":root"],
      ["dark", ".dark"],
    ] as const) {
      const tokens = parseThemeTokens(selector);
      for (const pair of tokenPairs) {
        const ratio = contrastRatio(requireToken(tokens, pair.foreground), requireToken(tokens, pair.background));
        expect(ratio, `${themeName} ${pair.label}: --${pair.foreground} on --${pair.background}`).toBeGreaterThanOrEqual(4.5);
      }
      // R-08: the focus indicator is its own token (mint family in BOTH
      // themes — rule 2's "mint means focus" no longer depends on theme) and
      // must clear the 3:1 non-text contrast floor against the page it draws
      // on (WCAG 1.4.11).
      const focusRatio = contrastRatio(requireToken(tokens, "focus"), requireToken(tokens, "background"));
      expect(focusRatio, `${themeName} focus ring on background`).toBeGreaterThanOrEqual(3);
      const focusHue = requireToken(tokens, "focus").h;
      expect(focusHue, `${themeName} --focus stays in the mint family`).toBeGreaterThanOrEqual(160);
      expect(focusHue, `${themeName} --focus stays in the mint family`).toBeLessThanOrEqual(185);

      // Live axe found the light warning orange readable-looking but below AA,
      // especially when used on its own 10% status tint. Guard the exact token
      // combinations used by StatusBadge, Toast, and route warning copy.
      const warning = requireToken(tokens, "status-warning");
      const card = requireToken(tokens, "card");
      expect(contrastRatio(warning, card), `${themeName} warning text on card`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatioOnTint(warning, card, 0.1), `${themeName} warning text on 10% warning tint`).toBeGreaterThanOrEqual(4.5);
      expect(
        contrastRatioOnLayeredTints(warning, card, [
          { color: requireToken(tokens, "muted"), alpha: 0.2 },
          { color: warning, alpha: 0.1 },
        ]),
        `${themeName} warning text on 10% warning tint nested in a 20% muted card`,
      ).toBeGreaterThanOrEqual(4.5);
      const brandAccent = requireToken(tokens, "brand-accent");
      expect(contrastRatio(brandAccent, card), `${themeName} brand link text on card`).toBeGreaterThanOrEqual(4.5);
      expect(
        contrastRatioOnLayeredTints(brandAccent, card, [{ color: requireToken(tokens, "muted"), alpha: 0.2 }]),
        `${themeName} brand link text on a 20% muted card`,
      ).toBeGreaterThanOrEqual(4.5);
      const success = requireToken(tokens, "status-success");
      expect(contrastRatio(success, card), `${themeName} success text on card`).toBeGreaterThanOrEqual(4.5);
      const critical = requireToken(tokens, "risk-critical");
      expect(contrastRatio(critical, card), `${themeName} critical text on card`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatioOnTint(critical, card, 0.1), `${themeName} critical text on 10% critical tint`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps tiny shell labels on live-audited contrast classes", () => {
    expect(appShellSource).not.toContain("text-sidebar-foreground/60");
    expect(appShellSource).toContain("text-sidebar-foreground/80");
    expect(appShellSource).toContain("tracking-wider text-muted-foreground sm:block");
  });

  it("uses type, density, and elevation tokens in representative card primitives", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Evidence queue</CardTitle>
        </CardHeader>
        <CardContent>Token-backed card body</CardContent>
      </Card>,
    );

    expect(screen.getByText("Evidence queue")).toHaveClass("text-title");
    expect(screen.getByText("Token-backed card body")).toHaveClass("text-body");
    expect(screen.getByText("Evidence queue").closest(".rounded-panel")).toHaveClass("shadow-none");
  });

  it("renders shared StatusBadge labels from one vocabulary and real token classes", async () => {
    const { container } = render(
      <div>
        <StatusBadge vocabulary="certificate" value="revoked" />
        <StatusBadge vocabulary="expiry" value="critical" />
        <StatusBadge vocabulary="honesty" value="disclose" />
        <StatusBadge vocabulary="risk" value={riskBand(95)} />
      </div>,
    );

    expect(screen.getByText("revoked")).toHaveAttribute("data-status-badge", "certificate");
    expect(screen.getByText("<7d critical")).toHaveClass("text-risk-critical");
    expect(screen.getByText("Disclose")).toHaveClass("border-border", "bg-transparent", "text-muted-foreground");
    expect(screen.getByText("Critical")).toHaveClass("text-risk-critical");
    expect(screen.getByText("Critical")).toHaveClass("bg-risk-critical/10");
    expect(describeStatus("agent", "online")).toMatchObject({ label: "online", tone: "success" });
    expect(expiryBandForDate(new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString())).toBe("critical");

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("removes bespoke status chip definitions and uses StatusBadge in representative pages", () => {
    expect(agentsSource).not.toMatch(/function\s+StatusChip/);
    expect(certsSource).not.toMatch(/function\s+Chip|function\s+statusChip|function\s+expiryBand/);
    for (const source of [agentsSource, certsSource, riskSource]) {
      expect(source).toMatch(/StatusBadge/);
    }
  });
});

describe("shared DataGrid", () => {
  it("renders configured columns, token-backed badges, sorting, and column chooser", async () => {
    const user = userEvent.setup();
    const onSort = vi.fn();
    const { container } = render(
      <MemoryRouter>
        <DataGrid
          ariaLabel="Credential rows"
          rows={rows}
          columns={columns}
          getRowId={(row) => row.id}
          sort={{ columnId: "name", direction: "asc" }}
          onSort={onSort}
          showColumnChooser
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole("table", { name: "Credential rows" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Scrollable columns for Credential rows" })).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("group", { name: "Scrollable columns for Credential rows" })).toHaveClass("focus-visible:ring-focus");
    expect(screen.getByRole("columnheader", { name: /name/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /owner/i })).not.toBeInTheDocument();
    expect(screen.getByText("revoked")).toHaveAttribute("data-status-badge", "certificate");

    await user.click(screen.getByRole("button", { name: /name/i }));
    expect(onSort).toHaveBeenCalledWith({ columnId: "name", direction: "desc" } satisfies DataGridSort);

    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByLabelText("Owner"));
    expect(screen.getByRole("columnheader", { name: /owner/i })).toBeInTheDocument();
    expect(screen.getByText("platform")).toBeInTheDocument();

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("renders the five standard list states through shared primitives", () => {
    for (const [state, primitive] of [
      ["loading", "loading"],
      ["empty", "empty"],
      ["error", "error"],
      ["permission-denied", "permission-denied"],
      ["unavailable", "unavailable"],
    ] as const) {
      const { container, unmount } = render(
        <MemoryRouter>
          <DataGrid
            ariaLabel={`${state} rows`}
            rows={[]}
            columns={columns}
            getRowId={(row) => row.id}
            state={state}
            stateTitle={`${state} title`}
            stateMessage={`${state} message`}
          />
        </MemoryRouter>,
      );
      expect(container.querySelector(`[data-state-primitive="${primitive}"]`)).toBeInTheDocument();
      unmount();
    }
  });

  it("renders a reusable toolbar with search, filters, bulk slot, and the grid column chooser", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <MemoryRouter>
        <ToolbarGridHarness />
      </MemoryRouter>,
    );

    expect(screen.getByRole("searchbox", { name: "Search credential rows" })).toBeInTheDocument();
    expect(screen.getByText("Owner filter")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /bulk rotate/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /columns/i })).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: "Search credential rows" }), "worker");
    expect(screen.getByText("worker")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByLabelText("Owner"));
    expect(screen.getByRole("columnheader", { name: /owner/i })).toBeInTheDocument();

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("persists column metadata and saved views without storing row values", async () => {
    localStorage.clear();
    const user = userEvent.setup();
    const first = render(
      <MemoryRouter>
        <PersistentGridHarness />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByLabelText("Status"));
    expect(screen.queryByRole("columnheader", { name: /status/i })).not.toBeInTheDocument();

    first.unmount();
    render(
      <MemoryRouter>
        <PersistentGridHarness />
      </MemoryRouter>,
    );

    expect(screen.queryByRole("columnheader", { name: /status/i })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Owner view filter"), "platform");
    await user.click(screen.getByRole("button", { name: /name/i }));
    await user.type(screen.getByLabelText("Saved view name"), "Platform focus");
    await user.click(screen.getByRole("button", { name: "Save view" }));

    const stored = localStorage.getItem("trstctl-grid-view:test-grid") ?? "";
    expect(stored).toContain("Platform focus");
    expect(stored).toContain("platform");
    expect(stored).not.toContain("payments-api");
    expect(stored).not.toContain("worker");

    await user.selectOptions(screen.getByLabelText("Owner view filter"), "all");
    expect(screen.getByText("worker")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Restore view Platform focus" }));
    expect(screen.queryByText("worker")).not.toBeInTheDocument();
    expect(screen.getByText("payments-api")).toBeInTheDocument();
  });
});

function ToolbarGridHarness() {
  const [query, setQuery] = useState("");
  const filtered = rows.filter((row) => row.name.toLowerCase().includes(query.toLowerCase()));
  return (
    <DataGrid
      ariaLabel="Toolbar credential rows"
      rows={filtered}
      columns={columns}
      getRowId={(row) => row.id}
      showColumnChooser
      toolbar={({ columnChooser }) => (
        <DataGridToolbar
          searchLabel="Search credential rows"
          searchPlaceholder="Search by name"
          searchValue={query}
          onSearchChange={setQuery}
          filters={<span>Owner filter</span>}
          bulkActions={<ButtonLike>Bulk rotate</ButtonLike>}
          columnChooser={columnChooser}
        />
      )}
    />
  );
}

function PersistentGridHarness() {
  const [owner, setOwner] = useState("all");
  const [sort, setSort] = useState<DataGridSort>({ columnId: "name", direction: "asc" });
  const filtered = rows.filter((row) => owner === "all" || row.owner === owner);
  const sorted = [...filtered].sort((left, right) => {
    const dir = sort.direction === "asc" ? 1 : -1;
    return left.name.localeCompare(right.name) * dir;
  });

  return (
    <DataGrid
      ariaLabel="Persistent credential rows"
      rows={sorted}
      columns={columns}
      getRowId={(row) => row.id}
      sort={sort}
      onSort={setSort}
      showColumnChooser
      viewStorageKey="test-grid"
      viewMetadata={{ owner }}
      onViewRestore={(metadata, restoredSort) => {
        setOwner(typeof metadata.owner === "string" ? metadata.owner : "all");
        if (restoredSort) setSort(restoredSort);
      }}
      toolbar={({ columnChooser, savedViews }) => (
        <DataGridToolbar
          filters={
            <label className="grid gap-1 text-sm font-medium">
              Owner view filter
              <select
                aria-label="Owner view filter"
                value={owner}
                onChange={(event) => setOwner(event.target.value)}
                className="rounded-control border border-border bg-background px-2 py-1"
              >
                <option value="all">All</option>
                <option value="platform">Platform</option>
                <option value="security">Security</option>
              </select>
            </label>
          }
          columnChooser={columnChooser}
          savedViews={savedViews}
        />
      )}
    />
  );
}

function ButtonLike({ children }: { children: string }) {
  return <button type="button">{children}</button>;
}

function DrawerHarness() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  return (
    <div>
      <button ref={triggerRef} type="button" onClick={() => setOpen(true)}>
        Open credential detail
      </button>
      <DetailDrawer
        open={open}
        title="payments-api"
        description="Fetched credential detail."
        actions={<button type="button">Request renewal</button>}
        onClose={() => setOpen(false)}
        returnFocusRef={triggerRef}
      >
        <dl>
          <div>
            <dt>Status</dt>
            <dd>
              <StatusBadge vocabulary="certificate" value="active" />
            </dd>
          </div>
        </dl>
      </DetailDrawer>
    </div>
  );
}

describe("shared DetailDrawer", () => {
  it("opens with resource fields and actions, closes with Escape, and returns focus", async () => {
    const user = userEvent.setup();
    const { container } = render(<DrawerHarness />);
    const trigger = screen.getByRole("button", { name: /open credential detail/i });

    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "payments-api" });
    expect(within(dialog).getByText("Fetched credential detail.")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /request renewal/i })).toBeInTheDocument();
    expect(within(dialog).getByText("active")).toHaveAttribute("data-status-badge", "certificate");
    expect(within(dialog).getByRole("button", { name: /close/i })).toHaveFocus();

    const results = await axe(container);
    expect(results).toHaveNoViolations();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "payments-api" })).not.toBeInTheDocument());
    expect(trigger).toHaveFocus();
  });
});
