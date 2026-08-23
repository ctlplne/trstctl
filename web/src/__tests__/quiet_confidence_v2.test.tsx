import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BrandMark } from "@/components/BrandMark";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";

const webRoot = process.cwd();
const css = readFileSync(path.join(webRoot, "src/index.css"), "utf8");
const shellSource = readFileSync(path.join(webRoot, "src/components/AppShell.tsx"), "utf8");
const kpiSource = readFileSync(path.join(webRoot, "src/components/ModuleKpiStrip.tsx"), "utf8");
const adminHeaderSource = readFileSync(path.join(webRoot, "src/components/AdminHeaderActions.tsx"), "utf8");
const certificateSource = readFileSync(path.join(webRoot, "src/pages/Certificates.tsx"), "utf8");
const dashboardSource = readFileSync(path.join(webRoot, "src/pages/Dashboard.tsx"), "utf8");
const protocolSource = readFileSync(path.join(webRoot, "src/pages/Protocols.tsx"), "utf8");
const buttonSource = readFileSync(path.join(webRoot, "src/components/ui/button.tsx"), "utf8");
const buttonStorySource = readFileSync(path.join(webRoot, "src/components/ui/button.stories.tsx"), "utf8");

function productTsxFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) return entry.name === "__tests__" ? [] : productTsxFiles(candidate);
    return entry.name.endsWith(".tsx") && !entry.name.endsWith(".test.tsx") ? [candidate] : [];
  });
}

describe("quiet confidence v2", () => {
  it("pins the approved warm-paper and forest palette as the light default", () => {
    expect(css).toContain("--background: 45 33% 95%");
    expect(css).toContain("--card: 48 100% 99%");
    expect(css).toContain("--foreground: 167 16% 11%");
    expect(css).toContain("--primary: 166 55% 20%");
    expect(css).toContain("--brand-accent: 166 55% 20%");
    expect(css).toContain("--sidebar: 60 15% 92%");
    expect(css).toContain("--sidebar-foreground: 163 14% 22%");
  });

  it("uses one reusable circular identity mark in sign-in and shell chrome", () => {
    render(<BrandMark size="md" />);
    const mark = screen.getByTestId("brand-mark");
    expect(mark).toHaveClass("rounded-full", "bg-primary", "text-primary-foreground");
    expect(mark.querySelector("svg")).not.toBeNull();
    expect(shellSource).toContain("<BrandMark");
    expect(shellSource).not.toContain("tracking-wider text-muted-foreground sm:block");
  });

  it("keeps Answer, Operate, and Prove semantics without making framework labels compete with the task", () => {
    render(
      <PageHeader
        title="Certificates"
        description="See every certificate, who owns it, and what needs attention."
        technicalDetails="Serials, policy IDs, and signed audit events."
        actions={<Button>Add certificate</Button>}
      />,
    );

    expect(screen.getByTestId("page-depth-answer")).toHaveTextContent("Answer");
    expect(screen.getByTestId("page-depth-answer").querySelector(".sr-only")).not.toBeNull();
    expect(screen.getByTestId("page-depth-operate").querySelector(".sr-only")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Add certificate" })).toBeVisible();
    expect(screen.getByTestId("page-depth-prove")).toHaveTextContent("Technical details");
  });

  it("renders module telemetry as one quiet strip instead of a row of dashboard cards", () => {
    expect(kpiSource).toContain("divide-x");
    expect(kpiSource).not.toContain("hover:-translate-y-0.5");
    expect(kpiSource).not.toContain("hover:shadow-elevation2");
  });

  it("keeps action labels on one readable line", () => {
    render(<Button>View details</Button>);
    expect(screen.getByRole("button", { name: "View details" })).toHaveClass("whitespace-nowrap");
  });

  it("keeps routine table hierarchy in sentence case", () => {
    const tableRule = css.slice(css.indexOf(".ui-table thead th"), css.indexOf(".ui-table tbody td"));
    expect(tableRule).not.toContain("text-transform: uppercase");
    expect(tableRule).not.toContain("letter-spacing: 0.04em");
  });

  it("does not force interface labels or technical identifiers into all caps", () => {
    const offenders = [path.join(webRoot, "src/components"), path.join(webRoot, "src/pages")]
      .flatMap(productTsxFiles)
      .filter((file) => /className\s*=\s*["'][^"']*\buppercase\b/.test(readFileSync(file, "utf8")))
      .map((file) => path.relative(webRoot, file));

    expect(offenders).toEqual([]);
  });

  it("keeps text-bearing pill shapes out of product pages", () => {
    const offenders = [path.join(webRoot, "src/components"), path.join(webRoot, "src/pages")]
      .flatMap(productTsxFiles)
      .filter((file) => /className\s*=\s*["'][^"']*\brounded-full\b[^"']*\bpx-/.test(readFileSync(file, "utf8")))
      .map((file) => path.relative(webRoot, file));

    expect(offenders).toEqual([]);
  });

  it("folds redundant administration links into one quiet secondary disclosure", () => {
    expect(adminHeaderSource).toContain('<details className="group relative">');
    expect(adminHeaderSource).toContain('t("dashboard.moreActions")');
    expect(adminHeaderSource.match(/<Link\b/g)).toHaveLength(2);
  });

  it("uses the shared forest action primitive on the certificate first impression", () => {
    const headerStart = certificateSource.indexOf("<PageHeader");
    const headerEnd = certificateSource.indexOf("/>", headerStart);
    const header = certificateSource.slice(headerStart, headerEnd);
    expect(header).toContain("<Button");
    expect(header).not.toContain("<button");
    expect(buttonSource.toLowerCase()).not.toContain("gold remains the single action");
    expect(buttonStorySource.toLowerCase()).not.toContain("gold means act");
  });

  it("keeps numeric risk scores out of the default Home answer", () => {
    expect(dashboardSource).toContain('t("dashboard.attention.itemReason"');
    expect(dashboardSource).not.toContain('t("dashboard.rotateFirst.contextualRisk"');
    expect(dashboardSource).not.toContain("`risk score ${Math.round(r.score)}`");
  });

  it("teaches protocol choices before revealing responder machinery", () => {
    const guide = protocolSource.indexOf('id="protocol-guide-heading"');
    const operations = protocolSource.indexOf('data-testid="protocol-operational-details"');
    expect(guide).toBeGreaterThan(0);
    expect(operations).toBeGreaterThan(guide);
    expect(protocolSource).toContain("open={operationsOpen}");
    expect(protocolSource).toContain('nameKey: "protocols.guide.acme.name"');
  });
});
