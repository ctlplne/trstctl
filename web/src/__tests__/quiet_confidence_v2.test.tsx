import { readFileSync } from "node:fs";
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

  it("keeps routine table hierarchy in sentence case", () => {
    const tableRule = css.slice(css.indexOf(".ui-table thead th"), css.indexOf(".ui-table tbody td"));
    expect(tableRule).not.toContain("text-transform: uppercase");
    expect(tableRule).not.toContain("letter-spacing: 0.04em");
  });
});
