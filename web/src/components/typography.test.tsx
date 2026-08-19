import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Eyebrow, Num } from "@/components/typography";

/** S-C9: the primitives pin the refinement rules — one quiet eyebrow style, one
 * inline-number style — so a class-cluster drift shows up here, not in a
 * design review. */

describe("typography primitives (S-C9)", () => {
  it("Eyebrow renders the single sentence-case micro-label cluster", () => {
    render(<Eyebrow>Needs action</Eyebrow>);
    const eyebrow = screen.getByText("Needs action");
    expect(eyebrow.tagName).toBe("SPAN");
    for (const cls of ["text-caption", "font-semibold", "text-muted-foreground"]) {
      expect(eyebrow.className).toContain(cls);
    }
    expect(eyebrow.className).not.toContain("uppercase");
    expect(eyebrow.className).not.toContain("tracking-wide");
  });

  it("Eyebrow supports semantic elements and class extension without losing the cluster", () => {
    render(
      <Eyebrow as="h3" className="text-brand-accent">
        Store & engines
      </Eyebrow>,
    );
    const eyebrow = screen.getByRole("heading", { level: 3, name: "Store & engines" });
    expect(eyebrow.className).not.toContain("uppercase");
    // tailwind-merge keeps the extension override.
    expect(eyebrow.className).toContain("text-brand-accent");
  });

  it("Num renders inline data values in the mono face with tabular figures", () => {
    render(<Num>1,284</Num>);
    const num = screen.getByText("1,284");
    expect(num.tagName).toBe("SPAN");
    expect(num.className).toContain("font-mono");
    expect(num.className).toContain("tabular-nums");
  });
});
