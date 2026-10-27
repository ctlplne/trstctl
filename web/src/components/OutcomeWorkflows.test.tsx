import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { OutcomeWorkflows } from "@/components/OutcomeWorkflows";
import { IntlProvider } from "@/i18n/I18nProvider";

describe("OutcomeWorkflows", () => {
  it("routes the console home to each outcome's starting screen", () => {
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <MemoryRouter>
          <OutcomeWorkflows />
        </MemoryRouter>
      </IntlProvider>,
    );
    const section = screen.getByRole("region", { name: "Outcomes" });
    const links = within(section).getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual(["/certificates", "/workloads", "/posture"]);
    expect(within(section).getByRole("link", { name: /Certificate automation and assurance/ })).toHaveAttribute("href", "/certificates");
    expect(within(section).getByRole("link", { name: /Agent and workload identity assurance/ })).toHaveAttribute("href", "/workloads");
    expect(within(section).getByRole("link", { name: /Cryptographic risk and migration assurance/ })).toHaveAttribute("href", "/posture");
  });
});
