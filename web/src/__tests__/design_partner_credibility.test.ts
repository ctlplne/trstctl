import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { messages } from "@/i18n/messages";

const root = process.cwd();
const discovery = readFileSync(path.join(root, "src/pages/Discovery.tsx"), "utf8");
const shell = readFileSync(path.join(root, "src/components/AppShell.tsx"), "utf8");
const platform = readFileSync(path.join(root, "src/pages/Platform.tsx"), "utf8");
const notifications = readFileSync(path.join(root, "src/pages/Notifications.tsx"), "utf8");
const limitations = readFileSync(path.join(root, "../docs/limitations.md"), "utf8");
const troubleshooting = readFileSync(path.join(root, "../docs/troubleshooting.md"), "utf8");

describe("cold design-partner credibility findings", () => {
  it("invalidates every cross-page read model changed by discovery triage", () => {
    for (const key of ["nhi-shadow-posture", "nhi-inventory", "risk", "contextual-priorities", "ownership-attribution"]) {
      expect(discovery).toContain(`["${key}"]`);
    }
  });

  it("does not promise a deployment repair or verified delivery when only evidence is available", () => {
    expect(messages["certificateCockpit.action.repairDeployment"].defaultMessage).toBe("Review deployment path");
    expect(messages["admin.system.deliveryCheck"].defaultMessage).toBe("Deployment verification failures");
    expect(notifications).toContain('detail.not_after ? formatDateTime(detail.not_after) : t("notifications.center.noDeadline")');
  });

  it("keeps exact source identity and seeded-demo status visible", () => {
    expect(platform).toContain("systemReadout.version");
    expect(platform).toContain("systemReadout.commit");
    expect(shell).toContain("seeded-demo-banner");
    expect(shell).toContain('deployment_id === "trstctl-local-demo"');
  });

  it("puts a one-minute boundary summary before the exhaustive limitations ledger", () => {
    const summary = limitations.indexOf("## The 60-second boundary summary");
    const matrix = limitations.indexOf("## Feature served-state matrix");
    expect(summary).toBeGreaterThan(0);
    expect(matrix).toBeGreaterThan(summary);
  });

  it("gives ordinary defects an actionable public issue path", () => {
    expect(troubleshooting).toContain("https://github.com/ctlplne/trstctl/issues/new/choose");
  });
});
