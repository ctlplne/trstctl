import type { Meta, StoryObj } from "@storybook/react-vite";
import { CapabilityRouteNotice } from "@/components/CapabilityTruth";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";

function row(overrides: Partial<CapabilityViewItem>): CapabilityViewItem {
  return {
    capability_id: "F1",
    name: "Certificate inventory",
    purpose: "See certificate health and decide what needs attention.",
    tool: "certificates",
    classification: "primary",
    console_route: "/",
    maturity: "complete_vertical_slice",
    release_blocking: false,
    edition: "core",
    runtime_state: "available",
    authorization_state: "full",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: "complete" }],
    actions: { allowed: ["listCertificates"], scoped: [], denied: [], unavailable: [] },
    ...overrides,
  };
}

const limitedView: CapabilityView = {
  schema_version: 1,
  contract_schema_version: 3,
  enforcement_note: "The server checks again at execution.",
  license: { tier: "community", state: "community" },
  items: [
    row({}),
    row({
      capability_id: "F19",
      name: "Risk scoring",
      tool: "operations",
      runtime_state: "partially_available",
      authorization_state: "partial",
      stages: [{ name: "verify", completion: "blocked", reason: "Risk projection is still catching up." }],
      actions: {
        allowed: ["listRisk"],
        scoped: [],
        denied: [],
        unavailable: [{ operation_id: "verifyRisk", code: "dependency_not_configured", detail: "Risk projection is still catching up." }],
      },
    }),
  ],
};

const meta = {
  title: "Components/CapabilityTruth",
  component: CapabilityRouteNotice,
} satisfies Meta<typeof CapabilityRouteNotice>;

export default meta;
type Story = StoryObj<typeof meta>;

export const LimitedRoute: Story = {
  render: () => (
    <CapabilityFixtureProvider view={limitedView}>
      <CapabilityRouteNotice />
    </CapabilityFixtureProvider>
  ),
};

export const ReadUnavailable: Story = {
  render: () => (
    <CapabilityFixtureProvider view={null} error>
      <CapabilityRouteNotice />
    </CapabilityFixtureProvider>
  ),
};

export const Loading: Story = {
  render: () => (
    <CapabilityFixtureProvider view={null} loading>
      <CapabilityRouteNotice />
    </CapabilityFixtureProvider>
  ),
};
