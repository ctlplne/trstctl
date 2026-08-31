import type { Meta, StoryObj } from "@storybook/react-vite";
import { WorkloadIdentityHandoff } from "@/components/WorkloadIdentityHandoff";

const meta = {
  title: "Components/WorkloadIdentityHandoff",
  component: WorkloadIdentityHandoff,
  decorators: [
    (Story) => (
      <div className="max-w-xl">
        <Story />
      </div>
    ),
  ],
} satisfies Meta<typeof WorkloadIdentityHandoff>;

export default meta;
type Story = StoryObj<typeof meta>;

export const SignedIdentity: Story = {
  args: {
    spiffeID:
      "spiffe://workloads.example.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/broker/agent/build-1/method/k8s_sat/subject/ns/payments/sa/api",
  },
};

export const OlderResponseWithoutIdentity: Story = { args: {} };

export const NarrowScreen: Story = {
  ...SignedIdentity,
  decorators: [
    (Story) => (
      <div className="w-64">
        <Story />
      </div>
    ),
  ],
};
