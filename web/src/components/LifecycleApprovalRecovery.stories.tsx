import type { Meta, StoryObj } from "@storybook/react-vite";
import { LifecycleApprovalRecovery } from "@/components/LifecycleApprovalRecovery";

const meta = {
  title: "Components/LifecycleApprovalRecovery",
  component: LifecycleApprovalRecovery,
  args: { onReviewNew: () => undefined },
} satisfies Meta<typeof LifecycleApprovalRecovery>;

export default meta;
type Story = StoryObj<typeof meta>;

export const AwaitingReview: Story = {
  args: { approval: { requestId: "1ca14715-666f-5ed8-bd88-7b262fe543f5", status: "pending" } },
};

export const ExpiredRequest: Story = {
  args: { approval: { requestId: "1ca14715-666f-5ed8-bd88-7b262fe543f5", status: "expired" } },
};
