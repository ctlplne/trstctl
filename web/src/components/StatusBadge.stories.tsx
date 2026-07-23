import type { Meta, StoryObj } from "@storybook/react-vite";
import { StatusBadge } from "@/components/StatusBadge";

const meta = {
  title: "Components/StatusBadge",
  component: StatusBadge,
} satisfies Meta<typeof StatusBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Lifecycle: Story = {
  args: { value: "issued" },
  render: () => (
    <div className="flex flex-wrap items-center gap-2">
      <StatusBadge vocabulary="lifecycle" value="requested" />
      <StatusBadge vocabulary="lifecycle" value="issued" />
      <StatusBadge vocabulary="lifecycle" value="deployed" />
      <StatusBadge vocabulary="lifecycle" value="revoked" />
      <StatusBadge vocabulary="lifecycle" value="retired" />
    </div>
  ),
};

export const CustomLabel: Story = {
  args: { vocabulary: "lifecycle", value: "issued", label: "active" },
};
