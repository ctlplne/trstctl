import type { Meta, StoryObj } from "@storybook/react-vite";
import { EmptyState } from "@/components/EmptyState";

const meta = {
  title: "Components/EmptyState",
  component: EmptyState,
} satisfies Meta<typeof EmptyState>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Basic: Story = {
  args: {
    title: "No owners yet",
    children: "Add an owner to start tracking accountability.",
  },
};
