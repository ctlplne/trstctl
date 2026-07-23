import type { Meta, StoryObj } from "@storybook/react-vite";
import { Eyebrow, Num } from "@/components/typography";

const meta = {
  title: "Primitives/Typography",
  component: Eyebrow,
} satisfies Meta<typeof Eyebrow>;

export default meta;
type Story = StoryObj<typeof meta>;

export const EyebrowLabel: Story = {
  args: { children: "Needs action" },
};

export const EyebrowAsHeading: Story = {
  args: { as: "h3", children: "Store & engines" },
};

export const InlineData: Story = {
  args: { children: "Inline data" },
  render: () => (
    <p className="text-body">
      Issued <Num>1,284</Num> certificates; the oldest secret is <Num>400d</Num> old and the lease expires at <Num>2026-07-24T12:00:00Z</Num>.
    </p>
  ),
};
