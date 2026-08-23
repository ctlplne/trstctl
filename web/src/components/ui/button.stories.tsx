import type { Meta, StoryObj } from "@storybook/react-vite";
import { Send } from "lucide-react";
import { Button } from "@/components/ui/button";

const meta = {
  title: "Primitives/Button",
  component: Button,
} satisfies Meta<typeof Button>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Primary: Story = {
  args: { children: "Issue certificate" },
};

export const WithIcon: Story = {
  render: () => (
    <Button>
      <Send className="h-4 w-4" aria-hidden="true" />
      Submit request
    </Button>
  ),
};

export const Variants: Story = {
  render: () => (
    <div className="flex flex-wrap items-center gap-3">
      <Button>Primary — forest means act</Button>
      <Button variant="outline">Outline</Button>
      <Button variant="ghost">Ghost</Button>
      <Button variant="destructive">Revoke</Button>
      <Button variant="destructive-outline">Delete owner</Button>
    </div>
  ),
};

export const Loading: Story = {
  args: { children: "Rotating…", loading: true },
};
