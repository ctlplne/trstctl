import type { Meta, StoryObj } from "@storybook/react-vite";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";

const meta = {
  title: "Components/PageHeader",
  component: PageHeader,
} satisfies Meta<typeof PageHeader>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Standard: Story = {
  args: {
    title: "Certificates",
    description: "Every certificate in inventory — served, discovered, and imported.",
  },
};

export const WithEyebrowAndActions: Story = {
  args: {
    title: "Automatic secret sources",
    eyebrow: "Secrets",
    description: "Dynamic leases, PKI-as-secrets, and transit/KMIP cryptographic operations.",
    actions: <Button>New lease</Button>,
  },
};
