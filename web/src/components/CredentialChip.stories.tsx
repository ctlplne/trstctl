import type { Meta, StoryObj } from "@storybook/react-vite";
import { CredentialChip } from "@/components/CredentialChip";

/** The one sanctioned rendering for cryptographic material and machine
 * identifiers: DM Mono, middle-truncated (operators compare the ENDS of a
 * fingerprint), full value on hover, one-click copy. */
const meta = {
  title: "Components/CredentialChip",
  component: CredentialChip,
} satisfies Meta<typeof CredentialChip>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Fingerprint: Story = {
  args: {
    value: "SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    label: "fingerprint",
  },
};

export const SerialNumber: Story = {
  args: { value: "03:ac:5c:26:6a:0b:40:9b:8f:0b:79:f2:ae:46:25:77", label: "serial number" },
};

export const ShortValueStaysWhole: Story = {
  args: { value: "spiffe://prod/api", label: "SPIFFE ID" },
};

export const CustomTruncation: Story = {
  args: {
    value: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3b3JrbG9hZC1hcGkifQ",
    label: "enrollment token",
    head: 16,
    tail: 8,
  },
};

export const ExactIdentityAfterDisclosure: Story = {
  args: {
    value: "spiffe://workloads.example.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/attested/method/k8s_sat/subject/ns/payments/sa/api",
    label: "Signed workload ID",
    fullValue: true,
  },
  decorators: [
    (Story) => (
      <div className="max-w-xs">
        <Story />
      </div>
    ),
  ],
};

export const InTableContext: Story = {
  args: { value: "SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", label: "fingerprint" },
  render: () => (
    <table className="w-full max-w-xl text-left text-sm tabular-nums">
      <thead>
        <tr className="border-b border-border text-muted-foreground">
          <th className="py-2 font-medium">Subject</th>
          <th className="py-2 font-medium">Fingerprint</th>
        </tr>
      </thead>
      <tbody>
        <tr className="border-b border-border/60">
          <td className="py-2">payments.example.com</td>
          <td className="py-2">
            <CredentialChip value="SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" label="fingerprint" />
          </td>
        </tr>
        <tr>
          <td className="py-2">web.example.com</td>
          <td className="py-2">
            <CredentialChip value="SHA256:60303ae22b998861bce3b28f33eec1be758a213c" label="fingerprint" />
          </td>
        </tr>
      </tbody>
    </table>
  ),
};
