import type { Meta, StoryObj } from "@storybook/react-vite";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

/** Rule 14: form controls are primitives. Field owns label/description/error
 * wiring (htmlFor, aria-describedby, aria-invalid); the controls wear the
 * .ui-input family. Flip the theme toolbar — the R-01 regression these
 * replace was white native fields in the dark theme. */
const meta = {
  title: "Primitives/FormControls",
  component: Field,
} satisfies Meta<typeof Field>;

export default meta;
type Story = StoryObj<typeof meta>;

const noop = () => undefined;

export const TextField: Story = {
  args: { label: "Credential name", children: noop },
  render: () => (
    <div className="max-w-md">
      <Field label="Credential name" description="Shown in the inventory and on certificates." required>
        {(control) => <Input {...control} placeholder="payments-api" required />}
      </Field>
    </div>
  ),
};

export const WithError: Story = {
  args: { label: "Owner id", children: noop },
  render: () => (
    <div className="max-w-md">
      <Field label="Owner id" error="Owner id is required." required>
        {(control) => <Input {...control} required />}
      </Field>
    </div>
  ),
};

export const SelectField: Story = {
  args: { label: "Issuance profile", children: noop },
  render: () => (
    <div className="max-w-md">
      <Field label="Issuance profile" description="Only active profiles can issue.">
        {(control) => (
          <Select {...control} defaultValue="web-server">
            <option value="web-server">web-server v2 — active</option>
            <option value="workload">workload-spiffe v1 — active</option>
            <option value="legacy">legacy-rsa v4 — inactive</option>
          </Select>
        )}
      </Field>
    </div>
  ),
};

export const TextareaField: Story = {
  args: { label: "Business purpose", children: noop },
  render: () => (
    <div className="max-w-md">
      <Field label="Business purpose">{(control) => <Textarea {...control} className="min-h-24" placeholder="Service TLS for staging" />}</Field>
    </div>
  ),
};

export const CheckboxField: Story = {
  args: { label: "Credential delivery", children: noop },
  render: () => (
    <label htmlFor="storybook-automatic-delivery" className="inline-flex items-center gap-2 text-body font-medium">
      <Checkbox id="storybook-automatic-delivery" defaultChecked />
      Enable automatic delivery
    </label>
  ),
};

export const DisabledAndMono: Story = {
  args: { label: "Fingerprint", children: noop },
  render: () => (
    <div className="grid max-w-md gap-4">
      <Field label="Enrollment token" description="Issued tokens cannot be edited.">
        {(control) => <Input {...control} className="font-mono" defaultValue="eyJhbGciOiJFZERTQSJ9.enrol" disabled />}
      </Field>
      <Field label="Hosts">
        {(control) => <Textarea {...control} className="min-h-20 font-mono text-xs" placeholder={"bastion-1.example.com\nbastion-2.example.com"} />}
      </Field>
    </div>
  ),
};
