import type { Meta, StoryObj } from "@storybook/react-vite";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";

/** The five list states (DESIGN.md rule 7) come from these primitives and
 * EmptyState only — pages never hand-roll a spinner line or an error box. */
const meta = {
  title: "Components/StatePrimitives",
  component: LoadingState,
} satisfies Meta<typeof LoadingState>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Loading: Story = {
  args: { children: "Loading certificates…" },
  render: () => <LoadingState>Loading certificates…</LoadingState>,
};

export const ErrorStory: Story = {
  name: "Error",
  args: { children: null },
  render: () => (
    <ErrorState title="Could not load certificates">The inventory endpoint returned 502. Retry, or check the agent&apos;s connectivity.</ErrorState>
  ),
};

export const PermissionDenied: Story = {
  args: { children: null },
  render: () => <PermissionDeniedState>Your role does not include certificate:read for this tenant.</PermissionDeniedState>,
};

export const Unavailable: Story = {
  args: { children: null },
  render: () => (
    <UnavailableState title="Code signing is not enabled">Enable the code-signing module in Platform → Settings to see signing events here.</UnavailableState>
  ),
};

export const AllFour: Story = {
  args: { children: null },
  render: () => (
    <div className="max-w-xl space-y-3">
      <LoadingState>Loading certificates…</LoadingState>
      <ErrorState title="Could not load certificates">The inventory endpoint returned 502.</ErrorState>
      <PermissionDeniedState>Your role does not include certificate:read.</PermissionDeniedState>
      <UnavailableState title="Code signing is not enabled">Enable the module in Platform → Settings.</UnavailableState>
    </div>
  ),
};
