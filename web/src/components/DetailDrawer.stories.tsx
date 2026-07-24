import { useRef, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { DetailDrawer } from "@/components/DetailDrawer";
import { Dialog } from "@/components/Dialog";
import { CredentialChip } from "@/components/CredentialChip";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";

/** Overlay surfaces: the end-edge DetailDrawer (row → details) and the
 * centered Dialog (confirmations). Both trap focus, restore it on close, and
 * animate only behind motion-safe. The stories keep them open inside a
 * relative frame so the overlay has a positioning context. */
const meta = {
  title: "Components/Overlays",
  component: DetailDrawer,
} satisfies Meta<typeof DetailDrawer>;

export default meta;
type Story = StoryObj<typeof meta>;

function Frame({ children }: { children: React.ReactNode }) {
  return <div className="relative h-[480px] overflow-hidden rounded-panel border border-border bg-background">{children}</div>;
}

function DrawerDemo() {
  const [open, setOpen] = useState(true);
  const openRef = useRef<HTMLButtonElement>(null);
  return (
    <Frame>
      <div className="p-6">
        <Button ref={openRef} onClick={() => setOpen(true)}>
          Open drawer
        </Button>
      </div>
      <DetailDrawer
        open={open}
        onClose={() => setOpen(false)}
        returnFocusRef={openRef}
        title="payments.example.com"
        description="Issued by trstctl Issuing CA 1 · expires in 61 days"
        actions={
          <>
            <Button size="sm">Renew now</Button>
            <Button size="sm" variant="destructive-outline">
              Revoke
            </Button>
          </>
        }
      >
        <dl className="space-y-3 text-body">
          <div>
            <dt className="text-caption uppercase tracking-wide text-muted-foreground">Status</dt>
            <dd className="mt-1">
              <StatusBadge vocabulary="lifecycle" value="issued" />
            </dd>
          </div>
          <div>
            <dt className="text-caption uppercase tracking-wide text-muted-foreground">Fingerprint</dt>
            <dd className="mt-1">
              <CredentialChip value="SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" label="fingerprint" />
            </dd>
          </div>
          <div>
            <dt className="text-caption uppercase tracking-wide text-muted-foreground">Owner</dt>
            <dd className="mt-1">payments-platform (team)</dd>
          </div>
        </dl>
      </DetailDrawer>
    </Frame>
  );
}

export const Drawer: Story = {
  args: { open: true, title: "", children: null, onClose: () => {} },
  render: () => <DrawerDemo />,
};

function ConfirmDemo() {
  const [open, setOpen] = useState(true);
  const openRef = useRef<HTMLButtonElement>(null);
  return (
    <Frame>
      <div className="p-6">
        <Button ref={openRef} variant="destructive-outline" onClick={() => setOpen(true)}>
          Revoke certificate…
        </Button>
      </div>
      <Dialog open={open} onClose={() => setOpen(false)} titleId="revoke-title" descriptionId="revoke-desc" role="alertdialog" returnFocusRef={openRef}>
        <div className="absolute inset-0 flex items-center justify-center p-6">
          <div className="w-full max-w-md rounded-panel border border-border bg-background p-6 shadow-elevation3">
            <h2 id="revoke-title" className="text-heading font-semibold">
              Revoke payments.example.com?
            </h2>
            <p id="revoke-desc" className="mt-2 text-body text-muted-foreground">
              Served traffic presenting this certificate will fail TLS immediately. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button variant="destructive" onClick={() => setOpen(false)}>
                Revoke
              </Button>
            </div>
          </div>
        </div>
      </Dialog>
    </Frame>
  );
}

export const ConfirmDialog: Story = {
  args: { open: true, title: "", children: null, onClose: () => {} },
  render: () => <ConfirmDemo />,
};
