import { useId, useState } from "react";

import { BrowserTerminal, type PodExec } from "@/components/access/BrowserTerminal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";

// A259 part 3: on a Kubernetes session opened for the browser, the operator
// names the pod (and optionally its container) and works in it through the
// browser terminal: the control plane opens an exec of sh through the
// session's gateway, which adds the session's own token and records the
// stream. No token or ticket reaches the browser.

const plain = { autoComplete: "off", spellCheck: false } as const;

export function PodTerminal({ sessionID }: { sessionID: string }) {
  const { t } = useTranslation();
  const ids = { namespace: useId(), pod: useId(), container: useId(), hint: useId() };
  const [fields, setFields] = useState({ namespace: "", pod: "", container: "" });
  const [open, setOpen] = useState<PodExec | null>(null);
  const set = (field: keyof typeof fields, value: string) => setFields((current) => ({ ...current, [field]: value }));

  if (open) return <BrowserTerminal sessionID={sessionID} exec={open} onClose={() => setOpen(null)} />;
  const namespace = fields.namespace.trim();
  const pod = fields.pod.trim();
  const container = fields.container.trim();
  return (
    <form
      aria-labelledby={`pam-pod-${sessionID}`}
      aria-describedby={ids.hint}
      className="grid gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (namespace && pod) setOpen({ namespace, pod, ...(container ? { container } : {}) });
      }}
    >
      <h3 id={`pam-pod-${sessionID}`} className="text-sm font-semibold">
        {t("admin.access.pod.title")}
      </h3>
      <p id={ids.hint} className="text-xs text-muted-foreground">
        {t("admin.access.pod.hint")}
      </p>
      <div className="grid gap-2 md:grid-cols-3">
        <label htmlFor={ids.namespace} className="grid gap-1 text-sm">
          {t("admin.access.pod.namespace")}
          <Input id={ids.namespace} value={fields.namespace} onChange={(event) => set("namespace", event.target.value)} {...plain} required />
        </label>
        <label htmlFor={ids.pod} className="grid gap-1 text-sm">
          {t("admin.access.pod.name")}
          <Input id={ids.pod} value={fields.pod} onChange={(event) => set("pod", event.target.value)} {...plain} required />
        </label>
        <label htmlFor={ids.container} className="grid gap-1 text-sm">
          {t("admin.access.pod.container")}
          <Input id={ids.container} value={fields.container} onChange={(event) => set("container", event.target.value)} {...plain} />
        </label>
      </div>
      <div>
        <Button type="submit" size="sm" disabled={!namespace || !pod}>
          {t("admin.access.openTerminal")}
        </Button>
      </div>
    </form>
  );
}
