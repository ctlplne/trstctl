import { useMemo, useState, type FormEvent, type RefObject } from "react";
import { Loader2, Plus } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, type Role } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// The wildcard and the agent channel's machine permissions never belong to a
// custom role; the server refuses them as well.
const notGrantable = new Set(["*", "agents:heartbeat", "agents:job.poll", "agents:job.complete", "agents:job.report"]);

/** The permissions a custom role can draw on: every concrete permission a built-in role grants. */
export function customRoleVocabulary(roles: Role[]): string[] {
  const out = new Set<string>();
  for (const role of roles) {
    if (role.custom) continue;
    for (const permission of role.permissions) if (!notGrantable.has(permission)) out.add(permission);
  }
  return [...out].sort();
}

export function CustomRoleDialog({
  roles,
  returnFocusRef,
  onClose,
  onDefined,
}: {
  roles: Role[];
  returnFocusRef: RefObject<HTMLButtonElement | null>;
  onClose: () => void;
  onDefined: (role: Role) => void;
}) {
  const { t } = useTranslation();
  const vocabulary = useMemo(() => customRoleVocabulary(roles), [roles]);
  const [name, setName] = useState("");
  const [summary, setSummary] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDefined(await api.defineTenantCustomRole(name.trim(), { description: summary.trim(), permissions }));
    } catch (err) {
      setError(apiProblemMessage(err, t("admin.access.customRoleFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId="custom-role-heading"
      descriptionId="custom-role-description"
      returnFocusRef={returnFocusRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id="custom-role-heading" className="text-title font-semibold">
          {t("admin.access.defineCustomRole")}
        </h2>
        <p id="custom-role-description" className="mt-1 text-sm text-muted-foreground">
          {t("admin.access.customRoleDescription")}
        </p>
      </header>
      <form onSubmit={(event) => void submit(event)} className="grid gap-3 p-5">
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
        <label className="grid gap-1 text-sm font-medium">
          {t("admin.access.customRoleName")}
          <Input value={name} onChange={(event) => setName(event.target.value)} required />
          <span className="text-xs font-normal text-muted-foreground">{t("admin.access.customRoleNameHint")}</span>
        </label>
        <label className="grid gap-1 text-sm font-medium">
          {t("admin.access.customRoleSummary")}
          <Input value={summary} maxLength={512} onChange={(event) => setSummary(event.target.value)} />
        </label>
        <fieldset className="grid gap-2 rounded-control border border-border p-3">
          <legend className="px-1 text-sm font-medium text-foreground">{t("admin.access.customRolePermissions")}</legend>
          <p className="text-xs text-foreground">{t("admin.access.customRolePermissionsHint")}</p>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {vocabulary.map((permission) => (
              <label key={permission} className="flex items-center gap-2 rounded-control border border-border bg-background px-3 py-1.5 text-sm">
                <Checkbox
                  checked={permissions.includes(permission)}
                  onChange={(event) =>
                    setPermissions((current) => (event.target.checked ? [...current, permission] : current.filter((candidate) => candidate !== permission)))
                  }
                />
                <code className="text-xs">{permission}</code>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="submit" disabled={busy || !name.trim() || permissions.length === 0}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
            {t("admin.access.defineCustomRole")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
