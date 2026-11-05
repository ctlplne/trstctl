import { useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { api, type PAMFolder, type PAMTarget } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { DataGrid } from "@/components/DataGrid";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Num } from "@/components/typography";

const folderSchema = z.object({
  name: z
    .string()
    .trim()
    .regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  template_id: z.string().min(1),
});
type FolderForm = z.infer<typeof folderSchema>;

/** Folder membership applies the same access template to every account.
 * Recording is enforced by the server, including check-out refusals. */
export function PAMFoldersPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const folders = useApiQuery(["pam-folders"], api.pamFolders, { retry: false });
  const templates = useApiQuery(["pam-templates"], api.pamTemplates, { retry: false });
  const targets = useApiQuery(["pam-targets"], api.pamTargets, { retry: false });
  const [editing, setEditing] = useState<PAMFolder | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const saveKey = useRef(crypto.randomUUID());
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FolderForm>({ resolver: zodResolver(folderSchema), defaultValues: { name: "", template_id: "" } });
  const act = async (work: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await work();
      await Promise.all([["pam-folders"], ["pam-templates"], ["pam-targets"]].map((queryKey) => cache.invalidateQueries({ queryKey })));
      setNotice(t("admin.access.folders.saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const save = (form: FolderForm) =>
    act(async () => {
      await api.savePAMFolder(
        form.name,
        { template_id: form.template_id, revision: editing?.revision ?? 0, description: editing?.description ?? "" },
        saveKey.current,
      );
      saveKey.current = crypto.randomUUID();
      setEditing(null);
      reset({ name: "", template_id: "" });
    });
  return (
    <section className="grid gap-4" aria-labelledby="pam-folders-heading">
      <h3 id="pam-folders-heading" className="text-body font-semibold">
        {t("admin.access.folders.panelHeading")}
      </h3>
      <p className="text-caption text-muted-foreground">{t("admin.access.folders.help")}</p>
      {error ? (
        <ErrorState title={t("admin.access.folders.failed")}>
          <p>{error}</p>
        </ErrorState>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <DataGrid<PAMFolder>
        ariaLabel={t("admin.access.folders.heading")}
        rows={folders.data?.items ?? []}
        getRowId={(r) => r.name}
        state={folders.error ? "error" : folders.loading ? "loading" : "ready"}
        columns={[
          { id: "name", header: t("admin.access.folders.name"), cell: (r) => r.name },
          {
            id: "template",
            header: t("admin.access.folders.template"),
            cell: (r) => templates.data?.items.find((v) => v.id === r.template_id)?.name ?? (r.template_id || t("admin.access.folders.none")),
          },
          { id: "targets", header: t("admin.access.folders.accounts"), cell: (r) => <Num>{r.targets}</Num> },
          {
            id: "actions",
            header: t("admin.access.targetAction"),
            cell: (r) =>
              canManage ? (
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => {
                      setEditing(r);
                      reset({ name: r.name, template_id: r.template_id });
                      saveKey.current = crypto.randomUUID();
                    }}
                  >
                    {t("admin.access.folders.edit")}
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive-outline"
                    disabled={busy || r.targets !== 0}
                    onClick={() => void act(() => api.deletePAMFolder(r.name, r.revision))}
                  >
                    {t("admin.access.folders.delete")}
                  </Button>
                </div>
              ) : null,
          },
        ]}
      />
      {canManage ? (
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            void handleSubmit(save)(event);
          }}
        >
          <Field label={t("admin.access.folders.name")} error={errors.name ? t("admin.access.targetIdHelp") : undefined}>
            {(control) => <Input {...control} {...register("name")} readOnly={editing !== null} />}
          </Field>
          <Field
            label={t("admin.access.folders.template")}
            description={t("admin.access.folders.templateHelp")}
            required
            error={errors.template_id ? t("admin.access.fieldRequired") : undefined}
          >
            {(control) => (
              <Select {...control} {...register("template_id")}>
                <option value="" disabled>
                  {t("admin.access.folders.selectTemplate")}
                </option>
                {templates.data?.items.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <div className="flex gap-2">
            <Button type="submit" loading={busy} disabled={!!templates.error}>
              {t("admin.access.folders.save")}
            </Button>
            {editing ? (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setEditing(null);
                  reset({ name: "", template_id: "" });
                  saveKey.current = crypto.randomUUID();
                }}
              >
                {t("admin.access.folders.cancel")}
              </Button>
            ) : null}
          </div>
        </form>
      ) : null}
      <h4 className="text-body font-semibold">{t("admin.access.folders.recording")}</h4>
      <p className="text-caption text-muted-foreground">{t("admin.access.folders.recordingHelp")}</p>
      <DataGrid
        ariaLabel={t("admin.access.folders.recording")}
        rows={templates.data?.items ?? []}
        getRowId={(r) => r.id}
        state={templates.error ? "error" : templates.loading ? "loading" : "ready"}
        columns={[
          { id: "name", header: t("admin.access.folders.template"), cell: (r) => r.name },
          {
            id: "recording",
            header: t("admin.access.folders.recording"),
            cell: (r) => t(r.require_recording ? "admin.access.folders.required" : "admin.access.folders.optional"),
          },
          {
            id: "action",
            header: t("admin.access.targetAction"),
            cell: (r) =>
              canManage ? (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void act(() => api.updatePAMTemplate(r.id, { ...r, require_recording: !r.require_recording }))}
                >
                  {t(r.require_recording ? "admin.access.folders.allowUnrecorded" : "admin.access.folders.requireRecording")}
                </Button>
              ) : null,
          },
        ]}
      />
      {canManage ? (
        <DataGrid<PAMTarget>
          ariaLabel={t("admin.access.folders.membership")}
          rows={targets.data?.items.filter((r) => r.source === "tenant") ?? []}
          getRowId={(r) => r.target_type + "/" + r.id}
          state={targets.error ? "error" : targets.loading ? "loading" : "ready"}
          columns={[
            { id: "target", header: t("admin.access.target"), cell: (r) => r.target_type + "/" + r.id },
            {
              id: "folder",
              header: t("admin.access.folders.name"),
              cell: (r) => (
                <FolderAssignment
                  key={r.folder ?? ""}
                  target={r}
                  folders={folders.data?.items ?? []}
                  disabled={busy || !!folders.error}
                  move={(folder) => act(() => api.setPAMTargetFolder(r.target_type, r.id, folder))}
                />
              ),
            },
          ]}
        />
      ) : null}
    </section>
  );
}

function FolderAssignment({
  target,
  folders,
  disabled,
  move,
}: {
  target: PAMTarget;
  folders: PAMFolder[];
  disabled: boolean;
  move: (folder: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [folder, setFolder] = useState(target.folder ?? "");
  return (
    <div className="flex items-end gap-2">
      <Field label={t("admin.access.folders.forTarget", { target: target.id })}>
        {(control) => (
          <Select {...control} value={folder} disabled={disabled} onChange={(e) => setFolder(e.target.value)}>
            <option value="">{t("admin.access.folders.none")}</option>
            {folders.map((r) => (
              <option key={r.name} value={r.name}>
                {r.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Button size="sm" variant="outline" disabled={disabled || folder === (target.folder ?? "")} onClick={() => void move(folder)}>
        {t("admin.access.folders.move")}
      </Button>
    </div>
  );
}
