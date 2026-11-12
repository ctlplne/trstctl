import { PAMCommandRulesPanel } from "@/pages/PAMCommandRulesPanel";
import { useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { api, type PAMAccessTemplate, type PAMFolder, type PAMTarget } from "@/lib/api";
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
// A269: a template's remote desktop clipboard policy.
const CLIPBOARD_POLICIES = ["deny", "to_target", "from_target", "both"] as const;
const CLIPBOARD_LABEL = {
  deny: "admin.access.folders.clipboard.deny",
  to_target: "admin.access.folders.clipboard.toTarget",
  from_target: "admin.access.folders.clipboard.fromTarget",
  both: "admin.access.folders.clipboard.both",
} as const;
// A277: a high-risk template's fresh sign-in window, in seconds (0: none).
const FRESH_SIGN_IN_WINDOWS = [0, 300, 900, 3600] as const;

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
            id: "clipboard",
            header: t("admin.access.folders.desktopClipboard"),
            cell: (r) =>
              canManage ? (
                <Select
                  aria-label={t("admin.access.folders.desktopClipboardFor", { template: r.name })}
                  value={r.desktop_clipboard ?? "deny"}
                  disabled={busy}
                  onChange={(event) => {
                    const desktop_clipboard = event.target.value as NonNullable<typeof r.desktop_clipboard>;
                    void act(() => api.updatePAMTemplate(r.id, { ...r, desktop_clipboard }));
                  }}
                >
                  {CLIPBOARD_POLICIES.map((policy) => (
                    <option key={policy} value={policy}>
                      {t(CLIPBOARD_LABEL[policy])}
                    </option>
                  ))}
                </Select>
              ) : (
                t(CLIPBOARD_LABEL[r.desktop_clipboard ?? "deny"])
              ),
          },
          {
            id: "fresh-sign-in",
            header: t("admin.access.folders.freshSignIn"),
            cell: (r) => {
              const current = r.reauthenticate_within_seconds ?? 0;
              const label = (seconds: number) =>
                seconds === 0 ? t("admin.access.folders.freshSignInNone") : t("admin.access.folders.freshSignInWithin", { minutes: Math.round(seconds / 60) });
              const windows: number[] = FRESH_SIGN_IN_WINDOWS.includes(current as (typeof FRESH_SIGN_IN_WINDOWS)[number])
                ? [...FRESH_SIGN_IN_WINDOWS]
                : [...FRESH_SIGN_IN_WINDOWS, current].sort((a, b) => a - b);
              return canManage ? (
                <Select
                  aria-label={t("admin.access.folders.freshSignInFor", { template: r.name })}
                  value={String(current)}
                  disabled={busy}
                  onChange={(event) => {
                    const reauthenticate_within_seconds = Number(event.target.value);
                    void act(() => api.updatePAMTemplate(r.id, { ...r, reauthenticate_within_seconds }));
                  }}
                >
                  {windows.map((seconds) => (
                    <option key={seconds} value={String(seconds)}>
                      {label(seconds)}
                    </option>
                  ))}
                </Select>
              ) : (
                label(current)
              );
            },
          },
          {
            id: "web-sign-in",
            header: t("admin.access.folders.webSignIn"),
            cell: (r) => (
              <WebSignInEditor
                template={r}
                canManage={canManage}
                disabled={busy}
                save={(web_sign_in) => act(() => api.updatePAMTemplate(r.id, { ...r, web_sign_in }))}
              />
            ),
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
      <PAMCommandRulesPanel canManage={canManage} />
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

// A273: how the gateway signs in to a web console for sessions through a
// template. It names fields and headers only; the credential is the target's.
type WebSignIn = NonNullable<PAMAccessTemplate["web_sign_in"]>;
const WEB_SIGN_IN_LABEL = {
  none: "admin.access.folders.webSignIn.none",
  form: "admin.access.folders.webSignIn.form",
  sso: "admin.access.folders.webSignIn.sso",
  header: "admin.access.folders.webSignIn.header",
  basic: "admin.access.folders.webSignIn.basic",
} as const;

function WebSignInEditor({
  template,
  canManage,
  disabled,
  save,
}: {
  template: PAMAccessTemplate;
  canManage: boolean;
  disabled: boolean;
  save: (signIn: WebSignIn | undefined) => Promise<void>;
}) {
  const { t } = useTranslation();
  const current = template.web_sign_in;
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<WebSignIn["mode"] | "none">(current?.mode ?? "none");
  const [loginPath, setLoginPath] = useState(current?.login_path ?? "/login");
  const [usernameField, setUsernameField] = useState(current?.username_field ?? "username");
  const [passwordField, setPasswordField] = useState(current?.password_field ?? "password");
  const [header, setHeader] = useState(current?.header ?? "Authorization");
  const [headerPrefix, setHeaderPrefix] = useState(current?.header_prefix ?? "");
  const [cookies, setCookies] = useState((current?.browser_cookies ?? []).join(", "));
  const label = t(WEB_SIGN_IN_LABEL[current?.mode ?? "none"]);
  if (!canManage || !open) {
    return (
      <div className="flex items-center gap-2">
        <span>{label}</span>
        {canManage ? (
          <Button size="sm" variant="outline" disabled={disabled} onClick={() => setOpen(true)}>
            {t("admin.access.folders.webSignIn.edit")}
          </Button>
        ) : null}
      </div>
    );
  }
  const browserCookies = cookies
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);
  const value = (): WebSignIn | undefined => {
    switch (mode) {
      case "form":
      case "sso":
        return { mode, login_path: loginPath, username_field: usernameField, password_field: passwordField, browser_cookies: browserCookies };
      case "header":
        return { mode, header, ...(headerPrefix ? { header_prefix: headerPrefix } : {}), browser_cookies: browserCookies };
      case "basic":
        return { mode, browser_cookies: browserCookies };
      default:
        return undefined;
    }
  };
  return (
    <fieldset className="grid gap-2" aria-label={t("admin.access.folders.webSignInFor", { template: template.name })}>
      <p className="text-caption text-muted-foreground">{t("admin.access.folders.webSignIn.help")}</p>
      <Field label={t("admin.access.folders.webSignIn.mode")}>
        {(control) => (
          <Select {...control} value={mode} onChange={(e) => setMode(e.target.value as WebSignIn["mode"] | "none")}>
            {(["none", "form", "sso", "header", "basic"] as const).map((m) => (
              <option key={m} value={m}>
                {t(WEB_SIGN_IN_LABEL[m])}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {mode === "sso" ? <p className="text-caption text-muted-foreground">{t("admin.access.folders.webSignIn.ssoHelp")}</p> : null}
      {mode === "form" || mode === "sso" ? (
        <>
          <Field label={t("admin.access.folders.webSignIn.loginPath")}>
            {(control) => <Input {...control} value={loginPath} onChange={(e) => setLoginPath(e.target.value)} />}
          </Field>
          <Field label={t("admin.access.folders.webSignIn.usernameField")}>
            {(control) => <Input {...control} value={usernameField} onChange={(e) => setUsernameField(e.target.value)} />}
          </Field>
          <Field label={t("admin.access.folders.webSignIn.passwordField")}>
            {(control) => <Input {...control} value={passwordField} onChange={(e) => setPasswordField(e.target.value)} />}
          </Field>
        </>
      ) : null}
      {mode === "header" ? (
        <>
          <Field label={t("admin.access.folders.webSignIn.headerName")}>
            {(control) => <Input {...control} value={header} onChange={(e) => setHeader(e.target.value)} />}
          </Field>
          <Field label={t("admin.access.folders.webSignIn.headerPrefix")}>
            {(control) => <Input {...control} value={headerPrefix} onChange={(e) => setHeaderPrefix(e.target.value)} />}
          </Field>
        </>
      ) : null}
      {mode !== "none" ? (
        <Field label={t("admin.access.folders.webSignIn.browserCookies")}>
          {(control) => <Input {...control} value={cookies} onChange={(e) => setCookies(e.target.value)} />}
        </Field>
      ) : null}
      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={disabled}
          onClick={() => {
            void save(value()).then(() => setOpen(false));
          }}
        >
          {t("admin.access.folders.webSignIn.save")}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
          {t("admin.access.folders.webSignIn.cancel")}
        </Button>
      </div>
    </fieldset>
  );
}
