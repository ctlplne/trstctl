/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { api, type PAMTarget, type PAMTargetRequest } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

const targetSchema = z
  .object({
    id: z
      .string()
      .trim()
      .regex(/^[a-z0-9_-]{1,64}$/),
    target_type: z.enum(["postgres", "ssh"]),
    provider_id: z.string().trim(),
    allowed_roles: z.string().trim(),
    host: z.string().trim(),
    port: z.string().trim(),
    principals: z.string().trim(),
  })
  .superRefine((value, ctx) => {
    if (value.target_type === "postgres") {
      if (!value.provider_id) ctx.addIssue({ code: "custom", path: ["provider_id"], message: translateNow("admin.access.providerRequired") });
      const roles = splitList(value.allowed_roles);
      if (roles.length === 0 || roles.some((role) => role !== "readonly" && role !== "writer"))
        ctx.addIssue({ code: "custom", path: ["allowed_roles"], message: translateNow("admin.access.rolesHelp") });
    } else {
      if (!value.host || /[\s/@]/.test(value.host)) ctx.addIssue({ code: "custom", path: ["host"], message: translateNow("admin.access.hostRequired") });
      const port = Number(value.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) ctx.addIssue({ code: "custom", path: ["port"], message: translateNow("admin.access.portHelp") });
      if (splitList(value.principals).length === 0)
        ctx.addIssue({ code: "custom", path: ["principals"], message: translateNow("admin.access.principalsRequired") });
    }
  });
type TargetForm = z.infer<typeof targetSchema>;
const emptyTarget: TargetForm = { id: "", target_type: "postgres", provider_id: "", allowed_roles: "readonly", host: "", port: "22", principals: "" };
function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Tenant target registration is separate from the requester form. A caller
 * with access:write can request a session but cannot change its destination. */
export function PAMTargetsPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const [formOpen, setFormOpen] = useState(false);
  const query = useApiQuery(["pam-targets"], api.pamTargets, { retry: false });
  const providers = useApiQuery(["dynamic-secret-providers"], api.dynamicSecretProviders, { enabled: formOpen, retry: false });
  const queryClient = useQueryClient();
  const [disableTarget, setDisableTarget] = useState<PAMTarget | null>(null);
  const [disableReason, setDisableReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const submitKey = useRef(crypto.randomUUID());
  const disableKey = useRef(crypto.randomUUID());
  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TargetForm>({
    resolver: zodResolver(targetSchema),
    defaultValues: emptyTarget,
  });
  const targetType = useWatch({ control, name: "target_type" });

  async function createTarget(form: TargetForm) {
    const input: PAMTargetRequest =
      form.target_type === "postgres"
        ? { id: form.id, target_type: "postgres", provider_id: form.provider_id, allowed_roles: splitList(form.allowed_roles) }
        : { id: form.id, target_type: "ssh", host: form.host, port: Number(form.port), principals: splitList(form.principals) };
    setBusy(true);
    setError(null);
    try {
      const created = await api.registerPAMTarget(input, submitKey.current);
      await queryClient.invalidateQueries({ queryKey: ["pam-targets"] });
      setNotice(t("admin.access.targetRegistered", { id: created.id }));
      setFormOpen(false);
      reset(emptyTarget);
      submitKey.current = crypto.randomUUID();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    if (!disableTarget || !disableReason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await api.disablePAMTarget(disableTarget.target_type, disableTarget.id, disableReason.trim(), disableKey.current);
      await queryClient.invalidateQueries({ queryKey: ["pam-targets"] });
      setNotice(t("admin.access.targetDisabled", { id: updated.id }));
      setDisableTarget(null);
      setDisableReason("");
      disableKey.current = crypto.randomUUID();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="pam-targets-heading" className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 id="pam-targets-heading" className="text-body font-semibold">
          {t("admin.access.targetsHeading")}
        </h3>
        {canManage ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setError(null);
              setFormOpen(true);
            }}
          >
            {t("admin.access.registerTarget")}
          </Button>
        ) : null}
      </div>
      <p className="text-caption text-muted-foreground">{t("admin.access.targetsHelp")}</p>
      {notice ? (
        <p role="status" className="text-sm">
          {notice}
        </p>
      ) : null}
      {query.loading ? <LoadingState>{t("admin.access.targetsHeading")}</LoadingState> : null}
      {query.error ? (
        <ErrorState title={t("admin.access.targetsLoadFailed")}>
          <Button type="button" variant="outline" size="sm" onClick={() => query.refetch()}>
            {t("admin.access.retry")}
          </Button>
        </ErrorState>
      ) : null}
      {query.data?.items.length === 0 ? <UnavailableState title={t("admin.access.noTargets")} /> : null}
      {query.data?.items.length ? (
        <div role="region" aria-label={t("admin.access.targetsHeading")} tabIndex={0} className="max-w-full overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[46rem]">
            <thead>
              <tr>
                <th scope="col">{t("admin.access.target")}</th>
                <th scope="col">{t("admin.access.destination")}</th>
                <th scope="col">{t("admin.access.allowedRoles")}</th>
                <th scope="col">{t("admin.access.targetSource")}</th>
                <th scope="col">{t("admin.access.targetStatus")}</th>
                <th scope="col">{t("admin.access.targetAction")}</th>
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((target) => (
                <tr key={`${target.target_type}:${target.id}`}>
                  <td className="font-mono text-xs">
                    {target.target_type}/{target.id}
                  </td>
                  <td className="font-mono text-xs">
                    {target.target_type === "postgres" ? target.provider_id : t("admin.access.hostPort", { host: target.host ?? "", port: target.port ?? 0 })}
                  </td>
                  <td>{target.target_type === "postgres" ? target.allowed_roles?.join(", ") : target.principals?.join(", ")}</td>
                  <td>{target.source === "tenant" ? t("admin.access.sourceTenant") : t("admin.access.sourceOperator")}</td>
                  <td>{target.enabled ? t("admin.access.targetEnabled") : t("admin.access.targetDisabledStatus")}</td>
                  <td>
                    {canManage && target.source === "tenant" && target.enabled ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setError(null);
                          setDisableTarget(target);
                        }}
                      >
                        {t("admin.access.disableTarget")}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <Dialog
        open={formOpen}
        onClose={() => {
          if (!busy) setFormOpen(false);
        }}
        titleId="pam-register-target-heading"
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card p-5 shadow-elevation2"
      >
        <h2 id="pam-register-target-heading" className="text-title font-semibold">
          {t("admin.access.registerTarget")}
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">{t("admin.access.targetImmutableHelp")}</p>
        <form
          className="mt-4 grid gap-3"
          onSubmit={(event) => {
            void handleSubmit(createTarget)(event);
          }}
        >
          {error ? (
            <ErrorState title={t("admin.access.targetSaveFailed")}>
              <p>{error}</p>
            </ErrorState>
          ) : null}
          <label className="grid gap-1 text-sm">
            {t("admin.access.targetId")}
            <Input {...register("id")} aria-invalid={!!errors.id} />
            {errors.id ? <span role="alert">{t("admin.access.targetIdHelp")}</span> : null}
          </label>
          <label className="grid gap-1 text-sm">
            {t("admin.access.targetType")}
            <Select {...register("target_type")}>
              <option value="postgres">{t("admin.access.postgresql")}</option>
              <option value="ssh">{t("admin.access.ssh")}</option>
            </Select>
          </label>
          {targetType === "postgres" ? (
            <>
              <label className="grid gap-1 text-sm">
                {t("admin.access.providerId")}
                <Input {...register("provider_id")} list="pam-postgres-providers" aria-invalid={!!errors.provider_id} />
                {errors.provider_id ? <span role="alert">{t("admin.access.providerRequired")}</span> : null}
              </label>
              <datalist id="pam-postgres-providers">
                {providers.data?.configured_providers
                  .filter((provider) => provider.type === "postgresql" && provider.ready)
                  .map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
              </datalist>
              <label className="grid gap-1 text-sm">
                {t("admin.access.allowedRoles")}
                <Input {...register("allowed_roles")} aria-invalid={!!errors.allowed_roles} />
                {errors.allowed_roles ? <span role="alert">{t("admin.access.rolesHelp")}</span> : null}
              </label>
            </>
          ) : (
            <>
              <label className="grid gap-1 text-sm">
                {t("admin.access.sshHost")}
                <Input {...register("host")} aria-invalid={!!errors.host} />
                {errors.host ? <span role="alert">{t("admin.access.hostRequired")}</span> : null}
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.sshPort")}
                <Input {...register("port")} aria-invalid={!!errors.port} />
                {errors.port ? <span role="alert">{t("admin.access.portHelp")}</span> : null}
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.sshPrincipals")}
                <Input {...register("principals")} aria-invalid={!!errors.principals} />
                {errors.principals ? <span role="alert">{t("admin.access.principalsRequired")}</span> : null}
              </label>
            </>
          )}
          <p className="text-caption text-muted-foreground">{t("admin.access.targetRetryHelp")}</p>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setFormOpen(false)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={busy}>
              {t("admin.access.registerTarget")}
            </Button>
          </div>
        </form>
      </Dialog>
      <Dialog
        open={disableTarget !== null}
        onClose={() => {
          if (!busy) setDisableTarget(null);
        }}
        titleId="pam-disable-target-heading"
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card p-5 shadow-elevation2"
      >
        <h2 id="pam-disable-target-heading" className="text-title font-semibold">
          {t("admin.access.disableTarget")}
        </h2>
        <p className="mt-2 text-sm">{t("admin.access.disableTargetHelp", { id: disableTarget?.id ?? "" })}</p>
        {error ? (
          <ErrorState title={t("admin.access.targetSaveFailed")}>
            <p>{error}</p>
          </ErrorState>
        ) : null}
        <label className="mt-3 grid gap-1 text-sm">
          {t("admin.access.disableReason")}
          <Textarea value={disableReason} onChange={(event) => setDisableReason(event.target.value)} maxLength={1000} />
        </label>
        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => setDisableTarget(null)}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="button" variant="destructive" disabled={busy || !disableReason.trim()} onClick={() => void disable()}>
            {t("admin.access.disableTarget")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}
