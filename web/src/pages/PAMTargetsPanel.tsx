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
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

const targetSchema = z
  .object({
    folder: z.string().trim(),
    id: z
      .string()
      .trim()
      .regex(/^[a-z0-9_-]{1,64}$/),
    target_type: z.enum([
      "postgres",
      "ssh",
      "snowflake",
      "aws",
      "gcp",
      "azure",
      "aws-console",
      "rdp",
      "netdevice",
      "webconsole",
      "windows_local",
      "account",
      "breakglass",
    ]),
    provider_id: z.string().trim(),
    gateway_agent_id: z.string().trim(),
    gateway_address: z.string().trim(),
    allowed_roles: z.string().trim(),
    host: z.string().trim(),
    port: z.string().trim(),
    principals: z.string().trim(),
    web_url: z.string().trim(),
    web_ca_pem: z.string().trim(),
    web_server_name: z.string().trim(),
    web_sign_in_url: z.string().trim(),
    web_sign_in_ca_pem: z.string().trim(),
  })
  .superRefine((value, ctx) => {
    if (value.target_type === "webconsole") {
      // A273: a web console's vaulted account and route; no provider.
      if (splitList(value.allowed_roles).length !== 1)
        ctx.addIssue({ code: "custom", path: ["allowed_roles"], message: translateNow("admin.access.webconsole.oneAccount") });
      // A273-O3: an origin, or the path the console lives under (no dot segments).
      if (!/^https:\/\/[^\s/?#@]+(?:\/(?!\.{1,2}(?:\/|$))[^\s/?#\\]+)*\/?$/.test(value.web_url))
        ctx.addIssue({ code: "custom", path: ["web_url"], message: translateNow("admin.access.webconsole.urlHelp") });
      // A273-O1: the identity provider is an origin of its own.
      if (value.web_sign_in_url && !/^https:\/\/[^\s/?#@]+\/?$/.test(value.web_sign_in_url))
        ctx.addIssue({ code: "custom", path: ["web_sign_in_url"], message: translateNow("admin.access.webconsole.signInURLHelp") });
      if (!value.gateway_agent_id) ctx.addIssue({ code: "custom", path: ["gateway_agent_id"], message: translateNow("admin.access.gatewayRequired") });
      if (!value.gateway_address) ctx.addIssue({ code: "custom", path: ["gateway_address"], message: translateNow("admin.access.gatewayRequired") });
    } else if (value.target_type !== "ssh") {
      if (!value.provider_id) ctx.addIssue({ code: "custom", path: ["provider_id"], message: translateNow("admin.access.providerRequired") });
      const roles = splitList(value.allowed_roles);
      if ((value.target_type === "rdp" || value.target_type === "netdevice" || isCheckoutAccount(value.target_type)) && roles.length !== 1)
        ctx.addIssue({ code: "custom", path: ["allowed_roles"], message: translateNow("admin.access.desktop.oneAccount") });
      if (roles.length === 0 || (value.target_type === "postgres" && roles.some((role) => role !== "readonly" && role !== "writer")))
        ctx.addIssue({
          code: "custom",
          path: ["allowed_roles"],
          message: translateNow(value.target_type === "postgres" ? "admin.access.rolesHelp" : "admin.access.providerRolesRequired"),
        });
      if (
        value.target_type === "snowflake" ||
        value.target_type === "aws" ||
        value.target_type === "gcp" ||
        value.target_type === "azure" ||
        value.target_type === "aws-console" ||
        value.target_type === "rdp" ||
        value.target_type === "netdevice"
      ) {
        if (!value.gateway_agent_id) ctx.addIssue({ code: "custom", path: ["gateway_agent_id"], message: translateNow("admin.access.gatewayRequired") });
        if (!value.gateway_address) ctx.addIssue({ code: "custom", path: ["gateway_address"], message: translateNow("admin.access.gatewayRequired") });
      }
    } else {
      if (!value.host || /[\s/@]/.test(value.host)) ctx.addIssue({ code: "custom", path: ["host"], message: translateNow("admin.access.hostRequired") });
      const port = Number(value.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) ctx.addIssue({ code: "custom", path: ["port"], message: translateNow("admin.access.portHelp") });
      if (splitList(value.principals).length === 0)
        ctx.addIssue({ code: "custom", path: ["principals"], message: translateNow("admin.access.principalsRequired") });
    }
  });
type TargetForm = z.infer<typeof targetSchema>;
const emptyTarget: TargetForm = {
  folder: "",
  id: "",
  target_type: "postgres",
  provider_id: "",
  gateway_agent_id: "",
  gateway_address: "",
  allowed_roles: "readonly",
  host: "",
  port: "22",
  principals: "",
  web_url: "",
  web_ca_pem: "",
  web_server_name: "",
  web_sign_in_url: "",
  web_sign_in_ca_pem: "",
};
// Check-out accounts (A268 windows_local, A271 account) are vaulted accounts a
// provider rotates in place: checked out, never a session, so they name no
// gateway.
const CHECKOUT_PROVIDER_TYPES: Record<string, string[]> = {
  windows_local: ["windows"],
  account: ["esxi", "vcenter-sso", "redfish", "iosxe", "junos", "eos", "fortigate", "bigip"],
  // A272: released only through emergency access.
  breakglass: ["okta-user", "entra-user", "google-workspace-user"],
};
function isCheckoutAccount(targetType: string): boolean {
  return targetType in CHECKOUT_PROVIDER_TYPES;
}
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
export function PAMTargetsPanel({ canManage, canAssignOwner = false }: { canManage: boolean; canAssignOwner?: boolean }) {
  const { t } = useTranslation();
  const [formOpen, setFormOpen] = useState(false);
  const query = useApiQuery(["pam-targets"], api.pamTargets, { retry: false });
  // A276: every brokered account has an accountable owner, assigned to its
  // inventory record pam-account/<type>/<id>.
  const owners = useApiQuery(["owners"], api.owners, { enabled: !!query.data?.items.length, retry: false });
  const ownerName = (id?: string) => (id ? (owners.data?.find((owner) => owner.id === id)?.name ?? id) : "");
  const [ownerTarget, setOwnerTarget] = useState<PAMTarget | null>(null);
  const [ownerChoice, setOwnerChoice] = useState({ owner: "", reason: "" });
  const folders = useApiQuery(["pam-folders"], api.pamFolders, { enabled: formOpen, retry: false });
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
  const providerID = useWatch({ control, name: "provider_id" });

  async function createTarget(form: TargetForm) {
    const input: PAMTargetRequest =
      form.target_type === "webconsole"
        ? {
            id: form.id,
            target_type: "webconsole",
            allowed_roles: splitList(form.allowed_roles),
            // A273-O4: an in-place account provider rotates the account after each session.
            ...(form.provider_id ? { provider_id: form.provider_id } : {}),
            web: {
              url: form.web_url,
              ...(form.web_ca_pem ? { ca_pem: form.web_ca_pem } : {}),
              ...(form.web_server_name ? { server_name: form.web_server_name } : {}),
              ...(form.web_sign_in_url ? { sign_in_url: form.web_sign_in_url } : {}),
              ...(form.web_sign_in_ca_pem ? { sign_in_ca_pem: form.web_sign_in_ca_pem } : {}),
            },
          }
        : form.target_type !== "ssh"
          ? { id: form.id, target_type: form.target_type, provider_id: form.provider_id, allowed_roles: splitList(form.allowed_roles) }
          : { id: form.id, target_type: "ssh", host: form.host, port: Number(form.port), principals: splitList(form.principals) };
    if (form.target_type === "rdp" || form.target_type === "netdevice" || form.target_type === "webconsole" || isCheckoutAccount(form.target_type))
      input.account_secret = splitList(form.allowed_roles)[0];
    if (form.folder) input.folder = form.folder;
    if (form.gateway_agent_id && !isCheckoutAccount(form.target_type)) input.gateway_agent_id = form.gateway_agent_id;
    if (form.gateway_address && !isCheckoutAccount(form.target_type)) input.gateway_address = form.gateway_address;
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

  async function assignOwner() {
    if (!ownerTarget || !ownerChoice.owner || !ownerChoice.reason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.assignOwnership({
        owner_id: ownerChoice.owner,
        inventory_ids: [`pam-account/${ownerTarget.target_type}/${ownerTarget.id}`],
        reason: ownerChoice.reason.trim(),
      });
      await queryClient.invalidateQueries({ queryKey: ["pam-targets"] });
      setNotice(t("admin.access.targetOwnerAssigned", { id: ownerTarget.id, owner: ownerName(ownerChoice.owner) }));
      setOwnerTarget(null);
      setOwnerChoice({ owner: "", reason: "" });
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
        <div role="region" aria-label={t("admin.access.targetsTable")} tabIndex={0} className="max-w-full overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-184">
            <thead>
              <tr>
                <th scope="col">{t("admin.access.target")}</th>
                <th scope="col">{t("admin.access.destination")}</th>
                <th scope="col">{t("admin.access.allowedRoles")}</th>
                <th scope="col">{t("admin.access.targetSource")}</th>
                <th scope="col">{t("admin.access.targetStatus")}</th>
                <th scope="col">{t("admin.access.targetOwner")}</th>
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
                    {target.target_type === "ssh" ? t("admin.access.hostPort", { host: target.host ?? "", port: target.port ?? 0 }) : target.provider_id}
                  </td>
                  <td>{target.target_type === "ssh" ? target.principals?.join(", ") : target.allowed_roles?.join(", ")}</td>
                  <td>{target.source === "tenant" ? t("admin.access.sourceTenant") : t("admin.access.sourceOperator")}</td>
                  <td>{target.enabled ? t("admin.access.targetEnabled") : t("admin.access.targetDisabledStatus")}</td>
                  <td>{target.owner_id ? ownerName(target.owner_id) : <span className="text-status-warning">{t("admin.access.targetNoOwner")}</span>}</td>
                  <td className="flex flex-wrap gap-2">
                    {canAssignOwner ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        aria-label={t("admin.access.assignTargetOwnerFor", { id: target.id })}
                        onClick={() => {
                          setError(null);
                          setOwnerChoice({ owner: target.owner_id ?? "", reason: "" });
                          setOwnerTarget(target);
                        }}
                      >
                        {t("admin.access.assignTargetOwner")}
                      </Button>
                    ) : null}
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
              <option value="snowflake">{t("admin.access.snowflake")}</option>
              <option value="aws">{t("admin.access.awsAPI")}</option>
              <option value="aws-console">{t("admin.access.awsConsole")}</option>
              <option value="rdp">{t("admin.access.desktop.target")}</option>
              <option value="netdevice">{t("admin.access.netdevice.target")}</option>
              <option value="webconsole">{t("admin.access.webconsole.target")}</option>
              <option value="windows_local">{t("admin.access.windowsLocal.target")}</option>
              <option value="account">{t("admin.access.inPlaceAccount.target")}</option>
              <option value="breakglass">{t("admin.access.breakglass.target")}</option>
              <option value="gcp">{t("admin.access.gcpAPI")}</option>
              <option value="azure">{t("admin.access.azureAPI")}</option>
            </Select>
          </label>
          <label className="grid gap-1 text-sm">
            {t("admin.access.folders.name")}
            <Select {...register("folder")} disabled={!!folders.error}>
              <option value="">{t("admin.access.folders.none")}</option>
              {folders.data?.items.map((folder) => (
                <option key={folder.name} value={folder.name}>
                  {folder.name}
                </option>
              ))}
            </Select>
          </label>
          {targetType === "webconsole" ? (
            <>
              <label className="grid gap-1 text-sm">
                {t("admin.access.desktop.accountSecret")}
                <Input {...register("allowed_roles")} aria-invalid={!!errors.allowed_roles} />
                {errors.allowed_roles ? <span role="alert">{t("admin.access.webconsole.oneAccount")}</span> : null}
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.url")}
                <Input {...register("web_url")} aria-invalid={!!errors.web_url} />
                {errors.web_url ? <span role="alert">{t("admin.access.webconsole.urlHelp")}</span> : null}
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.caPEM")}
                <textarea className="min-h-20 rounded-md border border-input bg-background p-2 font-mono text-caption" {...register("web_ca_pem")} />
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.serverName")}
                <Input {...register("web_server_name")} />
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.rotationProvider")}
                <Input {...register("provider_id")} list="pam-webconsole-rotation-providers" />
              </label>
              <p className="text-caption text-muted-foreground">{t("admin.access.webconsole.rotationProviderHelp")}</p>
              <datalist id="pam-webconsole-rotation-providers">
                {providers.data?.configured_providers
                  .filter((provider) => (CHECKOUT_PROVIDER_TYPES.account ?? []).includes(provider.type) && provider.ready)
                  .map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
              </datalist>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.signInURL")}
                <Input {...register("web_sign_in_url")} aria-invalid={!!errors.web_sign_in_url} />
                {errors.web_sign_in_url ? <span role="alert">{t("admin.access.webconsole.signInURLHelp")}</span> : null}
              </label>
              <label className="grid gap-1 text-sm">
                {t("admin.access.webconsole.signInCAPEM")}
                <Textarea className="min-h-20 font-mono text-caption" {...register("web_sign_in_ca_pem")} />
              </label>
            </>
          ) : targetType !== "ssh" ? (
            <>
              <label className="grid gap-1 text-sm">
                {t(targetType !== "postgres" ? "admin.access.accountProviderId" : "admin.access.providerId")}
                <Input {...register("provider_id")} list="pam-postgres-providers" aria-invalid={!!errors.provider_id} />
                {errors.provider_id ? <span role="alert">{t("admin.access.providerRequired")}</span> : null}
              </label>
              <datalist id="pam-postgres-providers">
                {providers.data?.configured_providers
                  .filter(
                    (provider) =>
                      (targetType === "rdp"
                        ? ["unix", "windows", "ldap"].includes(provider.type)
                        : isCheckoutAccount(targetType)
                          ? (CHECKOUT_PROVIDER_TYPES[targetType] ?? []).includes(provider.type)
                          : targetType === "netdevice"
                            ? ["iosxe", "junos", "eos", "fortigate", "bigip"].includes(provider.type)
                            : provider.type ===
                              (targetType === "postgres"
                                ? "postgresql"
                                : targetType === "snowflake"
                                  ? "snowflake"
                                  : targetType === "gcp"
                                    ? "gcp-iam"
                                    : targetType === "azure"
                                      ? "azure-entra"
                                      : "aws-sts")) && provider.ready,
                  )
                  .map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
              </datalist>
              <label className="grid gap-1 text-sm">
                {t(
                  targetType === "rdp" || targetType === "netdevice" || isCheckoutAccount(targetType)
                    ? "admin.access.desktop.accountSecret"
                    : "admin.access.allowedRoles",
                )}
                <Input
                  list={targetType === "rdp" || targetType === "netdevice" || isCheckoutAccount(targetType) ? "pam-desktop-accounts" : undefined}
                  {...register("allowed_roles")}
                  aria-invalid={!!errors.allowed_roles}
                />
                {errors.allowed_roles ? (
                  <span role="alert">{t(targetType === "postgres" ? "admin.access.rolesHelp" : "admin.access.providerRolesRequired")}</span>
                ) : null}
              </label>
              {targetType === "rdp" || targetType === "netdevice" || isCheckoutAccount(targetType) ? (
                <datalist id="pam-desktop-accounts">
                  {providers.data?.configured_providers
                    .find((p) => p.id === providerID)
                    ?.allowed_roles.map((role) => (
                      <option key={role} value={role} />
                    ))}
                </datalist>
              ) : null}
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
          {targetType === "rdp" ? <p>{t("admin.access.desktop.proof")}</p> : null}
          {targetType === "netdevice" ? <p>{t("admin.access.netdevice.proof")}</p> : null}
          {targetType === "webconsole" ? <p>{t("admin.access.webconsole.proof")}</p> : null}
          {targetType === "windows_local" ? <p>{t("admin.access.windowsLocal.proof")}</p> : null}
          {targetType === "account" ? <p>{t("admin.access.inPlaceAccount.proof")}</p> : null}
          {targetType === "breakglass" ? <p>{t("admin.access.breakglass.proof")}</p> : null}
          {targetType === "postgres" ? <p>{t("admin.access.postgresTLSProof")}</p> : null}
          {targetType === "snowflake" ? <p>{t("admin.access.snowflakeProof")}</p> : null}
          {targetType === "aws" ? <p>{t("admin.access.awsAPIProof")}</p> : null}
          {targetType === "aws-console" ? <p>{t("admin.access.awsConsoleProof")}</p> : null}
          {targetType === "gcp" ? <p>{t("admin.access.gcpAPIProof")}</p> : null}
          {targetType === "azure" ? <p>{t("admin.access.azureAPIProof")}</p> : null}
          {isCheckoutAccount(targetType) ? null : (
            <>
              <Field
                label={t("admin.access.gatewayAgent")}
                required={
                  targetType === "snowflake" ||
                  targetType === "aws" ||
                  targetType === "gcp" ||
                  targetType === "azure" ||
                  targetType === "aws-console" ||
                  targetType === "rdp"
                }
                error={errors.gateway_agent_id ? t("admin.access.gatewayRequired") : undefined}
              >
                {(control) => <Input {...control} {...register("gateway_agent_id")} />}
              </Field>
              <Field
                label={t("admin.access.gatewayAddress")}
                required={
                  targetType === "snowflake" ||
                  targetType === "aws" ||
                  targetType === "gcp" ||
                  targetType === "azure" ||
                  targetType === "aws-console" ||
                  targetType === "rdp"
                }
                error={errors.gateway_address ? t("admin.access.gatewayRequired") : undefined}
              >
                {(control) => <Input {...control} {...register("gateway_address")} />}
              </Field>
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
        open={ownerTarget !== null}
        onClose={() => {
          if (!busy) setOwnerTarget(null);
        }}
        titleId="pam-target-owner-heading"
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card p-5 shadow-elevation2"
      >
        <h2 id="pam-target-owner-heading" className="text-title font-semibold">
          {t("admin.access.assignTargetOwnerFor", { id: ownerTarget?.id ?? "" })}
        </h2>
        <p className="mt-2 text-sm">{t("admin.access.assignTargetOwnerHelp")}</p>
        {error ? (
          <ErrorState title={t("admin.access.targetSaveFailed")}>
            <p>{error}</p>
          </ErrorState>
        ) : null}
        <label className="mt-3 grid gap-1 text-sm">
          {t("admin.access.targetOwner")}
          <Select value={ownerChoice.owner} onChange={(event) => setOwnerChoice({ ...ownerChoice, owner: event.target.value })}>
            <option value="">{t("admin.access.chooseTargetOwner")}</option>
            {(owners.data ?? []).map((owner) => (
              <option key={owner.id} value={owner.id}>
                {owner.name}
              </option>
            ))}
          </Select>
        </label>
        <label className="mt-3 grid gap-1 text-sm">
          {t("admin.access.targetOwnerReason")}
          <Textarea value={ownerChoice.reason} onChange={(event) => setOwnerChoice({ ...ownerChoice, reason: event.target.value })} maxLength={1000} />
        </label>
        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => setOwnerTarget(null)}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="button" disabled={busy || !ownerChoice.owner || !ownerChoice.reason.trim()} onClick={() => void assignOwner()}>
            {t("admin.access.assignTargetOwner")}
          </Button>
        </div>
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
