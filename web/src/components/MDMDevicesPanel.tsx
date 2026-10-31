import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { api, type Agent, type MDMDeviceList, type MDMDeviceTrace, type MDMPollSchedule, type MDMPollScheduleInput, type MDMPollScheduleList } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";
import { useCan } from "@/components/rbac";

function readMDMDevices(): Promise<MDMDeviceList> {
  return optionalApiCall<MDMDeviceList>("mdmDevices", { items: [], failed: 0, unobserved: 0, guidance: "" });
}

function readMDMDeviceTrace(mdm: string, id: string): Promise<MDMDeviceTrace> {
  return api.mdmDeviceTrace(mdm, id);
}

function readMDMPollSchedules(): Promise<MDMPollScheduleList> {
  return optionalApiCall<MDMPollScheduleList>("mdmPollSchedules", { items: [], guidance: "" });
}

const scheduleSchema = z
  .object({
    mdm: z.enum(["intune", "jamf"]),
    base_url: z
      .string()
      .trim()
      .url({ error: translateNow("mdm.poll.invalid") })
      .refine((value) => {
        const url = new URL(value);
        return ["http:", "https:"].includes(url.protocol) && !!url.hostname && !url.username && !url.password;
      }, translateNow("mdm.poll.invalid")),
    token_ref: z
      .string()
      .trim()
      .regex(/^secret:\/\/.+$/, translateNow("mdm.poll.invalid")),
    required_agent_id: z.string().trim(),
    entra_directory_tenant_id: z.string().trim(),
    entra_client_id: z.string().trim(),
    filter: z.string().trim(),
    interval_seconds: z
      .string()
      .regex(/^\d+$/, translateNow("mdm.poll.invalid"))
      .refine((value) => Number(value) >= 300, translateNow("mdm.poll.invalid")),
    renewal_window_days: z
      .string()
      .regex(/^\d+$/, translateNow("mdm.poll.invalid"))
      .refine((value) => Number(value) <= 365, translateNow("mdm.poll.invalid")),
    enabled: z.boolean(),
  })
  .superRefine((value, ctx) => {
    if (value.enabled && !value.required_agent_id) {
      ctx.addIssue({ code: "custom", path: ["required_agent_id"], message: translateNow("mdm.poll.relayRequired") });
    }
    // A156: an Intune app registration needs both identifiers, and its client
    // ID is the registration's application GUID.
    const guid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    if (value.mdm === "intune" && (value.entra_directory_tenant_id || value.entra_client_id)) {
      if (!value.entra_directory_tenant_id) {
        ctx.addIssue({ code: "custom", path: ["entra_directory_tenant_id"], message: translateNow("mdm.poll.appIncomplete") });
      }
      if (!guid.test(value.entra_client_id)) {
        ctx.addIssue({ code: "custom", path: ["entra_client_id"], message: translateNow("mdm.poll.appIncomplete") });
      }
    }
  });
type ScheduleForm = z.infer<typeof scheduleSchema>;
const emptySchedule: ScheduleForm = {
  mdm: "intune",
  base_url: "",
  token_ref: "",
  required_agent_id: "",
  entra_directory_tenant_id: "",
  entra_client_id: "",
  filter: "",
  interval_seconds: "3600",
  renewal_window_days: "0",
  enabled: true,
};

// MDMDevicesPanel configures the relay read and shows Intune/Jamf correlation (I5).
//
// Failed and unobserved are rendered as different things, and counted
// separately, because they are different problems: one device reported trouble,
// the other is a device nothing has heard from. Merging them into one
// "unhealthy" number sends somebody to re-push a profile that is already
// installed — the MDM was simply unreachable.
export function MDMDevicesPanel() {
  const canConfigure = useCan("certs:write");
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const queryClient = useQueryClient();
  const form = useForm<ScheduleForm>({ resolver: zodResolver(scheduleSchema), defaultValues: emptySchedule });
  const scheduleMDM = useWatch({ control: form.control, name: "mdm" });
  const devices = useApiQuery(["mdm-devices"], readMDMDevices);
  const schedules = useApiQuery(["mdm-poll-schedules"], readMDMPollSchedules);
  const agents = useApiQuery<Agent[]>(["mdm-network-relays"], () => api.agents());
  const [selected, setSelected] = useState<{ mdm: string; id: string } | null>(null);
  const [reviewed, setReviewed] = useState<MDMPollScheduleInput | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");
  const [saved, setSaved] = useState(false);
  const trace = useApiQuery(["mdm-device-trace", selected?.mdm, selected?.id], () => readMDMDeviceTrace(selected?.mdm ?? "", selected?.id ?? ""), {
    enabled: selected !== null,
  });
  const items = devices.data?.items ?? [];
  const scheduleItems = schedules.data?.items ?? [];
  const networkRelays = (agents.data ?? []).filter((agent) => agent.status !== "offboarded" && agent.roles.includes("network"));

  function selectScheduleProvider(mdm: "intune" | "jamf", selectedSchedule?: MDMPollSchedule) {
    const schedule = selectedSchedule ?? scheduleItems.find((item) => item.mdm === mdm);
    form.reset({
      mdm,
      base_url: schedule?.base_url ?? "",
      token_ref: schedule?.token_ref ?? "",
      required_agent_id: schedule?.required_agent_id ?? "",
      entra_directory_tenant_id: schedule?.client_credentials?.directory_tenant_id ?? "",
      entra_client_id: schedule?.client_credentials?.client_id ?? "",
      filter: schedule?.filter ?? "",
      interval_seconds: String(schedule?.interval_seconds ?? 3600),
      renewal_window_days: String(schedule?.renewal_window_days ?? 0),
      enabled: schedule?.enabled ?? true,
    });
    setReviewed(null);
    setFormError("");
    setSaved(false);
  }

  function editSchedule(schedule: MDMPollSchedule) {
    selectScheduleProvider(schedule.mdm === "jamf" ? "jamf" : "intune", schedule);
    setScheduleOpen(true);
  }

  const reviewSchedule = form.handleSubmit((values) => {
    setReviewed(null);
    setSaved(false);
    const url = new URL(values.base_url);
    setReviewed({
      mdm: values.mdm,
      base_url: url.toString().replace(/\/$/, ""),
      token_ref: values.token_ref,
      required_agent_id: values.required_agent_id,
      filter: values.filter,
      interval_seconds: Number(values.interval_seconds),
      renewal_window_days: Number(values.renewal_window_days),
      enabled: values.enabled,
      execution: "relay",
      ...(values.mdm === "intune" && values.entra_client_id
        ? { client_credentials: { directory_tenant_id: values.entra_directory_tenant_id, client_id: values.entra_client_id } }
        : {}),
    });
    setFormError("");
  });

  async function saveSchedule() {
    if (!reviewed || saving) return;
    setSaving(true);
    setFormError("");
    try {
      const result = await api.putMDMPollSchedule(reviewed);
      if (
        !result.configured ||
        result.mdm !== reviewed.mdm ||
        result.execution !== "relay" ||
        result.base_url !== reviewed.base_url ||
        result.token_ref !== reviewed.token_ref ||
        (result.required_agent_id ?? "") !== (reviewed.required_agent_id ?? "") ||
        (result.filter ?? "") !== reviewed.filter ||
        result.interval_seconds !== reviewed.interval_seconds ||
        (result.renewal_window_days ?? 0) !== reviewed.renewal_window_days ||
        (result.client_credentials?.client_id ?? "") !== (reviewed.client_credentials?.client_id ?? "") ||
        result.enabled !== reviewed.enabled
      ) {
        throw new Error(translateNow("mdm.poll.unconfirmed"));
      }
      setReviewed(null);
      setSaved(true);
      queryClient.setQueryData<MDMPollScheduleList>(["mdm-poll-schedules"], (previous) => ({
        items: [...(previous?.items ?? []).filter((item) => item.mdm !== result.mdm), result],
        guidance: previous?.guidance ?? result.guidance,
      }));
      await queryClient.invalidateQueries({ queryKey: ["mdm-poll-schedules"] });
    } catch (error) {
      setFormError(error instanceof Error ? error.message : String(error));
    } finally {
      setSaving(false);
    }
  }

  return (
    <section aria-labelledby="mdm-devices-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="mdm-devices-heading" className="text-title font-semibold">
        {translateNow("source.mdm.devices.heading.i5mdm00001")}
      </h2>
      {schedules.error ? (
        <p role="alert" className="text-sm text-risk-critical">
          {schedules.error}
        </p>
      ) : null}
      {!schedules.loading && scheduleItems.length === 0 ? <p className="text-sm text-muted-foreground">{translateNow("mdm.poll.empty")}</p> : null}
      {scheduleItems.length > 0 ? (
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{translateNow("source.vantage.relay.a3vant0003")}</h3>
          <ul className="space-y-1 text-caption text-muted-foreground">
            {scheduleItems.map((schedule) => (
              <li key={schedule.mdm ?? schedule.base_url}>
                <span className="font-medium">{schedule.mdm ?? "—"}</span>
                {" · "}
                {translateNow(schedule.enabled ? "protocols.ari.schedulerEnabled" : "protocols.ari.schedulerDisabled")}
                {" · "}
                {schedule.execution ?? "—"}
                {" · "}
                {schedule.required_agent_id
                  ? ((agents.data ?? []).find((agent) => agent.id === schedule.required_agent_id)?.name ?? schedule.required_agent_id)
                  : translateNow("mdm.poll.relayUnbound")}
                {" · "}
                {translateNow("discovery.monitoring.columnLastRun")}: {schedule.last_run_at?.slice(0, 16).replace("T", " ") ?? "—"}
                {schedule.last_error ? <span className="mt-1 block text-risk-critical">{schedule.last_error}</span> : null}
                {canConfigure ? (
                  <button type="button" className="ms-2 text-brand-accent underline" onClick={() => editSchedule(schedule)}>
                    {translateNow("mdm.poll.edit")}
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="text-caption text-muted-foreground">{schedules.data?.guidance}</p>
        </div>
      ) : null}
      {canConfigure ? (
        <details open={scheduleOpen} className="border-t border-border pt-3">
          <summary
            className="cursor-pointer font-medium"
            onClick={(event) => {
              event.preventDefault();
              if (scheduleOpen) setReviewed(null);
              setScheduleOpen(!scheduleOpen);
            }}
          >
            {translateNow("mdm.poll.configure")}
          </summary>
          {scheduleOpen ? (
            <>
              <p className="mt-2 text-caption text-muted-foreground">{translateNow("mdm.poll.help")}</p>
              <form onSubmit={reviewSchedule} noValidate>
                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.provider")}</span>
                    <select
                      className="rounded-control border border-border bg-background p-2"
                      value={scheduleMDM}
                      {...form.register("mdm", { onChange: (event) => selectScheduleProvider(event.target.value === "jamf" ? "jamf" : "intune") })}
                    >
                      <option value="intune">{translateNow("mdm.poll.intune")}</option>
                      <option value="jamf">{translateNow("mdm.poll.jamf")}</option>
                    </select>
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.baseURL")}</span>
                    <input
                      className="rounded-control border border-border bg-background p-2"
                      type="url"
                      {...form.register("base_url", { onChange: () => setReviewed(null) })}
                    />
                    {form.formState.errors.base_url ? <span className="text-risk-critical">{form.formState.errors.base_url.message}</span> : null}
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.tokenRef")}</span>
                    <input
                      className="rounded-control border border-border bg-background p-2"
                      autoComplete="off"
                      {...form.register("token_ref", { onChange: () => setReviewed(null) })}
                      placeholder={translateNow("mdm.poll.tokenRefExample")}
                    />
                    {form.formState.errors.token_ref ? <span className="text-risk-critical">{form.formState.errors.token_ref.message}</span> : null}
                  </label>
                  {scheduleMDM === "intune" ? (
                    <>
                      <label className="grid gap-1 text-sm">
                        <span>{translateNow("mdm.poll.appDirectory")}</span>
                        <input
                          className="rounded-control border border-border bg-background p-2"
                          autoComplete="off"
                          {...form.register("entra_directory_tenant_id", { onChange: () => setReviewed(null) })}
                          placeholder={translateNow("mdm.poll.appDirectoryExample")}
                        />
                        {form.formState.errors.entra_directory_tenant_id ? (
                          <span className="text-risk-critical">{form.formState.errors.entra_directory_tenant_id.message}</span>
                        ) : null}
                      </label>
                      <label className="grid gap-1 text-sm">
                        <span>{translateNow("mdm.poll.appClient")}</span>
                        <input
                          className="rounded-control border border-border bg-background p-2"
                          autoComplete="off"
                          {...form.register("entra_client_id", { onChange: () => setReviewed(null) })}
                        />
                        {form.formState.errors.entra_client_id ? (
                          <span className="text-risk-critical">{form.formState.errors.entra_client_id.message}</span>
                        ) : null}
                      </label>
                      <p className="text-caption text-muted-foreground sm:col-span-2">{translateNow("mdm.poll.appHelp")}</p>
                    </>
                  ) : null}
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.relay")}</span>
                    <select
                      className="rounded-control border border-border bg-background p-2"
                      {...form.register("required_agent_id", { onChange: () => setReviewed(null) })}
                    >
                      <option value="">{translateNow("mdm.poll.relayChoose")}</option>
                      {networkRelays.map((agent) => (
                        <option key={agent.id} value={agent.id}>
                          {agent.name} · {agent.id}
                          {agent.presence?.state === "online" ? null : <span> · {translateNow("mdm.poll.relayOffline")}</span>}
                        </option>
                      ))}
                    </select>
                    {form.formState.errors.required_agent_id ? (
                      <span className="text-risk-critical">{form.formState.errors.required_agent_id.message}</span>
                    ) : null}
                    {agents.error ? (
                      <span role="alert" className="text-risk-critical">
                        {agents.error}
                      </span>
                    ) : null}
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.filter")}</span>
                    <input
                      className="rounded-control border border-border bg-background p-2"
                      {...form.register("filter", { onChange: () => setReviewed(null) })}
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.interval")}</span>
                    <input
                      className="rounded-control border border-border bg-background p-2"
                      type="number"
                      min="300"
                      step="1"
                      {...form.register("interval_seconds", { onChange: () => setReviewed(null) })}
                    />
                    {form.formState.errors.interval_seconds ? (
                      <span className="text-risk-critical">{form.formState.errors.interval_seconds.message}</span>
                    ) : null}
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span>{translateNow("mdm.poll.renewalWindow")}</span>
                    <input
                      className="rounded-control border border-border bg-background p-2"
                      type="number"
                      min="0"
                      max="365"
                      step="1"
                      {...form.register("renewal_window_days", { onChange: () => setReviewed(null) })}
                    />
                    {form.formState.errors.renewal_window_days ? (
                      <span className="text-risk-critical">{form.formState.errors.renewal_window_days.message}</span>
                    ) : null}
                  </label>
                  <label className="flex items-center gap-2 text-sm sm:col-span-2">
                    <input type="checkbox" {...form.register("enabled", { onChange: () => setReviewed(null) })} />
                    {translateNow("mdm.poll.enabled")}
                  </label>
                </div>
                <button type="submit" className="mt-3 rounded-control border border-border px-3 py-2 text-sm">
                  {translateNow("mdm.poll.review")}
                </button>
              </form>
              {reviewed ? (
                <div className="mt-3 space-y-2 rounded-control border border-brand-accent/40 p-3 text-sm">
                  <p>
                    {translateNow("mdm.poll.reviewSummary", {
                      provider: translateNow(reviewed.mdm === "jamf" ? "mdm.poll.jamf" : "mdm.poll.intune"),
                      seconds: reviewed.interval_seconds,
                    })}
                  </p>
                  <p className="break-all font-mono text-xs">
                    {reviewed.base_url} · {reviewed.token_ref}
                  </p>
                  {reviewed.client_credentials ? (
                    <p>
                      {translateNow("mdm.poll.reviewApp", {
                        client: reviewed.client_credentials.client_id,
                        directory: reviewed.client_credentials.directory_tenant_id,
                      })}
                    </p>
                  ) : null}
                  <p>{translateNow("mdm.poll.reviewFilter", { filter: reviewed.filter || "—" })}</p>
                  <p>{translateNow("mdm.poll.reviewWindow", { days: reviewed.renewal_window_days ?? 0 })}</p>
                  <p>{translateNow("mdm.poll.reviewExecution")}</p>
                  <p>
                    {translateNow("mdm.poll.reviewRelay", {
                      relay: networkRelays.find((agent) => agent.id === reviewed.required_agent_id)?.name ?? reviewed.required_agent_id ?? "—",
                      id: reviewed.required_agent_id ?? "—",
                    })}
                  </p>
                  <p>{translateNow(reviewed.enabled ? "mdm.poll.reviewEnabled" : "mdm.poll.reviewDisabled")}</p>
                  <button
                    type="button"
                    className="rounded-control bg-brand-accent px-3 py-2 text-sm text-white"
                    disabled={saving}
                    onClick={() => void saveSchedule()}
                  >
                    {translateNow("mdm.poll.save")}
                  </button>
                </div>
              ) : null}
              {formError ? (
                <p role="alert" className="mt-2 text-sm text-risk-critical">
                  {formError}
                </p>
              ) : null}
              {saved ? (
                <p role="status" className="mt-2 text-sm">
                  {translateNow("mdm.poll.saved")}
                </p>
              ) : null}
            </>
          ) : null}
        </details>
      ) : null}
      {items.length > 0 ? (
        <>
          <p className="text-sm">
            {translateNow("source.mdm.devices.counts.i5mdm00002", {
              value1: String(items.length),
              value2: String(devices.data?.failed ?? 0),
              value3: String(devices.data?.unobserved ?? 0),
            })}
          </p>
          {(devices.data?.renewal_at_risk ?? 0) > 0 ? (
            <p className="text-sm text-risk-critical">
              {translateNow("source.mdm.devices.renewalrisk.i5mdm00004", {
                value1: String(devices.data?.renewal_at_risk ?? 0),
              })}
            </p>
          ) : null}
          <ul className="space-y-2 text-sm">
            {items.slice(0, 25).map((item) => (
              <li key={`${item.mdm}:${item.mdm_device_id}:${item.transaction_id ?? ""}`} className="border-b border-border pb-2 last:border-0">
                <span className="font-mono text-xs">{item.device_name || item.mdm_device_id}</span>{" "}
                <span className="text-caption text-muted-foreground">
                  {item.install_state === "unknown" ? translateNow("source.mdm.devices.unobserved.i5mdm00003") : item.install_state}
                </span>
                {item.install_detail ? <span className="mt-1 block text-caption text-muted-foreground">{item.install_detail}</span> : null}
                {item.renewal_at_risk && item.renewal_detail ? <span className="mt-1 block text-caption text-risk-critical">{item.renewal_detail}</span> : null}
                <button
                  type="button"
                  className="mt-1 block text-caption text-brand-accent underline"
                  onClick={() => setSelected({ mdm: item.mdm, id: item.mdm_device_id })}
                >
                  {translateNow("source.view.details.d1bf045bb5")}
                </button>
                {selected?.mdm === item.mdm && selected.id === item.mdm_device_id && trace.data ? (
                  <div className="mt-2 rounded-control border border-border p-2" role="status">
                    <p>{trace.data.trace.summary}</p>
                    <ol className="mt-1 grid gap-1 text-caption text-muted-foreground">
                      {trace.data.trace.steps.map((step) => (
                        <li key={step.stage}>
                          <span className="font-mono">{step.stage}</span>: {step.outcome}
                          {step.detail ? <> {translateNow("source.mdm.devices.stepdetail.i5mdm00005", { value1: step.detail })}</> : null}
                        </li>
                      ))}
                    </ol>
                  </div>
                ) : null}
                {selected?.mdm === item.mdm && selected.id === item.mdm_device_id && trace.error ? (
                  <p className="mt-2 text-caption text-risk-critical" role="alert">
                    {trace.error}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="text-caption text-muted-foreground">{devices.data?.guidance}</p>
        </>
      ) : null}
    </section>
  );
}
