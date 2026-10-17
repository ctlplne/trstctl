import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { api, type CMDBReconcileSchedule, type CMDBReconcileScheduleInput } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// CMDBSyncPanel shows whether ownership is actually being re-read (I2).
//
// The setup form is visible before the first schedule exists. Hiding the entire
// panel in that state stranded the operator at an API-only setup path. After a
// schedule exists, paused, failed and incomplete coverage remain distinct.
function readCMDBSchedule(): Promise<CMDBReconcileSchedule> {
  return optionalApiCall<CMDBReconcileSchedule>("cmdbSchedule", {
    configured: false,
    enabled: false,
    read_count: 0,
    pages_completed: 0,
    coverage_complete: false,
    coverage_status: "not_configured",
    removed_count: 0,
    changed_count: 0,
    guidance: "",
  });
}

const scheduleSchema = z.object({
  instance_url: z
    .string()
    .trim()
    .url({ error: translateNow("cmdb.setup.invalidURL") })
    .refine((value) => {
      const url = new URL(value);
      return url.protocol === "https:" && !!url.hostname && !url.username && !url.password && !url.search && !url.hash;
    }, translateNow("cmdb.setup.invalidURL")),
  token_ref: z
    .string()
    .trim()
    .regex(/^secret:\/\/.+$/, translateNow("cmdb.setup.invalidTokenRef")),
  ci_query: z.string().trim(),
  interval_seconds: z
    .string()
    .regex(/^\d+$/, translateNow("cmdb.setup.invalidInterval"))
    .refine((value) => Number(value) >= 300, translateNow("cmdb.setup.invalidInterval")),
  enabled: z.boolean(),
});
type ScheduleForm = z.infer<typeof scheduleSchema>;
type ReviewedSchedule = { input: CMDBReconcileScheduleInput; idempotencyKey: string };

export function CMDBSyncPanel() {
  const canWrite = useCan("owners:write");
  const queryClient = useQueryClient();
  const schedule = useApiQuery(["cmdb-schedule"], readCMDBSchedule);
  const form = useForm<ScheduleForm>({
    resolver: zodResolver(scheduleSchema),
    defaultValues: { instance_url: "", token_ref: "", ci_query: "", interval_seconds: "3600", enabled: false },
  });
  const [editing, setEditing] = useState(false);
  const [reviewed, setReviewed] = useState<ReviewedSchedule | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saved, setSaved] = useState(false);
  const s = schedule.data ?? undefined;
  // Older preview/test clients may omit this optional surface. The production
  // client has both methods; a real fetch failure is shown instead of hidden.
  if (typeof api.cmdbSchedule !== "function") return null;

  function openEditor() {
    form.reset({
      instance_url: s?.instance_url ?? "",
      token_ref: s?.token_ref ?? "",
      ci_query: s?.ci_query ?? "",
      interval_seconds: String(s?.interval_seconds || 3600),
      enabled: s?.enabled ?? false,
    });
    setReviewed(null);
    setSaveError("");
    setSaved(false);
    setEditing(true);
  }

  const review = form.handleSubmit((values) => {
    setReviewed({
      input: {
        instance_url: values.instance_url.replace(/\/$/, ""),
        token_ref: values.token_ref,
        ci_query: values.ci_query,
        interval_seconds: Number(values.interval_seconds),
        enabled: values.enabled,
        execution: "relay",
        allow_private_endpoint: false,
      },
      idempotencyKey: newIdempotencyKey(),
    });
    setSaveError("");
  });

  async function save() {
    if (!reviewed || saving) return;
    setSaving(true);
    setSaveError("");
    try {
      const result = await api.putCMDBSchedule(reviewed.input, reviewed.idempotencyKey);
      queryClient.setQueryData(["cmdb-schedule"], result);
      void queryClient.invalidateQueries({ queryKey: ["cmdb-schedule"] });
      setSaved(true);
      setReviewed(null);
      setEditing(false);
    } catch (error) {
      // Retain the reviewed request and its idempotency key. A lost response
      // can be retried without creating a second configuration event.
      setSaveError(error instanceof Error ? error.message : String(error));
    } finally {
      setSaving(false);
    }
  }

  return (
    <section aria-labelledby="cmdb-sync-heading" className="ui-panel space-y-2 p-comfortable">
      <h2 id="cmdb-sync-heading" className="text-title font-semibold">
        {translateNow("source.cmdb.sync.heading.i2own00009")}
      </h2>
      {schedule.error && (
        <p role="alert" className="text-sm text-risk-critical">
          {schedule.error}
        </p>
      )}
      {s && !s.configured && <p className="text-sm">{translateNow("cmdb.setup.notConfigured")}</p>}
      {s?.configured && !s.enabled ? (
        <p className="text-sm">{translateNow("source.cmdb.sync.paused.i2own00010")}</p>
      ) : s?.last_run_at ? (
        <p className="text-sm">
          {translateNow("source.cmdb.sync.lastrun.i2own00011", {
            value1: s.last_run_at.slice(0, 16).replace("T", " "),
            value2: String(Math.round((s.interval_seconds ?? 0) / 60)),
          })}
        </p>
      ) : s?.configured && !s.sweep_id ? (
        <p className="text-sm">{translateNow("source.cmdb.sync.neverran.i2own00012")}</p>
      ) : null}
      {s?.last_error ? <p className="text-sm text-risk-critical">{translateNow("source.cmdb.sync.failing.i2own00013", { value1: s.last_error })}</p> : null}
      {s?.sweep_id ? (
        <div className="rounded-control border border-border bg-muted/30 p-3 text-sm" role="status">
          <p>
            {s.expected_count == null
              ? translateNow("cmdb.sync.coverage.unknown.aud460001", {
                  read: String(s.read_count),
                  pages: String(s.pages_completed),
                })
              : translateNow("cmdb.sync.coverage.known.aud460002", {
                  read: String(s.read_count),
                  expected: String(s.expected_count),
                  pages: String(s.pages_completed),
                })}
          </p>
          {s.coverage_complete ? (
            <p className="mt-1 text-success">
              {translateNow("cmdb.sync.coverage.complete.aud460003", {
                changed: String(s.changed_count),
                removed: String(s.removed_count),
              })}
            </p>
          ) : (
            <p className="mt-1 text-risk-warning">
              {translateNow("cmdb.sync.coverage.incomplete.aud460004", {
                cursor: s.next_cursor || "start of cmdb_ci",
              })}
            </p>
          )}
        </div>
      ) : null}
      {s?.execution === "relay" ? <p className="text-caption text-muted-foreground">{translateNow("source.cmdb.sync.relay.i2own00014")}</p> : null}
      {s?.guidance && <p className="text-caption text-muted-foreground">{s.guidance}</p>}
      {canWrite && !editing && s && (
        <Button type="button" variant="outline" onClick={openEditor}>
          {translateNow(s.configured ? "cmdb.setup.edit" : "cmdb.setup.configure")}
        </Button>
      )}
      {saved && (
        <p role="status" className="text-sm text-success">
          {translateNow("cmdb.setup.saved")}
        </p>
      )}
      {editing && !reviewed && (
        <form onSubmit={review} className="grid gap-3 rounded-control border border-border p-3">
          <p className="text-sm text-muted-foreground">{translateNow("cmdb.setup.bindingHelp")}</p>
          <label className="grid gap-1 text-sm">
            {translateNow("cmdb.setup.instanceURL")}
            <Input {...form.register("instance_url")} autoComplete="url" />
            {form.formState.errors.instance_url && (
              <span role="alert" className="text-risk-critical">
                {form.formState.errors.instance_url.message}
              </span>
            )}
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("cmdb.setup.tokenRef")}
            <Input {...form.register("token_ref")} autoComplete="off" />
            {form.formState.errors.token_ref && (
              <span role="alert" className="text-risk-critical">
                {form.formState.errors.token_ref.message}
              </span>
            )}
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("cmdb.setup.ciQuery")}
            <Input {...form.register("ci_query")} autoComplete="off" />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("cmdb.setup.interval")}
            <Input type="number" min={300} step={1} {...form.register("interval_seconds")} />
            {form.formState.errors.interval_seconds && (
              <span role="alert" className="text-risk-critical">
                {form.formState.errors.interval_seconds.message}
              </span>
            )}
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" {...form.register("enabled")} />
            {translateNow("cmdb.setup.enabled")}
          </label>
          <div className="flex gap-2">
            <Button type="submit">{translateNow("cmdb.setup.review")}</Button>
            <Button type="button" variant="outline" onClick={() => setEditing(false)}>
              {translateNow("cmdb.setup.cancel")}
            </Button>
          </div>
        </form>
      )}
      {reviewed && (
        <section aria-label={translateNow("cmdb.setup.reviewed")} className="grid gap-2 rounded-control border border-border p-3 text-sm">
          <p>
            {translateNow("cmdb.setup.instanceURL")}: {reviewed.input.instance_url}
          </p>
          <p>
            {translateNow("cmdb.setup.tokenRef")}: {reviewed.input.token_ref}
          </p>
          <p>
            {translateNow("cmdb.setup.ciQuery")}: {reviewed.input.ci_query || translateNow("cmdb.setup.allCIs")}
          </p>
          <p>
            {translateNow("cmdb.setup.interval")}: {reviewed.input.interval_seconds}
          </p>
          <p>{reviewed.input.enabled ? translateNow("cmdb.setup.enabledState") : translateNow("cmdb.setup.pausedState")}</p>
          <p>{translateNow("source.cmdb.sync.relay.i2own00014")}</p>
          {saveError && (
            <p role="alert" className="text-risk-critical">
              {saveError}
            </p>
          )}
          <div className="flex gap-2">
            <Button type="button" disabled={saving} onClick={() => void save()}>
              {translateNow("cmdb.setup.save")}
            </Button>
            <Button type="button" variant="outline" disabled={saving} onClick={() => setReviewed(null)}>
              {translateNow("cmdb.setup.editReview")}
            </Button>
          </div>
        </section>
      )}
    </section>
  );
}
