import { useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { StatusBadge } from "@/components/StatusBadge";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type AuditFeed, type AuditFeedRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery, useQueryClient } from "@/lib/query";

type ValidationMessage =
  | "audit.feeds.validation.required"
  | "audit.feeds.validation.uuid"
  | "audit.feeds.validation.url"
  | "audit.feeds.validation.tokenRef"
  | "audit.feeds.validation.interval"
  | "audit.feeds.validation.batch"
  | "audit.feeds.validation.cidrs";

function buildSchema(t: (key: ValidationMessage) => string) {
  return z
    .object({
      id: z
        .string()
        .trim()
        .uuid(t("audit.feeds.validation.uuid"))
        .refine((value) => value !== "00000000-0000-0000-0000-000000000000", t("audit.feeds.validation.uuid")),
      name: z.string().trim().min(1, t("audit.feeds.validation.required")),
      provider: z.enum(["splunk-hec", "sentinel"]),
      endpointUrl: z.string().trim().url(t("audit.feeds.validation.url")),
      tokenRef: z
        .string()
        .trim()
        .regex(/^env:[A-Z][A-Z0-9_]*$/, t("audit.feeds.validation.tokenRef")),
      intervalSeconds: z.number().int().min(60, t("audit.feeds.validation.interval")),
      batchSize: z.number().int().min(1, t("audit.feeds.validation.batch")).max(500, t("audit.feeds.validation.batch")),
      enabled: z.boolean(),
      allowPrivateEndpoint: z.boolean(),
      privateEgressCidrs: z.string(),
    })
    .superRefine((values, context) => {
      if (values.allowPrivateEndpoint && lines(values.privateEgressCidrs).length === 0) {
        context.addIssue({ code: "custom", path: ["privateEgressCidrs"], message: t("audit.feeds.validation.cidrs") });
      }
    });
}

type FeedValues = z.infer<ReturnType<typeof buildSchema>>;

function emptyValues(): FeedValues {
  return {
    id: newFeedID(),
    name: "",
    provider: "splunk-hec",
    endpointUrl: "",
    tokenRef: "",
    intervalSeconds: 300,
    batchSize: 100,
    enabled: true,
    allowPrivateEndpoint: false,
    privateEgressCidrs: "",
  };
}

export function AuditFeedPanel() {
  const { t, formatDateTime, formatNumber } = useTranslation();
  const canRead = useCan("audit:read");
  const canWrite = useCan("audit:write");
  const queryClient = useQueryClient();
  const available = typeof api.auditFeeds === "function" && typeof api.putAuditFeed === "function";
  const feeds = useApiQuery(["audit-feeds"], () => (available ? api.auditFeeds() : Promise.resolve({ items: [] })), { enabled: canRead && available });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const schema = useMemo(() => buildSchema(t), [t]);
  const form = useForm<FeedValues>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: emptyValues(),
  });

  if (!available) return null;
  const feedItems = feeds.data?.items ?? [];

  const save = form.handleSubmit(async (values) => {
    setBusy(true);
    setNotice(null);
    setOperationError(null);
    const request: AuditFeedRequest = {
      name: values.name.trim(),
      provider: values.provider,
      endpoint_url: values.endpointUrl.trim(),
      token_ref: values.tokenRef.trim(),
      interval_seconds: values.intervalSeconds,
      batch_size: values.batchSize,
      enabled: values.enabled,
      allow_private_endpoint: values.allowPrivateEndpoint,
      private_egress_cidrs: values.allowPrivateEndpoint ? lines(values.privateEgressCidrs) : [],
    };
    try {
      await api.putAuditFeed(values.id, request);
      form.reset(emptyValues());
      setNotice(t("audit.feeds.saved"));
      await queryClient.invalidateQueries({ queryKey: ["audit-feeds"] });
    } catch (error) {
      setOperationError(apiProblemMessage(error, t("audit.feeds.mutationFailed")));
    } finally {
      setBusy(false);
    }
  });

  function editFeed(feed: AuditFeed) {
    form.reset({
      id: feed.id,
      name: feed.name,
      provider: feed.provider,
      endpointUrl: feed.endpoint_url,
      tokenRef: feed.token_ref,
      intervalSeconds: feed.interval_seconds,
      batchSize: feed.batch_size,
      enabled: feed.enabled,
      allowPrivateEndpoint: feed.allow_private_endpoint,
      privateEgressCidrs: feed.private_egress_cidrs.join("\n"),
    });
    setNotice(null);
    setOperationError(null);
  }

  const columns: Array<DataGridColumn<AuditFeed>> = [
    {
      id: "destination",
      header: t("audit.feeds.destination"),
      cell: (feed) => (
        <span className="grid gap-1">
          <span className="font-medium">{feed.name}</span>
          <span className="font-mono text-xs uppercase text-muted-foreground">{feed.provider}</span>
          <span className="break-all font-mono text-xs text-muted-foreground">{feed.endpoint_url}</span>
          <span className="font-mono text-xs text-muted-foreground">{feed.token_ref}</span>
        </span>
      ),
    },
    {
      id: "status",
      header: t("audit.feeds.status"),
      cell: (feed) => (
        <span className="grid gap-1">
          <StatusBadge value={feed.status} label={statusLabel(feed.status, t)} tone={statusTone(feed.status)} />
          <span className="text-xs text-muted-foreground">{feed.enabled ? t("audit.feeds.enabled") : t("audit.feeds.disabled")}</span>
        </span>
      ),
    },
    {
      id: "lag",
      header: t("audit.feeds.lag"),
      cell: (feed) => (
        <span className="grid gap-1">
          <strong>{t("audit.feeds.recordCount", { count: formatNumber(feed.lag_records) })}</strong>
          <span className="text-xs text-muted-foreground">{t("audit.feeds.sequence", { sequence: formatNumber(feed.last_delivered_sequence) })}</span>
        </span>
      ),
    },
    {
      id: "delivery",
      header: t("audit.feeds.delivery"),
      cell: (feed) => (
        <span className="grid gap-1 text-xs">
          <span>{t("audit.feeds.attempts", { count: formatNumber(feed.attempts) })}</span>
          <span>{t("audit.feeds.nextRun", { time: formatDateTime(feed.next_attempt_at || feed.next_run_at) })}</span>
          {feed.last_error_code ? <span className="font-mono text-risk-critical">{feed.last_error_code}</span> : null}
          {feed.collector_request_id ? <span className="font-mono text-muted-foreground">{feed.collector_request_id}</span> : null}
        </span>
      ),
    },
    ...(canWrite
      ? [
          {
            id: "actions",
            header: t("audit.feeds.actions"),
            cell: (feed: AuditFeed) => (
              <Button type="button" size="sm" variant="outline" onClick={() => editFeed(feed)}>
                {t("audit.feeds.edit")}
              </Button>
            ),
          } satisfies DataGridColumn<AuditFeed>,
        ]
      : []),
  ];

  let state: DataGridState = "ready";
  let stateTitle: string | undefined;
  let stateMessage: string | undefined;
  if (!canRead) {
    state = "permission-denied";
    stateTitle = t("audit.feeds.permissionDenied");
  } else if (feeds.loading) {
    state = "loading";
    stateMessage = t("audit.feeds.loading");
  } else if (feeds.error) {
    state = "error";
    stateTitle = t("audit.feeds.loadFailed");
    stateMessage = feeds.error;
  } else if (feedItems.length === 0) {
    state = "empty";
    stateTitle = t("audit.feeds.empty");
    stateMessage = t("audit.feeds.emptyBody");
  }

  return (
    <section className="grid gap-4 rounded-panel border border-border p-comfortable" aria-labelledby="audit-feeds-heading">
      <div>
        <h2 id="audit-feeds-heading" className="text-lg font-semibold">
          {t("audit.feeds.heading")}
        </h2>
        <p className="mt-1 max-w-4xl text-sm text-muted-foreground">{t("audit.feeds.description")}</p>
      </div>

      <DataGrid
        ariaLabel={t("audit.feeds.listLabel")}
        rows={feedItems}
        columns={columns}
        getRowId={(feed) => feed.id}
        state={state}
        stateTitle={stateTitle}
        stateMessage={stateMessage}
        emptyStateHeadingAs="h3"
        virtualization={false}
      />

      {canWrite ? (
        <form aria-label={t("audit.feeds.configure")} className="grid gap-4 rounded-control border border-border p-3" onSubmit={save}>
          <h3 className="font-medium">{t("audit.feeds.configure")}</h3>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <Field label={t("audit.feeds.id")} error={form.formState.errors.id?.message} required>
              {(control) => <Input {...control} {...form.register("id")} />}
            </Field>
            <Field label={t("audit.feeds.name")} error={form.formState.errors.name?.message} required>
              {(control) => <Input {...control} {...form.register("name")} />}
            </Field>
            <Field label={t("audit.feeds.provider")} required>
              {(control) => (
                <Select {...control} {...form.register("provider")}>
                  <option value="splunk-hec">{t("audit.feeds.provider.splunk")}</option>
                  <option value="sentinel">{t("audit.feeds.provider.sentinel")}</option>
                </Select>
              )}
            </Field>
            <Field label={t("audit.feeds.endpoint")} error={form.formState.errors.endpointUrl?.message} required>
              {(control) => <Input {...control} type="url" placeholder={t("audit.feeds.endpointPlaceholder")} {...form.register("endpointUrl")} />}
            </Field>
            <Field label={t("audit.feeds.tokenRef")} description={t("audit.feeds.tokenRefHelp")} error={form.formState.errors.tokenRef?.message} required>
              {(control) => <Input {...control} placeholder={t("audit.feeds.tokenRefPlaceholder")} autoComplete="off" {...form.register("tokenRef")} />}
            </Field>
            <Field label={t("audit.feeds.interval")} error={form.formState.errors.intervalSeconds?.message} required>
              {(control) => <Input {...control} type="number" min={60} {...form.register("intervalSeconds", { valueAsNumber: true })} />}
            </Field>
            <Field label={t("audit.feeds.batch")} error={form.formState.errors.batchSize?.message} required>
              {(control) => <Input {...control} type="number" min={1} max={500} {...form.register("batchSize", { valueAsNumber: true })} />}
            </Field>
            <Field
              label={t("audit.feeds.cidrs")}
              description={t("audit.feeds.cidrsHelp")}
              error={form.formState.errors.privateEgressCidrs?.message}
              className="md:col-span-2"
            >
              {(control) => <Textarea {...control} rows={2} placeholder="10.20.0.0/16" {...form.register("privateEgressCidrs")} />}
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-5">
            <label className="inline-flex items-center gap-2 text-sm">
              <Checkbox {...form.register("enabled")} />
              {t("audit.feeds.enabledLabel")}
            </label>
            <label className="inline-flex items-center gap-2 text-sm">
              <Checkbox {...form.register("allowPrivateEndpoint")} />
              {t("audit.feeds.privateEndpoint")}
            </label>
          </div>
          {operationError ? (
            <p role="alert" className="text-sm text-risk-critical">
              {operationError}
            </p>
          ) : null}
          {notice ? (
            <p role="status" className="text-sm text-status-success">
              {notice}
            </p>
          ) : null}
          <div>
            <Button type="submit" disabled={busy}>
              {busy ? t("audit.feeds.saving") : t("audit.feeds.save")}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}

function lines(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function newFeedID(): string {
  return typeof crypto !== "undefined" && typeof crypto.randomUUID === "function" ? crypto.randomUUID() : "00000000-0000-4000-8000-000000000052";
}

function statusTone(status: AuditFeed["status"]): "success" | "warning" | "critical" | "info" | "neutral" {
  if (status === "delivered") return "success";
  if (status === "failed") return "critical";
  if (status === "retrying") return "warning";
  if (status === "queued" || status === "delivering") return "info";
  return "neutral";
}

function statusLabel(status: AuditFeed["status"], t: ReturnType<typeof useTranslation>["t"]): string {
  switch (status) {
    case "queued":
      return t("audit.feeds.status.queued");
    case "delivering":
      return t("audit.feeds.status.delivering");
    case "retrying":
      return t("audit.feeds.status.retrying");
    case "delivered":
      return t("audit.feeds.status.delivered");
    case "failed":
      return t("audit.feeds.status.failed");
    default:
      return t("audit.feeds.status.notStarted");
  }
}
