import { useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { RefreshCw, Save, Send } from "lucide-react";
import type { QueryClient } from "@tanstack/react-query";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { formatDateTime } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import {
  api,
  ApiError,
  type Notification,
  type NotificationChannel,
  type NotificationChannelTest,
  type NotificationRoutingPolicy,
  type NotificationRoutingPreview,
} from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import type { StatusTone } from "@/lib/statusVocab";
import {
  AlertCenterPanel,
  AlertCenterTabs,
  meaningfulAttention,
  NeedsAttention,
  ViewIntroduction,
  type AlertCenterView,
} from "@/pages/notifications/AlertCenterTabs";

type NotificationStatus = Notification["status"];
type TestSeverity = "low" | "informational" | "warning" | "critical";
type Notice = { title: string; detail?: string };
type PolicyFormState = {
  name: string;
  scopeKind: "manual" | "global" | "workspace" | "owner" | "asset";
  scopeRef: string;
  ownerRef: string;
  ownerEmail: string;
  digestInterval: string;
  defaultChannels: string;
  criticalChannels: string;
  warningChannels: string;
  lowChannels: string;
};
type ChannelFormState = {
  channelType: string;
  label: string;
  endpointUrl: string;
  credentialRef: string;
  enabled: boolean;
};
type TestFormState = {
  channelId: string;
  severity: TestSeverity;
  subject: string;
  credentialRef: string;
};

const maxNotificationAttempts = 10;
const initialChannelForm: ChannelFormState = {
  channelType: "webhook",
  label: "",
  endpointUrl: "",
  credentialRef: "",
  enabled: true,
};
const initialPolicyForm: PolicyFormState = {
  name: "",
  scopeKind: "workspace",
  scopeRef: "certificate-lifecycle",
  ownerRef: "",
  ownerEmail: "",
  digestInterval: "86400",
  defaultChannels: "",
  criticalChannels: "",
  warningChannels: "",
  lowChannels: "",
};
const initialTestForm: TestFormState = {
  channelId: "",
  severity: "critical",
  subject: "Notification channel test",
  credentialRef: "",
};

const statusOptions = [
  { value: "", labelKey: "notifications.filter.statusAll" },
  { value: "pending", labelKey: "notifications.status.pending" },
  { value: "sent", labelKey: "notifications.status.sent" },
  { value: "read", labelKey: "notifications.status.read" },
  { value: "dead", labelKey: "notifications.status.dead" },
] satisfies Array<{ value: "" | NotificationStatus; labelKey: MessageKey }>;
const digestOptions = [
  { value: "3600", labelKey: "notifications.routing.intervalOneHour" },
  { value: "43200", labelKey: "notifications.routing.intervalTwelveHours" },
  { value: "86400", labelKey: "notifications.routing.intervalOneDay" },
  { value: "604800", labelKey: "notifications.routing.intervalSevenDays" },
] as const;
const testSeverityOptions: TestSeverity[] = ["critical", "warning", "informational", "low"];
const channelTypeOptions = ["email", "slack", "msteams", "sms", "siem", "pagerduty", "opsgenie", "webhook"] as const;
const notificationQueryKey = ["alert-center", "notifications"] as const;
const channelQueryKey = ["alert-center", "channels"] as const;
const policyQueryKey = ["alert-center", "routing-policies"] as const;

export function Notifications() {
  const { toast } = useToast();
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const channelLoadError = t("notifications.channels.loadError");
  const notificationUnavailable = t("notifications.error.unavailable");
  const notificationLoadError = t("notifications.error.loadFailed");
  const markReadFailed = t("notifications.action.markReadFailed");
  const markReadLoadFailed = t("notifications.action.markReadLoadFailed");
  const requeueFailed = t("notifications.action.requeueFailed");
  const requeueLoadFailed = t("notifications.action.requeueLoadFailed");
  const [activeView, setActiveView] = useState<AlertCenterView>("attention");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<Notice | null>(null);
  const [typeFilter, setTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | NotificationStatus>("");
  const [channelForm, setChannelForm] = useState<ChannelFormState>(initialChannelForm);
  const [policyForm, setPolicyForm] = useState<PolicyFormState>(initialPolicyForm);
  const [testForm, setTestForm] = useState<TestFormState>(initialTestForm);
  const [channelBusy, setChannelBusy] = useState(false);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<NotificationChannelTest | null>(null);
  const [routePreview, setRoutePreview] = useState<NotificationRoutingPreview | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [detail, setDetail] = useState<Notification | null>(null);
  const [channelDialogOpen, setChannelDialogOpen] = useState(false);
  const channelDialogHeadingRef = useRef<HTMLHeadingElement>(null);

  const notificationQuery = useApiQuery(notificationQueryKey, () => api.notifications({ limit: 100 }), { live: { intervalMs: 30_000 } });
  const channelQuery = useApiQuery(channelQueryKey, () => api.notificationChannels(), { live: { intervalMs: 60_000 } });
  const policyQuery = useApiQuery(policyQueryKey, () => api.notificationRoutingPolicies(), { live: { intervalMs: 60_000 } });
  const notifications = useMemo(() => notificationQuery.data?.items ?? [], [notificationQuery.data]);
  const channels = channelQuery.data?.items ?? [];
  const policies = policyQuery.data?.items ?? [];
  const loading = notificationQuery.loading || channelQuery.loading || policyQuery.loading;
  const loadFailed = Boolean(notificationQuery.error || channelQuery.error || policyQuery.error);
  const loadError: Notice | null = loadFailed
    ? {
        title: notificationUnavailable,
        detail: errorText(notificationQuery.errorValue || channelQuery.errorValue || policyQuery.errorValue, notificationLoadError),
      }
    : null;
  const channelError = channelQuery.error ? errorText(channelQuery.errorValue, channelLoadError) : null;

  function refreshAlertCenter() {
    setError(null);
    notificationQuery.refetch();
    channelQuery.refetch();
    policyQuery.refetch();
  }

  const typeOptions = useMemo(() => Array.from(new Set(notifications.map(notificationType))).sort(), [notifications]);
  const filteredNotifications = useMemo(
    () =>
      notifications.filter((notification) => {
        if (activeView === "failures" && notification.status !== "dead") return false;
        if (typeFilter && notificationType(notification) !== typeFilter) return false;
        if (statusFilter && notification.status !== statusFilter) return false;
        return true;
      }),
    [activeView, notifications, statusFilter, typeFilter],
  );
  const unreadCount = filteredNotifications.filter(isUnread).length;

  async function markRead(notification: Notification) {
    const snapshot = notificationQuery.data;
    setBusyId(notification.id);
    setError(null);
    updateNotificationCache(queryClient, (candidate) =>
      candidate.id === notification.id ? { ...candidate, status: "read", read_at: new Date().toISOString() } : candidate,
    );
    try {
      const updated = await api.markNotificationRead(notification.id);
      updateNotificationCache(queryClient, (candidate) => (candidate.id === notification.id ? updated : candidate));
      void queryClient.invalidateQueries({ queryKey: notificationQueryKey, refetchType: "none" });
      void queryClient.invalidateQueries({ queryKey: ["header-alerts"], refetchType: "none" });
      toast({ kind: "success", title: t("notifications.action.markedRead"), description: notificationSubject(notification) });
    } catch (err) {
      queryClient.setQueryData(notificationQueryKey, snapshot);
      setError({ title: markReadFailed, detail: errorText(err, markReadLoadFailed) });
      toast({ kind: "error", title: markReadFailed, description: errorText(err, markReadLoadFailed) });
    } finally {
      setBusyId(null);
    }
  }

  async function openDetails(notification: Notification) {
    setDetail(notification);
    try {
      const fresh = await api.notification(notification.id);
      setDetail((current) => (current && current.id === notification.id ? fresh : current));
    } catch {
      // Keep the row snapshot when the fresh fetch fails.
    }
  }

  async function requeue(notification: Notification) {
    setBusyId(notification.id);
    setError(null);
    try {
      const updated = await api.requeueNotification(notification.id);
      updateNotificationCache(queryClient, (candidate) => (candidate.id === notification.id ? updated : candidate));
      void queryClient.invalidateQueries({ queryKey: notificationQueryKey, refetchType: "none" });
      void queryClient.invalidateQueries({ queryKey: ["header-alerts"], refetchType: "none" });
      toast({ kind: "success", title: t("notifications.action.requeued"), description: notificationSubject(notification) });
    } catch (err) {
      setError({ title: requeueFailed, detail: errorText(err, requeueLoadFailed) });
      toast({ kind: "error", title: requeueFailed, description: errorText(err, requeueLoadFailed) });
    } finally {
      setBusyId(null);
    }
  }

  async function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPolicyBusy(true);
    setError(null);
    try {
      const created = await api.createNotificationRoutingPolicy({
        name: policyForm.name.trim(),
        scope_kind: policyForm.scopeKind,
        scope_ref: policyForm.scopeKind === "manual" || policyForm.scopeKind === "global" ? undefined : policyForm.scopeRef.trim(),
        owner_ref: policyForm.ownerRef.trim() || undefined,
        owner_email: policyForm.ownerEmail.trim() || undefined,
        digest_interval_seconds: Number(policyForm.digestInterval),
        digest_timezone: "UTC",
        default_channels: splitChannels(policyForm.defaultChannels),
        channels_by_severity: {
          critical: splitChannels(policyForm.criticalChannels),
          warning: splitChannels(policyForm.warningChannels),
          low: splitChannels(policyForm.lowChannels),
        },
      });
      queryClient.setQueryData(policyQueryKey, { items: upsertPolicy(policies, created) });
      void queryClient.invalidateQueries({ queryKey: policyQueryKey, refetchType: "none" });
      toast({ kind: "success", title: t("notifications.routing.policyCreated"), description: created.name });
    } catch (err) {
      const detail = errorText(err, t("notifications.routing.createError"));
      setError({ title: t("notifications.routing.createError"), detail });
      toast({ kind: "error", title: t("notifications.routing.createError"), description: detail });
    } finally {
      setPolicyBusy(false);
    }
  }

  async function saveChannel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setChannelBusy(true);
    setError(null);
    const channelType = channelForm.channelType.trim();
    try {
      const saved = await api.createNotificationChannel({
        id: channelType,
        channel_type: channelType,
        label: channelForm.label.trim() || undefined,
        endpoint_url: channelForm.endpointUrl.trim(),
        credential_ref: channelForm.credentialRef.trim() || undefined,
        enabled: channelForm.enabled,
      });
      queryClient.setQueryData(channelQueryKey, { items: upsertChannel(channels, saved) });
      void queryClient.invalidateQueries({ queryKey: channelQueryKey, refetchType: "none" });
      setChannelForm((current) => ({ ...current, credentialRef: "" }));
      setChannelDialogOpen(false);
      toast({ kind: "success", title: t("notifications.channels.saved"), description: saved.label });
    } catch (err) {
      const detail = errorText(err, t("notifications.channels.saveError"));
      setError({ title: t("notifications.channels.saveError"), detail });
      toast({ kind: "error", title: t("notifications.channels.saveError"), description: detail });
    } finally {
      setChannelBusy(false);
    }
  }

  const configuredChannels = channels.filter(channelReady);
  const routablePolicies = policies.filter((policy) => policyHasReadyChannel(policy, channels));
  const deadDeliveries = notifications.filter((notification) => notification.status === "dead");
  const summaryTitle = loading
    ? t("notifications.design.checking")
    : loadFailed
      ? t("notifications.design.unavailable")
      : deadDeliveries.length === 1
        ? t("notifications.design.oneFailedTitle")
        : deadDeliveries.length > 1
          ? t("notifications.design.manyFailedTitle", { count: String(deadDeliveries.length) })
          : configuredChannels.length === 0
            ? t("notifications.design.noChannelTitle")
            : policies.length === 0
              ? t("notifications.design.noRuleTitle")
              : routablePolicies.length === 0
                ? t("notifications.design.unroutedTitle")
                : t("notifications.design.readyTitle");
  const summaryBody = loading
    ? t("notifications.design.checkingBody")
    : loadFailed
      ? t("notifications.design.unavailableBody")
      : deadDeliveries.length > 0
        ? t("notifications.design.failedBody")
        : configuredChannels.length === 0
          ? t("notifications.design.noChannelBody")
          : policies.length === 0
            ? t("notifications.design.noRuleBody")
            : routablePolicies.length === 0
              ? t("notifications.design.unroutedBody")
              : t("notifications.design.readyBody");
  const actionHelp = loading
    ? t("notifications.design.addChecking")
    : loadFailed
      ? t("notifications.design.addUnavailable")
      : t("notifications.design.addHelp");

  async function testChannel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const channelId = testForm.channelId || firstConfiguredChannel(channels)?.id || "";
    if (!channelId) return;
    setTestBusy(true);
    setError(null);
    try {
      const result = await api.testNotificationChannel(channelId, {
        severity: testForm.severity,
        subject: testForm.subject.trim() || undefined,
        credential_ref: testForm.credentialRef.trim() || undefined,
      });
      setTestResult(result);
      toast({ kind: "success", title: t("notifications.routing.testQueued"), description: `${result.channel_id} #${result.outbox_id}` });
    } catch (err) {
      const detail = errorText(err, t("notifications.routing.testError"));
      setError({ title: t("notifications.routing.testError"), detail });
      toast({ kind: "error", title: t("notifications.routing.testError"), description: detail });
    } finally {
      setTestBusy(false);
    }
  }

  async function previewRoute() {
    setPreviewBusy(true);
    setError(null);
    try {
      const preview = await api.notificationRoutingPreview({
        workspace: policyForm.scopeKind === "workspace" ? policyForm.scopeRef : undefined,
        owner_ref: policyForm.scopeKind === "owner" ? policyForm.scopeRef : undefined,
        asset_ref: policyForm.scopeKind === "asset" ? policyForm.scopeRef : undefined,
        severity: "critical",
      });
      setRoutePreview(preview);
    } catch (err) {
      setError({ title: t("notifications.routing.previewFailed"), detail: errorText(err, t("notifications.routing.previewFailedDetail")) });
    } finally {
      setPreviewBusy(false);
    }
  }

  return (
    <section aria-labelledby="notifications-heading" className="space-y-4">
      <PageHeader
        title={t("notifications.design.title")}
        titleId="notifications-heading"
        description={t("notifications.design.answer")}
        technicalDetails={t("notifications.design.technicalDetails")}
        actions={
          <Button type="button" aria-describedby="add-channel-action-help" disabled={loading || loadFailed} onClick={() => setChannelDialogOpen(true)}>
            {t("notifications.design.addChannel")}
          </Button>
        }
      />

      <section aria-labelledby="delivery-summary-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="grid gap-1">
          <h2 id="delivery-summary-heading" className="text-title font-semibold">
            {summaryTitle}
          </h2>
          <p className="max-w-3xl text-body">{summaryBody}</p>
          <p id="add-channel-action-help" className="max-w-3xl text-caption text-muted-foreground">
            {actionHelp}
          </p>
        </div>

        {!loading && !loadFailed ? (
          <dl className="grid gap-3 sm:grid-cols-3">
            <DeliveryCount label={channelCountLabel(t, configuredChannels.length)} />
            <DeliveryCount label={ruleCountLabel(t, policies.length)} />
            <DeliveryCount label={failedCountLabel(t, deadDeliveries.length)} tone={deadDeliveries.length > 0 ? "critical" : "neutral"} />
          </dl>
        ) : null}

        {!loading && !loadFailed && policies.length > 0 ? <RoutingPreview policies={policies} channels={channels} /> : null}
      </section>

      {(error || loadError) && <ErrorState title={(error || loadError)!.title}>{(error || loadError)!.detail}</ErrorState>}

      <section aria-label={t("notifications.center.views")} className="ui-panel p-comfortable">
        <AlertCenterTabs
          active={activeView}
          onChange={setActiveView}
          failureCount={deadDeliveries.length}
          attentionCount={meaningfulAttention(notifications).length}
        />

        {activeView === "attention" ? (
          <AlertCenterPanel view="attention">
            {loading ? (
              <LoadingState>{t("notifications.loading")}</LoadingState>
            ) : (
              <NeedsAttention
                notifications={notifications}
                busyId={busyId}
                onDetails={(notification) => void openDetails(notification)}
                onRequeue={(notification) => void requeue(notification)}
              />
            )}
          </AlertCenterPanel>
        ) : null}

        {activeView === "routing" ? (
          <AlertCenterPanel view="routing">
            <div className="grid gap-4">
              <ViewIntroduction view="routing" />
              <RoutingPolicyAuthoring
                channels={channels}
                policies={policies}
                policyForm={policyForm}
                policyBusy={policyBusy}
                routePreview={routePreview}
                previewBusy={previewBusy}
                onPolicyFormChange={setPolicyForm}
                onSavePolicy={(event) => void savePolicy(event)}
                onPreviewRoute={() => void previewRoute()}
              />
            </div>
          </AlertCenterPanel>
        ) : null}

        {activeView === "channels" ? (
          <AlertCenterPanel view="channels">
            <div className="grid gap-4">
              <ViewIntroduction view="channels" />
              <ChannelCatalog channels={channels} error={channelError} />
              <ChannelTestForm
                channels={channels}
                form={testForm}
                busy={testBusy}
                result={testResult}
                onFormChange={setTestForm}
                onSubmit={(event) => void testChannel(event)}
              />
            </div>
          </AlertCenterPanel>
        ) : null}

        {activeView === "failures" || activeView === "history" ? (
          <AlertCenterPanel view={activeView}>
            <div className="grid gap-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <ViewIntroduction view={activeView} />
                <Button type="button" variant="outline" onClick={refreshAlertCenter} disabled={loading}>
                  <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
                  {translateNow("source.refresh.0e91610117")}
                </Button>
              </div>
              <div className="grid gap-3 rounded-control border border-border bg-muted/20 p-3 lg:grid-cols-[minmax(12rem,16rem)_minmax(12rem,16rem)_1fr]">
                <Field label={t("notifications.filter.type")}>
                  {(control) => (
                    <Select {...control} aria-label={t("notifications.filter.type")} value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
                      <option value="">{t("notifications.filter.typeAll")}</option>
                      {typeOptions.map((type) => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <Field label={t("notifications.filter.status")}>
                  {(control) => (
                    <Select
                      {...control}
                      aria-label={t("notifications.filter.status")}
                      value={statusFilter}
                      onChange={(event) => setStatusFilter(event.target.value as "" | NotificationStatus)}
                    >
                      {statusOptions.map((option) => (
                        <option key={option.value || "all"} value={option.value}>
                          {t(option.labelKey)}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <div className="flex items-end justify-between gap-3 text-sm text-muted-foreground">
                  <span>{t("notifications.count.total", { count: filteredNotifications.length })}</span>
                  <span>{t("notifications.count.unread", { count: unreadCount })}</span>
                </div>
              </div>
              {loading ? (
                <LoadingState>{t("notifications.loading")}</LoadingState>
              ) : filteredNotifications.length === 0 ? (
                <EmptyState title={t("notifications.design.emptyDeliveryTitle")}>{t("notifications.design.emptyDeliveryBody")}</EmptyState>
              ) : (
                <NotificationsTable
                  notifications={filteredNotifications}
                  busyId={busyId}
                  onMarkRead={(notification) => void markRead(notification)}
                  onRequeue={(notification) => void requeue(notification)}
                  onDetails={(notification) => void openDetails(notification)}
                />
              )}
            </div>
          </AlertCenterPanel>
        ) : null}
      </section>

      <Dialog
        open={channelDialogOpen}
        onClose={() => setChannelDialogOpen(false)}
        titleId="add-notification-channel-heading"
        descriptionId="add-notification-channel-description"
        initialFocusRef={channelDialogHeadingRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        <div className="grid min-w-0 gap-4">
          <div>
            <h2 ref={channelDialogHeadingRef} id="add-notification-channel-heading" className="text-title font-semibold" tabIndex={-1}>
              {t("notifications.design.addChannel")}
            </h2>
            <p id="add-notification-channel-description" className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {t("notifications.design.addDialogHelp")}
            </p>
          </div>
          <ChannelAuthoring
            form={channelForm}
            busy={channelBusy}
            embedded
            onCancel={() => setChannelDialogOpen(false)}
            onFormChange={setChannelForm}
            onSaveChannel={(event) => void saveChannel(event)}
          />
        </div>
      </Dialog>

      {detail && (
        <Dialog
          open
          onClose={() => setDetail(null)}
          titleId="notification-detail-heading"
          descriptionId="notification-detail-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="notification-detail-heading" className="text-title font-semibold">
              {translateNow("source.notification.value1.81c16a52a8", { value1: detail.id })}
            </h2>
            <p id="notification-detail-description" className="mt-1 text-sm text-muted-foreground">
              {translateNow("source.created.d70b9e24bc")} {formatDateTime(detail.created_at)}{" "}
              {translateNow("source.full.delivery.subject.ownership.and.routin.32d5733727")}
            </p>
          </header>
          <div className="grid gap-4 p-5">
            <section aria-label={translateNow("source.delivery.52bfe584a5")}>
              <h3 className="text-sm font-semibold">{translateNow("source.delivery.52bfe584a5")}</h3>
              <dl className="mt-2 grid gap-2 text-sm">
                <NotificationDetailRow term="Destination">{detail.destination}</NotificationDetailRow>
                <NotificationDetailRow term="Status">
                  <StatusBadge value={detail.status} label={detail.status} tone={statusTone(detail.status)} />
                </NotificationDetailRow>
                <NotificationDetailRow term="Attempts">
                  {translateNow("source.value1.value2.9539417d74", { value1: detail.attempts, value2: maxNotificationAttempts })}
                </NotificationDetailRow>
                <NotificationDetailRow term="Delivered at">{detail.delivered_at ? formatDateTime(detail.delivered_at) : "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Read at">{detail.read_at ? formatDateTime(detail.read_at) : "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Last error">
                  {detail.last_error ? (
                    <span className="break-words font-medium text-risk-critical">{detail.last_error}</span>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </NotificationDetailRow>
                <NotificationDetailRow term="Idempotency key" mono>
                  {detail.idempotency_key || "-"}
                </NotificationDetailRow>
              </dl>
            </section>
            <section aria-label={translateNow("source.subject.6897128384")}>
              <h3 className="text-sm font-semibold">{translateNow("source.subject.6897128384")}</h3>
              <dl className="mt-2 grid gap-2 text-sm">
                <NotificationDetailRow term="Subject">{detail.subject || "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Detail">{detail.detail || "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Certificate" mono>
                  {detail.certificate_id || "-"}
                </NotificationDetailRow>
                <NotificationDetailRow term="Serial" mono>
                  {detail.serial || "-"}
                </NotificationDetailRow>
                <NotificationDetailRow term="Not after">
                  {detail.not_after ? formatDateTime(detail.not_after) : t("notifications.center.noDeadline")}
                </NotificationDetailRow>
                <NotificationDetailRow term="Threshold days">{detail.threshold_days != null ? String(detail.threshold_days) : "-"}</NotificationDetailRow>
              </dl>
            </section>
            <section aria-label={t("parity.ownership_3e90e4")}>
              <h3 className="text-sm font-semibold">{t("parity.ownership_3e90e4")}</h3>
              <dl className="mt-2 grid gap-2 text-sm">
                <NotificationDetailRow term="Owner">{detail.owner_name || "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Owner email">{detail.owner_email || "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Owner ID" mono>
                  {detail.owner_id || "-"}
                </NotificationDetailRow>
              </dl>
            </section>
            <section aria-label={t("parity.routing_7d15dd")}>
              <h3 className="text-sm font-semibold">{t("parity.routing_7d15dd")}</h3>
              <dl className="mt-2 grid gap-2 text-sm">
                <NotificationDetailRow term="Routing policy" mono>
                  {detail.routing_policy_id || "-"}
                </NotificationDetailRow>
                <NotificationDetailRow term="Kind">{detail.kind || "-"}</NotificationDetailRow>
                <NotificationDetailRow term="Severity">
                  {detail.severity ? (
                    <StatusBadge value={detail.severity} label={detail.severity} tone={severityTone(detail.severity)} />
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </NotificationDetailRow>
                <NotificationDetailRow term="Escalation recipients">
                  {detail.escalation_recipients?.length ? (
                    <ul className="grid gap-1">
                      {detail.escalation_recipients.map((recipient, index) => (
                        <li key={`${recipient.subject}-${index}`}>
                          <span className="text-muted-foreground">{recipient.kind}: </span>
                          {recipientLabel(recipient)}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </NotificationDetailRow>
              </dl>
            </section>
          </div>
          <div className="flex justify-end border-t border-border px-5 py-4">
            <Button type="button" variant="outline" onClick={() => setDetail(null)}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </div>
        </Dialog>
      )}
    </section>
  );
}

function ChannelCatalog({ channels, error }: { channels: NotificationChannel[]; error: string | null }) {
  const { t } = useTranslation();
  if (error) return <ErrorState title={t("notifications.channels.unavailableTitle")}>{error}</ErrorState>;
  if (channels.length === 0) return null;
  const configuredLabel = t("notifications.channels.configured");
  const unconfiguredLabel = t("notifications.channels.unconfigured");
  const disabledLabel = t("notifications.channels.disabled");
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">{t("notifications.channels.heading")}</h2>
        <span className="text-sm text-muted-foreground">{t("notifications.channels.configuredCount", { count: channels.filter(channelReady).length })}</span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {channels.map((channel) => {
          const ready = channelReady(channel);
          const status = ready ? "configured" : channel.configured ? "disabled" : "unconfigured";
          const label = ready ? configuredLabel : channel.configured ? disabledLabel : unconfiguredLabel;
          return (
            <div key={channel.id} className="rounded-control border border-border bg-background p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{channel.label}</p>
                  <p className="truncate text-xs text-muted-foreground">{channel.category}</p>
                </div>
                <StatusBadge value={status} label={label} tone={ready ? "success" : "neutral"} />
              </div>
              <p className="mt-2 truncate text-xs text-muted-foreground" title={channel.delivery}>
                {channel.delivery}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DeliveryCount({ label, tone = "neutral" }: { label: string; tone?: "neutral" | "critical" }) {
  const { t } = useTranslation();
  return (
    <div className={`rounded-control border p-3 ${tone === "critical" ? "border-status-critical/30 bg-status-critical/10" : "border-border bg-muted/20"}`}>
      <dt className="sr-only">{t("notifications.design.deliveryStatusCount")}</dt>
      <dd className={`text-body font-semibold ${tone === "critical" ? "text-status-critical" : "text-foreground"}`}>{label}</dd>
    </div>
  );
}

function RoutingPreview({ policies, channels }: { policies: NotificationRoutingPolicy[]; channels: NotificationChannel[] }) {
  const { t } = useTranslation();
  return (
    <section aria-label={t("notifications.design.routingPreview")} className="grid gap-2 rounded-control border border-border bg-muted/20 p-4">
      <p className="text-caption font-semibold text-muted-foreground">{t("notifications.design.routingPreview")}</p>
      <ul className="grid gap-2">
        {policies.slice(0, 3).map((policy) => (
          <li key={policy.id} className="grid gap-1 text-sm sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-center sm:gap-4">
            <span className="font-medium">
              {policy.name} → {previewChannels(policy, channels)}
            </span>
            <span className="text-muted-foreground">
              {t("notifications.routing.owner")}: {policy.owner_email || policy.owner_ref || t("notifications.design.ownerMissing")}
            </span>
            <StatusBadge
              value={policyHasReadyChannel(policy, channels) ? "ready" : "unrouted"}
              label={t(policyHasReadyChannel(policy, channels) ? "notifications.design.routeReady" : "notifications.design.routeNotReady")}
              tone={policyHasReadyChannel(policy, channels) ? "success" : "critical"}
            />
          </li>
        ))}
      </ul>
      {policies.length > 3 ? (
        <p className="text-caption text-muted-foreground">{t("notifications.design.moreRules", { count: String(policies.length - 3) })}</p>
      ) : null}
    </section>
  );
}

function previewChannels(policy: NotificationRoutingPolicy, channels: NotificationChannel[]): string {
  const unique = policyChannelIDs(policy);
  if (unique.length === 0) return "—";
  return unique.map((id) => channels.find((channel) => channel.id === id)?.label || id).join(", ");
}

function policyChannelIDs(policy: NotificationRoutingPolicy): string[] {
  const severityChannels = Object.values(policy.channels_by_severity ?? {}).flatMap((value) =>
    Array.isArray(value) ? value.filter((channelID): channelID is string => typeof channelID === "string") : [],
  );
  return Array.from(new Set([...policy.default_channels, ...severityChannels]));
}

function policyHasReadyChannel(policy: NotificationRoutingPolicy, channels: NotificationChannel[]): boolean {
  const ready = new Set(channels.filter(channelReady).map((channel) => channel.id));
  return policyChannelIDs(policy).some((id) => ready.has(id));
}

function channelReady(channel: NotificationChannel): boolean {
  return channel.configured && channel.enabled !== false;
}

function channelCountLabel(t: (key: MessageKey, values?: Record<string, string | number>) => string, count: number): string {
  return count === 1 ? t("notifications.design.oneChannel") : t("notifications.design.manyChannels", { count });
}

function ruleCountLabel(t: (key: MessageKey, values?: Record<string, string | number>) => string, count: number): string {
  return count === 1 ? t("notifications.design.oneRule") : t("notifications.design.manyRules", { count });
}

function failedCountLabel(t: (key: MessageKey, values?: Record<string, string | number>) => string, count: number): string {
  return count === 1 ? t("notifications.design.oneFailed") : t("notifications.design.manyFailed", { count });
}

function ChannelAuthoring({
  form,
  busy,
  embedded = false,
  onCancel,
  onFormChange,
  onSaveChannel,
}: {
  form: ChannelFormState;
  busy: boolean;
  embedded?: boolean;
  onCancel?: () => void;
  onFormChange: (next: ChannelFormState) => void;
  onSaveChannel: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const { t } = useTranslation();
  return (
    <form
      aria-label={t("notifications.design.addFormLabel")}
      className={embedded ? "grid gap-4" : "ui-panel grid gap-4 p-comfortable"}
      onSubmit={onSaveChannel}
    >
      <div className={`flex flex-wrap items-center gap-3 ${embedded ? "justify-end" : "justify-between"}`}>
        {!embedded ? <h2 className="text-base font-semibold">{t("notifications.channels.authoringHeading")}</h2> : null}
        <StatusBadge
          value={form.enabled ? "enabled" : "disabled"}
          label={form.enabled ? t("notifications.channels.enabled") : t("notifications.channels.disabled")}
          tone={form.enabled ? "success" : "neutral"}
        />
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Field label={t("notifications.channels.type")}>
          {(control) => (
            <Select {...control} value={form.channelType} onChange={(event) => onFormChange({ ...form, channelType: event.target.value })}>
              {channelTypeOptions.map((channelType) => (
                <option key={channelType} value={channelType}>
                  {channelType}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <TextInput label={t("notifications.channels.label")} value={form.label} onChange={(value) => onFormChange({ ...form, label: value })} />
        <TextInput
          label={t("notifications.channels.endpointUrl")}
          value={form.endpointUrl}
          onChange={(value) => onFormChange({ ...form, endpointUrl: value })}
          type="url"
          required={form.enabled}
        />
        <TextInput
          label={t("notifications.channels.credentialRef")}
          value={form.credentialRef}
          onChange={(value) => onFormChange({ ...form, credentialRef: value })}
        />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <label className="inline-flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(event) => onFormChange({ ...form, enabled: event.target.checked })}
            className="h-4 w-4 rounded border-border text-brand-accent focus:ring-focus"
          />
          {t("notifications.channels.enabled")}
        </label>
        {onCancel ? (
          <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
            {t("notifications.design.cancel")}
          </Button>
        ) : null}
        <Button type="submit" className="w-fit" disabled={busy}>
          <Save className="h-4 w-4" aria-hidden="true" />
          {busy ? t("notifications.channels.saving") : t("notifications.channels.save")}
        </Button>
      </div>
    </form>
  );
}

function ChannelTestForm({
  channels,
  form,
  busy,
  result,
  onFormChange,
  onSubmit,
}: {
  channels: NotificationChannel[];
  form: TestFormState;
  busy: boolean;
  result: NotificationChannelTest | null;
  onFormChange: (next: TestFormState) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const { t } = useTranslation();
  const configured = channels.filter(channelReady);
  const selected = form.channelId || firstConfiguredChannel(channels)?.id || "";
  return (
    <form
      aria-label={t("notifications.design.testFormLabel")}
      className="grid max-w-2xl gap-4 rounded-control border border-border bg-background p-4"
      onSubmit={onSubmit}
    >
      <h2 className="text-base font-semibold">{t("notifications.routing.testHeading")}</h2>
      <div className="grid gap-3 md:grid-cols-2">
        <Field label={t("notifications.routing.channel")}>
          {(control) => (
            <Select {...control} value={selected} onChange={(event) => onFormChange({ ...form, channelId: event.target.value })}>
              {configured.length === 0 ? <option value="">{t("notifications.routing.noReadyChannels")}</option> : null}
              {configured.map((channel) => (
                <option key={channel.id} value={channel.id}>
                  {channel.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("notifications.routing.severity")}>
          {(control) => (
            <Select {...control} value={form.severity} onChange={(event) => onFormChange({ ...form, severity: event.target.value as TestSeverity })}>
              {testSeverityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <TextInput label={t("notifications.routing.testSubject")} value={form.subject} onChange={(value) => onFormChange({ ...form, subject: value })} />
        <TextInput
          label={t("notifications.routing.credentialRef")}
          value={form.credentialRef}
          onChange={(value) => onFormChange({ ...form, credentialRef: value })}
        />
      </div>
      <Button type="submit" className="w-fit" disabled={busy || !selected}>
        <Send className="h-4 w-4" aria-hidden="true" />
        {busy ? t("notifications.routing.testing") : t("notifications.routing.sendTest")}
      </Button>
      {result ? (
        <p className="text-sm text-muted-foreground">
          {result.channel_id} #{result.outbox_id} - {result.credential_ref || result.secret_handling}
        </p>
      ) : null}
    </form>
  );
}

function RoutingPolicyAuthoring({
  channels,
  policies,
  policyForm,
  policyBusy,
  routePreview,
  previewBusy,
  onPolicyFormChange,
  onSavePolicy,
  onPreviewRoute,
}: {
  channels: NotificationChannel[];
  policies: NotificationRoutingPolicy[];
  policyForm: PolicyFormState;
  policyBusy: boolean;
  routePreview: NotificationRoutingPreview | null;
  previewBusy: boolean;
  onPolicyFormChange: (next: PolicyFormState) => void;
  onSavePolicy: (event: FormEvent<HTMLFormElement>) => void;
  onPreviewRoute: () => void;
}) {
  const { t } = useTranslation();
  const configured = channels.filter(channelReady);
  const readyChannelIDs = new Set(configured.map((channel) => channel.id));
  const requestedChannelIDs = Array.from(
    new Set([
      ...splitChannels(policyForm.defaultChannels),
      ...splitChannels(policyForm.criticalChannels),
      ...splitChannels(policyForm.warningChannels),
      ...splitChannels(policyForm.lowChannels),
    ]),
  );
  const requestedChannelsReady = requestedChannelIDs.length > 0 && requestedChannelIDs.every((channelID) => readyChannelIDs.has(channelID));
  const scopeReady = policyForm.scopeKind === "manual" || policyForm.scopeKind === "global" || policyForm.scopeRef.trim().length > 0;
  const policyReady = policyForm.name.trim().length > 0 && scopeReady && requestedChannelsReady;
  const routingReadiness =
    configured.length === 0
      ? t("notifications.routing.readinessNoChannels")
      : requestedChannelIDs.length === 0
        ? t("notifications.routing.readinessNoSelection")
        : !requestedChannelsReady
          ? t("notifications.routing.readinessUnknownSelection")
          : t("notifications.routing.readinessReady");
  return (
    <div className="grid gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1">
          <h2 className="text-base font-semibold">{t("notifications.routing.heading")}</h2>
          <p className="max-w-3xl text-sm text-muted-foreground">{t("notifications.routing.description")}</p>
        </div>
      </div>

      <div className="grid gap-5">
        <form aria-label={t("notifications.design.routingFormLabel")} className="grid gap-4" onSubmit={onSavePolicy}>
          <div className="grid gap-3 md:grid-cols-2">
            <TextInput
              label={t("notifications.routing.name")}
              value={policyForm.name}
              onChange={(value) => onPolicyFormChange({ ...policyForm, name: value })}
              placeholder={t("notifications.routing.namePlaceholder")}
              required
            />
            <Field label={t("notifications.routing.ruleLevel")}>
              {(control) => (
                <Select
                  {...control}
                  value={policyForm.scopeKind}
                  onChange={(event) => {
                    const scopeKind = event.target.value as PolicyFormState["scopeKind"];
                    onPolicyFormChange({ ...policyForm, scopeKind, scopeRef: scopeKind === "workspace" ? "certificate-lifecycle" : "" });
                  }}
                >
                  <option value="global">{t("notifications.routing.levelGlobal")}</option>
                  <option value="workspace">{t("notifications.routing.levelWorkspace")}</option>
                  <option value="owner">{t("notifications.routing.levelOwner")}</option>
                  <option value="asset">{t("notifications.routing.levelAsset")}</option>
                  <option value="manual">{t("notifications.routing.levelManual")}</option>
                </Select>
              )}
            </Field>
            {policyForm.scopeKind === "workspace" ? (
              <Field label={t("notifications.routing.workspace")}>
                {(control) => (
                  <Select {...control} value={policyForm.scopeRef} onChange={(event) => onPolicyFormChange({ ...policyForm, scopeRef: event.target.value })}>
                    <option value="certificate-lifecycle">{t("nav.module.certificates")}</option>
                    <option value="machine-workload-trust">{t("nav.space.workload")}</option>
                    <option value="secrets-access">{t("nav.module.secrets")}</option>
                    <option value="software-trust">{t("nav.space.posture")}</option>
                    <option value="trust-operations">{t("nav.space.platform")}</option>
                  </Select>
                )}
              </Field>
            ) : policyForm.scopeKind === "owner" || policyForm.scopeKind === "asset" ? (
              <TextInput
                label={t(policyForm.scopeKind === "owner" ? "notifications.routing.ownerRoute" : "notifications.routing.assetRoute")}
                value={policyForm.scopeRef}
                onChange={(value) => onPolicyFormChange({ ...policyForm, scopeRef: value })}
                required
              />
            ) : null}
            <TextInput
              label={t("notifications.routing.ownerEmail")}
              value={policyForm.ownerEmail}
              onChange={(value) => onPolicyFormChange({ ...policyForm, ownerEmail: value })}
              type="email"
            />
            <TextInput
              label={t("notifications.routing.ownerRef")}
              value={policyForm.ownerRef}
              onChange={(value) => onPolicyFormChange({ ...policyForm, ownerRef: value })}
              placeholder={t("notifications.routing.ownerRefPlaceholder")}
            />
            <Field label={t("notifications.routing.digestInterval")}>
              {(control) => (
                <Select
                  {...control}
                  value={policyForm.digestInterval}
                  onChange={(event) => onPolicyFormChange({ ...policyForm, digestInterval: event.target.value })}
                >
                  {digestOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {t(option.labelKey)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <TextInput
              label={t("notifications.routing.defaultChannels")}
              value={policyForm.defaultChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, defaultChannels: value })}
              placeholder={t("notifications.routing.channelIDsPlaceholder")}
              describedBy="notification-routing-readiness"
            />
            <TextInput
              label={t("notifications.routing.criticalChannels")}
              value={policyForm.criticalChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, criticalChannels: value })}
              placeholder={t("notifications.routing.channelIDsPlaceholder")}
              describedBy="notification-routing-readiness"
            />
            <TextInput
              label={t("notifications.routing.warningChannels")}
              value={policyForm.warningChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, warningChannels: value })}
              placeholder={t("notifications.routing.channelIDsPlaceholder")}
              describedBy="notification-routing-readiness"
            />
            <TextInput
              label={t("notifications.routing.lowChannels")}
              value={policyForm.lowChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, lowChannels: value })}
              placeholder={t("notifications.routing.channelIDsPlaceholder")}
              describedBy="notification-routing-readiness"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {configured.map((channel) => (
              <StatusBadge key={channel.id} value={channel.id} label={`${channel.label} — ${channel.id}`} tone="success" />
            ))}
          </div>
          <p id="notification-routing-readiness" className="text-sm text-muted-foreground" role="status">
            {routingReadiness}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" className="w-fit" aria-describedby="notification-routing-readiness" disabled={policyBusy || !policyReady}>
              <Save className="h-4 w-4" aria-hidden="true" />
              {policyBusy ? t("notifications.routing.saving") : t("notifications.routing.save")}
            </Button>
            <Button type="button" variant="outline" disabled={previewBusy || !scopeReady} onClick={onPreviewRoute}>
              {previewBusy ? t("notifications.routing.previewing") : t("notifications.routing.preview")}
            </Button>
          </div>
          {routePreview ? (
            <div className="grid gap-2 rounded-control border border-border bg-muted/20 p-3" role="status">
              <p className="text-sm font-medium">{routePreview.explanation}</p>
              <p className="text-sm text-muted-foreground">
                {t("notifications.routing.resolution")}: {(routePreview.resolution_order ?? []).join(" → ")}
              </p>
              <p className="text-sm text-muted-foreground">
                {t("notifications.routing.channelsLabel")}: {(routePreview.effective_channels ?? []).join(", ") || t("notifications.routing.none")} ·{" "}
                {t(routePreview.delivery_ready ? "notifications.routing.previewReady" : "notifications.routing.previewNotReady")}
              </p>
            </div>
          ) : null}
        </form>
      </div>

      <div className="grid gap-2">
        {policies.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("notifications.routing.noPolicies")}</p>
        ) : (
          policies.map((policy) => (
            <div key={policy.id} className="grid gap-2 rounded-control border border-border bg-background p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{policy.name}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    {policy.scope_kind}
                    {policy.scope_ref ? t("source.value1.550e636eaf", { value1: policy.scope_ref }) : ""} · {policy.id}
                  </p>
                </div>
                <StatusBadge value="configured" label={joinChannels(policy.default_channels)} tone="neutral" />
              </div>
              <div className="grid gap-2 text-sm text-muted-foreground md:grid-cols-3">
                <span>
                  {t("notifications.routing.owner")}: {policy.owner_email || policy.owner_ref || "-"}
                </span>
                <span>
                  {testSeverityOptions[0]}: {joinChannels(policyChannels(policy, "critical")) || "-"}
                </span>
                <span>
                  {t("notifications.routing.nextDigest")}: {formatDateTime(policy.digest_preview.next_run_at)}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function TextInput({
  label,
  value,
  onChange,
  type = "text",
  required = false,
  placeholder,
  describedBy,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  required?: boolean;
  placeholder?: string;
  describedBy?: string;
}) {
  return (
    <Field label={label} required={required}>
      {(control) => (
        <Input
          {...control}
          type={type}
          value={value}
          required={required}
          placeholder={placeholder}
          aria-describedby={[control["aria-describedby"], describedBy].filter(Boolean).join(" ") || undefined}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
    </Field>
  );
}

function NotificationsTable({
  busyId,
  notifications,
  onMarkRead,
  onRequeue,
  onDetails,
}: {
  notifications: Notification[];
  busyId: string | null;
  onMarkRead: (notification: Notification) => void;
  onRequeue: (notification: Notification) => void;
  onDetails: (notification: Notification) => void;
}) {
  const { t } = useTranslation();
  const columns: DataGridColumn<Notification>[] = [
    {
      id: "notification",
      header: "Notification",
      cell: (notification) => (
        <div className="grid gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm">{notification.id}</span>
            <span className="font-medium">{notificationSubject(notification)}</span>
          </div>
          <span className="text-sm text-muted-foreground">{notificationType(notification)}</span>
          {notification.detail && <span className="max-w-[28rem] truncate text-sm text-muted-foreground">{notification.detail}</span>}
        </div>
      ),
    },
    {
      id: "destination",
      header: "Destination",
      cell: (notification) => (
        <div className="grid gap-1">
          <span>{notification.destination}</span>
          {notification.routing_policy_id && <span className="font-mono text-xs text-muted-foreground">{notification.routing_policy_id}</span>}
        </div>
      ),
    },
    {
      id: "escalation",
      header: "Escalation",
      cell: (notification) => <EscalationSummary notification={notification} />,
    },
    {
      id: "status",
      header: "Status",
      cell: (notification) => <StatusBadge value={notification.status} label={notification.status} tone={statusTone(notification.status)} />,
    },
    { id: "attempts", header: "Attempts", cell: (notification) => `${notification.attempts} / ${maxNotificationAttempts}` },
    {
      id: "lastError",
      header: "Last error",
      cell: (notification) =>
        notification.last_error ? (
          <span className="max-w-[18rem] truncate text-risk-critical" title={notification.last_error}>
            {notification.last_error}
          </span>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    { id: "created", header: "Created", cell: (notification) => formatDateTime(notification.created_at) },
    {
      id: "actions",
      header: t("notifications.table.actions"),
      cell: (notification) => (
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onDetails(notification)}
            aria-label={translateNow("source.view.details.for.notification.value1.786c365358", { value1: notification.id })}
          >
            <span>{t("parity.details_dc3dec")}</span>
          </Button>
          {isUnread(notification) && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busyId === notification.id}
              onClick={() => onMarkRead(notification)}
              aria-label={t("notifications.action.markReadAria", { id: notification.id })}
            >
              <span>{t("notifications.action.markRead")}</span>
            </Button>
          )}
          {notification.status === "dead" && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busyId === notification.id}
              onClick={() => onRequeue(notification)}
              aria-label={t("notifications.action.requeueAria", { id: notification.id })}
            >
              <span>{t("notifications.action.requeue")}</span>
            </Button>
          )}
        </div>
      ),
    },
  ];
  return (
    <DataGrid
      ariaLabel={t("notifications.table.ariaLabel")}
      rows={notifications}
      columns={columns}
      getRowId={(notification) => notification.id}
      state="ready"
    />
  );
}

function EscalationSummary({ notification }: { notification: Notification }) {
  const owner = notification.owner_email || notification.owner_name || notification.owner_id;
  const approvers = (notification.escalation_recipients ?? [])
    .filter((recipient) => recipient.kind === "approver")
    .map(recipientLabel)
    .filter(Boolean);
  if (!owner && approvers.length === 0) return <span className="text-muted-foreground">-</span>;
  return (
    <div className="grid max-w-[18rem] gap-1 text-sm">
      {owner && (
        <span className="truncate" title={owner}>
          {translateNow("source.owner.9a638cfefd")} {owner}
        </span>
      )}
      {approvers.length > 0 && (
        <span className="truncate text-muted-foreground" title={approvers.join(", ")}>
          {translateNow("source.approvers.99f86511e2")} {approvers.join(", ")}
        </span>
      )}
    </div>
  );
}

function recipientLabel(recipient: NonNullable<Notification["escalation_recipients"]>[number]): string {
  return recipient.email || recipient.display_name || recipient.subject;
}

function splitChannels(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinChannels(value: string[] | undefined): string {
  return (value ?? []).join(", ");
}

function upsertPolicy(current: NotificationRoutingPolicy[], next: NotificationRoutingPolicy): NotificationRoutingPolicy[] {
  const found = current.some((policy) => policy.id === next.id);
  if (!found) return [...current, next].sort((a, b) => a.name.localeCompare(b.name));
  return current.map((policy) => (policy.id === next.id ? next : policy)).sort((a, b) => a.name.localeCompare(b.name));
}

function upsertChannel(current: NotificationChannel[], next: NotificationChannel): NotificationChannel[] {
  const found = current.some((channel) => channel.id === next.id);
  if (!found) return [...current, next].sort((a, b) => a.label.localeCompare(b.label));
  return current.map((channel) => (channel.id === next.id ? next : channel)).sort((a, b) => a.label.localeCompare(b.label));
}

function updateNotificationCache(queryClient: QueryClient, update: (notification: Notification) => Notification) {
  queryClient.setQueryData<{ items: Notification[] }>(notificationQueryKey, (current) => ({
    ...current,
    items: (current?.items ?? []).map(update),
  }));
}

function firstConfiguredChannel(channels: NotificationChannel[]): NotificationChannel | undefined {
  return channels.find(channelReady);
}

function policyChannels(policy: NotificationRoutingPolicy, severity: string): string[] {
  const matrix = policy.channels_by_severity;
  const value = matrix && typeof matrix === "object" ? matrix[severity] : undefined;
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function isUnread(notification: Notification): boolean {
  return notification.status === "pending" || (notification.status === "sent" && !notification.read_at);
}

function notificationType(notification: Notification): string {
  return notification.kind || notification.destination;
}

function notificationSubject(notification: Notification): string {
  return notification.subject || notification.certificate_id || notification.destination;
}

function statusTone(status: NotificationStatus): StatusTone {
  if (status === "dead") return "critical";
  if (status === "pending") return "warning";
  if (status === "sent") return "success";
  return "neutral";
}

function severityTone(severity: NonNullable<Notification["severity"]>): StatusTone {
  if (severity === "critical") return "critical";
  if (severity === "warning") return "warning";
  if (severity === "informational") return "info";
  return "low";
}

function NotificationDetailRow({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError && err.body) {
    try {
      const parsed = JSON.parse(err.body) as { detail?: string; title?: string };
      return parsed.detail || parsed.title || fallback;
    } catch {
      return err.body;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
