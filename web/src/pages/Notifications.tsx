import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { RefreshCw, Save, Send } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api, ApiError, type Notification, type NotificationChannel, type NotificationChannelTest, type NotificationRoutingPolicy } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

type ActiveTab = "all" | "dead";
type NotificationStatus = Notification["status"];
type TestSeverity = "low" | "informational" | "warning" | "critical";
type Notice = { title: string; detail?: string };
type PolicyFormState = {
  name: string;
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
  name: "Expiry escalation",
  ownerRef: "team/platform-security",
  ownerEmail: "",
  digestInterval: "86400",
  defaultChannels: "email",
  criticalChannels: "slack, webhook",
  warningChannels: "slack",
  lowChannels: "email",
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

export function Notifications() {
  const { toast } = useToast();
  const { t } = useTranslation();
  const channelLoadError = t("notifications.channels.loadError");
  const notificationUnavailable = t("notifications.error.unavailable");
  const notificationLoadError = t("notifications.error.loadFailed");
  const markReadFailed = t("notifications.action.markReadFailed");
  const markReadLoadFailed = t("notifications.action.markReadLoadFailed");
  const requeueFailed = t("notifications.action.requeueFailed");
  const requeueLoadFailed = t("notifications.action.requeueLoadFailed");
  const [activeTab, setActiveTab] = useState<ActiveTab>("all");
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<Notice | null>(null);
  const [channelError, setChannelError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | NotificationStatus>("");
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [policies, setPolicies] = useState<NotificationRoutingPolicy[]>([]);
  const [channelForm, setChannelForm] = useState<ChannelFormState>(initialChannelForm);
  const [policyForm, setPolicyForm] = useState<PolicyFormState>(initialPolicyForm);
  const [testForm, setTestForm] = useState<TestFormState>(initialTestForm);
  const [channelBusy, setChannelBusy] = useState(false);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<NotificationChannelTest | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setChannelError(null);
    try {
      const [result, channelResult, policyResult] = await Promise.all([
        api.notifications(activeTab === "dead" ? { limit: 100, status: "dead" } : { limit: 100 }),
        api.notificationChannels(),
        api.notificationRoutingPolicies(),
      ]);
      setNotifications(result.items ?? []);
      setChannels(channelResult.items ?? []);
      setPolicies(policyResult.items ?? []);
    } catch (err) {
      setNotifications([]);
      setPolicies([]);
      setError({ title: notificationUnavailable, detail: errorText(err, notificationLoadError) });
      setChannelError(errorText(err, channelLoadError));
    } finally {
      setLoading(false);
    }
  }, [activeTab, channelLoadError, notificationLoadError, notificationUnavailable]);

  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);

  useEffect(() => {
    const id = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(id);
  }, [load]);

  const typeOptions = useMemo(() => Array.from(new Set(notifications.map(notificationType))).sort(), [notifications]);
  const filteredNotifications = useMemo(
    () =>
      notifications.filter((notification) => {
        if (typeFilter && notificationType(notification) !== typeFilter) return false;
        if (statusFilter && notification.status !== statusFilter) return false;
        return true;
      }),
    [notifications, statusFilter, typeFilter],
  );
  const unreadCount = filteredNotifications.filter(isUnread).length;

  async function markRead(notification: Notification) {
    const snapshot = notifications;
    setBusyId(notification.id);
    setError(null);
    setNotifications((current) =>
      current.map((candidate) => (candidate.id === notification.id ? { ...candidate, status: "read", read_at: new Date().toISOString() } : candidate)),
    );
    try {
      const updated = await api.markNotificationRead(notification.id);
      setNotifications((current) => current.map((candidate) => (candidate.id === notification.id ? updated : candidate)));
      toast({ kind: "success", title: t("notifications.action.markedRead"), description: notificationSubject(notification) });
    } catch (err) {
      setNotifications(snapshot);
      setError({ title: markReadFailed, detail: errorText(err, markReadLoadFailed) });
      toast({ kind: "error", title: markReadFailed, description: errorText(err, markReadLoadFailed) });
    } finally {
      setBusyId(null);
    }
  }

  async function requeue(notification: Notification) {
    setBusyId(notification.id);
    setError(null);
    try {
      const updated = await api.requeueNotification(notification.id);
      setNotifications((current) => current.map((candidate) => (candidate.id === notification.id ? updated : candidate)));
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
      setPolicies((current) => upsertPolicy(current, created));
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
      setChannels((current) => upsertChannel(current, saved));
      setChannelForm((current) => ({ ...current, credentialRef: "" }));
      toast({ kind: "success", title: t("notifications.channels.saved"), description: saved.label });
    } catch (err) {
      const detail = errorText(err, t("notifications.channels.saveError"));
      setError({ title: t("notifications.channels.saveError"), detail });
      toast({ kind: "error", title: t("notifications.channels.saveError"), description: detail });
    } finally {
      setChannelBusy(false);
    }
  }

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

  return (
    <section aria-labelledby="notifications-heading" className="grid gap-6">
      <PageHeader
        title="Notifications"
        titleId="notifications-heading"
        description="Inbox for operator alerts, delivery failures, and dead-letter triage."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {error && <ErrorState title={error.title}>{error.detail}</ErrorState>}

      <ChannelCatalog channels={channels} error={channelError} />

      <ChannelAuthoring form={channelForm} busy={channelBusy} onFormChange={setChannelForm} onSaveChannel={(event) => void saveChannel(event)} />

      <RoutingPolicyAuthoring
        channels={channels}
        policies={policies}
        policyForm={policyForm}
        testForm={testForm}
        policyBusy={policyBusy}
        testBusy={testBusy}
        testResult={testResult}
        onPolicyFormChange={setPolicyForm}
        onTestFormChange={setTestForm}
        onSavePolicy={(event) => void savePolicy(event)}
        onTestChannel={(event) => void testChannel(event)}
      />

      <div className="ui-panel grid gap-3 p-comfortable lg:grid-cols-[auto_minmax(12rem,16rem)_minmax(12rem,16rem)_1fr]">
        <div
          role="tablist"
          aria-label={t("notifications.queue.tablist")}
          className="inline-flex h-10 w-fit overflow-hidden rounded-control border border-border"
        >
          <button type="button" role="tab" aria-selected={activeTab === "all"} className={tabClass(activeTab === "all")} onClick={() => setActiveTab("all")}>
            {t("notifications.queue.all")}
          </button>
          <button type="button" role="tab" aria-selected={activeTab === "dead"} className={tabClass(activeTab === "dead")} onClick={() => setActiveTab("dead")}>
            {t("notifications.queue.deadLetter")}
          </button>
        </div>
        <label className="grid gap-2 text-sm font-medium">
          {t("notifications.filter.type")}
          <select
            aria-label={t("notifications.filter.type")}
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            <option value="">{t("notifications.filter.typeAll")}</option>
            {typeOptions.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-2 text-sm font-medium">
          {t("notifications.filter.status")}
          <select
            aria-label={t("notifications.filter.status")}
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value as "" | NotificationStatus)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            {statusOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {t(option.labelKey)}
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-end justify-between gap-3 text-sm text-muted-foreground">
          <span>{t("notifications.count.total", { count: filteredNotifications.length })}</span>
          <span>{t("notifications.count.unread", { count: unreadCount })}</span>
        </div>
      </div>

      {loading ? (
        <LoadingState>{t("notifications.loading")}</LoadingState>
      ) : filteredNotifications.length === 0 ? (
        <EmptyState title={t("notifications.emptyTitle")}>{t("notifications.emptyBody")}</EmptyState>
      ) : (
        <NotificationsTable
          notifications={filteredNotifications}
          busyId={busyId}
          onMarkRead={(notification) => void markRead(notification)}
          onRequeue={(notification) => void requeue(notification)}
        />
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
  return (
    <div className="ui-panel grid gap-3 p-comfortable">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">{t("notifications.channels.heading")}</h2>
        <span className="text-sm text-muted-foreground">
          {t("notifications.channels.configuredCount", { count: channels.filter((channel) => channel.configured).length })}
        </span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {channels.map((channel) => (
          <div key={channel.id} className="rounded-control border border-border bg-background p-3">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{channel.label}</p>
                <p className="truncate text-xs text-muted-foreground">{channel.category}</p>
              </div>
              <StatusBadge
                value={channel.configured ? "configured" : "unconfigured"}
                label={channel.configured ? configuredLabel : unconfiguredLabel}
                tone={channel.configured ? "success" : "neutral"}
              />
            </div>
            <p className="mt-2 truncate text-xs text-muted-foreground" title={channel.delivery}>
              {channel.delivery}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChannelAuthoring({
  form,
  busy,
  onFormChange,
  onSaveChannel,
}: {
  form: ChannelFormState;
  busy: boolean;
  onFormChange: (next: ChannelFormState) => void;
  onSaveChannel: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const { t } = useTranslation();
  return (
    <form className="ui-panel grid gap-4 p-comfortable" onSubmit={onSaveChannel}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">{t("notifications.channels.authoringHeading")}</h2>
        <StatusBadge
          value={form.enabled ? "enabled" : "disabled"}
          label={form.enabled ? t("notifications.channels.enabled") : t("notifications.channels.disabled")}
          tone={form.enabled ? "success" : "neutral"}
        />
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label className="grid gap-2 text-sm font-medium">
          {t("notifications.channels.type")}
          <select
            value={form.channelType}
            onChange={(event) => onFormChange({ ...form, channelType: event.target.value })}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            {channelTypeOptions.map((channelType) => (
              <option key={channelType} value={channelType}>
                {channelType}
              </option>
            ))}
          </select>
        </label>
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
            className="h-4 w-4 rounded border-border text-brand-accent focus:ring-brand-accent"
          />
          {t("notifications.channels.enabled")}
        </label>
        <Button type="submit" className="w-fit" disabled={busy}>
          <Save className="h-4 w-4" aria-hidden="true" />
          {busy ? t("notifications.channels.saving") : t("notifications.channels.save")}
        </Button>
      </div>
    </form>
  );
}

function RoutingPolicyAuthoring({
  channels,
  policies,
  policyForm,
  testForm,
  policyBusy,
  testBusy,
  testResult,
  onPolicyFormChange,
  onTestFormChange,
  onSavePolicy,
  onTestChannel,
}: {
  channels: NotificationChannel[];
  policies: NotificationRoutingPolicy[];
  policyForm: PolicyFormState;
  testForm: TestFormState;
  policyBusy: boolean;
  testBusy: boolean;
  testResult: NotificationChannelTest | null;
  onPolicyFormChange: (next: PolicyFormState) => void;
  onTestFormChange: (next: TestFormState) => void;
  onSavePolicy: (event: FormEvent<HTMLFormElement>) => void;
  onTestChannel: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const { t } = useTranslation();
  const configured = channels.filter((channel) => channel.configured);
  const selectedChannel = testForm.channelId || firstConfiguredChannel(channels)?.id || "";
  return (
    <div className="ui-panel grid gap-5 p-comfortable">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1">
          <h2 className="text-base font-semibold">{t("notifications.routing.heading")}</h2>
          <p className="max-w-3xl text-sm text-muted-foreground">{t("notifications.routing.description")}</p>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(20rem,0.8fr)]">
        <form className="grid gap-4" onSubmit={onSavePolicy}>
          <div className="grid gap-3 md:grid-cols-2">
            <TextInput
              label={t("notifications.routing.name")}
              value={policyForm.name}
              onChange={(value) => onPolicyFormChange({ ...policyForm, name: value })}
              required
            />
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
            />
            <label className="grid gap-2 text-sm font-medium">
              {t("notifications.routing.digestInterval")}
              <select
                value={policyForm.digestInterval}
                onChange={(event) => onPolicyFormChange({ ...policyForm, digestInterval: event.target.value })}
                className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
              >
                {digestOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {t(option.labelKey)}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <TextInput
              label={t("notifications.routing.defaultChannels")}
              value={policyForm.defaultChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, defaultChannels: value })}
            />
            <TextInput
              label={t("notifications.routing.criticalChannels")}
              value={policyForm.criticalChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, criticalChannels: value })}
            />
            <TextInput
              label={t("notifications.routing.warningChannels")}
              value={policyForm.warningChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, warningChannels: value })}
            />
            <TextInput
              label={t("notifications.routing.lowChannels")}
              value={policyForm.lowChannels}
              onChange={(value) => onPolicyFormChange({ ...policyForm, lowChannels: value })}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {configured.map((channel) => (
              <StatusBadge key={channel.id} value={channel.id} label={channel.label} tone="success" />
            ))}
          </div>
          <Button type="submit" className="w-fit" disabled={policyBusy}>
            <Save className="h-4 w-4" aria-hidden="true" />
            {policyBusy ? t("notifications.routing.saving") : t("notifications.routing.save")}
          </Button>
        </form>

        <form className="grid content-start gap-4 rounded-control border border-border bg-background p-4" onSubmit={onTestChannel}>
          <h3 className="text-sm font-semibold">{t("notifications.routing.testHeading")}</h3>
          <label className="grid gap-2 text-sm font-medium">
            {t("notifications.routing.channel")}
            <select
              value={selectedChannel}
              onChange={(event) => onTestFormChange({ ...testForm, channelId: event.target.value })}
              className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
            >
              {configured.map((channel) => (
                <option key={channel.id} value={channel.id}>
                  {channel.label}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-2 text-sm font-medium">
            {t("notifications.routing.severity")}
            <select
              value={testForm.severity}
              onChange={(event) => onTestFormChange({ ...testForm, severity: event.target.value as TestSeverity })}
              className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
            >
              {testSeverityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>
          <TextInput
            label={t("notifications.routing.testSubject")}
            value={testForm.subject}
            onChange={(value) => onTestFormChange({ ...testForm, subject: value })}
          />
          <TextInput
            label={t("notifications.routing.credentialRef")}
            value={testForm.credentialRef}
            onChange={(value) => onTestFormChange({ ...testForm, credentialRef: value })}
          />
          <Button type="submit" className="w-fit" disabled={testBusy || !selectedChannel}>
            <Send className="h-4 w-4" aria-hidden="true" />
            {testBusy ? t("notifications.routing.testing") : t("notifications.routing.sendTest")}
          </Button>
          {testResult && (
            <p className="text-sm text-muted-foreground">
              {testResult.channel_id} #{testResult.outbox_id} - {testResult.credential_ref || testResult.secret_handling}
            </p>
          )}
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
                  <p className="truncate text-xs text-muted-foreground">{policy.id}</p>
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
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  required?: boolean;
}) {
  return (
    <label className="grid gap-2 text-sm font-medium">
      {label}
      <input
        type={type}
        value={value}
        required={required}
        onChange={(event) => onChange(event.target.value)}
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
      />
    </label>
  );
}

function NotificationsTable({
  busyId,
  notifications,
  onMarkRead,
  onRequeue,
}: {
  notifications: Notification[];
  busyId: string | null;
  onMarkRead: (notification: Notification) => void;
  onRequeue: (notification: Notification) => void;
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
          Owner: {owner}
        </span>
      )}
      {approvers.length > 0 && (
        <span className="truncate text-muted-foreground" title={approvers.join(", ")}>
          Approvers: {approvers.join(", ")}
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

function firstConfiguredChannel(channels: NotificationChannel[]): NotificationChannel | undefined {
  return channels.find((channel) => channel.configured);
}

function policyChannels(policy: NotificationRoutingPolicy, severity: string): string[] {
  const matrix = policy.channels_by_severity;
  const value = matrix && typeof matrix === "object" ? matrix[severity] : undefined;
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function tabClass(active: boolean): string {
  return active ? "bg-brand-accent px-4 text-sm font-medium text-white" : "bg-background px-4 text-sm text-muted-foreground hover:bg-muted/60";
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
