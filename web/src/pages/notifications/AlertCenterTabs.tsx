import { BellRing, History, RadioTower, RotateCcw, Route, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import type { Notification } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { StatusBadge } from "@/components/StatusBadge";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { Eyebrow } from "@/components/typography";

export type AlertCenterView = "attention" | "failures" | "history" | "routing" | "channels";

const views: Array<{
  id: AlertCenterView;
  key:
    | "notifications.center.attention"
    | "notifications.center.failures"
    | "notifications.center.history"
    | "notifications.center.routing"
    | "notifications.center.channels";
}> = [
  { id: "attention", key: "notifications.center.attention" },
  { id: "failures", key: "notifications.center.failures" },
  { id: "history", key: "notifications.center.history" },
  { id: "routing", key: "notifications.center.routing" },
  { id: "channels", key: "notifications.center.channels" },
];

export function AlertCenterTabs({
  active,
  onChange,
  failureCount,
  attentionCount,
}: {
  active: AlertCenterView;
  onChange: (view: AlertCenterView) => void;
  failureCount: number;
  attentionCount: number;
}) {
  const { t } = useTranslation();
  return (
    <div role="tablist" aria-label={t("notifications.center.views")} className="flex min-w-0 gap-1 overflow-x-auto border-b border-border">
      {views.map((view) => {
        const count = view.id === "attention" ? attentionCount : view.id === "failures" ? failureCount : 0;
        return (
          <button
            key={view.id}
            type="button"
            role="tab"
            aria-selected={active === view.id}
            aria-controls={`alert-center-panel-${view.id}`}
            onClick={() => onChange(view.id)}
            className={`min-h-11 whitespace-nowrap border-b-2 px-3 text-sm font-medium transition-colors ${active === view.id ? "border-brand-accent text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
          >
            {count > 0 ? t("notifications.center.tabWithCount", { label: t(view.key), count }) : t(view.key)}
          </button>
        );
      })}
    </div>
  );
}

export function NeedsAttention({
  notifications,
  busyId,
  onDetails,
  onRequeue,
}: {
  notifications: Notification[];
  busyId: string | null;
  onDetails: (notification: Notification) => void;
  onRequeue: (notification: Notification) => void;
}) {
  const { t } = useTranslation();
  const urgent = meaningfulAttention(notifications);
  if (urgent.length === 0) {
    return <EmptyState title={t("notifications.center.clearTitle")}>{t("notifications.center.clearBody")}</EmptyState>;
  }
  return (
    <section aria-labelledby="attention-chain-heading" className="grid min-w-0 max-w-full gap-3">
      <div className="grid gap-1">
        <h2 id="attention-chain-heading" className="text-title font-semibold">
          {t("notifications.center.attentionCount", { count: urgent.length })}
        </h2>
        <p className="max-w-3xl text-sm text-muted-foreground">{t("notifications.center.attentionHelp")}</p>
      </div>
      <div className="grid min-w-0 max-w-full gap-3">
        {urgent.map((notification) => (
          <article key={notification.id} className="min-w-0 max-w-full rounded-panel border border-border bg-card p-comfortable shadow-none">
            <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.3fr)_repeat(3,minmax(9rem,0.7fr))_auto] xl:items-center">
              <div className="grid min-w-0 gap-2">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  {notification.status === "dead" ? (
                    <TriangleAlert className="h-4 w-4 text-status-critical" aria-hidden="true" />
                  ) : (
                    <BellRing className="h-4 w-4 text-status-warning" aria-hidden="true" />
                  )}
                  <h3 className="min-w-0 [overflow-wrap:anywhere] font-semibold">
                    {notification.subject || notification.certificate_id || notification.destination}
                  </h3>
                  <StatusBadge
                    value={notification.severity || notification.status}
                    label={notification.severity || notification.status}
                    tone={notification.status === "dead" || notification.severity === "critical" ? "critical" : "warning"}
                  />
                </div>
                <p className="min-w-0 [overflow-wrap:anywhere] text-sm text-muted-foreground">
                  {notification.detail || t("notifications.center.defaultImpact")}
                </p>
              </div>
              <Fact label={t("notifications.center.deadline")} value={deadlineLabel(notification, t)} />
              <Fact
                label={t("notifications.center.owner")}
                value={notification.owner_name || notification.owner_email || notification.owner_id || t("notifications.center.ownerMissing")}
              />
              <Fact label={t("notifications.center.automation")} value={automationLabel(notification, t)} />
              <div className="flex flex-wrap gap-2 xl:justify-end">
                <Button type="button" size="sm" variant="outline" onClick={() => onDetails(notification)}>
                  {t("notifications.center.review")}
                </Button>
                {notification.status === "dead" ? (
                  <Button type="button" size="sm" disabled={busyId === notification.id} onClick={() => onRequeue(notification)}>
                    <RotateCcw className="h-4 w-4" aria-hidden="true" />
                    {t("notifications.center.retry")}
                  </Button>
                ) : null}
              </div>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export function AlertCenterPanel({ view, children }: { view: AlertCenterView; children: ReactNode }) {
  return (
    <div id={`alert-center-panel-${view}`} role="tabpanel" className="pt-4">
      {children}
    </div>
  );
}

export function ViewIntroduction({ view }: { view: "failures" | "history" | "routing" | "channels" }) {
  const { t } = useTranslation();
  const icons = { failures: TriangleAlert, history: History, routing: Route, channels: RadioTower };
  const Icon = icons[view];
  return (
    <div className="flex max-w-3xl gap-3">
      <Icon className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <p className="text-sm text-muted-foreground">{t(`notifications.center.${view}Help`)}</p>
    </div>
  );
}

export function meaningfulAttention(notifications: Notification[]): Notification[] {
  const bySubject = new Map<string, Notification>();
  for (const notification of notifications) {
    const meaningful =
      notification.status === "dead" ||
      ((notification.severity === "critical" || notification.severity === "warning") && notification.status !== "read" && !notification.read_at);
    if (!meaningful) continue;
    const key = notification.certificate_id || notification.subject || notification.id;
    const current = bySubject.get(key);
    if (!current || priority(notification) > priority(current)) bySubject.set(key, notification);
  }
  return [...bySubject.values()].sort(
    (left, right) => priority(right) - priority(left) || String(left.not_after || left.created_at).localeCompare(String(right.not_after || right.created_at)),
  );
}

function priority(notification: Notification): number {
  if (notification.status === "dead") return 4;
  if (notification.severity === "critical") return 3;
  if (notification.severity === "warning") return 2;
  return 1;
}

function deadlineLabel(notification: Notification, t: (key: "notifications.center.noDeadline") => string): string {
  if (!notification.not_after) return t("notifications.center.noDeadline");
  return formatDateTime(notification.not_after);
}

function automationLabel(
  notification: Notification,
  t: (
    key:
      | "notifications.center.failedAutomation"
      | "notifications.center.queuedAutomation"
      | "notifications.center.acceptedAutomation"
      | "notifications.center.recordedAutomation",
  ) => string,
): string {
  if (notification.status === "dead") return t("notifications.center.failedAutomation");
  if (notification.status === "pending") return t("notifications.center.queuedAutomation");
  if (notification.status === "sent") return t("notifications.center.acceptedAutomation");
  return t("notifications.center.recordedAutomation");
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <dl className="grid min-w-0 gap-1 text-sm">
      <Eyebrow as="dt">{label}</Eyebrow>
      <dd className="min-w-0 [overflow-wrap:anywhere] font-medium">{value}</dd>
    </dl>
  );
}
