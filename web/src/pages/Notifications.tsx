import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { api, ApiError, type Notification } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

type ActiveTab = "all" | "dead";
type NotificationStatus = Notification["status"];
type Notice = { title: string; detail?: string };

const maxNotificationAttempts = 10;

const statusOptions: Array<{ value: "" | NotificationStatus; label: string }> = [
  { value: "", label: "All statuses" },
  { value: "pending", label: "pending" },
  { value: "sent", label: "sent" },
  { value: "read", label: "read" },
  { value: "dead", label: "dead" },
];

export function Notifications() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<ActiveTab>("all");
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<Notice | null>(null);
  const [typeFilter, setTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | NotificationStatus>("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const result = await api.notifications(activeTab === "dead" ? { limit: 100, status: "dead" } : { limit: 100 });
      setNotifications(result.items ?? []);
    } catch (err) {
      setNotifications([]);
      setError({ title: "Notifications unavailable", detail: errorText(err, "Could not load notifications") });
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

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
      toast({ kind: "success", title: "Notification marked read", description: notificationSubject(notification) });
    } catch (err) {
      setNotifications(snapshot);
      setError({ title: "Mark read failed", detail: errorText(err, "Could not mark notification read") });
      toast({ kind: "error", title: "Mark read failed", description: errorText(err, "Could not mark notification read") });
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
      toast({ kind: "success", title: "Notification requeued", description: notificationSubject(notification) });
    } catch (err) {
      setError({ title: "Requeue failed", detail: errorText(err, "Could not requeue notification") });
      toast({ kind: "error", title: "Requeue failed", description: errorText(err, "Could not requeue notification") });
    } finally {
      setBusyId(null);
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

      <div className="ui-panel grid gap-3 p-comfortable lg:grid-cols-[auto_minmax(12rem,16rem)_minmax(12rem,16rem)_1fr]">
        <div role="tablist" aria-label="Notification queues" className="inline-flex h-10 w-fit overflow-hidden rounded-control border border-border">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "all"}
            className={tabClass(activeTab === "all")}
            onClick={() => setActiveTab("all")}
          >
            All
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "dead"}
            className={tabClass(activeTab === "dead")}
            onClick={() => setActiveTab("dead")}
          >
            Dead-letter
          </button>
        </div>
        <label className="grid gap-2 text-sm font-medium">
          Type filter
          <select
            aria-label="Type filter"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            <option value="">All types</option>
            {typeOptions.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-2 text-sm font-medium">
          Status filter
          <select
            aria-label="Status filter"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value as "" | NotificationStatus)}
            className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
          >
            {statusOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-end justify-between gap-3 text-sm text-muted-foreground">
          <span>{filteredNotifications.length} notifications</span>
          <span>{unreadCount} unread</span>
        </div>
      </div>

      {loading ? (
        <LoadingState>Loading notifications...</LoadingState>
      ) : filteredNotifications.length === 0 ? (
        <EmptyState title="No notifications found">Adjust filters or refresh the inbox.</EmptyState>
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
      header: "Actions",
      cell: (notification) => (
        <div className="flex flex-wrap gap-2">
          {isUnread(notification) && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busyId === notification.id}
              onClick={() => onMarkRead(notification)}
              aria-label={`Mark notification ${notification.id} read`}
            >
              <span>Mark read</span>
            </Button>
          )}
          {notification.status === "dead" && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busyId === notification.id}
              onClick={() => onRequeue(notification)}
              aria-label={`Requeue notification ${notification.id}`}
            >
              <span>Requeue</span>
            </Button>
          )}
        </div>
      ),
    },
  ];
  return <DataGrid ariaLabel="Notifications inbox" rows={notifications} columns={columns} getRowId={(notification) => notification.id} state="ready" />;
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
