import type { Notification } from "@/lib/api";

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
