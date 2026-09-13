import type { Notification } from "@/lib/api";

export function meaningfulAttention(notifications: Notification[]): Notification[] {
  const byRisk = new Map<string, Notification>();
  for (const notification of notifications) {
    const meaningful =
      notification.status === "dead" ||
      ((notification.severity === "critical" || notification.severity === "warning") && notification.status !== "read" && !notification.read_at);
    if (!meaningful) continue;
    // A display name cannot identify a risk: a replacement identity can reuse
    // the same hostname, and one certificate can have different kinds of alert.
    // Distinct operations remain distinct even when they refer to one leaf.
    // Otherwise collapse repeated alerts for the same tenant, certificate and kind.
    // Without that stable identity, preserve the individual notification.
    const key = notification.operation_id
      ? JSON.stringify([notification.tenant_id, "operation", notification.operation_id])
      : notification.certificate_id
        ? JSON.stringify([notification.tenant_id, notification.certificate_id, notification.kind || notification.destination])
        : `notification:${notification.id}`;
    const current = byRisk.get(key);
    if (!current || priority(notification) > priority(current)) byRisk.set(key, notification);
  }
  return [...byRisk.values()].sort(
    (left, right) => priority(right) - priority(left) || String(left.not_after || left.created_at).localeCompare(String(right.not_after || right.created_at)),
  );
}

function priority(notification: Notification): number {
  if (notification.status === "dead") return 4;
  if (notification.severity === "critical") return 3;
  if (notification.severity === "warning") return 2;
  return 1;
}
