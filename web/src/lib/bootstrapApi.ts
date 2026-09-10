import { createPreviewAwareApi, req } from "./apiTransport";
import type { Api, Me, AuthMethods, EditionsInfo, CapabilityView, NotificationList, Notification } from "./api";

// Only the endpoints needed before a customer route loads. The full client
// reuses these wrapped function objects instead of owning a second transport.
export type BootstrapApi = Pick<Api, "me" | "authMethods" | "logout" | "capabilities" | "editions" | "notifications">;

export const bootstrapApi: BootstrapApi = createPreviewAwareApi<BootstrapApi>({
  me: () => req<Me>("/auth/me"),
  authMethods: () => req<AuthMethods>("/auth/methods"),
  logout: () => req<void>("/auth/logout", { method: "POST" }),
  capabilities: () => req<CapabilityView>("/api/v1/capabilities"),
  editions: () => req<EditionsInfo>("/api/v1/editions"),
  notifications: (options) => req<NotificationList>(`/api/v1/notifications${notificationQueryString(options)}`),
});

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";

function notificationQueryString(options?: { limit?: number; cursor?: string; status?: Notification["status"] }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.status) qs.set("status", options.status);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}
