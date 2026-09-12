import { AlertTriangle, CircleSlash2 } from "lucide-react";
import { useLocation } from "react-router-dom";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import {
  capabilityLimitationReason,
  capabilitySurfaceState,
  summarizeCapabilities,
  useCapabilities,
  type CapabilityExecutionPosture,
  type CapabilitySurfaceState,
} from "@/lib/capabilities";
import type { CapabilityViewItem } from "@/lib/api-types.gen";
import type { CanonicalCapabilityID } from "@/lib/feature-contracts.gen";
import { featureIdsForPath } from "@/lib/navigation";
import { cn } from "@/lib/utils";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";

function stateLabel(state: CapabilitySurfaceState, t: I18nContextValue["t"]): string {
  switch (state) {
    case "ready":
      return t("capabilities.state.ready");
    case "limited":
      return t("capabilities.state.limited");
    case "permission_blocked":
      return t("capabilities.state.permissionBlocked");
    case "unavailable":
      return t("capabilities.state.unavailable");
    case "unknown":
      return t("capabilities.state.unknown");
  }
}

function itemReason(item: CapabilityViewItem, state: CapabilitySurfaceState, t: I18nContextValue["t"]): string {
  const exact = capabilityLimitationReason(item);
  if (exact) return exact;
  if (item.runtime_state === "catalog_only") return t("capabilities.reason.catalogOnly");
  if (item.runtime_state === "unavailable") return t("capabilities.reason.notAttached");
  if (state === "permission_blocked") return t("capabilities.reason.permissionBlocked");
  if (state === "limited") return t("capabilities.reason.partial");
  return t("capabilities.reason.unknown");
}

/** One explanation vocabulary for every exact-action preflight. Server detail
 * wins when it is present; the fallbacks keep unknown and denied distinct. */
export function capabilityExecutionReason(action: CapabilityExecutionPosture, t: I18nContextValue["t"]): string {
  if (action.checking) return t("capabilities.action.checking");
  if (action.unavailable?.detail) return action.unavailable.detail;
  if (action.state === "denied") return t("capabilities.action.denied");
  if (action.state === "unknown") return t("capabilities.action.unknown");
  return t("capabilities.action.unavailable");
}

/** Reusable, quiet fail-closed state for a form or worklist whose exact server
 * operation is not runnable. Isolated component tests without the live provider
 * stay unchanged; the authenticated shell always enforces this boundary. */
export function CapabilityActionNotice({ action }: { action: CapabilityExecutionPosture }) {
  const { t } = useTranslation();
  if (!action.enforced || action.checking || action.runnable) return null;
  return <UnavailableState title={t("capabilities.action.unavailableTitle")}>{capabilityExecutionReason(action, t)}</UnavailableState>;
}

export function CapabilityNavStatus({ featureIds }: { featureIds: readonly CanonicalCapabilityID[] }) {
  const { view, enabled } = useCapabilities();
  const { t } = useTranslation();
  if (!enabled || !view || featureIds.length === 0) return null;
  const summary = summarizeCapabilities(view, featureIds);
  if (summary.state === "ready") return null;
  const label = stateLabel(summary.state, t);
  return (
    <span
      data-capability-nav-state={summary.state}
      className={cn(
        "ms-auto shrink-0 rounded-control border px-1.5 py-0.5 text-2xs font-semibold",
        summary.state === "permission_blocked"
          ? "border-status-warning/40 bg-status-warning/10 text-status-warning"
          : "border-border bg-muted/50 text-muted-foreground",
      )}
    >
      {label}
    </span>
  );
}

export function CapabilityToolSummary({ featureIds }: { featureIds: readonly CanonicalCapabilityID[] }) {
  const { view, enabled } = useCapabilities();
  const { t } = useTranslation();
  if (!enabled || !view || featureIds.length === 0) return null;
  const summary = summarizeCapabilities(view, featureIds);
  const text =
    summary.state === "ready"
      ? t("capabilities.tool.ready", { count: summary.total })
      : t("capabilities.tool.mixed", { ready: summary.counts.ready, total: summary.total });
  return (
    <p className="mt-2 text-2xs leading-relaxed text-sidebar-foreground" data-capability-tool-state={summary.state}>
      {text}
    </p>
  );
}

export function CapabilityRouteNotice() {
  const { pathname } = useLocation();
  const featureIds = featureIdsForPath(pathname);
  const { view, loading, error, enabled, refetch } = useCapabilities();
  const { t } = useTranslation();
  if (!enabled || featureIds.length === 0) return null;

  if (loading) {
    return (
      <p role="status" className="mb-4 text-caption text-muted-foreground" data-capability-route-state="loading">
        {t("capabilities.loading")}
      </p>
    );
  }
  if (error || !view) {
    return (
      <section className="mb-4 rounded-control border border-dashed border-border bg-muted/30 px-3 py-2" data-capability-route-state="unknown">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold">{t("capabilities.readFailed.title")}</h2>
            <p className="mt-0.5 max-w-4xl text-caption text-muted-foreground">{t("capabilities.readFailed.body")}</p>
          </div>
          <Button type="button" size="sm" variant="outline" onClick={refetch}>
            {t("capabilities.retry")}
          </Button>
        </div>
      </section>
    );
  }

  const summary = summarizeCapabilities(view, featureIds);
  if (summary.state === "ready") return null;
  const affected = summary.items.filter((item) => capabilitySurfaceState(item) !== "ready");
  const usable = summary.items.filter((item) => item.actions.allowed.length + item.actions.scoped.length > 0).length;
  const hasUsableActions = summary.state === "limited" && usable > 0;
  const Icon = summary.state === "permission_blocked" ? CircleSlash2 : AlertTriangle;
  return (
    <section
      aria-labelledby="route-capability-heading"
      className={cn(
        "mb-4 rounded-control border px-3 py-2",
        summary.state === "permission_blocked" ? "border-status-warning/40 bg-status-warning/10" : "border-border bg-muted/30",
      )}
      data-capability-route-state={summary.state}
    >
      <div className="flex items-start gap-2.5">
        <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0 flex-1">
          <h2 id="route-capability-heading" className="text-sm font-semibold">
            {hasUsableActions
              ? t("capabilities.route.usableTitle", { usable, total: summary.total })
              : t("capabilities.route.title", { ready: summary.counts.ready, total: summary.total })}
          </h2>
          <p className="mt-0.5 max-w-4xl text-caption text-muted-foreground">
            {hasUsableActions ? t("capabilities.route.usableBody") : t("capabilities.route.body")}
          </p>
          <details className="mt-2 text-caption">
            <summary className="cursor-pointer font-medium text-foreground">
              {t("capabilities.route.details", { count: affected.length + summary.missingIds.length })}
            </summary>
            <ul className="mt-2 grid gap-2" aria-label={t("capabilities.route.detailsLabel")}>
              {affected.map((item) => {
                const state = capabilitySurfaceState(item);
                return (
                  <li key={item.capability_id} className="border-s-2 border-border ps-2">
                    <p className="font-medium text-foreground">
                      {item.name} · {stateLabel(state, t)}
                    </p>
                    <p className="text-muted-foreground">{itemReason(item, state, t)}</p>
                  </li>
                );
              })}
              {summary.missingIds.map((id) => (
                <li key={id} className="border-s-2 border-border ps-2">
                  <p className="font-medium text-foreground">
                    {id} · {t("capabilities.state.unknown")}
                  </p>
                  <p className="text-muted-foreground">{t("capabilities.reason.missingRow")}</p>
                </li>
              ))}
            </ul>
          </details>
        </div>
      </div>
    </section>
  );
}
