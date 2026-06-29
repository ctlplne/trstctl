import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type RefObject } from "react";
import { Search, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { hasAnyPermission } from "@/lib/access";
import { api, type Me } from "@/lib/api";
import { appRoutePaths, contextualRouteItems, navGroups, permissionAnyForPath } from "@/lib/navigation";
import { useGlobalSearch, type GlobalSearchResult } from "@/lib/search";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

interface RouteCommand {
  id: string;
  label: string;
  description: string;
  to: string;
}

interface ActionCommand {
  id: string;
  label: string;
  description: string;
  permissionAny?: string[];
  run: () => void | Promise<void>;
}

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement>;
  user?: Me | null;
}

function titleFromPath(path: string): string {
  if (path === "/") return "nav.item.dashboard";
  return path
    .slice(1)
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

function routeCommands(t: (key: MessageKey, values?: Record<string, string | number>) => string, user: Me | null | undefined): RouteCommand[] {
  const labels = new Map<string, { labelKey: MessageKey; groupKey: MessageKey }>();
  for (const group of navGroups) {
    for (const item of group.items) {
      const path = basePath(item.to);
      if (!labels.has(path)) {
        labels.set(path, { labelKey: item.labelKey, groupKey: group.labelKey });
      }
    }
  }
  for (const item of contextualRouteItems) {
    const path = basePath(item.to);
    if (!labels.has(path)) {
      labels.set(path, { labelKey: item.labelKey, groupKey: item.groupKey });
    }
  }
  return appRoutePaths
    .filter((path) => hasAnyPermission(user, permissionAnyForPath(path)))
    .map((path) => {
      const nav = labels.get(path);
      const fallback = titleFromPath(path);
      return {
        id: `route:${path}`,
        label: nav ? t(nav.labelKey) : fallback === "nav.item.dashboard" ? t(fallback) : fallback,
        description: t("command.routeDescription", { group: nav ? t(nav.groupKey) : path }),
        to: path,
      };
    });
}

function matchesRoute(command: RouteCommand, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [command.label, command.description, command.to].some((value) => value.toLowerCase().includes(needle));
}

function routeScore(command: RouteCommand, query: string): number {
  const needle = query.trim().toLowerCase();
  if (!needle) return 0;
  const label = command.label.toLowerCase();
  const to = command.to.toLowerCase();
  const description = command.description.toLowerCase();
  if (label === needle) return 0;
  if (label.startsWith(needle)) return 1;
  if (to.includes(needle)) return 2;
  if (description.includes(needle)) return 3;
  return 4;
}

function matchesAction(command: ActionCommand, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [command.label, command.description].some((value) => value.toLowerCase().includes(needle));
}

function useDebouncedValue<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), ms);
    return () => window.clearTimeout(timer);
  }, [ms, value]);
  return debounced;
}

export function CommandPalette({ open, onClose, returnFocusRef, user }: CommandPaletteProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebouncedValue(query, 250);
  const debouncedTrimmed = debouncedQuery.trim();
  const search = useGlobalSearch(debouncedQuery, { enabled: open && debouncedTrimmed.length > 0 });
  const commands = useMemo(() => routeCommands(t, user), [t, user]);
  const actions = useMemo<ActionCommand[]>(
    () => [
      {
        id: "action:issue-credential",
        label: "Issue credential",
        description: "Open the self-service request workflow",
        permissionAny: ["certs:request"],
        run: () => {
          navigate("/request");
          onClose();
        },
      },
      {
        id: "action:connect-issuer",
        label: "Connect issuer",
        description: "Open CA hierarchy and issuer catalog",
        permissionAny: ["issuers:write"],
        run: () => {
          navigate("/ca-hierarchy");
          onClose();
        },
      },
      {
        id: "action:run-discovery-scan",
        label: "Run discovery scan",
        description: "Queue a run for the first configured discovery source",
        permissionAny: ["discovery:write"],
        run: async () => {
          try {
            const sources = await api.discoverySources({ limit: 1 });
            const source = sources.items?.[0];
            if (source) await api.startDiscoveryRun({ source_id: source.id, dry_run: false });
          } finally {
            navigate("/discovery");
            onClose();
          }
        },
      },
    ],
    [navigate, onClose],
  );
  const filteredRoutes = useMemo(
    () => commands.filter((command) => matchesRoute(command, query)).sort((left, right) => routeScore(left, query) - routeScore(right, query)),
    [commands, query],
  );
  const filteredActions = useMemo(() => actions.filter((command) => hasAnyPermission(user, command.permissionAny) && matchesAction(command, query)), [actions, query, user]);
  const choices: Array<ActionCommand | RouteCommand | GlobalSearchResult> = [...filteredActions, ...filteredRoutes, ...search.results];
  const titleId = "command-palette-title";
  const descriptionId = "command-palette-description";

  useEffect(() => {
    if (!open) return;
    return () => {
      setQuery("");
    };
  }, [open]);

  function activate(target: ActionCommand | RouteCommand | GlobalSearchResult) {
    if ("run" in target) {
      void target.run();
      return;
    }
    navigate(target.to);
    onClose();
  }

  function onInputKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key !== "Enter") return;
    const target = choices[0];
    if (!target) return;
    event.preventDefault();
    activate(target);
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      returnFocusRef={returnFocusRef}
      initialFocusRef={inputRef}
      panelClassName="absolute left-1/2 top-16 flex w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 flex-col overflow-hidden rounded-panel border border-border bg-background shadow-elevation3"
    >
        <div className="flex items-start justify-between gap-3 border-b border-border p-comfortable">
          <div>
            <h2 id={titleId} className="text-heading font-semibold">
              {t("command.title")}
            </h2>
            <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
              {t("command.description")}
            </p>
          </div>
          <Button type="button" size="sm" variant="ghost" onClick={onClose}>
            <X className="h-4 w-4" aria-hidden="true" />
            <span>{t("command.close")}</span>
          </Button>
        </div>
        <div className="border-b border-border p-comfortable">
          <label className="relative block">
            <Search aria-hidden="true" className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              ref={inputRef}
              type="search"
              aria-label={t("command.searchLabel")}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder={t("command.searchPlaceholder")}
              className="h-10 w-full rounded-md border border-border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          {search.unavailableSources.length > 0 && <p className="mt-2 text-xs text-muted-foreground">{t("command.sourcesUnavailable")}</p>}
        </div>
        <div className="max-h-[24rem] overflow-y-auto p-2">
          {search.loading && <p className="px-3 py-2 text-sm text-muted-foreground">{t("command.searchingInventory")}</p>}
          {filteredActions.length > 0 && (
            <PaletteSection title="Actions">
              {filteredActions.map((command) => (
                <PaletteButton key={command.id} label={command.label} description={command.description} onClick={() => void activate(command)} />
              ))}
            </PaletteSection>
          )}
          {filteredRoutes.length > 0 && (
            <PaletteSection title={t("command.routes")}>
              {filteredRoutes.map((command) => (
                <PaletteButton key={command.id} label={command.label} description={command.description} onClick={() => activate(command)} />
              ))}
            </PaletteSection>
          )}
          {search.results.length > 0 && (
            <PaletteSection title={t("command.inventory")}>
              {search.results.map((result) => (
                <PaletteButton
                  key={result.id}
                  label={result.label}
                  description={`${kindLabel(result.kind, t)} · ${result.description}`}
                  onClick={() => activate(result)}
                />
              ))}
            </PaletteSection>
          )}
          {!search.loading && choices.length === 0 && <p className="px-3 py-6 text-center text-sm text-muted-foreground">{t("command.noResults")}</p>}
        </div>
    </Dialog>
  );
}

function PaletteSection({ children, title }: { children: ReactNode; title: string }) {
  return (
    <section className="py-1" aria-label={title}>
      <h3 className="px-3 py-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3>
      <div className="space-y-1">{children}</div>
    </section>
  );
}

function PaletteButton({ description, label, onClick }: { description: string; label: string; onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-start text-sm",
        "hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring",
      )}
    >
      <span className="min-w-0">
        <span className="block truncate font-medium">{label}</span>
        <span className="block truncate text-xs text-muted-foreground">{description}</span>
      </span>
      <span className="shrink-0 text-xs text-muted-foreground">{t("command.enter")}</span>
    </button>
  );
}

function kindLabel(kind: GlobalSearchResult["kind"], t: (key: MessageKey) => string): string {
  switch (kind) {
    case "certificate":
      return t("search.kind.certificate");
    case "identity":
      return t("search.kind.identity");
    case "issuer":
      return "Issuer";
    case "secret":
      return t("search.kind.secret");
    case "agent":
      return "Agent";
  }
}
