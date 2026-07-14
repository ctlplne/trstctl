import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  Braces,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  Compass,
  FileClock,
  GitFork,
  LayoutDashboard,
  Menu,
  Network,
  Radar,
  RadioTower,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Languages,
  LockKeyhole,
  LogOut,
  Rocket,
  ServerCog,
  Signature,
  Siren,
  Search,
  Users,
  Vault,
  X,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { CommandPalette } from "@/components/CommandPalette";
import { ShortcutsHelp } from "@/components/ShortcutsHelp";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import { hasAnyPermission } from "@/lib/access";
import {
  contextualRouteItems,
  globalBandRoutes,
  lockedModuleIds,
  moduleForRoute,
  navGroups,
  navModules,
  permissionAnyForPath,
  primaryNavItems,
  taskNavItems,
  type ModuleId,
  type NavIcon,
  type NavItem,
} from "@/lib/navigation";
import { persistActiveModule, persistCollapsedGroups, readActiveModule, readCollapsedGroups } from "@/lib/navPreferences";
import { cn } from "@/lib/utils";
import type { Me } from "@/lib/api";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";
import { localeLabelKeys, productionLocales, supportedLocales, type Locale, type MessageKey } from "@/i18n/messages";

// Pseudo-locales (en-XA/ar-XB) are i18n test fixtures; only offer them in dev
// builds so real users never see them in the language picker.
const localeChoices: readonly Locale[] = import.meta.env.DEV ? supportedLocales : productionLocales;

const iconMap: Record<NavIcon, typeof Activity> = {
  activity: Activity,
  agent: Radar,
  approval: ClipboardCheck,
  audit: FileClock,
  bot: Bot,
  certificate: ScrollText,
  connector: Boxes,
  dashboard: LayoutDashboard,
  graph: GitFork,
  identity: KeyRound,
  incident: Siren,
  journey: Compass,
  key: LockKeyhole,
  owner: Users,
  platform: ServerCog,
  policy: Settings2,
  posture: ShieldCheck,
  profile: Settings2,
  protocol: RadioTower,
  notification: Bell,
  risk: ShieldAlert,
  rocket: Rocket,
  secret: KeyRound,
  signature: Signature,
  spiffe: Network,
  ssh: Braces,
  vault: Vault,
};

function navBasePath(to: string): string {
  return to.split("?")[0] || "/";
}

/** A worklist link ("/certificates?expiry=30d") is active only when the
 * current URL carries its query; the plain page row stands down at the same
 * time, so the rail never highlights two rows for one location. */
function worklistMatches(to: string, pathname: string, search: string): boolean {
  const [path, query = ""] = to.split("?");
  if (pathname !== path) return false;
  const wanted = new URLSearchParams(query);
  const current = new URLSearchParams(search);
  for (const [key, value] of wanted) {
    if (current.get(key) !== value) return false;
  }
  return true;
}

function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(() => (typeof window === "undefined" ? true : window.innerWidth >= 768));

  useEffect(() => {
    const updateWidth = () => setIsDesktop(window.innerWidth >= 768);
    updateWidth();
    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, []);

  return isDesktop;
}

type PrimaryNavProps = {
  className?: string;
  id?: string;
  onNavigate?: () => void;
  user: Me | null;
};

function navItemClass(isActive: boolean): string {
  return cn(
    "flex min-h-9 items-center gap-2 rounded-control px-3 py-2 text-sm transition-colors",
    isActive ? "bg-sidebar-active font-semibold text-primary" : "text-sidebar-foreground hover:bg-sidebar-hover hover:text-white",
  );
}

function PrimaryNav({ className, id, onNavigate, user }: PrimaryNavProps) {
  const { t } = useTranslation();
  const location = useLocation();
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => readCollapsedGroups());
  const visiblePrimaryItems = primaryNavItems.filter((item) => hasAnyPermission(user, permissionAnyForPath(item.to)));
  const visibleTaskItems = taskNavItems.filter((item) => hasAnyPermission(user, permissionAnyForPath(item.to)));
  const activeWorklist = visibleTaskItems.find((item) => worklistMatches(item.to, location.pathname, location.search));

  // S-B2: the rail's middle band is scoped by a module switcher. A route is
  // either global (always shown) or owned by exactly one module (shown only
  // when that module is active). Build a lookup of every rail item so the
  // module band can borrow each route's label and icon from the S-A1 groups.
  const routeItemByPath = useMemo(() => {
    const map = new Map<string, NavItem>();
    for (const group of navGroups) for (const item of group.items) map.set(navBasePath(item.to), item);
    return map;
  }, []);
  const globalRouteSet = useMemo(() => new Set(globalBandRoutes), []);

  const permittedModules = useMemo(
    () => navModules.filter((module) => module.routes.some((route) => hasAnyPermission(user, permissionAnyForPath(route)))),
    [user],
  );

  // S-B5: modules whose required commercial feature is unlicensed render as a
  // single graceful upsell row instead of being selectable. trstctl's modules
  // are all MPL-core (moduleRequiredFeature is empty), so this is empty today;
  // the seam avoids scattered locked panels if a commercial module is ever
  // added. No editions fetch is made here while the map is empty.
  const lockedModuleSet = useMemo(() => {
    const noneLicensed: ReadonlySet<string> = new Set();
    return new Set(lockedModuleIds(noneLicensed));
  }, []);

  const routeModule = moduleForRoute(location.pathname);
  const [activeModule, setActiveModule] = useState<ModuleId | null>(() => {
    if (routeModule) return routeModule;
    const stored = readActiveModule();
    if (stored && permittedModules.some((module) => module.id === stored)) return stored as ModuleId;
    return permittedModules[0]?.id ?? null;
  });

  // Navigating to a module-owned route auto-selects that module, mirroring the
  // collapsed-group re-open below. This keys on the pathname ONLY (not on
  // activeModule) so a manual switch while staying on a module route is not
  // immediately reverted. Global routes leave the selection alone.
  useEffect(() => {
    const owner = moduleForRoute(location.pathname);
    if (owner) {
      setActiveModule(owner);
      persistActiveModule(owner);
    }
    // Intentionally pathname-only: a manual module switch must not be reverted.
  }, [location.pathname]);

  // Keep a valid selection if the permitted set changes (e.g., session load).
  useEffect(() => {
    if (permittedModules.length === 0) return;
    if (!activeModule || !permittedModules.some((module) => module.id === activeModule)) {
      setActiveModule(permittedModules[0].id);
    }
  }, [permittedModules, activeModule]);

  function selectModule(moduleId: ModuleId) {
    setActiveModule(moduleId);
    persistActiveModule(moduleId);
  }

  const activeModuleDef = permittedModules.find((module) => module.id === activeModule) ?? null;
  const moduleBandItems: NavItem[] = activeModuleDef
    ? activeModuleDef.routes
        .filter((route) => hasAnyPermission(user, permissionAnyForPath(route)))
        .map((route) => routeItemByPath.get(navBasePath(route)))
        .filter((item): item is NavItem => Boolean(item))
    : [];

  // Global groups are the S-A1 bands with module-owned routes removed, so each
  // route appears exactly once: in the module band or a global group.
  const visibleGroups = navGroups
    .map((group) => ({
      ...group,
      items: group.items.filter(
        (item) => globalRouteSet.has(navBasePath(item.to)) && hasAnyPermission(user, permissionAnyForPath(item.to)),
      ),
    }))
    .filter((group) => group.items.length > 0);

  // Deep-linking into a collapsed group re-opens it so the active row is
  // always visible; manual collapse choices persist otherwise.
  useEffect(() => {
    const owning = navGroups.find((group) => group.items.some((item) => location.pathname === navBasePath(item.to)));
    if (!owning) return;
    setCollapsedGroups((current) => {
      if (!current.has(owning.labelKey)) return current;
      const next = new Set(current);
      next.delete(owning.labelKey);
      persistCollapsedGroups(next);
      return next;
    });
  }, [location.pathname]);

  function toggleGroup(labelKey: string) {
    setCollapsedGroups((current) => {
      const next = new Set(current);
      if (next.has(labelKey)) {
        next.delete(labelKey);
      } else {
        next.add(labelKey);
      }
      persistCollapsedGroups(next);
      return next;
    });
  }

  return (
    <nav aria-label={t("shell.primaryNavigation")} className={cn("p-3", className)} id={id}>
      <ul className="space-y-4">
        {visiblePrimaryItems.length > 0 && (
          <li>
            <ul className="space-y-1">
              {visiblePrimaryItems.map(({ to, labelKey, icon, end }) => {
                const Icon = iconMap[icon];
                return (
                  <li key={`primary-${to}`}>
                    <NavLink to={to} end={end} onClick={onNavigate} className={({ isActive }) => navItemClass(isActive)}>
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1 truncate">{t(labelKey)}</span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        )}
        {visibleTaskItems.length > 0 && (
          <li>
            <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60">{t("nav.section.needsAction")}</p>
            <ul aria-label={t("nav.section.needsActionWorklists")} className="space-y-1">
              {visibleTaskItems.map(({ to, labelKey, descriptionKey, icon }) => {
                const Icon = iconMap[icon];
                const label = t(labelKey);
                const description = t(descriptionKey);
                const active = worklistMatches(to, location.pathname, location.search);
                return (
                  <li key={`task-${to}`}>
                    <NavLink
                      to={to}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "flex min-h-12 items-start gap-2 rounded-control px-3 py-2 text-sm transition-colors",
                        active ? "bg-sidebar-active font-semibold text-primary" : "text-sidebar-foreground hover:bg-sidebar-hover hover:text-white",
                      )}
                    >
                      <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate">{label}</span>
                        <span className="block truncate text-xs font-normal text-sidebar-foreground/60">{description}</span>
                      </span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        )}
        {permittedModules.length !== 0 && (
          <li>
            <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60">{t("nav.section.module")}</p>
            <div role="tablist" aria-label={t("nav.section.module")} className="mb-2 flex flex-wrap gap-1 px-1">
              {permittedModules.map((module) => {
                const Icon = iconMap[module.icon];
                const selected = module.id === activeModule;
                if (lockedModuleSet.has(module.id)) {
                  // S-B5: one graceful upsell row, linking to Editions & license (C-A1: /admin/editions).
                  return (
                    <NavLink
                      key={module.id}
                      to="/admin/editions"
                      onClick={onNavigate}
                      className="inline-flex items-center gap-1.5 rounded-control px-2.5 py-1.5 text-xs font-semibold text-sidebar-foreground/50 transition-colors hover:text-sidebar-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent"
                      title={t("nav.module.upsell")}
                    >
                      <LockKeyhole aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
                      <span className="truncate">{t(module.labelKey)}</span>
                      <span className="rounded bg-sidebar-foreground/10 px-1 text-[0.65rem] uppercase tracking-wide">{t("nav.module.upsellBadge")}</span>
                    </NavLink>
                  );
                }
                return (
                  <button
                    key={module.id}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    onClick={() => selectModule(module.id)}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-control px-2.5 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent",
                      selected ? "bg-sidebar-active text-primary" : "text-sidebar-foreground/70 hover:bg-sidebar-hover hover:text-white",
                    )}
                  >
                    <Icon aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
                    <span className="truncate">{t(module.labelKey)}</span>
                  </button>
                );
              })}
            </div>
            {moduleBandItems.length !== 0 && activeModuleDef && (
              <ul aria-label={t(activeModuleDef.labelKey)} className="space-y-1">
                {moduleBandItems.map((item) => {
                  const { to, labelKey, icon, end } = item;
                  const Icon = iconMap[icon];
                  const suppressed = activeWorklist != null && navBasePath(activeWorklist.to) === navBasePath(to);
                  return (
                    <li key={`module-${to}-${labelKey}`}>
                      <NavLink to={to} end={end} onClick={onNavigate} className={({ isActive }) => navItemClass(isActive && !suppressed)}>
                        <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                        <span className="min-w-0 flex-1 truncate">{t(labelKey)}</span>
                      </NavLink>
                    </li>
                  );
                })}
                {hasAnyPermission(user, permissionAnyForPath("/audit")) &&
                  (() => {
                    const AuditLensIcon = iconMap.audit;
                    return (
                      <li key="module-audit-scope">
                        {/* S-B4: a scoped lens into the ONE shared audit stream. */}
                        <NavLink to={`/audit?module=${activeModuleDef.id}`} onClick={onNavigate} className={navItemClass(false)}>
                          <AuditLensIcon aria-hidden="true" className="h-4 w-4 shrink-0" />
                          <span className="min-w-0 flex-1 truncate">{t("nav.module.auditLens")}</span>
                        </NavLink>
                      </li>
                    );
                  })()}
              </ul>
            )}
          </li>
        )}
        {visibleGroups.map((group) => {
          const collapsed = collapsedGroups.has(group.labelKey);
          const contentId = `nav-group-${group.labelKey.replace(/[^a-zA-Z0-9]+/g, "-")}`;
          return (
            <li key={group.labelKey}>
              <button
                type="button"
                aria-expanded={!collapsed}
                aria-controls={contentId}
                onClick={() => toggleGroup(group.labelKey)}
                className="flex w-full items-center justify-between gap-2 rounded-control px-3 pb-1 pt-0.5 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60 transition-colors duration-fast hover:text-sidebar-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent"
              >
                <span>{t(group.labelKey)}</span>
                <ChevronDown aria-hidden="true" className={cn("h-3.5 w-3.5 transition-transform duration-fast", collapsed && "-rotate-90")} />
              </button>
              <ul id={contentId} hidden={collapsed} className="space-y-1">
                {group.items.map((item) => {
                  const { to, labelKey, icon, end } = item;
                  const label = t(labelKey);
                  const Icon = iconMap[icon];
                  const suppressed = activeWorklist != null && navBasePath(activeWorklist.to) === navBasePath(to);
                  return (
                    <li key={`${group.labelKey}-${to}-${labelKey}`}>
                      <NavLink to={to} end={end} onClick={onNavigate} className={({ isActive }) => navItemClass(isActive && !suppressed)}>
                        <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                        <span className="min-w-0 flex-1 truncate">{label}</span>
                      </NavLink>
                    </li>
                  );
                })}
              </ul>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return target.isContentEditable || tag === "input" || tag === "textarea" || tag === "select";
}

/** routeLabel resolves a stable, localized page name for a pathname so SPA
 * navigation can update document.title and announce the new page context. It
 * prefers a navigation label for the matched route and falls back to a
 * title-cased path segment for routes that are not in the primary nav. */
function routeLabel(pathname: string, t: (key: MessageKey) => string): string {
  if (pathname === "/") return t("nav.item.dashboard");
  for (const group of navGroups) {
    for (const item of group.items) {
      const base = item.to.split("?")[0];
      if (base === pathname) return t(item.labelKey);
    }
  }
  for (const item of contextualRouteItems) {
    if (item.to === pathname) return t(item.labelKey);
  }
  const segment = pathname.split("/").filter(Boolean)[0] ?? "";
  if (!segment) return t("nav.item.dashboard");
  return segment
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** useRouteFocus moves keyboard focus to the routed main region (or its first
 * heading) on each SPA navigation, updates document.title, and returns a live
 * announcement string so a screen reader is told which page is now active.
 * Browser full-page loads do this for free; client-side routing does not, so a
 * keyboard or screen-reader user would otherwise stay parked on the activated
 * nav link with no context change. */
function useRouteFocus(mainRef: RefObject<HTMLElement>, t: I18nContextValue["t"]): string {
  const location = useLocation();
  const [announcement, setAnnouncement] = useState("");
  const isFirstRender = useRef(true);

  useEffect(() => {
    const label = routeLabel(location.pathname, t);
    document.title = `${label} · ${t("app.brand.name")}`;
    // Skip stealing focus on the very first mount: the user has not navigated
    // yet, and an initial focus jump would fight the browser's own restore.
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }
    setAnnouncement(t("shell.routeAnnouncement", { page: label }));
    const main = mainRef.current;
    if (!main) return;
    // Prefer the page's h1 so the screen reader reads the page title on arrival.
    // Headings are not focusable by default, so make it programmatically focusable
    // (without entering the tab order) before moving focus; otherwise fall back to
    // the main landmark, which is already tabIndex=-1.
    const heading = main.querySelector<HTMLElement>("h1");
    if (heading && !heading.hasAttribute("tabindex")) {
      heading.setAttribute("tabindex", "-1");
    }
    (heading ?? main).focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  return announcement;
}

/** AppShell is the authenticated layout: a skip link, a banner header, a
 * navigation sidebar, and the routed main content — landmarked and keyboard
 * navigable for WCAG 2.1 AA. */
export function AppShell() {
  const { user, logout } = useAuth();
  const { locale, setLocale, t } = useTranslation();
  const isDesktop = useIsDesktop();
  const commandButtonRef = useRef<HTMLButtonElement>(null);
  const shortcutsButtonRef = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const routeAnnouncement = useRouteFocus(mainRef, t);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [logoutPending, setLogoutPending] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const mobileNavId = "mobile-primary-nav";

  async function handleLogout() {
    setLogoutPending(true);
    setLogoutError(null);
    try {
      await logout();
    } catch {
      setLogoutPending(false);
      setLogoutError(t("shell.signOutFailed"));
    }
  }

  function toggleSidebar() {
    setSidebarCollapsed((collapsed) => !collapsed);
  }

  useEffect(() => {
    if (isDesktop) {
      setMobileNavOpen(false);
    }
  }, [isDesktop]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandPaletteOpen(true);
        return;
      }
      if (event.key === "?" && !isEditableTarget(event.target)) {
        event.preventDefault();
        setShortcutsOpen(true);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        {t("app.skipToMain")}
      </a>

      <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background/85 px-4 backdrop-blur">
        <div className="flex min-w-0 items-center gap-2">
          {!isDesktop && (
            <button
              type="button"
              aria-controls={mobileNavId}
              aria-expanded={mobileNavOpen}
              aria-label={t(mobileNavOpen ? "shell.closePrimaryNavigation" : "shell.openPrimaryNavigation")}
              onClick={() => setMobileNavOpen((open) => !open)}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {mobileNavOpen ? <X aria-hidden="true" className="h-4 w-4" /> : <Menu aria-hidden="true" className="h-4 w-4" />}
            </button>
          )}
          {isDesktop && (
            <button
              type="button"
              aria-controls="desktop-primary-nav"
              aria-expanded={!sidebarCollapsed}
              aria-label={t(sidebarCollapsed ? "shell.showPrimaryNavigation" : "shell.hidePrimaryNavigation")}
              onClick={toggleSidebar}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <Menu aria-hidden="true" className="h-4 w-4" />
            </button>
          )}
          <span
            aria-hidden="true"
            className="grid h-7 w-7 shrink-0 place-items-center rounded-control bg-brand-accent text-brand-accent-foreground shadow-elevation1"
          >
            <svg viewBox="0 0 32 32" className="h-4 w-4" fill="none">
              <path d="M8 11h16M16 6v20M11 21l5 4 5-4" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="16" cy="16" r="4.2" stroke="currentColor" strokeWidth="1.8" />
            </svg>
          </span>
          <span className="min-w-0 leading-tight">
            <span className="block truncate font-display text-sm font-bold tracking-tight">{t("app.brand.name")}</span>
            <span className="hidden truncate text-[10px] font-medium uppercase tracking-wider text-brand-accent sm:block">{t("app.brand.subtitle")}</span>
          </span>
        </div>
        <div className="flex min-w-0 items-center gap-2">
          {!isDesktop && (
            <Button type="button" size="icon" variant="ghost" aria-label={t("shell.openCommandPalette")} onClick={() => setCommandPaletteOpen(true)}>
              <Search className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
          <Button
            ref={commandButtonRef}
            type="button"
            variant="outline"
            size="sm"
            aria-label={t("shell.openCommandPalette")}
            onClick={() => setCommandPaletteOpen(true)}
            className="hidden min-w-56 justify-between gap-2 px-2.5 text-muted-foreground hover:text-foreground md:inline-flex"
          >
            <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate text-start">{t("shell.searchOrJump")}</span>
            <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px]">Cmd K</kbd>
          </Button>
          {user && (
            <div aria-label={t("shell.tenantContext")} className="hidden min-w-0 items-center gap-2 rounded-md border border-border px-2 py-1 text-xs lg:flex">
              <span className="text-muted-foreground">{t("shell.tenant")}</span>
              <strong className="max-w-32 truncate font-semibold">{user.tenant_id}</strong>
            </div>
          )}
          <label className="relative hidden h-9 items-center sm:flex">
            <span className="sr-only">{t("shell.locale")}</span>
            <Languages aria-hidden="true" className="pointer-events-none absolute start-2 h-4 w-4 text-muted-foreground" />
            <select
              aria-label={t("shell.locale")}
              className="h-9 rounded-md border border-border bg-background ps-8 pe-7 text-xs text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
              value={locale}
              onChange={(event) => setLocale(event.target.value as Locale)}
            >
              {localeChoices.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {t(localeLabelKeys[candidate])}
                </option>
              ))}
            </select>
          </label>
          {user && hasAnyPermission(user, permissionAnyForPath("/notifications")) && (
            <Link
              to="/notifications"
              aria-label={t("nav.item.notifications")}
              title={t("nav.item.notifications")}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-foreground transition-colors duration-fast hover:bg-foreground/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              <Bell className="h-4 w-4" aria-hidden="true" />
            </Link>
          )}
          <Button
            ref={shortcutsButtonRef}
            type="button"
            size="icon"
            variant="ghost"
            aria-label={t("shell.openKeyboardShortcuts")}
            onClick={() => setShortcutsOpen(true)}
          >
            <CircleHelp className="h-4 w-4" aria-hidden="true" />
          </Button>
          <ThemeToggle />
          {user && (
            <span className="hidden max-w-44 truncate text-sm text-muted-foreground sm:inline" data-testid="current-user">
              {user.email || user.subject}
            </span>
          )}
          {logoutError && (
            <span className="max-w-40 truncate text-xs text-destructive" role="alert">
              {logoutError}
            </span>
          )}
          {user && (
            <Button
              type="button"
              size="icon"
              variant="ghost"
              aria-label={t("shell.signOut")}
              title={t("shell.signOut")}
              onClick={handleLogout}
              disabled={logoutPending}
            >
              <LogOut className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
        </div>
      </header>

      {!isDesktop && mobileNavOpen && (
        <div className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm">
          <div
            aria-label={t("shell.primaryNavigationDialog")}
            aria-modal="true"
            className="h-full w-[min(20rem,calc(100vw-2rem))] overflow-y-auto border-e border-sidebar-active/40 bg-sidebar text-sidebar-foreground shadow-xl"
            role="dialog"
          >
            <div className="flex h-14 items-center justify-between border-b border-border px-4">
              <span className="text-sm font-semibold">{t("shell.navigation")}</span>
              <button
                type="button"
                aria-label={t("shell.closePrimaryNavigation")}
                onClick={() => setMobileNavOpen(false)}
                className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <X aria-hidden="true" className="h-4 w-4" />
              </button>
            </div>
            <PrimaryNav id={mobileNavId} user={user} onNavigate={() => setMobileNavOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0">
        {isDesktop && !sidebarCollapsed && (
          <PrimaryNav
            className="sticky top-14 h-[calc(100vh-3.5rem)] w-64 shrink-0 overflow-y-auto border-e border-sidebar-active/40 bg-sidebar text-sidebar-foreground"
            id="desktop-primary-nav"
            user={user}
          />
        )}

        <main id="main" ref={mainRef} className="min-w-0 flex-1 p-4 md:p-6" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      {/* Politely announce SPA route transitions so screen-reader users learn the
          new page context after focus moves to the main region (WCAG 2.4.3 / 4.1.3).
          aria-live (not role=status) keeps this out of getByRole("status") queries
          while still announcing; the two are equivalent for assistive tech. */}
      <div aria-live="polite" aria-atomic="true" className="sr-only" data-testid="route-announcer">
        {routeAnnouncement}
      </div>
      <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} returnFocusRef={commandButtonRef} user={user} />
      <ShortcutsHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} returnFocusRef={shortcutsButtonRef} />
    </div>
  );
}
