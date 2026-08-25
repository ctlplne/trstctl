import { Suspense, useEffect, useRef, useState, type RefObject } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
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
  Home as HomeIcon,
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
  LockKeyhole,
  LogOut,
  Rocket,
  ServerCog,
  Signature,
  Siren,
  Search,
  Users,
  UserRound,
  Vault,
  X,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { CommandPalette } from "@/components/CommandPalette";
import { BrandMark } from "@/components/BrandMark";
import { Dialog } from "@/components/Dialog";
import { ShortcutsHelp } from "@/components/ShortcutsHelp";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import { hasAnyPermission } from "@/lib/access";
import { navGroups, navSpaces, permissionAnyForPath, primaryNavItems, spaceForRoute, taskNavItems, type NavIcon, type NavSpace } from "@/lib/navigation";
import { persistCollapsedGroups, readCollapsedGroups } from "@/lib/navPreferences";
import { Eyebrow } from "@/components/typography";
import { cn } from "@/lib/utils";
import type { Me } from "@/lib/api";
import { api } from "@/lib/api";
import { useApiQuery, useHasAppQueryProvider } from "@/lib/query";
import { meaningfulAttention } from "@/pages/notifications/AlertCenterTabs";
import { useTranslation, type I18nContextValue, translateNow } from "@/i18n/I18nProvider";
import { localeLabelKeys, productionLocales, supportedLocales, type Locale, type MessageKey } from "@/i18n/messages";
import { CapabilityNavStatus, CapabilityRouteNotice, CapabilityToolSummary } from "@/components/CapabilityTruth";

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
    "flex min-h-9 items-start gap-2 rounded-control px-3 py-2 text-sm leading-snug transition-colors",
    isActive ? "bg-sidebar-active font-semibold text-brand-accent" : "text-sidebar-foreground hover:bg-sidebar-hover hover:text-foreground",
  );
}

/** spaceLandingRoute: where a space's rail button lands — the first route in
 * the space the session may read, or null when the whole space is off-limits
 * (its button is then hidden). */
function spaceLandingRoute(space: NavSpace, user: Me | null): string | null {
  for (const group of space.groups) {
    for (const item of group.items) {
      if (hasAnyPermission(user, permissionAnyForPath(item.to))) return item.to;
    }
  }
  return null;
}

type SpaceRailProps = {
  user: Me | null;
  onNavigate?: () => void;
  orientation: "vertical" | "horizontal";
};

/** SpaceRail (S-C1): the tool switcher. One button per permitted tool plus
 * Home; activating a button navigates to that space's landing route, and the
 * active space is derived from the current location — the URL stays the single
 * source of truth, unlike the chrome-only S-B2 chips this replaces. */
function SpaceRail({ user, onNavigate, orientation }: SpaceRailProps) {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const active = spaceForRoute(location.pathname) ?? "home";
  const permitted = navSpaces
    .map((space) => ({ space, landing: spaceLandingRoute(space, user) }))
    .filter((entry): entry is { space: NavSpace; landing: string } => entry.landing !== null);
  const homePermitted = hasAnyPermission(user, permissionAnyForPath("/"));

  function railButtonClass(selected: boolean): string {
    return cn(
      "relative flex h-10 w-10 items-center justify-center rounded-control transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus",
      selected ? "bg-sidebar-active text-brand-accent" : "text-sidebar-foreground/70 hover:bg-sidebar-hover hover:text-foreground",
    );
  }

  return (
    <nav
      aria-label={t("shell.spaces")}
      className={cn(
        "bg-sidebar",
        orientation === "vertical"
          ? "sticky top-14 flex h-[calc(100vh-3.5rem)] w-14 shrink-0 flex-col items-center gap-1 border-e border-sidebar-active/40 py-3"
          : "flex flex-row items-center gap-1 border-b border-sidebar-active/40 px-3 py-2",
      )}
    >
      {homePermitted && (
        <button
          type="button"
          aria-label={t("nav.space.home")}
          aria-current={active === "home" ? "true" : undefined}
          title={t("nav.space.home")}
          onClick={() => {
            navigate("/");
            onNavigate?.();
          }}
          className={railButtonClass(active === "home")}
        >
          <HomeIcon aria-hidden="true" className="h-[18px] w-[18px]" />
        </button>
      )}
      {permitted.map(({ space, landing }) => {
        const Icon = iconMap[space.icon];
        const selected = active === space.id;
        return (
          <button
            key={space.id}
            type="button"
            aria-label={t(space.labelKey)}
            aria-current={selected ? "true" : undefined}
            title={t(space.labelKey)}
            onClick={() => {
              navigate(landing);
              onNavigate?.();
            }}
            className={railButtonClass(selected)}
          >
            <Icon aria-hidden="true" className="h-[18px] w-[18px]" />
            {selected && <span aria-hidden="true" className="absolute inset-y-2 start-0 w-0.5 rounded-e bg-brand-accent" />}
          </button>
        );
      })}
    </nav>
  );
}

function PrimaryNav({ className, id, onNavigate, user }: PrimaryNavProps) {
  const { t } = useTranslation();
  const location = useLocation();
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => readCollapsedGroups());
  const visiblePrimaryItems = primaryNavItems.filter((item) => hasAnyPermission(user, permissionAnyForPath(item.to)));
  const visibleTaskItems = taskNavItems.filter((item) => hasAnyPermission(user, permissionAnyForPath(item.to)));
  const activeWorklist = visibleTaskItems.find((item) => worklistMatches(item.to, location.pathname, location.search));

  // S-C1: the sidebar is scoped by the active space (derived from the URL).
  // On the Home plane it shows the primary items and needs-action worklists;
  // inside a space it shows that space's groups and nothing else.
  const activeSpaceId = spaceForRoute(location.pathname);
  const activeSpace = (activeSpaceId && activeSpaceId !== "home" ? navSpaces.find((space) => space.id === activeSpaceId) : null) ?? null;

  const visibleGroups = (activeSpace?.groups ?? [])
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => hasAnyPermission(user, permissionAnyForPath(item.to))),
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
        {!activeSpace && visiblePrimaryItems.length > 0 && (
          <li>
            <ul className="space-y-1">
              {visiblePrimaryItems.map((item) => {
                const { to, labelKey, icon, end } = item;
                const Icon = iconMap[icon];
                return (
                  <li key={`primary-${to}`}>
                    <NavLink to={to} end={end} onClick={onNavigate} className={({ isActive }) => navItemClass(isActive)}>
                      <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1 break-words">{t(labelKey)}</span>
                      <CapabilityNavStatus featureIds={item.featureIds} />
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        )}
        {!activeSpace && visibleTaskItems.length > 0 && (
          <li>
            <Eyebrow as="p" className="px-3 pb-1 text-sidebar-foreground/80">
              {t("nav.section.needsAction")}
            </Eyebrow>
            <ul aria-label={t("nav.section.needsActionWorklists")} className="space-y-1">
              {visibleTaskItems.map((item) => {
                const { to, labelKey, descriptionKey, icon } = item;
                const Icon = iconMap[icon];
                const label = t(labelKey);
                const description = t(descriptionKey);
                return (
                  <li key={`task-${to}`}>
                    <NavLink
                      to={to}
                      onClick={onNavigate}
                      className="flex min-h-12 items-start gap-2 rounded-control px-3 py-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-hover hover:text-foreground"
                    >
                      <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1">
                        <span className="block break-words leading-snug">{label}</span>
                        <span className="mt-0.5 block break-words text-xs font-normal leading-snug text-sidebar-foreground/80">{description}</span>
                      </span>
                      <CapabilityNavStatus featureIds={item.featureIds} />
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        )}
        {activeSpace && (
          <li>
            {/* S-C1: the sidebar names the active space; the rail switches it. */}
            <div className="border-b border-sidebar-active/55 px-3 pb-3 pt-0.5">
              <p className="text-sm font-bold text-sidebar-foreground">{t(activeSpace.labelKey)}</p>
              <p className="mt-1 text-caption leading-relaxed text-sidebar-foreground/75">{t(activeSpace.questionKey)}</p>
              <CapabilityToolSummary featureIds={Array.from(new Set(activeSpace.groups.flatMap((group) => group.items.flatMap((item) => item.featureIds))))} />
            </div>
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
                className="flex w-full items-center justify-between gap-2 rounded-control px-3 pb-1 pt-0.5 text-sidebar-foreground/80 transition-colors duration-fast hover:text-sidebar-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              >
                <Eyebrow className="text-inherit">{t(group.labelKey)}</Eyebrow>
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
                        <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                        <span className="min-w-0 flex-1 break-words">{label}</span>
                        <CapabilityNavStatus featureIds={item.featureIds} />
                      </NavLink>
                    </li>
                  );
                })}
              </ul>
            </li>
          );
        })}
        {activeSpace && activeSpace.id !== "platform" && hasAnyPermission(user, permissionAnyForPath("/audit")) && (
          <li>
            {/* S-B4 survives the spaces re-carve: every space keeps a scoped
                lens into the ONE shared audit stream (Platform hosts the
                unscoped Audit row itself, so it needs no extra lens). */}
            <NavLink to={`/audit?module=${activeSpace.id}`} onClick={onNavigate} className={navItemClass(false)}>
              <AuditLensIcon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
              <span className="min-w-0 flex-1 break-words">{t("nav.module.auditLens")}</span>
            </NavLink>
          </li>
        )}
      </ul>
    </nav>
  );
}

const AuditLensIcon = iconMap.audit;

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
  if (pathname === "/wizard") return t("source.set.up.trstctl.b56c208e41");
  if (pathname === "/styleguide") return "Design system";
  for (const item of primaryNavItems) {
    const base = item.to.split("?")[0];
    if (base === pathname) return t(item.labelKey);
  }
  for (const group of navGroups) {
    for (const item of group.items) {
      const base = item.to.split("?")[0];
      if (base === pathname) return t(item.labelKey);
    }
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
  const { user, logout, preview } = useAuth();
  const { locale, setLocale, t } = useTranslation();
  const isDesktop = useIsDesktop();
  const commandButtonRef = useRef<HTMLButtonElement>(null);
  const mobileNavButtonRef = useRef<HTMLButtonElement>(null);
  const shortcutsButtonRef = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const routeAnnouncement = useRouteFocus(mainRef, t);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
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

      <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-card/90 px-4 backdrop-blur">
        <div className="flex min-w-0 items-center gap-2">
          {!isDesktop && (
            <Button
              ref={mobileNavButtonRef}
              type="button"
              size="icon"
              variant="outline"
              aria-controls={mobileNavId}
              aria-expanded={mobileNavOpen}
              aria-label={t(mobileNavOpen ? "shell.closePrimaryNavigation" : "shell.openPrimaryNavigation")}
              onClick={() => setMobileNavOpen((open) => !open)}
              className="shrink-0"
            >
              {mobileNavOpen ? <X aria-hidden="true" className="h-4 w-4" /> : <Menu aria-hidden="true" className="h-4 w-4" />}
            </Button>
          )}
          {isDesktop && (
            <Button
              type="button"
              size="icon"
              variant="outline"
              aria-controls="desktop-primary-nav"
              aria-expanded={!sidebarCollapsed}
              aria-label={t(sidebarCollapsed ? "shell.showPrimaryNavigation" : "shell.hidePrimaryNavigation")}
              onClick={toggleSidebar}
              className="shrink-0"
            >
              <Menu aria-hidden="true" className="h-4 w-4" />
            </Button>
          )}
          <BrandMark />
          <span className="min-w-0 leading-tight">
            <span className="block truncate font-display text-sm font-bold tracking-tight">{t("app.brand.name")}</span>
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
            <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-2xs">{translateNow("source.cmd.k.abdd8e293f")}</kbd>
          </Button>
          {user && hasAnyPermission(user, permissionAnyForPath("/notifications")) ? <HeaderAlertIndicator /> : null}
          {user && (
            <div className="relative">
              <Button
                type="button"
                size={isDesktop ? "sm" : "icon"}
                variant="ghost"
                aria-controls="account-menu"
                aria-expanded={accountOpen}
                aria-label={t("shell.accountMenu")}
                onClick={() => setAccountOpen((open) => !open)}
                className="max-w-52 gap-2"
              >
                <UserRound className="h-4 w-4" aria-hidden="true" />
                {isDesktop ? (
                  <span className="min-w-0 truncate text-sm font-medium" data-testid="current-user">
                    {user.email || user.subject}
                  </span>
                ) : null}
              </Button>
              {accountOpen && (
                <div
                  id="account-menu"
                  role="dialog"
                  aria-label={t("shell.accountMenu")}
                  className="absolute end-0 top-11 z-50 grid w-[min(19rem,calc(100vw-1rem))] gap-3 rounded-panel border border-border bg-card p-3 text-card-foreground shadow-elevation3"
                >
                  <div className="min-w-0 border-b border-border pb-3 text-sm">
                    <strong className="block truncate">{user.email || user.subject}</strong>
                    <span aria-label={t("shell.tenantContext")} className="block truncate text-caption text-muted-foreground">
                      <span className="sr-only">{t("shell.tenant")}: </span>
                      {user.tenant_id}
                    </span>
                  </div>
                  <label className="grid gap-1 text-caption font-medium text-muted-foreground">
                    {t("shell.locale")}
                    <select
                      aria-label={t("shell.locale")}
                      className="h-9 rounded-control border border-border bg-background px-3 text-sm text-foreground"
                      value={locale}
                      onChange={(event) => setLocale(event.target.value as Locale)}
                    >
                      {localeChoices.map((candidate) => (
                        <option key={`mobile-${candidate}`} value={candidate}>
                          {t(localeLabelKeys[candidate])}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="flex items-center justify-between gap-2">
                    <ThemeToggle />
                    <Button
                      ref={shortcutsButtonRef}
                      type="button"
                      size="icon"
                      variant="ghost"
                      aria-label={t("shell.openKeyboardShortcuts")}
                      onClick={() => {
                        setAccountOpen(false);
                        setShortcutsOpen(true);
                      }}
                    >
                      <CircleHelp className="h-4 w-4" aria-hidden="true" />
                    </Button>
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
                  </div>
                </div>
              )}
            </div>
          )}
          {logoutError && (
            <span className="max-w-40 truncate text-xs text-destructive" role="alert">
              {logoutError}
            </span>
          )}
        </div>
      </header>

      {preview && (
        <div
          role="note"
          data-testid="preview-read-only-banner"
          className="border-b border-status-warning/40 bg-status-warning/10 px-4 py-2 text-center text-sm"
        >
          {t("preview.readOnlyBanner")}
        </div>
      )}

      {!preview ? <SeededDemoBanner user={user} /> : null}

      {!isDesktop && (
        <Dialog
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          titleId="mobile-primary-navigation-title"
          returnFocusRef={mobileNavButtonRef}
          className="fixed inset-0 z-40"
          overlayClassName="absolute inset-0 bg-background/80 backdrop-blur-sm"
          panelClassName="h-full w-[min(20rem,calc(100vw-2rem))] overflow-y-auto border-e border-sidebar-active/40 bg-sidebar text-sidebar-foreground shadow-xl"
          panelAnimation="drawer"
        >
          <div id={mobileNavId} className="min-h-full">
            <div className="flex h-14 items-center justify-between border-b border-border px-4">
              <h2 id="mobile-primary-navigation-title" className="text-sm font-semibold">
                {t("shell.primaryNavigationDialog")}
              </h2>
              <Button type="button" size="icon" variant="outline" aria-label={t("shell.closePrimaryNavigation")} onClick={() => setMobileNavOpen(false)}>
                <X aria-hidden="true" className="h-4 w-4" />
              </Button>
            </div>
            <SpaceRail user={user} orientation="horizontal" onNavigate={() => setMobileNavOpen(false)} />
            <PrimaryNav id={`${mobileNavId}-links`} user={user} onNavigate={() => setMobileNavOpen(false)} />
          </div>
        </Dialog>
      )}

      <div className="flex min-w-0">
        {isDesktop && <SpaceRail user={user} orientation="vertical" />}
        {isDesktop && !sidebarCollapsed && (
          <PrimaryNav
            className="sticky top-14 h-[calc(100vh-3.5rem)] w-64 shrink-0 overflow-y-auto border-e border-sidebar-active/40 bg-sidebar text-sidebar-foreground"
            id="desktop-primary-nav"
            user={user}
          />
        )}

        <main id="main" ref={mainRef} className="mx-auto min-w-0 w-full max-w-[104rem] flex-1 p-4 md:p-7" tabIndex={-1}>
          {/* S-C3: pages are lazy chunks; the boundary announces while loading. */}
          <Suspense
            fallback={
              <p role="status" className="p-6">
                {t("app.loading")}
              </p>
            }
          >
            <CapabilityRouteNotice />
            <Outlet />
          </Suspense>
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

function SeededDemoBanner({ user }: { user: Me | null }) {
  const { t } = useTranslation();
  const hasQueryProvider = useHasAppQueryProvider();
  const isDemoPrincipal =
    user?.subject === "demo-admin" && user.email === "demo-admin@trstctl.local" && user.tenant_id === "11111111-1111-4111-8111-111111111111";
  // Ordinary deployments never pay for the Editions self-test here. Only the
  // exact local-demo principal asks the public license readout to prove that
  // this process is the bound demo deployment before the banner is shown.
  if (!hasQueryProvider || !isDemoPrincipal || typeof api.editions !== "function") return null;
  return <LiveSeededDemoBanner label={t("shell.seededDemoBanner")} />;
}

function LiveSeededDemoBanner({ label }: { label: string }) {
  const editions = useApiQuery(["deployment-edition"], api.editions);
  const isSeededDemo = editions.data?.deployment_entitlement?.deployment_id === "trstctl-local-demo";
  if (!isSeededDemo) return null;
  return (
    <div
      role="note"
      data-testid="seeded-demo-banner"
      className="border-b border-status-warning/40 bg-status-warning/10 px-4 py-2 text-center text-sm text-foreground"
    >
      {label}
    </div>
  );
}

function HeaderAlertIndicator() {
  const { t } = useTranslation();
  const hasQueryProvider = useHasAppQueryProvider();
  if (!hasQueryProvider || typeof api.notifications !== "function") {
    return <HeaderAlertLink label={t("nav.item.notifications")} />;
  }
  return <LiveHeaderAlertIndicator />;
}

function LiveHeaderAlertIndicator() {
  const { t } = useTranslation();
  const query = useApiQuery(["header-alerts"], () => api.notifications({ limit: 100 }), { live: { intervalMs: 30_000 } });
  const count = meaningfulAttention(query.data?.items ?? []).length;
  const label =
    count > 0
      ? t("notifications.center.headerCount", { count })
      : query.error
        ? t("notifications.center.headerUnavailable")
        : t("notifications.center.headerClear");
  return <HeaderAlertLink label={label} count={count} />;
}

function HeaderAlertLink({ label, count = 0 }: { label: string; count?: number }) {
  return (
    <Link
      to="/notifications"
      aria-label={label}
      title={label}
      className="relative inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-foreground transition-colors duration-fast hover:bg-foreground/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      <Bell className="h-4 w-4" aria-hidden="true" />
      {count > 0 ? (
        <span
          className="absolute -end-1 -top-1 min-w-4 rounded-control bg-risk-critical px-1 text-center text-2xs font-semibold leading-4 text-white"
          aria-hidden="true"
        >
          {count > 99 ? "99+" : count}
        </span>
      ) : null}
    </Link>
  );
}
