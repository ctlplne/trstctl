import { useEffect, useRef, useState, type RefObject } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  Braces,
  CircleHelp,
  FileClock,
  GitFork,
  LayoutDashboard,
  Menu,
  Network,
  RadioTower,
  ScrollText,
  Settings2,
  ShieldAlert,
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
  X,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { CommandPalette } from "@/components/CommandPalette";
import { ShortcutsHelp } from "@/components/ShortcutsHelp";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import { contextualRouteItems, navGroups, taskNavItems, type NavIcon } from "@/lib/navigation";
import { cn } from "@/lib/utils";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";
import { localeLabelKeys, supportedLocales, type Locale, type MessageKey } from "@/i18n/messages";

const iconMap: Record<NavIcon, typeof Activity> = {
  activity: Activity,
  audit: FileClock,
  bot: Bot,
  certificate: ScrollText,
  connector: Boxes,
  dashboard: LayoutDashboard,
  graph: GitFork,
  identity: KeyRound,
  incident: Siren,
  key: LockKeyhole,
  owner: Users,
  platform: ServerCog,
  policy: Settings2,
  profile: Settings2,
  protocol: RadioTower,
  notification: Bell,
  risk: ShieldAlert,
  rocket: Rocket,
  secret: KeyRound,
  signature: Signature,
  spiffe: Network,
  ssh: Braces,
};

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
};

function PrimaryNav({ className, id, onNavigate }: PrimaryNavProps) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t("shell.primaryNavigation")} className={cn("p-3", className)} id={id}>
      <ul className="space-y-4">
        <li>
          <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60">{t("nav.section.needsAction")}</p>
          <ul aria-label={t("nav.section.needsActionWorklists")} className="space-y-1">
            {taskNavItems.map(({ to, labelKey, descriptionKey, icon }) => {
              const Icon = iconMap[icon];
              const label = t(labelKey);
              const description = t(descriptionKey);
              return (
                <li key={`task-${to}`}>
                  <NavLink
                    to={to}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        "flex min-h-12 items-start gap-2 rounded-control px-3 py-2 text-sm transition-colors",
                        isActive ? "bg-sidebar-active font-semibold text-white" : "text-sidebar-foreground hover:bg-sidebar-hover hover:text-white",
                      )
                    }
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
        {navGroups.map((group) => (
          <li key={group.labelKey}>
            <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60">{t(group.labelKey)}</p>
            <ul className="space-y-1">
              {group.items.map((item) => {
                const { to, labelKey, icon, end } = item;
                const label = t(labelKey);
                const Icon = iconMap[icon];
                return (
                  <li key={`${group.labelKey}-${to}-${labelKey}`}>
                    <NavLink
                      to={to}
                      end={end}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        cn(
                          "flex min-h-9 items-center gap-2 rounded-control px-3 py-2 text-sm transition-colors",
                          isActive ? "bg-sidebar-active font-semibold text-white" : "text-sidebar-foreground hover:bg-sidebar-hover hover:text-white",
                        )
                      }
                    >
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1 truncate">{label}</span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
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
            <span className="block truncate text-sm font-semibold tracking-tight">{t("app.brand.name")}</span>
            <span className="hidden truncate text-[10px] font-medium uppercase tracking-wider text-brand-accent sm:block">{t("app.brand.subtitle")}</span>
          </span>
        </div>
        <div className="flex min-w-0 items-center gap-2">
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
              {supportedLocales.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {t(localeLabelKeys[candidate])}
                </option>
              ))}
            </select>
          </label>
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
            <PrimaryNav id={mobileNavId} onNavigate={() => setMobileNavOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0">
        {isDesktop && !sidebarCollapsed && (
          <PrimaryNav
            className="sticky top-14 h-[calc(100vh-3.5rem)] w-64 shrink-0 overflow-y-auto border-e border-sidebar-active/40 bg-sidebar text-sidebar-foreground"
            id="desktop-primary-nav"
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
      <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} returnFocusRef={commandButtonRef} />
      <ShortcutsHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} returnFocusRef={shortcutsButtonRef} />
    </div>
  );
}
