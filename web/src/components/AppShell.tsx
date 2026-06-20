import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  Braces,
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
  LockKeyhole,
  Rocket,
  ServerCog,
  Siren,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { ThemeToggle } from "@/components/ThemeToggle";
import { navGroups, type NavIcon } from "@/lib/navigation";
import { cn } from "@/lib/utils";

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
  risk: ShieldAlert,
  rocket: Rocket,
  secret: KeyRound,
  spiffe: Network,
  ssh: Braces,
};

function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window === "undefined" ? true : window.innerWidth >= 768,
  );

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
  return (
    <nav aria-label="Primary" className={cn("p-3", className)} id={id}>
      <ul className="space-y-4">
        {navGroups.map((group) => (
          <li key={group.label}>
            <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {group.label}
            </p>
            <ul className="space-y-1">
              {group.items.map(({ to, label, icon, end, mode }) => {
                const Icon = iconMap[icon];
                return (
                  <li key={`${group.label}-${to}-${label}`}>
                    <NavLink
                      to={to}
                      end={end}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        cn(
                          "flex min-h-9 items-center gap-2 rounded-md px-3 py-2 text-sm",
                          isActive ? "bg-muted font-medium" : "hover:bg-muted",
                        )
                      }
                    >
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1 truncate">{label}</span>
                      {mode === "disclosure" && (
                        <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                          map
                        </span>
                      )}
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

/** AppShell is the authenticated layout: a skip link, a banner header, a
 * navigation sidebar, and the routed main content — landmarked and keyboard
 * navigable for WCAG 2.1 AA. */
export function AppShell() {
  const { user } = useAuth();
  const isDesktop = useIsDesktop();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileNavId = "mobile-primary-nav";

  useEffect(() => {
    if (isDesktop) {
      setMobileNavOpen(false);
    }
  }, [isDesktop]);

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to main content
      </a>

      <header className="flex h-14 items-center justify-between border-b border-border px-4">
        <div className="flex min-w-0 items-center gap-2">
          {!isDesktop && (
            <button
              type="button"
              aria-controls={mobileNavId}
              aria-expanded={mobileNavOpen}
              aria-label={mobileNavOpen ? "Close primary navigation" : "Open primary navigation"}
              onClick={() => setMobileNavOpen((open) => !open)}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {mobileNavOpen ? (
                <X aria-hidden="true" className="h-4 w-4" />
              ) : (
                <Menu aria-hidden="true" className="h-4 w-4" />
              )}
            </button>
          )}
          <span className="truncate text-base font-semibold">trstctl</span>
        </div>
        <div className="flex items-center gap-3">
          <ThemeToggle />
          {user && (
            <span className="text-sm text-muted-foreground" data-testid="current-user">
              {user.email || user.subject}
            </span>
          )}
        </div>
      </header>

      {!isDesktop && mobileNavOpen && (
        <div className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm">
          <div
            aria-label="Primary navigation"
            aria-modal="true"
            className="h-full w-[min(20rem,calc(100vw-2rem))] overflow-y-auto border-r border-border bg-background shadow-xl"
            role="dialog"
          >
            <div className="flex h-14 items-center justify-between border-b border-border px-4">
              <span className="text-sm font-semibold">Navigation</span>
              <button
                type="button"
                aria-label="Close primary navigation"
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
        {isDesktop && (
          <PrimaryNav
            className="max-h-[calc(100vh-3.5rem)] w-72 shrink-0 overflow-y-auto border-r border-border"
            id="desktop-primary-nav"
          />
        )}

        <main id="main" className="min-w-0 flex-1 p-4 md:p-6" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
