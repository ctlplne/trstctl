import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  Braces,
  FileClock,
  GitFork,
  LayoutDashboard,
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

/** AppShell is the authenticated layout: a skip link, a banner header, a
 * navigation sidebar, and the routed main content — landmarked and keyboard
 * navigable for WCAG 2.1 AA. */
export function AppShell() {
  const { user } = useAuth();
  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to main content
      </a>

      <header className="flex h-14 items-center justify-between border-b border-border px-4">
        <span className="text-base font-semibold">trstctl</span>
        <div className="flex items-center gap-3">
          <ThemeToggle />
          {user && (
            <span className="text-sm text-muted-foreground" data-testid="current-user">
              {user.email || user.subject}
            </span>
          )}
        </div>
      </header>

      <div className="flex">
        <nav
          aria-label="Primary"
          className="max-h-[calc(100vh-3.5rem)] w-72 shrink-0 overflow-y-auto border-r border-border p-3"
        >
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

        <main id="main" className="flex-1 p-6" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
