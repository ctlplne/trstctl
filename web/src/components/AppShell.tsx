import { NavLink, Outlet } from "react-router-dom";
import { LayoutDashboard, ScrollText, Users, ShieldAlert, KeyRound, Rocket } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { ThemeToggle } from "@/components/ThemeToggle";
import { cn } from "@/lib/utils";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/certificates", label: "Certificates", icon: ScrollText },
  { to: "/identities", label: "Identities", icon: KeyRound },
  { to: "/owners", label: "Owners", icon: Users },
  { to: "/risk", label: "Risk", icon: ShieldAlert },
  { to: "/wizard", label: "Set up", icon: Rocket },
];

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
        <nav aria-label="Primary" className="w-56 shrink-0 border-r border-border p-3">
          <ul className="space-y-1">
            {nav.map(({ to, label, icon: Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                      isActive ? "bg-muted font-medium" : "hover:bg-muted",
                    )
                  }
                >
                  <Icon aria-hidden="true" className="h-4 w-4" />
                  {label}
                </NavLink>
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
