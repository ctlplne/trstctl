import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { lazy, type ComponentType, type ReactElement } from "react";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider, useAuth } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { RbacProvider } from "@/components/rbac";
import { ToastProvider } from "@/components/ToastProvider";
import { IntlProvider, useTranslation } from "@/i18n/I18nProvider";
import { isSupportedLocale } from "@/i18n/messages";
import { AppQueryProvider } from "@/lib/query";
// Login stays an eager import: it is the pre-auth fast path and must render
// without waiting on a second chunk.
import { Login } from "@/pages/Login";

/** S-C3: every authenticated page is lazy-loaded, so the entry chunk is the
 * shell (providers, AppShell, Login) and each surface loads on first visit —
 * Vite emits one chunk per page module, which composes naturally with the
 * spaces IA. Pages use named exports; lazyPage adapts them to React.lazy's
 * default-export contract. The Suspense boundary wraps the shell's Outlet. */
function lazyPage<M extends Record<K, ComponentType>, K extends string>(loader: () => Promise<M>, name: K) {
  return lazy(() => loader().then((module) => ({ default: module[name] })));
}

const Dashboard = lazyPage(() => import("@/pages/Dashboard"), "Dashboard");
const Certificates = lazyPage(() => import("@/pages/Certificates"), "Certificates");
const Identities = lazyPage(() => import("@/pages/Identities"), "Identities");
const Owners = lazyPage(() => import("@/pages/Owners"), "Owners");
const Risk = lazyPage(() => import("@/pages/Risk"), "Risk");
const Agents = lazyPage(() => import("@/pages/Agents"), "Agents");
const Wizard = lazyPage(() => import("@/pages/Wizard"), "Wizard");
const Assistant = lazyPage(() => import("@/pages/Assistant"), "Assistant");
const Profiles = lazyPage(() => import("@/pages/Profiles"), "Profiles");
const Audit = lazyPage(() => import("@/pages/Audit"), "Audit");
const Graph = lazyPage(() => import("@/pages/Graph"), "Graph");
const Migration = lazyPage(() => import("@/pages/Migration"), "Migration");
const AdminAccess = lazyPage(() => import("@/pages/Platform"), "AdminAccess");
const AdminEditions = lazyPage(() => import("@/pages/Platform"), "AdminEditions");
const AdminSystem = lazyPage(() => import("@/pages/Platform"), "AdminSystem");
const PlatformRedirect = lazyPage(() => import("@/pages/Platform"), "PlatformRedirect");
const Protocols = lazyPage(() => import("@/pages/Protocols"), "Protocols");
const Secrets = lazyPage(() => import("@/pages/Secrets"), "Secrets");
const Policy = lazyPage(() => import("@/pages/Policy"), "Policy");
const Privacy = lazyPage(() => import("@/pages/Privacy"), "Privacy");
const Integrate = lazyPage(() => import("@/pages/Integrate"), "Integrate");
const ApiExplorer = lazyPage(() => import("@/pages/ApiExplorer"), "ApiExplorer");
const Discovery = lazyPage(() => import("@/pages/Discovery"), "Discovery");
const Posture = lazyPage(() => import("@/pages/Posture"), "Posture");
const CAHierarchy = lazyPage(() => import("@/pages/CAHierarchy"), "CAHierarchy");
const Workloads = lazyPage(() => import("@/pages/Workloads"), "Workloads");
const SSHTrust = lazyPage(() => import("@/pages/SSHTrust"), "SSHTrust");
const Connectors = lazyPage(() => import("@/pages/Connectors"), "Connectors");
const CodeSigning = lazyPage(() => import("@/pages/CodeSigning"), "CodeSigning");
const Incidents = lazyPage(() => import("@/pages/Incidents"), "Incidents");
const Approvals = lazyPage(() => import("@/pages/Approvals"), "Approvals");
const Operations = lazyPage(() => import("@/pages/Operations"), "Operations");
const Notifications = lazyPage(() => import("@/pages/Notifications"), "Notifications");
const RequestCredential = lazyPage(() => import("@/pages/RequestCredential"), "RequestCredential");
const Styleguide = lazyPage(() => import("@/pages/Styleguide"), "Styleguide");
const Journeys = lazyPage(() => import("@/pages/Journeys"), "Journeys");

/** RequireAuth gates the app behind a resolved session, redirecting to login
 * when there is none. */
function RequireAuth({ children }: { children: ReactElement }) {
  const { user, loading } = useAuth();
  const { t } = useTranslation();
  if (loading) {
    return (
      <p role="status" className="p-6">
        {t("app.loading")}
      </p>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <RbacProvider permissions={user.permissions ?? null}>{children}</RbacProvider>;
}

/** AppRoutes is the route table, separated from the router so tests can mount it
 * inside a MemoryRouter. */
export function AppRoutes() {
  return (
    <AppQueryProvider>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="certificates" element={<Certificates />} />
            <Route path="identities" element={<Identities />} />
            <Route path="owners" element={<Owners />} />
            <Route path="agents" element={<Agents />} />
            <Route path="discovery" element={<Discovery />} />
            <Route path="profiles" element={<Profiles />} />
            <Route path="request" element={<RequestCredential />} />
            <Route path="ca-hierarchy" element={<CAHierarchy />} />
            <Route path="workloads" element={<Workloads />} />
            <Route path="protocols" element={<Protocols />} />
            <Route path="ssh" element={<SSHTrust />} />
            <Route path="codesign" element={<CodeSigning />} />
            <Route path="secrets" element={<Secrets />} />
            {/* S-C2: the Secrets workspaces are routes in the Secrets space
              sidebar; the page derives its workspace from the pathname, and
              historical /secrets?tab= deep links redirect permanently. */}
            <Route path="secrets/access" element={<Secrets />} />
            <Route path="secrets/sharing" element={<Secrets />} />
            <Route path="secrets/engines" element={<Secrets />} />
            <Route path="secrets/scanning" element={<Secrets />} />
            <Route path="secrets/sync" element={<Secrets />} />
            <Route path="connectors" element={<Connectors />} />
            <Route path="policy" element={<Policy />} />
            <Route path="risk" element={<Risk />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="approvals" element={<Approvals />} />
            <Route path="operations" element={<Operations />} />
            <Route path="notifications" element={<Notifications />} />
            <Route path="posture" element={<Posture />} />
            <Route path="graph" element={<Graph />} />
            <Route path="migration" element={<Migration />} />
            <Route path="audit" element={<Audit />} />
            <Route path="privacy" element={<Privacy />} />
            <Route path="integrate" element={<Integrate />} />
            <Route path="integrate/api" element={<ApiExplorer />} />
            <Route path="assistant" element={<Assistant />} />
            <Route path="wizard" element={<Wizard />} />
            <Route path="admin/access" element={<AdminAccess />} />
            <Route path="admin/system" element={<AdminSystem />} />
            <Route path="admin/editions" element={<AdminEditions />} />
            {/* C-A1: /platform (and its historical ?tab= deep links) redirects
              permanently to the split /admin/* routes. */}
            <Route path="platform" element={<PlatformRedirect />} />
            <Route path="styleguide" element={<Styleguide />} />
            <Route path="journeys" element={<Journeys />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ToastProvider>
    </AppQueryProvider>
  );
}

function SessionI18nProvider({ children }: { children: ReactElement }) {
  const { user } = useAuth();
  const serverLocale = user?.locale && isSupportedLocale(user.locale) ? user.locale : undefined;
  return (
    <IntlProvider serverLocale={serverLocale} serverTimeZone={user?.time_zone}>
      {children}
    </IntlProvider>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <SessionI18nProvider>
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </SessionI18nProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
