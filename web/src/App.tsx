import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import type { ReactElement } from "react";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider, useAuth } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { Login } from "@/pages/Login";
import { Dashboard } from "@/pages/Dashboard";
import { Certificates } from "@/pages/Certificates";
import { Identities } from "@/pages/Identities";
import { Owners } from "@/pages/Owners";
import { Risk } from "@/pages/Risk";
import { Agents } from "@/pages/Agents";
import { Wizard } from "@/pages/Wizard";
import { Assistant } from "@/pages/Assistant";
import { Profiles } from "@/pages/Profiles";
import { Audit } from "@/pages/Audit";
import { Graph } from "@/pages/Graph";
import { FeatureCoverage } from "@/pages/FeatureCoverage";
import { Platform } from "@/pages/Platform";
import { Protocols } from "@/pages/Protocols";
import { Secrets } from "@/pages/Secrets";
import { Policy } from "@/pages/Policy";
import { Discovery } from "@/pages/Discovery";
import { Posture } from "@/pages/Posture";
import { CAHierarchy } from "@/pages/CAHierarchy";
import { Workloads } from "@/pages/Workloads";
import { SSHTrust } from "@/pages/SSHTrust";

/** RequireAuth gates the app behind a resolved session, redirecting to login
 * when there is none. */
function RequireAuth({ children }: { children: ReactElement }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <p role="status" className="p-6">
        Loading…
      </p>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

/** AppRoutes is the route table, separated from the router so tests can mount it
 * inside a MemoryRouter. */
export function AppRoutes() {
  return (
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
        <Route path="coverage" element={<FeatureCoverage />} />
        <Route path="identities" element={<Identities />} />
        <Route path="owners" element={<Owners />} />
        <Route path="agents" element={<Agents />} />
        <Route path="discovery" element={<Discovery />} />
        <Route path="profiles" element={<Profiles />} />
        <Route path="ca-hierarchy" element={<CAHierarchy />} />
        <Route path="workloads" element={<Workloads />} />
        <Route path="protocols" element={<Protocols />} />
        <Route path="ssh" element={<SSHTrust />} />
        <Route path="secrets" element={<Secrets />} />
        <Route path="policy" element={<Policy />} />
        <Route path="risk" element={<Risk />} />
        <Route path="posture" element={<Posture />} />
        <Route path="graph" element={<Graph />} />
        <Route path="audit" element={<Audit />} />
        <Route path="assistant" element={<Assistant />} />
        <Route path="wizard" element={<Wizard />} />
        <Route path="platform" element={<Platform />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}
