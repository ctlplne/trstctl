import { useAuth } from "@/auth/AuthProvider";
import { UnavailableState } from "@/components/StatePrimitives";
import { realGuiSurfaces } from "@/lib/navigation";

function browserTransport(): { label: string; detail: string } {
  if (typeof window === "undefined") {
    return { label: "Unknown", detail: "Browser transport is evaluated at runtime." };
  }
  if (window.location.protocol === "https:") {
    return {
      label: "HTTPS observed",
      detail: "The console is currently loaded over an encrypted browser connection.",
    };
  }
  return {
    label: "Local preview HTTP",
    detail: "The local Vite preview is HTTP. The production binary serves TLS by default.",
  };
}

export function Platform() {
  const { user } = useAuth();
  const transport = browserTransport();
  const nonLedgerSurfaces = realGuiSurfaces.filter((s) => s.routes.some((route) => route !== "/coverage"));

  return (
    <section aria-labelledby="platform-heading" className="grid gap-6">
      <div>
        <h1 id="platform-heading" className="text-2xl font-semibold">
          Platform
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Tenant context, browser transport posture, and the registry of GUI surfaces that are
          real routes rather than only rows on the coverage ledger.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="border-y border-border py-4" aria-labelledby="tenant-heading">
          <h2 id="tenant-heading" className="text-lg font-semibold">
            Tenant boundary
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{user?.email || user?.subject || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Tenant ID</dt>
              <dd className="break-all font-mono text-xs">{user?.tenant_id || "-"}</dd>
            </div>
          </dl>
        </section>

        <section className="border-y border-border py-4" aria-labelledby="transport-heading">
          <h2 id="transport-heading" className="text-lg font-semibold">
            Transport
          </h2>
          <p className="mt-3 text-sm font-medium">{transport.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
        </section>

        <section className="border-y border-border py-4" aria-labelledby="parity-heading">
          <h2 id="parity-heading" className="text-lg font-semibold">
            Route parity
          </h2>
          <p className="mt-3 text-3xl font-semibold">{nonLedgerSurfaces.length}</p>
          <p className="text-sm text-muted-foreground">
            served-feature GUI mappings point at non-ledger routes.
          </p>
        </section>
      </div>

      <section aria-labelledby="surfaces-heading">
        <h2 id="surfaces-heading" className="mb-3 text-lg font-semibold">
          Registered real surfaces
        </h2>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Real GUI route registry</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Feature</th>
              <th scope="col" className="py-2 pr-4 font-medium">Routes</th>
              <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
              <th scope="col" className="py-2 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {realGuiSurfaces.map((surface) => (
              <tr key={surface.featureId} className="border-b border-border align-top">
                <td className="py-2 pr-4 font-mono text-xs">{surface.featureId}</td>
                <td className="py-2 pr-4">{surface.routes.join(", ")}</td>
                <td className="py-2 pr-4">{surface.kind}</td>
                <td className="py-2">{surface.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <UnavailableState title="Platform status endpoint not served yet">
        Live build info, datastore mode, signer-child state, feature flags, tenant admin,
        and runtime OpenAPI publication are tracked as backend-serving gaps. This page
        shows only data the browser and authenticated session can honestly observe today.
      </UnavailableState>
    </section>
  );
}
