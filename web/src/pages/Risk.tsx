import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";

const privilegeLabel = ["Low", "Standard", "High", "Critical"];

export function Risk() {
  const { data, loading, error } = useResource(api.risk);
  return (
    <section aria-labelledby="risk-heading">
      <h1 id="risk-heading" className="mb-4 text-2xl font-semibold">
        Credential risk
      </h1>
      <p className="mb-4 text-sm text-muted-foreground">Ranked by composite score — what to rotate first.</p>
      {loading && <p role="status">Loading risk scores…</p>}
      {error && <p role="alert">Could not load risk scores: {error}</p>}
      {data && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Credentials ranked by risk score</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Credential</th>
              <th scope="col" className="py-2 pr-4 font-medium">Score</th>
              <th scope="col" className="py-2 pr-4 font-medium">Exposure</th>
              <th scope="col" className="py-2 font-medium">Owner</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td colSpan={4} className="py-4 text-muted-foreground">No credentials scored yet.</td>
              </tr>
            )}
            {data.map((c) => (
              <tr key={c.credential_id} className="border-b border-border">
                <td className="py-2 pr-4">{c.subject}</td>
                <td className="py-2 pr-4 font-medium">{Math.round(c.score)}</td>
                <td className="py-2 pr-4">{c.exposure}</td>
                <td className="py-2">{c.owner_active ? "active" : "orphaned"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export { privilegeLabel };
