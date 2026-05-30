import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";

export function Certificates() {
  const { data, loading, error } = useResource(api.certificates);
  return (
    <section aria-labelledby="certs-heading">
      <h1 id="certs-heading" className="mb-4 text-2xl font-semibold">
        Certificates
      </h1>
      {loading && <p role="status">Loading certificates…</p>}
      {error && <p role="alert">Could not load certificates: {error}</p>}
      {data && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Inventoried certificates</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Subject</th>
              <th scope="col" className="py-2 pr-4 font-medium">Issuer</th>
              <th scope="col" className="py-2 pr-4 font-medium">Expires</th>
              <th scope="col" className="py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td colSpan={4} className="py-4 text-muted-foreground">No certificates yet.</td>
              </tr>
            )}
            {data.map((c) => (
              <tr key={c.id} className="border-b border-border">
                <td className="py-2 pr-4">{c.subject}</td>
                <td className="py-2 pr-4">{c.issuer ?? "—"}</td>
                <td className="py-2 pr-4">{c.not_after ? new Date(c.not_after).toLocaleDateString() : "—"}</td>
                <td className="py-2">{c.status ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
