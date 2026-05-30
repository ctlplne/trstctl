import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";

export function Owners() {
  const { data, loading, error } = useResource(api.owners);
  return (
    <section aria-labelledby="owners-heading">
      <h1 id="owners-heading" className="mb-4 text-2xl font-semibold">
        Owners
      </h1>
      {loading && <p role="status">Loading owners…</p>}
      {error && <p role="alert">Could not load owners: {error}</p>}
      {data && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Credential owners</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Name</th>
              <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
              <th scope="col" className="py-2 font-medium">Email</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td colSpan={3} className="py-4 text-muted-foreground">No owners yet.</td>
              </tr>
            )}
            {data.map((o) => (
              <tr key={o.id} className="border-b border-border">
                <td className="py-2 pr-4">{o.name}</td>
                <td className="py-2 pr-4">{o.kind}</td>
                <td className="py-2">{o.email ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
