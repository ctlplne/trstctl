import { type FormEvent, useCallback, useEffect, useState } from "react";
import { api, type Profile } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";

export function Profiles() {
  const [items, setItems] = useState<Profile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  const load = useCallback(async () => {
    try {
      setItems(await api.profiles());
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section aria-labelledby="profiles-heading">
      <div className="mb-4 flex items-center justify-between">
        <h1 id="profiles-heading" className="text-2xl font-semibold">
          Profiles
        </h1>
        <Button type="button" onClick={() => setShowForm((s) => !s)}>
          New profile
        </Button>
      </div>

      {showForm && (
        <ProfileForm
          onDone={() => {
            setShowForm(false);
            void load();
          }}
        />
      )}

      {error && (
        <p role="alert" className="mb-3 text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}

      {!items && <p role="status">Loading profiles...</p>}

      {items && items.length === 0 && !showForm && (
        <EmptyState title="No profiles yet">Create a certificate profile before issuing from a constrained template.</EmptyState>
      )}

      {items && items.length > 0 && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Certificate profile versions</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Name</th>
              <th scope="col" className="py-2 pr-4 font-medium">Version</th>
              <th scope="col" className="py-2 pr-4 font-medium">Active</th>
              <th scope="col" className="py-2 font-medium">Created by</th>
            </tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={`${p.name}:${p.version}`} className="border-b border-border">
                <td className="py-2 pr-4">{p.name}</td>
                <td className="py-2 pr-4">{p.version}</td>
                <td className="py-2 pr-4">{p.active ? "yes" : "no"}</td>
                <td className="py-2">{p.created_by ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ProfileForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [spec, setSpec] = useState('{"subject":{"common_name":"{{ identity.name }}"}}');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.createProfile({ name: name.trim(), spec: JSON.parse(spec) });
      onDone();
    } catch (err) {
      setError(`Could not create profile: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mb-4 space-y-3 rounded-md border border-border p-4">
      <div className="space-y-1">
        <label htmlFor="profile-name" className="block text-sm font-medium">
          Profile name
        </label>
        <input
          id="profile-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          required
        />
      </div>
      <div className="space-y-1">
        <label htmlFor="profile-spec" className="block text-sm font-medium">
          JSON spec
        </label>
        <textarea
          id="profile-spec"
          value={spec}
          onChange={(e) => setSpec(e.target.value)}
          className="min-h-28 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
          required
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        Create profile
      </Button>
    </form>
  );
}
