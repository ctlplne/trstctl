import { useCallback, useEffect, useState } from "react";
import { api, ApiError, identityState, type Identity, type TransitionTo } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";

/** action is a lifecycle transition offered for a given state. `to` is bound to the
 * OpenAPI-generated transition enum (TransitionTo), so the UI can never offer (or send)
 * a target the served contract does not accept — drift here fails the build. */
interface Action {
  label: string;
  to: TransitionTo;
}

/** isDestructive reports whether a target state is a destructive transition that must
 * be confirmed before it runs — revoke permanently invalidates the credential, and
 * retire discards it (SURFACE-007). */
function isDestructive(to: TransitionTo): boolean {
  return to === "revoked" || to === "retired";
}

/** errorMessage renders an action error, special-casing a 429 so the user sees a
 * concrete retry hint (Retry-After) instead of a bare failure (SURFACE-007). */
function errorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null
      ? `Rate limited — please retry in ${err.retryAfterSeconds}s.`
      : "Rate limited — please retry shortly.";
  }
  return `Action failed: ${String(err)}`;
}

/** actionsFor returns the lifecycle actions valid from a state — the UI mirror
 * of the orchestrator's transition table (issue → deploy → renew, revoke, and
 * retire). */
function actionsFor(state: string): Action[] {
  switch (state) {
    case "requested":
      return [{ label: "Issue", to: "issued" }];
    case "issued":
      return [
        { label: "Deploy", to: "deployed" },
        { label: "Revoke", to: "revoked" },
      ];
    case "deployed":
      return [
        { label: "Renew", to: "renewing" },
        { label: "Revoke", to: "revoked" },
      ];
    case "renewing":
      return [{ label: "Revoke", to: "revoked" }];
    case "revoked":
      return [{ label: "Retire", to: "retired" }];
    default:
      return [];
  }
}

export function Identities() {
  const [items, setItems] = useState<Identity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  // A destructive transition awaiting explicit confirmation (SURFACE-007). null
  // means no confirmation is pending.
  const [pending, setPending] = useState<{ id: string; name: string; to: TransitionTo; label: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setItems(await api.identities());
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function act(id: string, to: TransitionTo) {
    setBusyId(id);
    setError(null);
    try {
      await api.transitionIdentity(id, to, `${to} via UI`);
      await load();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  /** request runs a transition immediately, EXCEPT a destructive one (revoke/retire)
   * which is first parked in `pending` so the user must confirm it in a dialog that
   * names the credential (SURFACE-007). */
  function request(id: string, name: string, to: TransitionTo, label: string) {
    if (isDestructive(to)) {
      setPending({ id, name, to, label });
      return;
    }
    void act(id, to);
  }

  return (
    <section aria-labelledby="identities-heading">
      <div className="mb-4 flex items-center justify-between">
        <h1 id="identities-heading" className="text-2xl font-semibold">
          Identities
        </h1>
        <Button type="button" onClick={() => setShowForm((s) => !s)}>
          New identity
        </Button>
      </div>

      {showForm && (
        <NewIdentityForm
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

      {pending && (
        <div
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="confirm-title"
          aria-describedby="confirm-desc"
          className="mb-4 rounded-md border border-red-300 bg-red-50 p-4 dark:border-red-800 dark:bg-red-950"
        >
          <h2 id="confirm-title" className="text-sm font-semibold text-red-700 dark:text-red-300">
            {pending.label} “{pending.name}”?
          </h2>
          <p id="confirm-desc" className="mt-1 text-sm text-red-700 dark:text-red-300">
            {pending.to === "revoked"
              ? `Revoking “${pending.name}” permanently invalidates the credential; relying parties will stop trusting it. This cannot be undone.`
              : `Retiring “${pending.name}” discards the credential record. This cannot be undone.`}
          </p>
          <div className="mt-3 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="border-red-400 text-red-700 hover:bg-red-100 dark:text-red-300"
              disabled={busyId === pending.id}
              onClick={() => {
                const p = pending;
                setPending(null);
                void act(p.id, p.to);
              }}
            >
              {`Yes, ${pending.label.toLowerCase()}`}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setPending(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {!items && <p role="status">Loading identities…</p>}

      {items && items.length === 0 && !showForm && (
        <EmptyState
          title="No identities yet"
          ctaTo="/wizard"
          ctaLabel="Set up your first certificate"
        >
          Issue your first certificate to start tracking and rotating credentials.
        </EmptyState>
      )}

      {items && items.length > 0 && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Credential identities and their lifecycle state</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Name</th>
              <th scope="col" className="py-2 pr-4 font-medium">State</th>
              <th scope="col" className="py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => {
              const state = identityState(i);
              return (
                <tr key={i.id} className="border-b border-border">
                  <td className="py-2 pr-4">{i.name}</td>
                  <td className="py-2 pr-4">
                    <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{state}</span>
                  </td>
                  <td className="py-2">
                    <div className="flex gap-2">
                      {actionsFor(state).map((a) => (
                        <Button
                          key={a.to}
                          type="button"
                          size="sm"
                          variant={isDestructive(a.to) ? "outline" : "default"}
                          disabled={busyId === i.id}
                          onClick={() => request(i.id, i.name, a.to, a.label)}
                        >
                          {a.label}
                        </Button>
                      ))}
                      {actionsFor(state).length === 0 && (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NewIdentityForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.issueCertificate({ name: name.trim() || "new-service" });
      onDone();
    } catch (err) {
      setError(`Could not issue: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mb-4 flex items-end gap-3 rounded-md border border-border p-4">
      <div className="flex-1 space-y-1">
        <label htmlFor="new-identity-name" className="block text-sm font-medium">
          Service name
        </label>
        <input
          id="new-identity-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder="e.g. payments-api"
        />
      </div>
      <Button type="submit" disabled={busy}>
        Issue
      </Button>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </form>
  );
}
