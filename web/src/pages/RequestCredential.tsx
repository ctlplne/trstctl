import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Send } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { api, ApiError, identityState, type Identity, type Profile } from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

function problemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : String(err);
}

function profileKey(profile: Profile): string {
  return `${profile.name}:${profile.version}`;
}

function requesterFor(user: ReturnType<typeof useAuth>["user"]): string {
  return user?.email || user?.subject || "";
}

function isRequesterIdentity(identity: Identity, requester: string, subject?: string): boolean {
  const attrRequester = identity.attributes?.requester;
  return (typeof attrRequester === "string" && attrRequester === requester) || (subject != null && identity.owner_id === subject);
}

function profileLabel(identity: Identity): string {
  const name = identity.attributes?.profile_name;
  const version = identity.attributes?.profile_version;
  if (typeof name !== "string" || !name) return "not served";
  return typeof version === "number" || typeof version === "string" ? `${name} v${version}` : name;
}

function approvalCount(identity: Identity): string | null {
  const approvals = identity.attributes?.approvals;
  if (typeof approvals !== "string" || !approvals.trim()) return null;
  const [done, total] = approvals.split("/");
  if (!done || !total) return approvals;
  return `${done.trim()} of ${total.trim()}`;
}

function requestStage(identity: Identity): string {
  const state = identityState(identity);
  if (state === "requested") {
    const approvals = approvalCount(identity);
    return approvals ? `Awaiting approval ${approvals}` : "Accepted";
  }
  if (state === "issued" || state === "deployed") return "Issued";
  if (state === "revoked") return "Revoked";
  if (state === "retired") return "Retired";
  return state ? state.replace(/[_-]+/g, " ") : "Unknown";
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

export function RequestCredential() {
  const { user } = useAuth();
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [requests, setRequests] = useState<Identity[] | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [selectedProfileKey, setSelectedProfileKey] = useState("");
  const [name, setName] = useState("");
  const [ownerId, setOwnerId] = useState("");
  const [purpose, setPurpose] = useState("");
  const [busy, setBusy] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const requester = requesterFor(user);

  const loadProfiles = useCallback(async () => {
    try {
      setProfiles(await api.profiles());
      setProfileError(null);
    } catch (err) {
      setProfiles([]);
      setProfileError(problemMessage(err, "Could not load profiles"));
    }
  }, []);

  const loadRequests = useCallback(async () => {
    try {
      const identities = await api.identities();
      setRequests(identities);
      setRequestError(null);
    } catch (err) {
      setRequests([]);
      setRequestError(problemMessage(err, "Could not load requests"));
    }
  }, []);

  useEffect(() => {
    void loadProfiles();
    void loadRequests();
  }, [loadProfiles, loadRequests]);

  useEffect(() => {
    if (!ownerId && user?.subject) setOwnerId(user.subject);
  }, [ownerId, user?.subject]);

  const activeProfiles = useMemo(() => (profiles ?? []).filter((profile) => profile.active !== false).sort((a, b) => a.name.localeCompare(b.name)), [profiles]);

  useEffect(() => {
    if (!selectedProfileKey && activeProfiles.length > 0) setSelectedProfileKey(profileKey(activeProfiles[0]));
  }, [activeProfiles, selectedProfileKey]);

  const selectedProfile = activeProfiles.find((profile) => profileKey(profile) === selectedProfileKey) ?? null;
  const myRequests = useMemo(
    () =>
      (requests ?? [])
        .filter((identity) => isRequesterIdentity(identity, requester, user?.subject))
        .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? "")),
    [requester, requests, user?.subject],
  );

  const requestColumns = useMemo<Array<DataGridColumn<Identity>>>(
    () => [
      {
        id: "name",
        header: "Credential",
        cell: (identity) => <span className="font-medium">{identity.name}</span>,
      },
      {
        id: "profile",
        header: "Profile",
        cell: (identity) => profileLabel(identity),
      },
      {
        id: "stage",
        header: "Request stage",
        cell: (identity) => requestStage(identity),
      },
      {
        id: "lifecycle",
        header: "Lifecycle",
        cell: (identity) => <StatusBadge vocabulary="lifecycle" value={identityState(identity) || "requested"} />,
      },
      {
        id: "requested",
        header: "Requested",
        cell: (identity) => formatDate(identity.created_at),
      },
    ],
    [],
  );

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitError(null);
    setNotice(null);

    const trimmedName = name.trim();
    const trimmedOwner = ownerId.trim();
    if (!selectedProfile || !trimmedName || !trimmedOwner) {
      setSubmitError("Profile, credential name, and owner id are required.");
      return;
    }

    setBusy(true);
    try {
      const created = await api.createIdentity({
        kind: "x509_certificate",
        name: trimmedName,
        owner_id: trimmedOwner,
        attributes: {
          requester,
          profile_name: selectedProfile.name,
          profile_version: selectedProfile.version,
          purpose: purpose.trim(),
        },
      });
      setRequests((current) => {
        const rows = current ?? [];
        return [created, ...rows.filter((identity) => identity.id !== created.id)];
      });
      setNotice(`Request accepted for ${created.name}. It is awaiting approval; no certificate has been minted yet.`);
      setName("");
      setPurpose("");
    } catch (err) {
      setSubmitError(problemMessage(err, "Could not submit request"));
    } finally {
      setBusy(false);
    }
  }

  const requestGridState: DataGridState = requestError ? "error" : requests == null ? "loading" : myRequests.length ? "ready" : "empty";

  return (
    <section aria-labelledby="request-credential-heading" className="grid gap-6">
      <PageHeader
        title="Request a credential"
        titleId="request-credential-heading"
        description="Submit a profile-bound X.509 request as the session requester. Approval and issuance stay separate lifecycle steps."
      />

      {notice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-body text-status-success">
          {notice}
        </p>
      )}

      <section aria-labelledby="new-request-heading">
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.6fr)]">
          <form aria-labelledby="new-request-heading" className="grid gap-4" onSubmit={submit}>
            <h2 id="new-request-heading" className="text-title font-semibold">
              New request
            </h2>

            {profileError && <ErrorState title="Profile list unavailable">{profileError}</ErrorState>}
            {profiles == null && !profileError && <LoadingState>Loading profiles...</LoadingState>}
            {profiles && activeProfiles.length === 0 && (
              <EmptyState title="No active profiles">Create or activate a certificate profile before self-service requests can be accepted.</EmptyState>
            )}

            <div className="grid gap-4 md:grid-cols-2">
              <label className="grid gap-1 text-body font-medium" htmlFor="request-profile">
                Profile
                <select
                  id="request-profile"
                  value={selectedProfileKey}
                  onChange={(event) => setSelectedProfileKey(event.target.value)}
                  className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                  disabled={activeProfiles.length === 0}
                  required
                >
                  {activeProfiles.map((profile) => (
                    <option key={profileKey(profile)} value={profileKey(profile)}>
                      {`${profile.name} v${profile.version}${profile.active ? " active" : ""}`}
                    </option>
                  ))}
                </select>
              </label>

              <label className="grid gap-1 text-body font-medium" htmlFor="request-owner">
                Owner id
                <input
                  id="request-owner"
                  value={ownerId}
                  onChange={(event) => setOwnerId(event.target.value)}
                  className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                  required
                />
              </label>
            </div>

            <label className="grid gap-1 text-body font-medium" htmlFor="request-name">
              Credential name
              <input
                id="request-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                placeholder="payments-api"
                required
              />
            </label>

            <label className="grid gap-1 text-body font-medium" htmlFor="request-purpose">
              Business purpose
              <textarea
                id="request-purpose"
                value={purpose}
                onChange={(event) => setPurpose(event.target.value)}
                className="min-h-20 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                placeholder="service TLS for staging"
              />
            </label>

            {submitError && <ErrorState title="Request failed">{submitError}</ErrorState>}

            <div>
              <Button type="submit" disabled={busy || activeProfiles.length === 0}>
                <Send className="h-4 w-4" aria-hidden="true" />
                Submit request
              </Button>
            </div>
          </form>

          <div className="ui-panel grid content-start gap-3 p-comfortable text-body">
            <h2 className="text-title font-semibold">Request boundary</h2>
            <dl className="grid gap-2">
              <div>
                <dt className="text-caption text-muted-foreground">Requester</dt>
                <dd>{requester || "session principal not served"}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">Mutation</dt>
                <dd className="font-mono text-caption">POST /api/v1/identities with Idempotency-Key</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">Result</dt>
                <dd>accepted request; approval and issuance remain separate states</dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      <DataGrid
        ariaLabel="My credential requests"
        rows={myRequests}
        columns={requestColumns}
        getRowId={(identity) => identity.id}
        state={requestGridState}
        stateTitle={requestError ? "Request status unavailable" : "No requests yet"}
        stateMessage={requestError ?? "Self-service requests created by this session principal appear here after the backend accepts them."}
      />
    </section>
  );
}
