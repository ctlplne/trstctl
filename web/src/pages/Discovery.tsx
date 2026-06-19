import { useEffect, useMemo, useState } from "react";
import { Cloud, Database, Fingerprint, KeyRound, Network, RefreshCw, Server } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError, type Identity, type SecretMeta } from "@/lib/api";

type Notice = { kind: "permission" | "error"; message: string };

const sourceCards = [
  {
    feature: "F2",
    title: "Network discovery",
    icon: Network,
    body: "Port-range TLS scanning is library-complete in `internal/discovery/netscan`, but the control plane does not serve a scan schedule, run, or findings API yet.",
    next: "Use the served certificate ingest page to land a certificate found outside the product.",
    href: "/certificates",
    link: "Open certificate ingest",
  },
  {
    feature: "F49",
    title: "Cloud certificate discovery",
    icon: Cloud,
    body: "AWS ACM, Azure Key Vault, and GCP certificate enumeration are library-only. Cloud credentials must be sealed references, never raw browser fields.",
    next: "Store credential references in the native secret store, then wait for the discovery API to mount.",
    href: "/secrets",
    link: "Open sealed secret store",
  },
  {
    feature: "F42",
    title: "SSH discovery",
    icon: Server,
    body: "Authorized_keys, host keys, trusted CAs, and standing SSH access discovery run in library/agent code only today.",
    next: "The served inventory below can show existing ssh_key and ssh_certificate identities, but not discovered host findings.",
    href: "/agents",
    link: "Open agent enrollment",
  },
  {
    feature: "F35/F36",
    title: "Secret and API-key discovery",
    icon: KeyRound,
    body: "External store enumeration and leaked-key scanner ingestion are not served. Discovery records references and fingerprints, not secret values.",
    next: "The served slices below show native secret names and api_key identities only.",
    href: "/secrets",
    link: "Open native secrets",
  },
];

export function Discovery() {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [identityError, setIdentityError] = useState<Notice | null>(null);
  const [secretError, setSecretError] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    setIdentityError(null);
    setSecretError(null);
    const [identityResult, secretResult] = await Promise.allSettled([
      api.identities(),
      api.secretPage({ limit: 20 }),
    ]);
    if (identityResult.status === "fulfilled") {
      setIdentities(identityResult.value);
    } else {
      setIdentities([]);
      setIdentityError(noticeForError(identityResult.reason, "Could not load identities"));
    }
    if (secretResult.status === "fulfilled") {
      setSecrets(secretResult.value.items ?? []);
    } else {
      setSecrets([]);
      setSecretError(noticeForError(secretResult.reason, "Could not load secret metadata"));
    }
    setLoading(false);
  }

  useEffect(() => {
    void load();
  }, []);

  const sshIdentities = useMemo(
    () => identities.filter((identity) => identity.kind === "ssh_key" || identity.kind === "ssh_certificate"),
    [identities],
  );
  const apiKeyIdentities = useMemo(
    () => identities.filter((identity) => identity.kind === "api_key"),
    [identities],
  );

  return (
    <section aria-labelledby="discovery-heading" className="grid gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 id="discovery-heading" className="text-2xl font-semibold">
            Discovery
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Discovery scanners are library-complete but not served as control-plane APIs. This page is read-only: it names the backend gaps and shows only metadata that is already served.
          </p>
        </div>
        <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
          Refresh
        </Button>
      </div>

      <UnavailableState title="Discovery scan API not served yet">
        `BACKEND-DISCOVERY-SCAN` must expose scan sources, schedules, dry-run previews, runs, findings, and agent source evidence before the GUI can offer scan execution. `BACKEND-SECRETSCAN` is also required before leaked-token scanner findings can appear here.
      </UnavailableState>

      <div className="grid gap-3 lg:grid-cols-2">
        {sourceCards.map(({ feature, title, icon: Icon, body, next, href, link }) => (
          <section key={title} aria-labelledby={`${feature}-heading`} className="grid gap-3 rounded-md border border-border p-3 text-sm">
            <div className="flex items-start gap-3">
              <Icon className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div>
                <h2 id={`${feature}-heading`} className="font-semibold">
                  {title}
                </h2>
                <p className="mt-1 text-muted-foreground">{body}</p>
              </div>
            </div>
            <p className="text-muted-foreground">{next}</p>
            <a className="text-sm font-medium text-primary underline" href={href}>
              {link}
            </a>
          </section>
        ))}
      </div>

      {loading && <LoadingState>Loading served discovery-adjacent metadata...</LoadingState>}

      <section aria-labelledby="ssh-inventory-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="ssh-inventory-heading" className="text-lg font-semibold">
            SSH identity inventory
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Served `GET /api/v1/identities` rows where kind is `ssh_key` or `ssh_certificate`. Trust mutation and host-key remediation controls are intentionally absent.
          </p>
        </div>
        {renderNotice(identityError)}
        {!loading && !identityError && sshIdentities.length === 0 && (
          <EmptyState title="No SSH identities in served inventory">
            Enroll agents or create SSH identities elsewhere; discovery scan findings need `BACKEND-DISCOVERY-SCAN`.
          </EmptyState>
        )}
        {!loading && !identityError && sshIdentities.length > 0 && <SSHIdentityTable identities={sshIdentities} />}
        <UnavailableState title="SSH discovery findings not served yet">
          Weak trust flags, discovered host keys, authorized_keys entries, trusted CAs, and agent source paths need `BACKEND-DISCOVERY-SCAN`. No browser control can rewrite sshd trust from this page.
        </UnavailableState>
      </section>

      <section aria-labelledby="api-key-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="api-key-heading" className="text-lg font-semibold">
            API key and token inventory
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Served `api_key` identities with masked fingerprints and expiry. Token values are never fetched, rendered, or stored.
          </p>
        </div>
        {renderNotice(identityError)}
        {!loading && !identityError && apiKeyIdentities.length === 0 && (
          <EmptyState title="No API-key identities in served inventory">
            Scan-based key discovery and leaked-token ingestion need `BACKEND-SECRETSCAN`.
          </EmptyState>
        )}
        {!loading && !identityError && apiKeyIdentities.length > 0 && <APIKeyTable identities={apiKeyIdentities} />}
        <UnavailableState title="Scanner findings not served yet">
          `BACKEND-SECRETSCAN` must mount findings from gitleaks, trufflehog, and external secret-store enumerators before the GUI can show discovered tokens.
        </UnavailableState>
      </section>

      <section aria-labelledby="secret-store-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="secret-store-heading" className="text-lg font-semibold">
            Native secret metadata
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Served `GET /api/v1/secrets/store` returns names and versions only. This table never asks for or renders secret values.
          </p>
        </div>
        {renderNotice(secretError)}
        {!loading && !secretError && secrets.length === 0 && (
          <EmptyState title="No native secrets in served store">
            Create sealed secrets on `/secrets`; external-store discovery is still waiting for `BACKEND-DISCOVERY-SCAN`.
          </EmptyState>
        )}
        {!loading && !secretError && secrets.length > 0 && <SecretMetadataTable secrets={secrets} />}
        <UnavailableState title="External secret-store discovery not served yet">
          Kubernetes, GitHub, cloud-provider, and other external store enumeration needs `BACKEND-DISCOVERY-SCAN`. This page shows only native-store metadata.
        </UnavailableState>
      </section>
    </section>
  );
}

function SSHIdentityTable({ identities }: { identities: Identity[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">Served SSH identity inventory</caption>
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th scope="col" className="py-2 pl-3 pr-4 font-medium">Name</th>
            <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
            <th scope="col" className="py-2 pr-4 font-medium">Owner</th>
            <th scope="col" className="py-2 pr-4 font-medium">Status</th>
            <th scope="col" className="py-2 pr-4 font-medium">Expires</th>
            <th scope="col" className="py-2 pr-3 font-medium">Fingerprint</th>
          </tr>
        </thead>
        <tbody>
          {identities.map((identity) => (
            <tr key={identity.id} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{identity.name}</td>
              <td className="py-2 pr-4">{identity.kind}</td>
              <td className="py-2 pr-4 font-mono text-xs">{identity.owner_id}</td>
              <td className="py-2 pr-4">{identity.status}</td>
              <td className="py-2 pr-4">{formatDate(identity.not_after)}</td>
              <td className="py-2 pr-3 font-mono text-xs">{maskFingerprint(stringAttr(identity, "fingerprint"))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function APIKeyTable({ identities }: { identities: Identity[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">Served API key identity inventory</caption>
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th scope="col" className="py-2 pl-3 pr-4 font-medium">Name</th>
            <th scope="col" className="py-2 pr-4 font-medium">Owner</th>
            <th scope="col" className="py-2 pr-4 font-medium">Status</th>
            <th scope="col" className="py-2 pr-4 font-medium">Expires</th>
            <th scope="col" className="py-2 pr-4 font-medium">Scopes</th>
            <th scope="col" className="py-2 pr-3 font-medium">Masked fingerprint</th>
          </tr>
        </thead>
        <tbody>
          {identities.map((identity) => (
            <tr key={identity.id} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{identity.name}</td>
              <td className="py-2 pr-4 font-mono text-xs">{identity.owner_id}</td>
              <td className="py-2 pr-4">{identity.status}</td>
              <td className="py-2 pr-4">{formatDate(identity.not_after)}</td>
              <td className="py-2 pr-4">{scopes(identity)}</td>
              <td className="py-2 pr-3 font-mono text-xs">
                <Fingerprint className="mr-1 inline h-3 w-3" aria-hidden="true" />
                {maskFingerprint(stringAttr(identity, "fingerprint"))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SecretMetadataTable({ secrets }: { secrets: SecretMeta[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[38rem] text-left text-sm">
        <caption className="sr-only">Served native secret metadata</caption>
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th scope="col" className="py-2 pl-3 pr-4 font-medium">Name</th>
            <th scope="col" className="py-2 pr-4 font-medium">Version</th>
            <th scope="col" className="py-2 pr-4 font-medium">Updated</th>
            <th scope="col" className="py-2 pr-3 font-medium">Created</th>
          </tr>
        </thead>
        <tbody>
          {secrets.map((secret) => (
            <tr key={secret.name} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">
                <Database className="mr-1 inline h-3 w-3" aria-hidden="true" />
                {secret.name}
              </td>
              <td className="py-2 pr-4">v{secret.version}</td>
              <td className="py-2 pr-4">{formatDate(secret.updated_at)}</td>
              <td className="py-2 pr-3">{formatDate(secret.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function renderNotice(notice: Notice | null) {
  if (!notice) return null;
  if (notice.kind === "permission") {
    return <PermissionDeniedState>{notice.message}</PermissionDeniedState>;
  }
  return <ErrorState title="Discovery metadata unavailable">{notice.message}</ErrorState>;
}

function noticeForError(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return {
        kind: err.status === 403 ? "permission" : "error",
        message: problem.detail || problem.title || fallback,
      };
    } catch {
      return { kind: err.status === 403 ? "permission" : "error", message: err.body || fallback };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : fallback };
}

function stringAttr(identity: Identity, key: string): string {
  const value = identity.attributes?.[key];
  return typeof value === "string" ? value : "";
}

function scopes(identity: Identity): string {
  const value = identity.attributes?.scopes;
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").join(", ") || "-";
  return typeof value === "string" ? value : "-";
}

function maskFingerprint(value: string): string {
  if (!value) return "-";
  if (value.length <= 16) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function formatDate(value?: string): string {
  if (!value) return "-";
  return new Date(value).toLocaleDateString();
}
