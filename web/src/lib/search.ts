import { useEffect, useState } from "react";
import { api, type Agent, type Api, type Certificate, type Identity, type SecretMeta } from "@/lib/api";

export type SearchClient = Pick<Api, "certificatePage" | "identities" | "secretPage" | "agents">;
export type GlobalSearchKind = "certificate" | "identity" | "secret" | "agent";
export type SearchSource = "certificates" | "identities" | "secrets" | "agents";

export interface GlobalSearchResult {
  id: string;
  kind: GlobalSearchKind;
  label: string;
  description: string;
  to: string;
  source: SearchSource;
}

export interface GlobalSearchResponse {
  results: GlobalSearchResult[];
  unavailableSources: SearchSource[];
}

export interface GlobalSearchState extends GlobalSearchResponse {
  loading: boolean;
}

const emptyResponse: GlobalSearchResponse = { results: [], unavailableSources: [] };

function norm(value: unknown): string {
  return String(value ?? "").toLowerCase();
}

function matches(query: string, values: unknown[]): boolean {
  const needle = norm(query).trim();
  if (!needle) return false;
  return values.some((value) => norm(value).includes(needle));
}

function certificateResult(certificate: Certificate): GlobalSearchResult {
  const fingerprint = certificate.fingerprint ? ` · ${certificate.fingerprint}` : "";
  return {
    id: `certificate:${certificate.id}`,
    kind: "certificate",
    label: certificate.subject,
    description: `Certificate · ${certificate.status}${fingerprint}`,
    to: "/certificates",
    source: "certificates",
  };
}

function identityResult(identity: Identity): GlobalSearchResult {
  return {
    id: `identity:${identity.id}`,
    kind: "identity",
    label: identity.name,
    description: `Identity · ${identity.kind} · ${identity.status}`,
    to: "/identities",
    source: "identities",
  };
}

function secretResult(secret: SecretMeta): GlobalSearchResult {
  return {
    id: `secret:${secret.name}`,
    kind: "secret",
    label: secret.name,
    description: `Secret metadata · version ${secret.version}`,
    to: "/secrets",
    source: "secrets",
  };
}

function agentResult(agent: Agent): GlobalSearchResult {
  return {
    id: `agent:${agent.id}`,
    kind: "agent",
    label: agent.name ?? agent.id,
    description: `Agent · ${agent.status}`,
    to: "/agents",
    source: "agents",
  };
}

export async function searchInventory(query: string, client: SearchClient = api): Promise<GlobalSearchResponse> {
  const trimmed = query.trim();
  if (!trimmed) return emptyResponse;

  const tasks: Array<{ source: SearchSource; load: () => Promise<GlobalSearchResult[]> }> = [
    {
      source: "certificates",
      load: async () => {
        const page = await client.certificatePage({ limit: 25 });
        return (page.items ?? [])
          .filter((certificate) =>
            matches(trimmed, [
              certificate.subject,
              certificate.fingerprint,
              certificate.serial,
              certificate.issuer,
              certificate.status,
              ...(certificate.sans ?? []),
            ]),
          )
          .map(certificateResult);
      },
    },
    {
      source: "identities",
      load: async () =>
        (await client.identities())
          .filter((identity) => matches(trimmed, [identity.name, identity.id, identity.kind, identity.status, identity.owner_id, identity.issuer_id]))
          .map(identityResult),
    },
    {
      source: "secrets",
      load: async () => {
        const page = await client.secretPage({ limit: 25 });
        return (page.items ?? []).filter((secret) => matches(trimmed, [secret.name, secret.version, secret.created_at, secret.updated_at])).map(secretResult);
      },
    },
    {
      source: "agents",
      load: async () => (await client.agents()).filter((agent) => matches(trimmed, [agent.name, agent.id, agent.status, agent.version])).map(agentResult),
    },
  ];

  const settled = await Promise.allSettled(tasks.map((task) => task.load().then((results) => ({ source: task.source, results }))));
  const results: GlobalSearchResult[] = [];
  const unavailableSources: SearchSource[] = [];

  settled.forEach((entry, index) => {
    if (entry.status === "fulfilled") {
      results.push(...entry.value.results);
    } else {
      unavailableSources.push(tasks[index].source);
    }
  });

  return {
    results: results.slice(0, 12),
    unavailableSources,
  };
}

export function useGlobalSearch(query: string, options: { client?: SearchClient; enabled?: boolean } = {}): GlobalSearchState {
  const { client = api, enabled = true } = options;
  const [state, setState] = useState<GlobalSearchState>({ ...emptyResponse, loading: false });

  useEffect(() => {
    if (!enabled || !query.trim()) {
      setState({ ...emptyResponse, loading: false });
      return;
    }

    let active = true;
    setState((current) => ({ ...current, loading: true }));
    searchInventory(query, client)
      .then((response) => {
        if (active) setState({ ...response, loading: false });
      })
      .catch(() => {
        if (active) setState({ results: [], unavailableSources: ["certificates", "identities", "secrets", "agents"], loading: false });
      });
    return () => {
      active = false;
    };
  }, [client, enabled, query]);

  return state;
}
