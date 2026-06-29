import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Clipboard, KeyRound, Loader2, Play, RefreshCw } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type APITokenCreateResponse } from "@/lib/api";

const specURL = "/api/v1/openapi.json";
const docsTokenTTLMinutes = 15;
const methods = ["get", "post", "put", "patch", "delete"] as const;
const sampleUUID = "00000000-0000-4000-8000-000000000001";

type HTTPMethod = (typeof methods)[number];

interface JSONSchema {
  $ref?: string;
  type?: string;
  format?: string;
  enum?: unknown[];
  items?: JSONSchema;
  properties?: Record<string, JSONSchema>;
  required?: string[];
}

interface OpenAPIParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  description?: string;
  schema?: JSONSchema;
}

interface OpenAPIResponse {
  description?: string;
  content?: Record<string, { schema?: JSONSchema }>;
}

interface OpenAPIOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  parameters?: OpenAPIParameter[];
  requestBody?: {
    required?: boolean;
    content?: Record<string, { schema?: JSONSchema }>;
  };
  responses?: Record<string, OpenAPIResponse>;
  security?: Array<Record<string, string[]>>;
  "x-trstctl-permission"?: string;
  "x-trstctl-sensitive-response"?: boolean;
}

interface OpenAPIDocument {
  openapi: string;
  info?: { title?: string; version?: string };
  paths: Record<string, Partial<Record<HTTPMethod, OpenAPIOperation>>>;
  components?: { schemas?: Record<string, JSONSchema> };
}

interface OperationEntry {
  key: string;
  method: HTTPMethod;
  path: string;
  operation: OpenAPIOperation;
  permission: string;
  samplePath: string;
  sampleBody: unknown;
}

interface ExplorerResponse {
  status: number;
  statusText: string;
  contentType: string;
  bodyText: string;
  problem?: {
    title?: string;
    detail?: string;
    status?: number;
    type?: string;
    instance?: string;
  };
}

function methodLabel(method: HTTPMethod): string {
  return method.toUpperCase();
}

function isUnsafe(method: HTTPMethod): boolean {
  return method !== "get";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `docs-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function schemaRefName(schema?: JSONSchema): string | undefined {
  return schema?.$ref?.split("/").pop();
}

function dereference(schema: JSONSchema | undefined, spec: OpenAPIDocument): JSONSchema | undefined {
  const ref = schemaRefName(schema);
  if (!ref) return schema;
  return spec.components?.schemas?.[ref] ?? schema;
}

function sampleForSchema(schema: JSONSchema | undefined, spec: OpenAPIDocument, propertyName = "value", depth = 0): unknown {
  const resolved = dereference(schema, spec);
  if (!resolved || depth > 3) return sampleForName(propertyName);
  if (resolved.enum && resolved.enum.length > 0) return resolved.enum[0];
  if (resolved.type === "array") return [sampleForSchema(resolved.items, spec, propertyName, depth + 1)];
  if (resolved.type === "object" || resolved.properties) {
    const required = new Set(resolved.required ?? Object.keys(resolved.properties ?? {}).slice(0, 3));
    const body: Record<string, unknown> = {};
    for (const [name, child] of Object.entries(resolved.properties ?? {})) {
      if (!required.has(name)) continue;
      body[name] = sampleForSchema(child, spec, name, depth + 1);
    }
    return Object.keys(body).length > 0 ? body : {};
  }
  if (resolved.type === "integer" || resolved.type === "number") return 20;
  if (resolved.type === "boolean") return true;
  if (resolved.format === "date-time") return new Date(Date.now() + 60 * 60 * 1000).toISOString();
  if (resolved.format === "uuid") return sampleUUID;
  return sampleForName(propertyName);
}

function sampleForName(name: string): string {
  const normalized = name.toLowerCase();
  if (normalized.includes("subject")) return "docs-operator";
  if (normalized.includes("email")) return "docs@example.test";
  if (normalized.includes("owner")) return sampleUUID;
  if (normalized.includes("issuer")) return sampleUUID;
  if (normalized.includes("profile")) return "server-tls";
  if (normalized.includes("name")) return "docs-sample";
  if (normalized.includes("id")) return sampleUUID;
  if (normalized.includes("pem")) return "-----BEGIN CERTIFICATE-----";
  if (normalized.includes("ttl")) return "24h";
  if (normalized.includes("scope")) return "certs:read";
  return "sample";
}

function requestBodySample(operation: OpenAPIOperation, spec: OpenAPIDocument): unknown {
  const schema = operation.requestBody?.content?.["application/json"]?.schema;
  return schema ? sampleForSchema(schema, spec, schemaRefName(schema) ?? "request") : undefined;
}

function replacePathParameters(path: string, parameters: OpenAPIParameter[]): string {
  let next = path;
  for (const parameter of parameters.filter((param) => param.in === "path")) {
    next = next.replace(`{${parameter.name}}`, encodeURIComponent(sampleForName(parameter.name)));
  }
  return next;
}

function queryString(parameters: OpenAPIParameter[]): string {
  const qs = new URLSearchParams();
  for (const parameter of parameters.filter((param) => param.in === "query" && param.required)) {
    const sample = sampleForSchema(parameter.schema, { openapi: "3.1.0", paths: {} }, parameter.name);
    qs.set(parameter.name, String(sample));
  }
  const out = qs.toString();
  return out ? `?${out}` : "";
}

function buildOperations(spec: OpenAPIDocument): OperationEntry[] {
  const entries: OperationEntry[] = [];
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const method of methods) {
      const operation = pathItem[method];
      if (!operation?.operationId) continue;
      const parameters = operation.parameters ?? [];
      const samplePath = `${replacePathParameters(path, parameters)}${queryString(parameters)}`;
      entries.push({
        key: `${method}:${path}`,
        method,
        path,
        operation,
        permission: operation["x-trstctl-permission"] ?? "access:read",
        samplePath,
        sampleBody: requestBodySample(operation, spec),
      });
    }
  }
  return entries.sort((left, right) => `${left.path}:${left.method}`.localeCompare(`${right.path}:${right.method}`));
}

function schemaNameForOperation(operation: OpenAPIOperation): string {
  const schema = operation.requestBody?.content?.["application/json"]?.schema;
  return schemaRefName(schema) ?? "JSON";
}

function responseNames(operation: OpenAPIOperation): string[] {
  return Object.entries(operation.responses ?? {})
    .map(([status, response]) => {
      const schema = response.content?.["application/json"]?.schema ?? response.content?.["application/problem+json"]?.schema;
      const name = schemaRefName(schema);
      return name ? `${status} ${name}` : status;
    })
    .slice(0, 5);
}

function curlExample(entry: OperationEntry): string {
  const lines = [
    `curl -sS -X ${methodLabel(entry.method)} https://control-plane.example${entry.samplePath}`,
    `  -H 'Authorization: Bearer $TRSTCTL_DOCS_TOKEN'`,
    `  -H 'Accept: application/json'`,
  ];
  if (isUnsafe(entry.method)) lines.push(`  -H 'Idempotency-Key: ${newIdempotencyKey()}'`);
  if (entry.sampleBody !== undefined) {
    lines.push(`  -H 'Content-Type: application/json'`);
    lines.push(`  --data '${JSON.stringify(entry.sampleBody)}'`);
  }
  return lines.join(" \\\n");
}

function sdkExample(entry: OperationEntry): string {
  const callName = entry.operation.operationId ?? "call";
  if (entry.sampleBody === undefined) return `await client.${callName}();`;
  return `await client.${callName}(${JSON.stringify(entry.sampleBody, null, 2)});`;
}

function safeJSON(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

async function fetchSpec(): Promise<OpenAPIDocument> {
  const res = await fetch(specURL, { credentials: "include", headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`contract load failed (${res.status})`);
  return (await res.json()) as OpenAPIDocument;
}

async function readExplorerResponse(res: Response): Promise<ExplorerResponse> {
  const contentType = res.headers.get("Content-Type") ?? "";
  const bodyText = await res.text();
  let problem: ExplorerResponse["problem"];
  if (contentType.includes("application/problem+json") && bodyText) {
    const parsed = JSON.parse(bodyText) as unknown;
    if (isObject(parsed)) {
      problem = {
        title: typeof parsed.title === "string" ? parsed.title : undefined,
        detail: typeof parsed.detail === "string" ? parsed.detail : undefined,
        status: typeof parsed.status === "number" ? parsed.status : undefined,
        type: typeof parsed.type === "string" ? parsed.type : undefined,
        instance: typeof parsed.instance === "string" ? parsed.instance : undefined,
      };
    }
  }
  return {
    status: res.status,
    statusText: res.statusText,
    contentType,
    bodyText,
    problem,
  };
}

function CopyButton({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={() => {
        void globalThis.navigator?.clipboard?.writeText(value);
        setCopied(true);
      }}
    >
      <Clipboard className="h-4 w-4" aria-hidden="true" />
      {copied ? t("apiExplorer.copied") : label}
    </Button>
  );
}

function MethodBadge({ method }: { method: HTTPMethod }) {
  return <span className="rounded-control bg-brand-accent/10 px-2 py-1 font-mono text-xs font-semibold text-brand-accent">{methodLabel(method)}</span>;
}

function CodeBlock({ value, labelledBy }: { value: string; labelledBy?: string }) {
  return (
    <pre aria-labelledby={labelledBy} className="max-h-72 overflow-auto rounded-panel border border-border bg-muted p-3 text-xs leading-relaxed">
      <code>{value}</code>
    </pre>
  );
}

export function ApiExplorer() {
  const { user } = useAuth();
  const { t, formatDateTime } = useTranslation();
  const [spec, setSpec] = useState<OpenAPIDocument | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [tokenSubject, setTokenSubject] = useState(user?.email ?? user?.subject ?? "");
  const [testKey, setTestKey] = useState<APITokenCreateResponse | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [response, setResponse] = useState<ExplorerResponse | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [runBusy, setRunBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const nextSpec = await fetchSpec();
      setSpec(nextSpec);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!tokenSubject && user) setTokenSubject(user.email ?? user.subject);
  }, [tokenSubject, user]);

  const operations = useMemo(() => (spec ? buildOperations(spec) : []), [spec]);

  useEffect(() => {
    if (!selectedKey && operations.length > 0) setSelectedKey(operations[0].key);
  }, [operations, selectedKey]);

  const selected = operations.find((entry) => entry.key === selectedKey) ?? operations[0];
  const loweredFilter = filter.trim().toLowerCase();
  const visibleOperations = operations.filter((entry) => {
    if (!loweredFilter) return true;
    return [entry.path, entry.operation.operationId, entry.operation.summary, entry.permission]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(loweredFilter);
  });

  async function mintTestKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setKeyBusy(true);
    setKeyError(null);
    setTestKey(null);
    const expiresAt = new Date(Date.now() + docsTokenTTLMinutes * 60 * 1000).toISOString();
    try {
      const created = await api.createAPIToken({
        subject: tokenSubject.trim(),
        scopes: [selected.permission],
        expires_at: expiresAt,
      });
      setTestKey(created);
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : String(err));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runRequest() {
    if (!selected || !testKey) return;
    setRunBusy(true);
    setRunError(null);
    setResponse(null);
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${testKey.token}`,
    };
    let body: string | undefined;
    if (selected.sampleBody !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(selected.sampleBody);
    }
    if (isUnsafe(selected.method)) headers["Idempotency-Key"] = newIdempotencyKey();
    try {
      const res = await fetch(selected.samplePath, {
        method: methodLabel(selected.method),
        headers,
        body,
      });
      setResponse(await readExplorerResponse(res));
    } catch (err) {
      setRunError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunBusy(false);
    }
  }

  const pathParameters = selected?.operation.parameters?.filter((parameter) => parameter.in === "path") ?? [];
  const queryParameters = selected?.operation.parameters?.filter((parameter) => parameter.in === "query") ?? [];
  const requestBody = selected?.sampleBody === undefined ? "" : safeJSON(selected.sampleBody);
  const curl = selected ? curlExample(selected) : "";
  const sdk = selected ? sdkExample(selected) : "";

  return (
    <section aria-labelledby="api-explorer-heading" className="grid gap-6">
      <PageHeader
        titleId="api-explorer-heading"
        title={t("apiExplorer.title")}
        description={t("apiExplorer.description")}
        actions={
          <Link
            to="/integrate"
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
          >
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            {t("apiExplorer.back")}
          </Link>
        }
      />

      {loading && (
        <p role="status" className="rounded-panel border border-border bg-card p-4 text-sm text-muted-foreground">
          <Loader2 className="mr-2 inline h-4 w-4 animate-spin" aria-hidden="true" />
          {t("apiExplorer.loading")}
        </p>
      )}

      {loadError && (
        <div role="alert" className="rounded-panel border border-status-danger/30 bg-status-danger/10 p-4 text-sm text-status-danger">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-medium">{t("apiExplorer.loadFailed")}</p>
              <p>{loadError}</p>
            </div>
            <Button type="button" size="sm" variant="outline" onClick={() => void load()}>
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              {t("apiExplorer.reload")}
            </Button>
          </div>
        </div>
      )}

      {selected && (
        <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)_minmax(22rem,0.9fr)]">
          <aside className="ui-panel min-h-0 p-comfortable" aria-labelledby="api-operation-list-heading">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h2 id="api-operation-list-heading" className="text-title font-semibold">
                {t("apiExplorer.operations")}
              </h2>
              <span className="text-caption text-muted-foreground">{t("apiExplorer.operationCount", { count: operations.length })}</span>
            </div>
            <label className="mb-3 grid gap-1 text-sm">
              <span className="sr-only">{t("apiExplorer.searchLabel")}</span>
              <input
                className="ui-input"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder={t("apiExplorer.searchPlaceholder")}
              />
            </label>
            <div className="max-h-[34rem] overflow-auto pr-1">
              {visibleOperations.length === 0 ? (
                <p className="rounded-control bg-muted px-3 py-2 text-sm text-muted-foreground">{t("apiExplorer.noMatches")}</p>
              ) : (
                <div className="grid gap-2">
                  {visibleOperations.map((entry) => (
                    <button
                      key={entry.key}
                      type="button"
                      className={`rounded-control border px-3 py-2 text-left transition ${
                        entry.key === selected.key
                          ? "border-brand-accent bg-brand-accent/10 text-foreground"
                          : "border-border bg-background hover:border-brand-accent/40 hover:bg-muted/60"
                      }`}
                      onClick={() => {
                        setSelectedKey(entry.key);
                        setResponse(null);
                        setRunError(null);
                      }}
                    >
                      <span className="flex items-center gap-2">
                        <MethodBadge method={entry.method} />
                        <span className="truncate font-mono text-xs">{entry.operation.operationId}</span>
                      </span>
                      <span className="mt-1 block truncate text-xs text-muted-foreground">{entry.path}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </aside>

          <main className="grid gap-4" aria-labelledby="api-operation-detail-heading">
            <section className="ui-panel p-comfortable">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 id="api-operation-detail-heading" className="text-title font-semibold">
                    {selected.operation.summary ?? selected.operation.operationId}
                  </h2>
                  {selected.operation.description && <p className="mt-1 text-sm text-muted-foreground">{selected.operation.description}</p>}
                </div>
                <MethodBadge method={selected.method} />
              </div>
              <dl className="mt-4 grid gap-3 text-sm md:grid-cols-2">
                <div>
                  <dt className="font-medium text-muted-foreground">{t("apiExplorer.route")}</dt>
                  <dd className="break-all font-mono text-xs">{selected.path}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("apiExplorer.operationId")}</dt>
                  <dd className="break-all font-mono text-xs">{selected.operation.operationId}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("apiExplorer.permission")}</dt>
                  <dd className="font-mono text-xs">{selected.permission}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("apiExplorer.response")}</dt>
                  <dd className="font-mono text-xs">{responseNames(selected.operation).join(", ")}</dd>
                </div>
              </dl>
            </section>

            <section className="grid gap-4 lg:grid-cols-2">
              <div className="ui-panel p-comfortable">
                <h3 className="text-body font-semibold">{t("apiExplorer.pathParameters")}</h3>
                {pathParameters.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">{t("apiExplorer.noParameters")}</p>
                ) : (
                  <ul className="mt-2 grid gap-2 text-sm">
                    {pathParameters.map((parameter) => (
                      <li key={parameter.name} className="rounded-control border border-border px-3 py-2">
                        <span className="font-mono text-xs">{parameter.name}</span>
                        <span className="ml-2 text-caption text-muted-foreground">{parameter.required ? t("apiExplorer.required") : t("apiExplorer.optional")}</span>
                        {parameter.description && <p className="mt-1 text-xs text-muted-foreground">{parameter.description}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="ui-panel p-comfortable">
                <h3 className="text-body font-semibold">{t("apiExplorer.queryParameters")}</h3>
                {queryParameters.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">{t("apiExplorer.noParameters")}</p>
                ) : (
                  <ul className="mt-2 grid gap-2 text-sm">
                    {queryParameters.map((parameter) => (
                      <li key={parameter.name} className="rounded-control border border-border px-3 py-2">
                        <span className="font-mono text-xs">{parameter.name}</span>
                        <span className="ml-2 text-caption text-muted-foreground">{parameter.required ? t("apiExplorer.required") : t("apiExplorer.optional")}</span>
                        {parameter.description && <p className="mt-1 text-xs text-muted-foreground">{parameter.description}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            <section className="ui-panel p-comfortable">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 id="api-request-body-heading" className="text-body font-semibold">
                    {t("apiExplorer.requestBody")}
                  </h3>
                  <p className="text-caption text-muted-foreground">{schemaNameForOperation(selected.operation)}</p>
                </div>
              </div>
              {requestBody ? <CodeBlock labelledBy="api-request-body-heading" value={requestBody} /> : <p className="text-sm text-muted-foreground">{t("apiExplorer.noRequestBody")}</p>}
            </section>

            <section className="ui-panel p-comfortable">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h3 id="api-examples-heading" className="text-body font-semibold">
                  {t("apiExplorer.examples")}
                </h3>
                <div className="flex flex-wrap gap-2">
                  <CopyButton label={t("apiExplorer.copyCurl")} value={curl} />
                  <CopyButton label={t("apiExplorer.copySdk")} value={sdk} />
                </div>
              </div>
              <CodeBlock labelledBy="api-examples-heading" value={`${curl}\n\n${sdk}`} />
            </section>
          </main>

          <aside className="grid content-start gap-4">
            <section className="ui-panel p-comfortable" aria-labelledby="api-runner-heading">
              <h2 id="api-runner-heading" className="text-title font-semibold">
                {t("apiExplorer.runner")}
              </h2>
              <form onSubmit={(event) => void mintTestKey(event)} className="mt-4 grid gap-3">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{t("apiExplorer.subject")}</span>
                  <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
                </label>
                <div className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{t("apiExplorer.tokenScope")}</span>
                  <code className="rounded-control bg-muted px-2 py-1 text-xs">{selected.permission}</code>
                </div>
                <Button type="submit" disabled={keyBusy || !tokenSubject.trim()}>
                  {keyBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                  {keyBusy ? t("apiExplorer.generating") : t("apiExplorer.testKey")}
                </Button>
              </form>
              {keyError && (
                <p role="alert" className="mt-3 rounded-control border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
                  {t("apiExplorer.keyFailed")} {keyError}
                </p>
              )}
              {testKey && (
                <div role="status" className="mt-3 rounded-panel border border-status-success/30 bg-status-success/10 p-3 text-sm text-status-success">
                  <p className="font-medium">{t("apiExplorer.keyReady", { scope: testKey.scopes.join(", ") })}</p>
                  <p className="mt-1 text-xs">{t("apiExplorer.revealOnce")}</p>
                  {testKey.expires_at && (
                    <p className="mt-1 text-xs">
                      {t("apiExplorer.expires")}: {formatDateTime(testKey.expires_at)}
                    </p>
                  )}
                </div>
              )}

              <div className="mt-4 grid gap-3">
                <div>
                  <h3 id="api-request-preview-heading" className="mb-2 text-body font-semibold">
                    {t("apiExplorer.requestPreview")}
                  </h3>
                  <CodeBlock labelledBy="api-request-preview-heading" value={`${methodLabel(selected.method)} ${selected.samplePath}`} />
                </div>
                <Button type="button" onClick={() => void runRequest()} disabled={runBusy || !testKey}>
                  {runBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
                  {runBusy ? t("apiExplorer.running") : t("apiExplorer.run")}
                </Button>
                {!testKey && <p className="text-sm text-muted-foreground">{t("apiExplorer.needsKey")}</p>}
              </div>
            </section>

            <section className="ui-panel p-comfortable" aria-labelledby="api-response-heading">
              <h2 id="api-response-heading" className="text-title font-semibold">
                {t("apiExplorer.response")}
              </h2>
              {runError && (
                <p role="alert" className="mt-3 rounded-control border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
                  {t("apiExplorer.runFailed")} {runError}
                </p>
              )}
              {!runError && !response && <p className="mt-3 text-sm text-muted-foreground">{t("apiExplorer.noResponse")}</p>}
              {response && (
                <div className="mt-3 grid gap-3 text-sm">
                  <dl className="grid gap-2">
                    <div>
                      <dt className="font-medium text-muted-foreground">{t("apiExplorer.status")}</dt>
                      <dd>
                        {response.status} {response.statusText}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-medium text-muted-foreground">{t("apiExplorer.contentType")}</dt>
                      <dd className="break-all font-mono text-xs">{response.contentType || "-"}</dd>
                    </div>
                  </dl>
                  {response.problem && (
                    <div className="rounded-panel border border-status-warning/30 bg-status-warning/10 p-3" aria-labelledby="api-problem-heading">
                      <h3 id="api-problem-heading" className="text-body font-semibold">
                        {t("apiExplorer.problemResponse")}
                      </h3>
                      <dl className="mt-2 grid gap-2">
                        <div>
                          <dt className="font-medium text-muted-foreground">{t("apiExplorer.status")}</dt>
                          <dd>{response.problem.status ?? response.status}</dd>
                        </div>
                        {response.problem.title && (
                          <div>
                            <dt className="font-medium text-muted-foreground">{t("apiExplorer.problemTitle")}</dt>
                            <dd>{response.problem.title}</dd>
                          </div>
                        )}
                        {response.problem.detail && (
                          <div>
                            <dt className="font-medium text-muted-foreground">{t("apiExplorer.problemDetail")}</dt>
                            <dd>{response.problem.detail}</dd>
                          </div>
                        )}
                      </dl>
                    </div>
                  )}
                  <div>
                    <h3 id="api-response-body-heading" className="mb-2 text-body font-semibold">
                      {t("apiExplorer.responseBody")}
                    </h3>
                    <CodeBlock labelledBy="api-response-body-heading" value={response.bodyText || "{}"} />
                  </div>
                </div>
              )}
            </section>
          </aside>
        </div>
      )}
    </section>
  );
}
