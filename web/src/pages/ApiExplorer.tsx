/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- Exact request and response code blocks must be keyboard-scrollable at narrow viewports. */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, Clipboard, KeyRound, Loader2, Play, RefreshCw } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";
import { api, type APITokenCreateResponse } from "@/lib/api";

export const apiExplorerSpecURL = "/api/v1/openapi.json";
const docsTokenTTLMinutes = 15;
const operationResultLimit = 12;
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
  oneOf?: JSONSchema[];
  additionalProperties?: boolean | JSONSchema;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

interface OpenAPIParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  description?: string;
  schema?: JSONSchema;
  style?: string;
  explode?: boolean;
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

export interface OpenAPIDocument {
  openapi: string;
  info?: { title?: string; version?: string };
  paths: Record<string, Partial<Record<HTTPMethod, OpenAPIOperation>>>;
  components?: { schemas?: Record<string, JSONSchema> };
}

export interface OperationEntry {
  key: string;
  method: HTTPMethod;
  path: string;
  operation: OpenAPIOperation;
  permission: string;
  examplePath: string;
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

export interface RequestDraft {
  parameterValues: Record<string, string>;
  bodyText: string;
}

interface DraftIssue {
  key: string;
  message: string;
}

interface FinalRequest {
  path: string;
  headers: Record<string, string>;
  body?: string;
  preview: string;
}

interface PreparedDraft {
  issues: DraftIssue[];
  request?: FinalRequest;
}

type Translate = I18nContextValue["t"];

function methodLabel(method: HTTPMethod): string {
  return method.toUpperCase();
}

function isUnsafe(method: HTTPMethod): boolean {
  return method !== "get";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbortError(value: unknown): boolean {
  return isObject(value) && value.name === "AbortError";
}

function parameterKey(parameter: OpenAPIParameter): string {
  return `${parameter.in}:${parameter.name}`;
}

function uuidValue(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
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

function parameterSample(parameter: OpenAPIParameter, spec: OpenAPIDocument): string {
  const sampled = sampleForSchema(parameter.schema, spec, parameter.name);
  if (Array.isArray(sampled)) return sampled.map(String).join(",");
  if (isObject(sampled)) return JSON.stringify(sampled);
  return String(sampled ?? "");
}

export function buildInitialRequestDraft(entry: OperationEntry, spec: OpenAPIDocument): RequestDraft {
  const parameterValues: Record<string, string> = {};
  for (const parameter of entry.operation.parameters ?? []) {
    if (parameter.in === "cookie") continue;
    const key = parameterKey(parameter);
    if (parameter.in === "header" && parameter.name.toLowerCase() === "idempotency-key") {
      parameterValues[key] = newIdempotencyKey();
      continue;
    }
    parameterValues[key] = parameter.required || parameter.in === "path" ? parameterSample(parameter, spec) : "";
  }
  return {
    parameterValues,
    bodyText: entry.sampleBody === undefined ? "" : safeJSON(entry.sampleBody),
  };
}

function validatePrimitive(name: string, rawValue: string, schema: JSONSchema | undefined, spec: OpenAPIDocument, t: Translate): string | undefined {
  const resolved = dereference(schema, spec);
  if (!resolved) return undefined;
  if (resolved.enum && !resolved.enum.some((value) => String(value) === rawValue)) {
    return t("apiExplorer.validation.enum", { name, values: resolved.enum.map(String).join(", ") });
  }
  if (resolved.type === "integer" && !/^-?\d+$/.test(rawValue)) return t("apiExplorer.validation.integer", { name });
  if (resolved.type === "number" && !Number.isFinite(Number(rawValue))) return t("apiExplorer.validation.number", { name });
  if (resolved.type === "boolean" && rawValue !== "true" && rawValue !== "false") return t("apiExplorer.validation.boolean", { name });
  if ((resolved.type === "integer" || resolved.type === "number") && resolved.minimum !== undefined && Number(rawValue) < resolved.minimum) {
    return t("apiExplorer.validation.minimum", { name, value: resolved.minimum });
  }
  if ((resolved.type === "integer" || resolved.type === "number") && resolved.maximum !== undefined && Number(rawValue) > resolved.maximum) {
    return t("apiExplorer.validation.maximum", { name, value: resolved.maximum });
  }
  if (resolved.type === "array") {
    const values = rawValue
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (values.length === 0) return t("apiExplorer.validation.arrayValue", { name });
    for (const value of values) {
      const issue = validatePrimitive(name, value, resolved.items, spec, t);
      if (issue) return issue;
    }
  }
  if (resolved.format === "uuid" && !uuidValue(rawValue)) return t("apiExplorer.validation.uuid", { name });
  if (resolved.format === "date-time" && Number.isNaN(Date.parse(rawValue))) return t("apiExplorer.validation.dateTime", { name });
  if (resolved.minLength !== undefined && rawValue.length < resolved.minLength)
    return t("apiExplorer.validation.minLength", { name, value: resolved.minLength });
  if (resolved.maxLength !== undefined && rawValue.length > resolved.maxLength)
    return t("apiExplorer.validation.maxLength", { name, value: resolved.maxLength });
  if (resolved.pattern) {
    try {
      if (!new RegExp(resolved.pattern).test(rawValue)) return t("apiExplorer.validation.pattern", { name });
    } catch {
      return t("apiExplorer.validation.invalidPattern", { name });
    }
  }
  return undefined;
}

function validateJSONValue(value: unknown, schema: JSONSchema | undefined, spec: OpenAPIDocument, t: Translate, path = "request body", depth = 0): string[] {
  const resolved = dereference(schema, spec);
  if (!resolved || depth > 12) return [];
  if (resolved.oneOf?.length) {
    if (resolved.oneOf.some((candidate) => validateJSONValue(value, candidate, spec, t, path, depth + 1).length === 0)) return [];
    return [t("apiExplorer.validation.oneOf", { name: path })];
  }
  if (resolved.enum && !resolved.enum.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value))) {
    return [t("apiExplorer.validation.enum", { name: path, values: resolved.enum.map(String).join(", ") })];
  }
  if (resolved.type === "object" || resolved.properties) {
    if (!isObject(value)) return [t("apiExplorer.validation.object", { name: path })];
    const issues: string[] = [];
    for (const name of resolved.required ?? []) {
      if (!(name in value)) issues.push(t("apiExplorer.validation.required", { name: path === "request body" ? name : `${path}.${name}` }));
    }
    for (const [name, child] of Object.entries(resolved.properties ?? {})) {
      if (name in value) issues.push(...validateJSONValue(value[name], child, spec, t, path === "request body" ? name : `${path}.${name}`, depth + 1));
    }
    if (resolved.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!(name in (resolved.properties ?? {}))) issues.push(t("apiExplorer.validation.notAllowed", { name: `${path}.${name}` }));
      }
    } else if (isObject(resolved.additionalProperties)) {
      for (const name of Object.keys(value)) {
        if (!(name in (resolved.properties ?? {})))
          issues.push(...validateJSONValue(value[name], resolved.additionalProperties, spec, t, `${path}.${name}`, depth + 1));
      }
    }
    return issues;
  }
  if (resolved.type === "array") {
    if (!Array.isArray(value)) return [t("apiExplorer.validation.array", { name: path })];
    return value.flatMap((item, index) => validateJSONValue(item, resolved.items, spec, t, `${path}[${index}]`, depth + 1));
  }
  if (resolved.type === "string" && typeof value !== "string") return [t("apiExplorer.validation.string", { name: path })];
  if (resolved.type === "integer" && (typeof value !== "number" || !Number.isInteger(value))) return [t("apiExplorer.validation.integer", { name: path })];
  if (resolved.type === "number" && (typeof value !== "number" || !Number.isFinite(value))) return [t("apiExplorer.validation.number", { name: path })];
  if (resolved.type === "boolean" && typeof value !== "boolean") return [t("apiExplorer.validation.boolean", { name: path })];
  if (typeof value === "number" && resolved.minimum !== undefined && value < resolved.minimum) {
    return [t("apiExplorer.validation.minimum", { name: path, value: resolved.minimum })];
  }
  if (typeof value === "number" && resolved.maximum !== undefined && value > resolved.maximum) {
    return [t("apiExplorer.validation.maximum", { name: path, value: resolved.maximum })];
  }
  if (typeof value === "string" && resolved.format === "uuid" && !uuidValue(value)) return [t("apiExplorer.validation.uuid", { name: path })];
  if (typeof value === "string" && resolved.format === "date-time" && Number.isNaN(Date.parse(value)))
    return [t("apiExplorer.validation.dateTime", { name: path })];
  if (typeof value === "string" && resolved.minLength !== undefined && value.length < resolved.minLength) {
    return [t("apiExplorer.validation.minLength", { name: path, value: resolved.minLength })];
  }
  if (typeof value === "string" && resolved.maxLength !== undefined && value.length > resolved.maxLength) {
    return [t("apiExplorer.validation.maxLength", { name: path, value: resolved.maxLength })];
  }
  if (typeof value === "string" && resolved.pattern) {
    try {
      if (!new RegExp(resolved.pattern).test(value)) return [t("apiExplorer.validation.pattern", { name: path })];
    } catch {
      return [t("apiExplorer.validation.invalidPattern", { name: path })];
    }
  }
  return [];
}

function appendQueryValue(search: URLSearchParams, parameter: OpenAPIParameter, rawValue: string): void {
  const schema = parameter.schema;
  if (schema?.type !== "array") {
    search.set(parameter.name, rawValue);
    return;
  }
  const values = rawValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (parameter.explode === false) search.set(parameter.name, values.join(","));
  else values.forEach((value) => search.append(parameter.name, value));
}

function prepareRequest(entry: OperationEntry, spec: OpenAPIDocument, draft: RequestDraft, t: Translate): PreparedDraft {
  const issues: DraftIssue[] = [];
  let path = entry.path;
  const query = new URLSearchParams();
  const headers: Record<string, string> = {};
  for (const parameter of entry.operation.parameters ?? []) {
    if (parameter.in === "cookie") continue;
    const key = parameterKey(parameter);
    const value = (draft.parameterValues[key] ?? "").trim();
    if (!value) {
      if (parameter.required || parameter.in === "path") issues.push({ key, message: t("apiExplorer.validation.required", { name: parameter.name }) });
      continue;
    }
    const issue = validatePrimitive(parameter.name, value, parameter.schema, spec, t);
    if (issue) {
      issues.push({ key, message: issue });
      continue;
    }
    if (parameter.in === "path") path = path.replaceAll(`{${parameter.name}}`, encodeURIComponent(value));
    if (parameter.in === "query") appendQueryValue(query, parameter, value);
    if (parameter.in === "header") headers[parameter.name] = value;
  }
  if (/\{[^}]+\}/.test(path)) issues.push({ key: "path", message: t("apiExplorer.validation.allPath") });

  let body: string | undefined;
  let previewBody = "";
  const bodySchema = entry.operation.requestBody?.content?.["application/json"]?.schema;
  if (bodySchema || entry.operation.requestBody) {
    const bodyText = draft.bodyText.trim();
    if (!bodyText) {
      if (entry.operation.requestBody?.required) issues.push({ key: "body", message: t("apiExplorer.validation.bodyRequired") });
    } else {
      try {
        const parsed = JSON.parse(bodyText) as unknown;
        for (const message of validateJSONValue(parsed, bodySchema, spec, t)) issues.push({ key: "body", message });
        body = JSON.stringify(parsed);
        previewBody = safeJSON(parsed);
        headers["Content-Type"] = "application/json";
      } catch (error) {
        issues.push({ key: "body", message: t("apiExplorer.validation.json", { detail: error instanceof Error ? error.message : String(error) }) });
      }
    }
  }

  const queryText = query.toString();
  const finalPath = `${path}${queryText ? `?${queryText}` : ""}`;
  const previewHeaders = {
    ...headers,
    // The scoped test key and response contract are runner-owned. A future
    // OpenAPI header parameter cannot replace either one with operator text.
    Accept: "application/json",
    Authorization: "Bearer [scoped test key hidden]",
  };
  const preview = [
    `${methodLabel(entry.method)} ${finalPath}`,
    ...Object.entries(previewHeaders).map(([name, value]) => `${name}: ${value}`),
    ...(previewBody ? ["", previewBody] : []),
  ].join("\n");
  return { issues, request: issues.length === 0 ? { path: finalPath, headers, body, preview } : undefined };
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

export function buildOperations(spec: OpenAPIDocument): OperationEntry[] {
  const entries: OperationEntry[] = [];
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const method of methods) {
      const operation = pathItem[method];
      if (!operation?.operationId) continue;
      const parameters = operation.parameters ?? [];
      const examplePath = `${replacePathParameters(path, parameters)}${queryString(parameters)}`;
      entries.push({
        key: `${method}:${path}`,
        method,
        path,
        operation,
        permission: operation["x-trstctl-permission"] ?? "access:read",
        examplePath,
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
    `curl -sS -X ${methodLabel(entry.method)} https://control-plane.example${entry.examplePath}`,
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
  const res = await fetch(apiExplorerSpecURL, { credentials: "include", headers: { Accept: "application/json" } });
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
  return <span className="rounded-control bg-muted px-2 py-1 font-mono text-xs font-semibold text-foreground">{methodLabel(method)}</span>;
}

function CodeBlock({ value, labelledBy }: { value: string; labelledBy?: string }) {
  return (
    <pre
      aria-labelledby={labelledBy}
      role="region"
      tabIndex={0}
      className="max-h-72 min-w-0 max-w-full overflow-auto rounded-panel border border-border bg-muted p-3 text-xs leading-relaxed"
    >
      <code>{value}</code>
    </pre>
  );
}

function safeStartingOperation(operations: OperationEntry[]): OperationEntry | undefined {
  return (
    operations.find(
      (entry) => entry.method === "get" && !(entry.operation.parameters ?? []).some((parameter) => parameter.in === "path" || parameter.required),
    ) ?? operations.find((entry) => entry.method === "get")
  );
}

function responseSummaryKey(
  response: ExplorerResponse,
):
  | "apiExplorer.responseSummary.success"
  | "apiExplorer.responseSummary.denied"
  | "apiExplorer.responseSummary.notFound"
  | "apiExplorer.responseSummary.server"
  | "apiExplorer.responseSummary.other" {
  if (response.status >= 200 && response.status < 300) return "apiExplorer.responseSummary.success";
  if (response.status === 401 || response.status === 403) return "apiExplorer.responseSummary.denied";
  if (response.status === 404) return "apiExplorer.responseSummary.notFound";
  if (response.status >= 500) return "apiExplorer.responseSummary.server";
  return "apiExplorer.responseSummary.other";
}

function PlaygroundFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-control border border-border bg-background p-4">
      <dt className="font-medium text-foreground">{label}</dt>
      <dd className="mt-1 text-sm leading-relaxed text-muted-foreground">{value}</dd>
    </div>
  );
}

function ParameterEditor({
  title,
  parameters,
  values,
  issues,
  onChange,
  noParameters,
  requiredLabel,
  optionalLabel,
  schemaFallback,
  inputLabel,
}: {
  title: string;
  parameters: OpenAPIParameter[];
  values: Record<string, string>;
  issues: Map<string, string>;
  onChange: (parameter: OpenAPIParameter, value: string) => void;
  noParameters: string;
  requiredLabel: string;
  optionalLabel: string;
  schemaFallback: string;
  inputLabel: (parameter: OpenAPIParameter) => string;
}) {
  return (
    <div className="ui-panel p-comfortable">
      <h3 className="text-body font-semibold">{title}</h3>
      {parameters.length === 0 ? (
        <p className="mt-2 text-sm text-muted-foreground">{noParameters}</p>
      ) : (
        <div className="mt-3 grid gap-3">
          {parameters.map((parameter) => {
            const key = parameterKey(parameter);
            const issue = issues.get(key);
            return (
              <Field
                key={key}
                className="rounded-control border border-border px-3 py-2 text-sm"
                required={parameter.required}
                description={parameter.description}
                error={issue}
                label={
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{parameter.name}</span>
                    <span className="text-caption font-normal text-muted-foreground">{parameter.required ? requiredLabel : optionalLabel}</span>
                    <span className="text-caption font-normal text-muted-foreground">{parameter.schema?.type ?? schemaFallback}</span>
                  </span>
                }
              >
                {(control) => (
                  <Input
                    {...control}
                    className="font-mono text-xs"
                    aria-label={inputLabel(parameter)}
                    required={parameter.required}
                    value={values[key] ?? ""}
                    onChange={(event) => onChange(parameter, event.target.value)}
                  />
                )}
              </Field>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function ApiExplorer() {
  const { user } = useAuth();
  const { t, formatDateTime } = useTranslation();
  const [searchParams] = useSearchParams();
  const [spec, setSpec] = useState<OpenAPIDocument | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [requestDetailsOpen, setRequestDetailsOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [tokenSubject, setTokenSubject] = useState(user?.email ?? user?.subject ?? "");
  const [testKey, setTestKey] = useState<APITokenCreateResponse | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyRevoked, setKeyRevoked] = useState(false);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [tokenNow, setTokenNow] = useState(() => Date.now());
  const [draft, setDraft] = useState<RequestDraft>({ parameterValues: {}, bodyText: "" });
  const [mutationConfirmed, setMutationConfirmed] = useState(false);
  const [response, setResponse] = useState<ExplorerResponse | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [runBusy, setRunBusy] = useState(false);
  const runController = useRef<AbortController | null>(null);
  const workspaceHeading = useRef<HTMLHeadingElement | null>(null);
  const appliedOperationQuery = useRef("");

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
  const requestedOperation = searchParams.get("operation")?.trim() ?? "";

  useEffect(() => {
    if (requestedOperation && appliedOperationQuery.current !== requestedOperation && operations.length > 0) {
      appliedOperationQuery.current = requestedOperation;
      const requested = operations.find((entry) => entry.operation.operationId === requestedOperation);
      if (requested) {
        setSelectedKey(requested.key);
        setWorkspaceOpen(true);
        return;
      }
    }
    if (!selectedKey && operations.length > 0) setSelectedKey((safeStartingOperation(operations) ?? operations[0]).key);
  }, [operations, requestedOperation, selectedKey]);

  const selected = operations.find((entry) => entry.key === selectedKey) ?? safeStartingOperation(operations) ?? operations[0];
  useEffect(() => {
    if (!selected || !spec) return;
    runController.current?.abort();
    runController.current = null;
    setDraft(buildInitialRequestDraft(selected, spec));
    setMutationConfirmed(false);
    setRequestDetailsOpen(isUnsafe(selected.method));
    setRunBusy(false);
    setResponse(null);
    setRunError(null);
  }, [selected, spec]);

  useEffect(() => {
    const expiresAt = testKey?.expires_at ? Date.parse(testKey.expires_at) : Number.NaN;
    if (!Number.isFinite(expiresAt)) return;
    const delay = Math.max(0, expiresAt - Date.now());
    if (delay === 0) {
      setTokenNow(Date.now());
      return;
    }
    const timer = globalThis.setTimeout(() => setTokenNow(Date.now()), delay);
    return () => globalThis.clearTimeout(timer);
  }, [testKey]);

  useEffect(() => () => runController.current?.abort(), []);

  const loweredFilter = filter.trim().toLowerCase();
  const matchingOperations = operations.filter((entry) => {
    if (!loweredFilter) return true;
    return [entry.path, entry.operation.operationId, entry.operation.summary, entry.permission].filter(Boolean).join(" ").toLowerCase().includes(loweredFilter);
  });
  const visibleOperations = matchingOperations.slice(0, operationResultLimit);

  function openWorkspace() {
    setWorkspaceOpen(true);
    globalThis.requestAnimationFrame?.(() => workspaceHeading.current?.focus());
  }

  async function mintTestKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setKeyBusy(true);
    setKeyError(null);
    const expiresAt = new Date(Date.now() + docsTokenTTLMinutes * 60 * 1000).toISOString();
    try {
      if (testKey && !keyRevoked && !tokenExpired) {
        await api.revokeAPIToken(testKey.id);
        setKeyRevoked(true);
      }
      const created = await api.createAPIToken({
        subject: tokenSubject.trim(),
        scopes: [selected.permission],
        expires_at: expiresAt,
      });
      setTestKey(created);
      setKeyRevoked(false);
      setTokenNow(Date.now());
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : String(err));
    } finally {
      setKeyBusy(false);
    }
  }

  async function revokeTestKey() {
    if (!testKey || keyRevoked) return;
    setRevokeBusy(true);
    setKeyError(null);
    try {
      await api.revokeAPIToken(testKey.id);
      setKeyRevoked(true);
      runController.current?.abort();
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : String(err));
    } finally {
      setRevokeBusy(false);
    }
  }

  async function runRequest() {
    if (!selected || !testKey || !prepared.request || tokenExpired || keyRevoked || (isUnsafe(selected.method) && !mutationConfirmed)) return;
    setRunBusy(true);
    setRunError(null);
    setResponse(null);
    const headers: Record<string, string> = {
      ...prepared.request.headers,
      Accept: "application/json",
      Authorization: `Bearer ${testKey.token}`,
    };
    const controller = new AbortController();
    runController.current = controller;
    try {
      const res = await fetch(prepared.request.path, {
        method: methodLabel(selected.method),
        headers,
        body: prepared.request.body,
        signal: controller.signal,
      });
      const nextResponse = await readExplorerResponse(res);
      if (!controller.signal.aborted) setResponse(nextResponse);
    } catch (err) {
      if (runController.current === controller) {
        setRunError(isAbortError(err) ? t("apiExplorer.cancelled") : err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (runController.current === controller) {
        runController.current = null;
        setRunBusy(false);
      }
    }
  }

  const pathParameters = selected?.operation.parameters?.filter((parameter) => parameter.in === "path") ?? [];
  const queryParameters = selected?.operation.parameters?.filter((parameter) => parameter.in === "query") ?? [];
  const headerParameters = selected?.operation.parameters?.filter((parameter) => parameter.in === "header") ?? [];
  const prepared = selected && spec ? prepareRequest(selected, spec, draft, t) : { issues: [] };
  const issueByKey = new Map(prepared.issues.map((issue) => [issue.key, issue.message]));
  const bodyIssues = prepared.issues.filter((issue) => issue.key === "body");
  const tokenExpiry = testKey?.expires_at ? Date.parse(testKey.expires_at) : Number.NaN;
  const tokenExpired = Boolean(testKey && (!Number.isFinite(tokenExpiry) || tokenExpiry <= tokenNow));
  const keyUsable = Boolean(testKey && !tokenExpired && !keyRevoked && testKey.scopes.includes(selected?.permission ?? ""));
  const canRun = Boolean(prepared.request && keyUsable && !runBusy && (!selected || !isUnsafe(selected.method) || mutationConfirmed));
  const curl = selected ? curlExample(selected) : "";
  const sdk = selected ? sdkExample(selected) : "";

  function updateParameter(parameter: OpenAPIParameter, value: string) {
    runController.current?.abort();
    setDraft((current) => ({ ...current, parameterValues: { ...current.parameterValues, [parameterKey(parameter)]: value } }));
    setMutationConfirmed(false);
    setResponse(null);
  }

  function updateBody(value: string) {
    runController.current?.abort();
    setDraft((current) => ({ ...current, bodyText: value }));
    setMutationConfirmed(false);
    setResponse(null);
  }

  return (
    <section aria-labelledby="api-explorer-heading" className="grid min-w-0 gap-6">
      <PageHeader
        titleId="api-explorer-heading"
        title={t("apiExplorer.title")}
        description={t("apiExplorer.description")}
        technicalDetails={t("apiExplorer.technicalDetails")}
        actions={
          <Button type="button" onClick={openWorkspace} disabled={loading || Boolean(loadError) || !selected}>
            <Play className="h-4 w-4" aria-hidden="true" />
            {t("apiExplorer.primaryAction")}
          </Button>
        }
      />

      <Link className="inline-flex w-fit items-center gap-2 text-sm font-medium text-muted-foreground underline hover:text-foreground" to="/integrate">
        <ArrowLeft className="h-4 w-4" aria-hidden="true" />
        {t("apiExplorer.back")}
      </Link>

      <section aria-labelledby="api-playground-map-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="grid gap-1">
          <h2 id="api-playground-map-heading" className="text-title font-semibold">
            {t("apiExplorer.design.summaryTitle")}
          </h2>
          <p className="max-w-3xl text-body text-muted-foreground">{t("apiExplorer.design.summaryDescription")}</p>
        </div>
        <dl className="grid gap-3 md:grid-cols-3">
          <PlaygroundFact label={t("apiExplorer.design.readLabel")} value={t("apiExplorer.design.readValue")} />
          <PlaygroundFact label={t("apiExplorer.design.accessLabel")} value={t("apiExplorer.design.accessValue")} />
          <PlaygroundFact label={t("apiExplorer.design.answerLabel")} value={t("apiExplorer.design.answerValue")} />
        </dl>
      </section>

      {loading && (
        <p role="status" className="rounded-panel border border-border bg-card p-4 text-sm text-muted-foreground">
          <Loader2 className="mr-2 inline h-4 w-4 animate-spin" aria-hidden="true" />
          {t("apiExplorer.loading")}
        </p>
      )}

      {loadError && (
        <div role="alert" className="rounded-panel border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-medium">{t("apiExplorer.loadFailed")}</p>
              <p className="mt-1">{t("apiExplorer.loadFailedHelp")}</p>
              <details className="mt-2 text-xs">
                <summary className="cursor-pointer">{t("apiExplorer.loadFailedDetails")}</summary>
                <code className="mt-1 block break-all">{loadError}</code>
              </details>
            </div>
            <Button type="button" size="sm" variant="outline" onClick={() => void load()}>
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              {t("apiExplorer.reload")}
            </Button>
          </div>
        </div>
      )}

      {!loading && !loadError && spec && operations.length === 0 && (
        <div className="rounded-panel border border-border bg-card p-4 text-sm">
          <p className="font-medium">{t("apiExplorer.empty")}</p>
          <p className="mt-1 text-muted-foreground">{t("apiExplorer.emptyHelp")}</p>
        </div>
      )}

      {workspaceOpen && selected && (
        <section aria-labelledby="api-workspace-heading" className="grid min-w-0 gap-4">
          <div className="grid gap-1">
            <h2 ref={workspaceHeading} id="api-workspace-heading" tabIndex={-1} className="text-title font-semibold outline-none">
              {t("apiExplorer.workspaceTitle")}
            </h2>
            <p className="max-w-3xl text-sm text-muted-foreground">{t("apiExplorer.workspaceDescription")}</p>
          </div>

          <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(20rem,0.85fr)]">
            <div className="grid min-w-0 gap-4">
              <section className="ui-panel min-w-0 p-comfortable" aria-labelledby="api-operation-detail-heading">
                <p className="text-caption font-medium uppercase tracking-wide text-muted-foreground">
                  {isUnsafe(selected.method) ? t("apiExplorer.changesData") : t("apiExplorer.safeStartingPoint")}
                </p>
                <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 id="api-operation-detail-heading" className="text-title font-semibold">
                      {selected.operation.summary ?? selected.operation.operationId}
                    </h3>
                    {selected.operation.description && <p className="mt-1 text-sm text-muted-foreground">{selected.operation.description}</p>}
                  </div>
                  <MethodBadge method={selected.method} />
                </div>
                <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
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
                    <dd className="break-all font-mono text-xs">{selected.permission}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("apiExplorer.response")}</dt>
                    <dd className="break-all font-mono text-xs">{responseNames(selected.operation).join(", ")}</dd>
                  </div>
                </dl>
              </section>

              <details className="ui-panel min-w-0 p-comfortable">
                <summary className="cursor-pointer font-medium text-foreground">{t("apiExplorer.allOperations")}</summary>
                <div className="mt-4 grid min-w-0 gap-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-body font-semibold">{t("apiExplorer.chooseRequest")}</h3>
                    <span className="text-caption text-muted-foreground">{t("apiExplorer.operationCount", { count: operations.length })}</span>
                  </div>
                  <label className="grid gap-1 text-sm">
                    <span className="sr-only">{t("apiExplorer.searchLabel")}</span>
                    <Input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={t("apiExplorer.searchPlaceholder")} />
                  </label>
                  {visibleOperations.length === 0 ? (
                    <p className="rounded-control bg-muted px-3 py-2 text-sm text-muted-foreground">{t("apiExplorer.noMatches")}</p>
                  ) : (
                    <div className="grid gap-2">
                      {visibleOperations.map((entry) => (
                        <button
                          key={entry.key}
                          type="button"
                          className={`rounded-control border px-3 py-2 text-left transition ${
                            entry.key === selected.key ? "border-foreground/40 bg-muted text-foreground" : "border-border bg-background hover:bg-muted/60"
                          }`}
                          onClick={() => {
                            setSelectedKey(entry.key);
                            setResponse(null);
                            setRunError(null);
                          }}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <MethodBadge method={entry.method} />
                            <span className="truncate font-mono text-xs">{entry.operation.operationId}</span>
                          </span>
                          <span className="mt-1 block truncate text-xs text-muted-foreground">{entry.path}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {matchingOperations.length > operationResultLimit && (
                    <p className="text-caption text-muted-foreground">
                      {t("apiExplorer.resultLimit", { shown: operationResultLimit, count: matchingOperations.length })}
                    </p>
                  )}
                </div>
              </details>

              <details
                className="ui-panel min-w-0 p-comfortable"
                open={requestDetailsOpen}
                onToggle={(event) => setRequestDetailsOpen(event.currentTarget.open)}
              >
                <summary className="cursor-pointer font-medium text-foreground">{t("apiExplorer.requestDetailsDisclosure")}</summary>
                <div className="mt-4 grid min-w-0 gap-4">
                  <section className="grid gap-4 lg:grid-cols-3">
                    {[
                      { title: t("apiExplorer.pathParameters"), parameters: pathParameters },
                      { title: t("apiExplorer.queryParameters"), parameters: queryParameters },
                      { title: t("apiExplorer.headerParameters"), parameters: headerParameters },
                    ].map(({ title, parameters }) => (
                      <ParameterEditor
                        key={title}
                        title={title}
                        parameters={parameters}
                        values={draft.parameterValues}
                        issues={issueByKey}
                        onChange={updateParameter}
                        noParameters={t("apiExplorer.noParameters")}
                        requiredLabel={t("apiExplorer.required")}
                        optionalLabel={t("apiExplorer.optional")}
                        schemaFallback={t("apiExplorer.schemaString")}
                        inputLabel={(parameter) => t("apiExplorer.parameterValue", { name: parameter.name, location: parameter.in })}
                      />
                    ))}
                  </section>

                  <section className="rounded-control border border-border p-4">
                    <h3 id="api-request-body-heading" className="text-body font-semibold">
                      {t("apiExplorer.requestBody")}
                    </h3>
                    {selected.operation.requestBody ? (
                      <Field
                        className="mt-3"
                        label={t("apiExplorer.bodyInput")}
                        description={schemaNameForOperation(selected.operation)}
                        required={selected.operation.requestBody.required}
                        error={
                          bodyIssues.length > 0 ? (
                            <span className="grid gap-1">
                              {bodyIssues.map((issue, index) => (
                                <span key={`${issue.message}-${index}`}>{issue.message}</span>
                              ))}
                            </span>
                          ) : undefined
                        }
                      >
                        {(control) => (
                          <Textarea
                            {...control}
                            className="min-h-52 font-mono text-xs leading-relaxed"
                            aria-label={t("apiExplorer.bodyInput")}
                            required={selected.operation.requestBody?.required}
                            value={draft.bodyText}
                            onChange={(event) => updateBody(event.target.value)}
                          />
                        )}
                      </Field>
                    ) : (
                      <p className="mt-2 text-sm text-muted-foreground">{t("apiExplorer.noRequestBody")}</p>
                    )}
                  </section>

                  <div className="min-w-0">
                    <h3 id="api-request-preview-heading" className="mb-2 text-body font-semibold">
                      {t("apiExplorer.requestPreview")}
                    </h3>
                    <p className="mb-2 text-caption text-muted-foreground">{t("apiExplorer.previewSecretNote")}</p>
                    <CodeBlock
                      labelledBy="api-request-preview-heading"
                      value={prepared.request?.preview ?? `${methodLabel(selected.method)} ${selected.path}\n\n${t("apiExplorer.fixValidation")}`}
                    />
                  </div>
                  {prepared.issues.length > 0 && (
                    <div role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                      <p className="font-medium">{t("apiExplorer.validationFailed")}</p>
                      <ul className="mt-1 list-disc ps-5 text-xs">
                        {prepared.issues.map((issue, index) => (
                          <li key={`${issue.key}-${issue.message}-${index}`}>{issue.message}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </details>

              <details className="ui-panel min-w-0 p-comfortable">
                <summary className="cursor-pointer font-medium text-foreground">{t("apiExplorer.schemaExamplesDisclosure")}</summary>
                <div className="mt-4 grid min-w-0 gap-3">
                  <a className="w-fit text-sm font-medium underline" href={apiExplorerSpecURL} target="_blank" rel="noreferrer">
                    {t("apiExplorer.openSchema")}
                  </a>
                  <div className="flex flex-wrap gap-2">
                    <CopyButton label={t("apiExplorer.copyCurl")} value={curl} />
                    <CopyButton label={t("apiExplorer.copySdk")} value={sdk} />
                  </div>
                  <h3 id="api-examples-heading" className="sr-only">
                    {t("apiExplorer.examples")}
                  </h3>
                  <CodeBlock labelledBy="api-examples-heading" value={`${curl}\n\n${sdk}`} />
                </div>
              </details>
            </div>

            <div className="grid min-w-0 gap-4">
              <section className="ui-panel min-w-0 p-comfortable" aria-labelledby="api-runner-heading">
                <p className="text-caption font-medium uppercase tracking-wide text-muted-foreground">{t("apiExplorer.stepTwo")}</p>
                <h3 id="api-runner-heading" className="mt-1 text-title font-semibold">
                  {t("apiExplorer.runner")}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("apiExplorer.runnerHelp")}</p>
                <form onSubmit={(event) => void mintTestKey(event)} className="mt-4 grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3">
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium text-muted-foreground">{t("apiExplorer.subject")}</span>
                    <Input value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
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
                  <p role="alert" className="mt-3 rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {t("apiExplorer.keyFailed")} {keyError}
                  </p>
                )}
                {testKey && (
                  <div
                    role="status"
                    className={`mt-3 rounded-panel border p-3 text-sm ${
                      tokenExpired || keyRevoked
                        ? "border-status-warning/30 bg-status-warning/10 text-status-warning"
                        : "border-status-success/30 bg-status-success/10 text-status-success"
                    }`}
                  >
                    <p className="font-medium">
                      {tokenExpired
                        ? t("apiExplorer.keyExpired")
                        : keyRevoked
                          ? t("apiExplorer.keyRevoked")
                          : t("apiExplorer.keyReady", { scope: testKey.scopes.join(", ") })}
                    </p>
                    <p className="mt-1 text-xs">{t("apiExplorer.revealOnce")}</p>
                    {testKey.expires_at && (
                      <p className="mt-1 text-xs">
                        {t("apiExplorer.expires")}: {formatDateTime(testKey.expires_at)}
                      </p>
                    )}
                    {!tokenExpired && !keyRevoked && (
                      <Button className="mt-3" type="button" size="sm" variant="outline" disabled={revokeBusy} onClick={() => void revokeTestKey()}>
                        {revokeBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : null}
                        {revokeBusy ? t("apiExplorer.revokingKey") : t("apiExplorer.revokeKey")}
                      </Button>
                    )}
                  </div>
                )}

                <div className="mt-4 grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3">
                  {isUnsafe(selected.method) && prepared.request && (
                    <label
                      htmlFor="api-explorer-confirm-mutation"
                      className="flex items-start gap-2 rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm"
                    >
                      <Checkbox
                        id="api-explorer-confirm-mutation"
                        className="mt-0.5 accent-brand-accent"
                        aria-label={t("apiExplorer.confirmMutation")}
                        checked={mutationConfirmed}
                        onChange={(event) => setMutationConfirmed(event.target.checked)}
                      />
                      <span>
                        <span className="font-medium">{t("apiExplorer.confirmMutation")}</span>
                        <span className="mt-1 block text-xs text-muted-foreground">{t("apiExplorer.confirmMutationDetail")}</span>
                      </span>
                    </label>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" onClick={() => void runRequest()} disabled={!canRun}>
                      {runBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
                      {runBusy ? t("apiExplorer.running") : t("apiExplorer.run")}
                    </Button>
                    {runBusy && (
                      <Button type="button" variant="outline" onClick={() => runController.current?.abort()}>
                        {t("apiExplorer.cancel")}
                      </Button>
                    )}
                  </div>
                  {!testKey && <p className="text-sm text-muted-foreground">{t("apiExplorer.needsKey")}</p>}
                </div>
              </section>

              <section className="ui-panel p-comfortable" aria-labelledby="api-response-heading">
                <p className="text-caption font-medium uppercase tracking-wide text-muted-foreground">{t("apiExplorer.stepThree")}</p>
                <h3 id="api-response-heading" className="mt-1 text-title font-semibold">
                  {t("apiExplorer.response")}
                </h3>
                {runError && (
                  <p role="alert" className="mt-3 rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {runError === t("apiExplorer.cancelled") ? runError : t("apiExplorer.runFailedDetail", { detail: runError })}
                  </p>
                )}
                {!runError && !response && <p className="mt-3 text-sm text-muted-foreground">{t("apiExplorer.noResponse")}</p>}
                {response && (
                  <div className="mt-3 grid gap-3 text-sm">
                    <p className="rounded-control bg-muted px-3 py-2 font-medium">{t(responseSummaryKey(response))}</p>
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
                    <details className="min-w-0 rounded-control border border-border p-3">
                      <summary className="cursor-pointer font-medium">{t("apiExplorer.rawResponse")}</summary>
                      <div className="mt-3 min-w-0">
                        <h4 id="api-response-body-heading" className="sr-only">
                          {t("apiExplorer.responseBody")}
                        </h4>
                        <CodeBlock labelledBy="api-response-body-heading" value={response.bodyText || "{}"} />
                      </div>
                    </details>
                  </div>
                )}
              </section>
            </div>
          </div>
        </section>
      )}
    </section>
  );
}
