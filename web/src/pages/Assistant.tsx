import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Bot, Search, ShieldAlert, Wrench } from "lucide-react";
import { api, ApiError, type AIAnswer, type AIStatus } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { UnavailableState } from "@/components/StatePrimitives";
import { cn } from "@/lib/utils";

type Tab = "query" | "rca" | "mcp";

const surfaceOptions = [
  { value: "certificates", label: "Certificates" },
  { value: "owners", label: "Owners" },
  { value: "graph", label: "Graph" },
  { value: "cbom", label: "CBOM" },
  { value: "log", label: "Audit log" },
];

function formatError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) return "Permission denied for this evidence scope.";
    if (err.status === 404) return "Tool is not available.";
    if (err.status === 429) {
      return err.retryAfterSeconds != null ? `Rate limited. Try again in ${err.retryAfterSeconds}s.` : "Rate limited. Try again later.";
    }
    if (err.status === 503) return "Assistant surface is not enabled.";
    return `Request failed (${err.status}).`;
  }
  return err instanceof Error ? err.message : String(err);
}

function ToggleTab({ active, children, icon, onClick }: { active: boolean; children: ReactNode; icon: ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex h-9 items-center gap-2 rounded-control border px-3 text-body font-medium transition-colors",
        active
          ? "border-brand-accent bg-brand-accent text-brand-accent-foreground shadow-elevation1"
          : "border-border hover:border-brand-accent/40 hover:bg-muted/60",
      )}
      aria-pressed={active}
    >
      {icon}
      {children}
    </button>
  );
}

function HelpTerm({ children, title }: { children: ReactNode; title: string }) {
  return (
    <span className="underline decoration-dotted underline-offset-2" title={title}>
      {children}
    </span>
  );
}

function AnswerPanel({ answer, tool }: { answer: AIAnswer | null; tool?: string }) {
  if (!answer) return null;
  const citations = answer.citations ?? [];
  return (
    <section aria-label="Assistant answer" className="mt-5 ui-panel p-comfortable">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-caption font-medium">
        {tool && <span className="rounded-control border border-border px-2 py-1">Tool: {tool}</span>}
        <span className="rounded-control border border-border px-2 py-1">
          <HelpTerm title="Grounded means the answer cites tenant evidence returned by the API.">
            {answer.grounded ? "Grounded" : "No cited evidence"}
          </HelpTerm>
        </span>
        <span className="rounded-control border border-border px-2 py-1">
          <HelpTerm title="Sufficient means the cited evidence is enough to answer without guessing.">
            {answer.sufficient ? "Sufficient" : "Insufficient"}
          </HelpTerm>
        </span>
      </div>
      <p className="whitespace-pre-wrap text-body" data-testid="assistant-answer">
        {answer.text}
      </p>
      <div className="mt-4">
        <h3 className="text-body font-semibold">Cited evidence</h3>
        {citations.length === 0 ? (
          <p className="mt-2 text-body text-muted-foreground">No citations returned.</p>
        ) : (
          <ul className="mt-2 space-y-1 text-body">
            {citations.map((citation) => (
              <li key={citation} className="rounded-control border border-border px-2 py-1 font-mono text-caption">
                {citation}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function AssistantRuntimeDisclosure({ status, error, loading }: { status: AIStatus | null; error: string | null; loading: boolean }) {
  const [open, setOpen] = useState(false);
  const enabled = status?.enabled ? "enabled" : "disabled";
  const model = status?.model_configured ? (status.model_name ? `${status.model_mode}: ${status.model_name}` : status.model_mode) : "not configured";
  const egress = status?.egress ?? "none";
  const endpoint = status?.endpoint_host ?? "not disclosed";
  return (
    <details className="group mb-6 border-b border-border pb-6" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="inline-flex cursor-pointer items-center rounded-control border border-border px-3 py-2 text-body font-medium hover:border-brand-accent/40 hover:bg-muted/60">
        Advanced runtime diagnostics
      </summary>
      {open && (
        <div className="mt-4 grid gap-3">
          <div>
            <h2 id="assistant-runtime-heading" className="text-title font-semibold">
              AI runtime boundary
            </h2>
            <p className="mt-1 max-w-3xl text-body text-muted-foreground">
              Query, RCA, and MCP fail closed when disabled. Tenant and RBAC scope come from the authenticated session/API token, never from a browser field.
            </p>
          </div>
          <dl className="grid gap-3 md:grid-cols-4">
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">Surface</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : enabled}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">Model</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : model}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">Egress</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : egress}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">Endpoint host</dt>
              <dd className="mt-1 break-words text-title font-semibold">{loading ? "loading" : endpoint}</dd>
            </div>
          </dl>
          <p className="text-body text-muted-foreground">
            Redaction boundary: {status?.redaction ?? "default-redactor"}; residual refusal gate:{" "}
            {status?.residual_refusal_gate === false ? "inactive" : "active"}.
          </p>
          {error && (
            <UnavailableState title="AI runtime status unavailable">
              The console could not read runtime status, so it shows the safe baseline: no confirmed model means no confirmed prompt egress.
            </UnavailableState>
          )}
        </div>
      )}
    </details>
  );
}

function QueryPreview({ surfaces, subject }: { surfaces: string[]; subject: string }) {
  return (
    <section aria-labelledby="query-preview-heading" className="mb-4 ui-panel p-comfortable text-body">
      <h3 id="query-preview-heading" className="font-semibold">
        Structured query preview
      </h3>
      <dl className="mt-2 grid gap-2 md:grid-cols-3">
        <div>
          <dt className="text-caption text-muted-foreground">Surfaces</dt>
          <dd>{surfaces.join(", ") || "none selected"}</dd>
        </div>
        <div>
          <dt className="text-caption text-muted-foreground">Subject</dt>
          <dd>{subject.trim() || "not scoped"}</dd>
        </div>
        <div>
          <dt className="text-caption text-muted-foreground">Limit</dt>
          <dd>25 cited records</dd>
        </div>
      </dl>
      <p className="mt-2 text-muted-foreground">
        Tenant/RBAC filtering is applied below this request; a prompt cannot ask for another tenant.
      </p>
    </section>
  );
}

function RCAWorkspaceDisclosure() {
  return (
    <section aria-labelledby="rca-workspace-heading" className="mb-4 ui-panel p-comfortable text-body">
      <h3 id="rca-workspace-heading" className="font-semibold">
        RCA evidence workspace
      </h3>
      <p className="mt-2 text-muted-foreground">
        RCA answers are sufficient or insufficient based on cited evidence. Hostile record text is rendered as inert text, and next actions stay links or text
        until a remediation workflow exists.
      </p>
    </section>
  );
}

function MCPBoundary({ readOnly }: { readOnly?: boolean }) {
  return (
    <section aria-labelledby="mcp-boundary-heading" className="mb-4 ui-panel p-comfortable text-body">
      <h3 id="mcp-boundary-heading" className="font-semibold">
        <HelpTerm title="Model Context Protocol: read-only assistant tools exposed by policy.">MCP</HelpTerm> permission boundary
      </h3>
      <p className="mt-2 text-muted-foreground">
        Tools are {readOnly ? "read-only" : "treated as unavailable until policy allows them"} and cannot remediate or mutate credentials. Model egress and
        redaction posture are read from the runtime status above.
      </p>
    </section>
  );
}

export function Assistant() {
  const [tab, setTab] = useState<Tab>("query");
  const [question, setQuestion] = useState("");
  const [subject, setSubject] = useState("");
  const [surfaces, setSurfaces] = useState<string[]>(["certificates", "owners", "graph"]);
  const [queryAnswer, setQueryAnswer] = useState<AIAnswer | null>(null);
  const [rcaQuestion, setRCAQuestion] = useState("");
  const [rcaSubject, setRCASubject] = useState("");
  const [rcaAnswer, setRCAAnswer] = useState<AIAnswer | null>(null);
  const [selectedTool, setSelectedTool] = useState("");
  const [toolSubject, setToolSubject] = useState("");
  const [toolAnswer, setToolAnswer] = useState<(AIAnswer & { tool?: string }) | null>(null);
  const [loading, setLoading] = useState<Tab | null>(null);
  const [error, setError] = useState<string | null>(null);
  const runtime = useResource(api.aiStatus);
  const tools = useResource(api.mcpTools);

  useEffect(() => {
    if (!selectedTool && tools.data?.tools?.length) setSelectedTool(tools.data.tools[0]);
  }, [selectedTool, tools.data]);

  function toggleSurface(value: string) {
    setSurfaces((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]));
  }

  async function runQuery(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading("query");
    setQueryAnswer(null);
    try {
      if (surfaces.length === 0) throw new Error("Choose at least one evidence surface.");
      const answer = await api.aiQuery({
        question: question.trim(),
        subject: subject.trim() || undefined,
        surfaces,
        limit: 25,
      });
      setQueryAnswer(answer);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(null);
    }
  }

  async function runRCA(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading("rca");
    setRCAAnswer(null);
    try {
      const answer = await api.aiRCA({
        question: rcaQuestion.trim(),
        subject: rcaSubject.trim() || undefined,
      });
      setRCAAnswer(answer);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(null);
    }
  }

  async function runTool(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading("mcp");
    setToolAnswer(null);
    try {
      const result = await api.callMCPTool(selectedTool, { subject: toolSubject.trim() || undefined });
      setToolAnswer({
        text: result.text,
        citations: result.citations ?? [],
        sufficient: (result.citations ?? []).length > 0,
        grounded: (result.citations ?? []).length > 0,
        tool: result.tool,
      });
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(null);
    }
  }

  return (
    <section aria-labelledby="assistant-heading">
      <PageHeader
        title="Assistant"
        titleId="assistant-heading"
        description="Grounded query, root-cause analysis, and read-only MCP tools."
        actions={
          tools.data ? (
            <span className="rounded-control border border-border bg-card px-3 py-2 text-caption font-medium shadow-elevation1">
              {tools.data.read_only ? "Read-only tools" : "Tool policy unavailable"}
            </span>
          ) : undefined
        }
      />
      <AssistantRuntimeDisclosure status={runtime.data} error={runtime.error} loading={runtime.loading} />

      <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label="Assistant workflow">
        <ToggleTab active={tab === "query"} onClick={() => setTab("query")} icon={<Search aria-hidden="true" className="h-4 w-4" />}>
          Query
        </ToggleTab>
        <ToggleTab active={tab === "rca"} onClick={() => setTab("rca")} icon={<ShieldAlert aria-hidden="true" className="h-4 w-4" />}>
          RCA
        </ToggleTab>
        <ToggleTab active={tab === "mcp"} onClick={() => setTab("mcp")} icon={<Wrench aria-hidden="true" className="h-4 w-4" />}>
          <HelpTerm title="Model Context Protocol: read-only assistant tools exposed by policy.">MCP</HelpTerm> tools
        </ToggleTab>
      </div>

      {error && (
        <p role="alert" className="mb-4 rounded-control border border-destructive/40 bg-destructive/10 p-3 text-body text-destructive">
          {error}
        </p>
      )}

      {tab === "query" && (
        <Card>
          <CardHeader>
            <CardTitle>Grounded query</CardTitle>
          </CardHeader>
          <CardContent>
            <QueryPreview surfaces={surfaces} subject={subject} />
            <form onSubmit={runQuery} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-body font-medium">
                  Question
                  <textarea
                    className="min-h-24 w-full rounded-control border border-border bg-background p-3 text-body font-normal"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder="Which certificates should rotate first?"
                    required
                  />
                </label>
                <label className="space-y-2 text-body font-medium">
                  Subject
                  <input
                    className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="Optional"
                  />
                </label>
              </div>
              <fieldset className="space-y-2">
                <legend className="text-body font-medium">Evidence surfaces</legend>
                <div className="flex flex-wrap gap-3">
                  {surfaceOptions.map((surface) => (
                    <label key={surface.value} className="inline-flex items-center gap-2 text-body">
                      <input type="checkbox" checked={surfaces.includes(surface.value)} onChange={() => toggleSurface(surface.value)} />
                      {surface.value === "cbom" ? (
                        <HelpTerm title="Cryptographic Bill of Materials: an inventory of algorithms, key sizes, protocols, and crypto posture.">
                          CBOM
                        </HelpTerm>
                      ) : (
                        surface.label
                      )}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Button type="submit" disabled={loading === "query"}>
                <Bot aria-hidden="true" className="h-4 w-4" />
                {loading === "query" ? "Asking" : "Ask"}
              </Button>
            </form>
            <AnswerPanel answer={queryAnswer} />
          </CardContent>
        </Card>
      )}

      {tab === "rca" && (
        <Card>
          <CardHeader>
            <CardTitle>Root-cause analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <RCAWorkspaceDisclosure />
            <form onSubmit={runRCA} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-body font-medium">
                  Question
                  <textarea
                    className="min-h-24 w-full rounded-control border border-border bg-background p-3 text-body font-normal"
                    value={rcaQuestion}
                    onChange={(e) => setRCAQuestion(e.target.value)}
                    placeholder="Why did this identity become high risk?"
                    required
                  />
                </label>
                <label className="space-y-2 text-body font-medium">
                  Subject
                  <input
                    className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                    value={rcaSubject}
                    onChange={(e) => setRCASubject(e.target.value)}
                    placeholder="Optional"
                  />
                </label>
              </div>
              <Button type="submit" disabled={loading === "rca"}>
                <ShieldAlert aria-hidden="true" className="h-4 w-4" />
                {loading === "rca" ? "Analyzing" : "Analyze"}
              </Button>
            </form>
            <AnswerPanel answer={rcaAnswer} />
          </CardContent>
        </Card>
      )}

      {tab === "mcp" && (
        <Card>
          <CardHeader>
            <CardTitle>MCP tools</CardTitle>
          </CardHeader>
          <CardContent>
            <MCPBoundary readOnly={tools.data?.read_only} />
            {tools.loading && (
              <p role="status" className="text-body text-muted-foreground">
                Loading tools...
              </p>
            )}
            {tools.error && (
              <p role="alert" className="text-body text-destructive">
                Could not load tools: {tools.error}
              </p>
            )}
            {tools.data && tools.data.tools.length === 0 && <p className="text-body text-muted-foreground">No MCP tools are available for this tenant.</p>}
            {tools.data && tools.data.tools.length > 0 && (
              <form onSubmit={runTool} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[1fr_2fr]">
                  <label className="space-y-2 text-body font-medium">
                    Tool
                    <select
                      className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                      value={selectedTool}
                      onChange={(e) => setSelectedTool(e.target.value)}
                    >
                      {tools.data.tools.map((tool) => (
                        <option key={tool} value={tool}>
                          {tool}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="space-y-2 text-body font-medium">
                    Subject
                    <input
                      className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                      value={toolSubject}
                      onChange={(e) => setToolSubject(e.target.value)}
                      placeholder="Optional"
                    />
                  </label>
                </div>
                <Button type="submit" disabled={loading === "mcp" || !selectedTool}>
                  <Wrench aria-hidden="true" className="h-4 w-4" />
                  {loading === "mcp" ? "Invoking" : "Invoke"}
                </Button>
              </form>
            )}
            <AnswerPanel answer={toolAnswer} tool={toolAnswer?.tool} />
          </CardContent>
        </Card>
      )}
    </section>
  );
}
