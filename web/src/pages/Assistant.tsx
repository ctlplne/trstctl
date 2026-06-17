import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Bot, Search, ShieldAlert, Wrench } from "lucide-react";
import { api, ApiError, type AIAnswer } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
      return err.retryAfterSeconds != null
        ? `Rate limited. Try again in ${err.retryAfterSeconds}s.`
        : "Rate limited. Try again later.";
    }
    if (err.status === 503) return "Assistant surface is not enabled.";
    return `Request failed (${err.status}).`;
  }
  return err instanceof Error ? err.message : String(err);
}

function ToggleTab({
  active,
  children,
  icon,
  onClick,
}: {
  active: boolean;
  children: ReactNode;
  icon: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm font-medium",
        active ? "border-primary bg-primary text-primary-foreground" : "border-border hover:bg-muted",
      )}
      aria-pressed={active}
    >
      {icon}
      {children}
    </button>
  );
}

function AnswerPanel({ answer, tool }: { answer: AIAnswer | null; tool?: string }) {
  if (!answer) return null;
  const citations = answer.citations ?? [];
  return (
    <section aria-label="Assistant answer" className="mt-5 rounded-md border border-border p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs font-medium">
        {tool && <span className="rounded border border-border px-2 py-1">Tool: {tool}</span>}
        <span className="rounded border border-border px-2 py-1">
          {answer.grounded ? "Grounded" : "No cited evidence"}
        </span>
        <span className="rounded border border-border px-2 py-1">
          {answer.sufficient ? "Sufficient" : "Insufficient"}
        </span>
      </div>
      <p className="whitespace-pre-wrap text-sm leading-6" data-testid="assistant-answer">
        {answer.text}
      </p>
      <div className="mt-4">
        <h3 className="text-sm font-semibold">Cited evidence</h3>
        {citations.length === 0 ? (
          <p className="mt-2 text-sm text-muted-foreground">No citations returned.</p>
        ) : (
          <ul className="mt-2 space-y-1 text-sm">
            {citations.map((citation) => (
              <li key={citation} className="rounded border border-border px-2 py-1 font-mono text-xs">
                {citation}
              </li>
            ))}
          </ul>
        )}
      </div>
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
  const tools = useResource(api.mcpTools);

  useEffect(() => {
    if (!selectedTool && tools.data?.tools?.length) setSelectedTool(tools.data.tools[0]);
  }, [selectedTool, tools.data]);

  function toggleSurface(value: string) {
    setSurfaces((current) =>
      current.includes(value) ? current.filter((v) => v !== value) : [...current, value],
    );
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
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 id="assistant-heading" className="text-2xl font-semibold">
            Assistant
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Grounded query, root-cause analysis, and read-only MCP tools.
          </p>
        </div>
        {tools.data && (
          <span className="rounded-md border border-border px-3 py-2 text-xs font-medium">
            {tools.data.read_only ? "Read-only tools" : "Tool policy unavailable"}
          </span>
        )}
      </div>

      <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label="Assistant workflow">
        <ToggleTab
          active={tab === "query"}
          onClick={() => setTab("query")}
          icon={<Search aria-hidden="true" className="h-4 w-4" />}
        >
          Query
        </ToggleTab>
        <ToggleTab
          active={tab === "rca"}
          onClick={() => setTab("rca")}
          icon={<ShieldAlert aria-hidden="true" className="h-4 w-4" />}
        >
          RCA
        </ToggleTab>
        <ToggleTab
          active={tab === "mcp"}
          onClick={() => setTab("mcp")}
          icon={<Wrench aria-hidden="true" className="h-4 w-4" />}
        >
          MCP tools
        </ToggleTab>
      </div>

      {error && (
        <p role="alert" className="mb-4 rounded-md border border-destructive/40 p-3 text-sm">
          {error}
        </p>
      )}

      {tab === "query" && (
        <Card>
          <CardHeader>
            <CardTitle>Grounded query</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={runQuery} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-sm font-medium">
                  Question
                  <textarea
                    className="min-h-24 w-full rounded-md border border-input bg-background p-3 text-sm"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder="Which certificates should rotate first?"
                    required
                  />
                </label>
                <label className="space-y-2 text-sm font-medium">
                  Subject
                  <input
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="Optional"
                  />
                </label>
              </div>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Evidence surfaces</legend>
                <div className="flex flex-wrap gap-3">
                  {surfaceOptions.map((surface) => (
                    <label key={surface.value} className="inline-flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={surfaces.includes(surface.value)}
                        onChange={() => toggleSurface(surface.value)}
                      />
                      {surface.label}
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
            <form onSubmit={runRCA} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-sm font-medium">
                  Question
                  <textarea
                    className="min-h-24 w-full rounded-md border border-input bg-background p-3 text-sm"
                    value={rcaQuestion}
                    onChange={(e) => setRCAQuestion(e.target.value)}
                    placeholder="Why did this identity become high risk?"
                    required
                  />
                </label>
                <label className="space-y-2 text-sm font-medium">
                  Subject
                  <input
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
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
            {tools.loading && <p role="status">Loading tools...</p>}
            {tools.error && <p role="alert">Could not load tools: {tools.error}</p>}
            {tools.data && tools.data.tools.length === 0 && (
              <p className="text-sm text-muted-foreground">No MCP tools are available for this tenant.</p>
            )}
            {tools.data && tools.data.tools.length > 0 && (
              <form onSubmit={runTool} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[1fr_2fr]">
                  <label className="space-y-2 text-sm font-medium">
                    Tool
                    <select
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
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
                  <label className="space-y-2 text-sm font-medium">
                    Subject
                    <input
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
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
