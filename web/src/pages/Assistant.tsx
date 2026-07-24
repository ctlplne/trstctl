import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Bot, Search, ShieldAlert, Wrench } from "lucide-react";
import { api, ApiError, type AIAnswer, type AIStatus } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { UnavailableState } from "@/components/StatePrimitives";
import { cn } from "@/lib/utils";
import { useTranslation, type I18nContextValue, translateNow } from "@/i18n/I18nProvider";

type Tab = "query" | "rca" | "mcp";

const surfaceOptions = [
  { value: "certificates", label: translateNow("source.certificates.16f637921e") },
  { value: "owners", label: translateNow("source.owners.58f5df9b24") },
  { value: "graph", label: translateNow("source.graph.32ab018fd3") },
  { value: "cbom", label: translateNow("source.cbom.b79109c7e7") },
  { value: "log", label: translateNow("source.audit.log.e4d36f9a4e") },
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

function personalDataEgressCopy(mode: string | undefined, t: I18nContextValue["t"]): { label: string; detail: string } {
  switch (mode) {
    case "block":
      return {
        label: t("assistant.runtime.piiEgress.blockLabel"),
        detail: t("assistant.runtime.piiEgress.blockDetail"),
      };
    case "allow":
      return {
        label: t("assistant.runtime.piiEgress.allowLabel"),
        detail: t("assistant.runtime.piiEgress.allowDetail"),
      };
    case "redact":
      return {
        label: t("assistant.runtime.piiEgress.redactLabel"),
        detail: t("assistant.runtime.piiEgress.redactDetail"),
      };
    default:
      return {
        label: t("assistant.runtime.piiEgress.unknownLabel"),
        detail: t("assistant.runtime.piiEgress.unknownDetail"),
      };
  }
}

function AnswerPanel({ answer, tool }: { answer: AIAnswer | null; tool?: string }) {
  if (!answer) return null;
  const citations = answer.citations ?? [];
  return (
    <section aria-label={translateNow("source.assistant.answer.ba33c88efb")} className="mt-5 ui-panel p-comfortable">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-caption font-medium">
        {tool && (
          <span className="rounded-control border border-border px-2 py-1">
            {translateNow("source.tool.ef19e27e34")} {tool}
          </span>
        )}
        <span className="rounded-control border border-border px-2 py-1">
          <HelpTerm title={translateNow("source.grounded.means.the.answer.cites.tenant.evi.0c488b912f")}>
            {answer.grounded ? "Grounded" : "No cited evidence"}
          </HelpTerm>
        </span>
        <span className="rounded-control border border-border px-2 py-1">
          <HelpTerm title={translateNow("source.sufficient.means.the.cited.evidence.is.eno.07cb72f36c")}>
            {answer.sufficient ? "Sufficient" : "Insufficient"}
          </HelpTerm>
        </span>
      </div>
      <p className="whitespace-pre-wrap text-body" data-testid="assistant-answer">
        {answer.text}
      </p>
      <div className="mt-4">
        <h3 className="text-body font-semibold">{translateNow("source.cited.evidence.ca23c85308")}</h3>
        {citations.length === 0 ? (
          <p className="mt-2 text-body text-muted-foreground">{translateNow("source.no.citations.returned.4c4de9598c")}</p>
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
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const enabled = status?.enabled ? "enabled" : "disabled";
  const model = status?.model_configured ? (status.model_name ? `${status.model_mode}: ${status.model_name}` : status.model_mode) : "not configured";
  const egress = status?.egress ?? "none";
  const personalData = personalDataEgressCopy(status?.pii_egress, t);
  const endpoint = status?.endpoint_host ?? "not disclosed";
  return (
    <details className="group mb-6 border-b border-border pb-6" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="inline-flex cursor-pointer items-center rounded-control border border-border px-3 py-2 text-body font-medium hover:border-brand-accent/40 hover:bg-muted/60">
        {translateNow("source.advanced.runtime.diagnostics.c1b601f9f3")}
      </summary>
      {open && (
        <div className="mt-4 grid gap-3">
          <div>
            <h2 id="assistant-runtime-heading" className="text-title font-semibold">
              {translateNow("source.ai.runtime.boundary.0126aa890a")}
            </h2>
            <p className="mt-1 max-w-3xl text-body text-muted-foreground">{translateNow("source.query.rca.and.mcp.fail.closed.when.disable.255478de84")}</p>
          </div>
          <dl className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">{translateNow("source.surface.0905f7f590")}</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : enabled}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">{translateNow("source.model.5e2c614c23")}</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : model}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">{translateNow("source.egress.66a3afae15")}</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : egress}</dd>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">{t("assistant.runtime.personalData")}</dt>
              <dd className="mt-1 text-title font-semibold">{loading ? "loading" : personalData.label}</dd>
              <p className="mt-2 text-caption text-muted-foreground">{loading ? t("assistant.runtime.statusLoading") : personalData.detail}</p>
            </div>
            <div className="ui-panel p-comfortable">
              <dt className="text-caption text-muted-foreground">{translateNow("source.endpoint.host.4f0d916bb9")}</dt>
              <dd className="mt-1 break-words text-title font-semibold">{loading ? "loading" : endpoint}</dd>
            </div>
          </dl>
          <p className="text-body text-muted-foreground">
            {translateNow("source.redaction.boundary.134ed7be9f")} {status?.redaction ?? "default-redactor"}; residual refusal gate:{" "}
            {status?.residual_refusal_gate === false ? "inactive" : "active"}.
          </p>
          {error && (
            <UnavailableState title={translateNow("source.ai.runtime.status.unavailable.b36957005d")}>
              {translateNow("source.the.console.could.not.read.runtime.status.a01258a71d")}
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
        {translateNow("source.structured.query.preview.706d53d9be")}
      </h3>
      <dl className="mt-2 grid gap-2 md:grid-cols-3">
        <div>
          <dt className="text-caption text-muted-foreground">{translateNow("source.surfaces.fbb4dbb2d8")}</dt>
          <dd>{surfaces.join(", ") || "none selected"}</dd>
        </div>
        <div>
          <dt className="text-caption text-muted-foreground">{translateNow("source.subject.6897128384")}</dt>
          <dd>{subject.trim() || "not scoped"}</dd>
        </div>
        <div>
          <dt className="text-caption text-muted-foreground">{translateNow("source.limit.674b0ed54b")}</dt>
          <dd>{translateNow("source.25.cited.records.8fedaba2c8")}</dd>
        </div>
      </dl>
      <p className="mt-2 text-muted-foreground">Tenant/RBAC filtering is applied below this request; a prompt cannot ask for another tenant.</p>
    </section>
  );
}

function RCAWorkspaceDisclosure() {
  return (
    <section aria-labelledby="rca-workspace-heading" className="mb-4 ui-panel p-comfortable text-body">
      <h3 id="rca-workspace-heading" className="font-semibold">
        {translateNow("source.rca.evidence.workspace.418f458f5f")}
      </h3>
      <p className="mt-2 text-muted-foreground">{translateNow("source.rca.answers.are.sufficient.or.insufficient.5a9397d141")}</p>
    </section>
  );
}

function MCPBoundary({ readOnly }: { readOnly?: boolean }) {
  return (
    <section aria-labelledby="mcp-boundary-heading" className="mb-4 ui-panel p-comfortable text-body">
      <h3 id="mcp-boundary-heading" className="font-semibold">
        <HelpTerm title={translateNow("source.model.context.protocol.read.only.assistant.6c1913a3c9")}>{translateNow("source.mcp.53f13ae99e")}</HelpTerm>{" "}
        {translateNow("source.permission.boundary.c0d351ef86")}
      </h3>
      <p className="mt-2 text-muted-foreground">
        {translateNow("source.tools.are.7c933884d0")} {readOnly ? "read-only" : "treated as unavailable until policy allows them"}{" "}
        {translateNow("source.and.cannot.remediate.or.mutate.credentials.564b159ab9")}
      </p>
    </section>
  );
}

export function Assistant() {
  const { t } = useTranslation();
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
  const mcpToolCount = tools.data?.tools.length ?? 0;
  const mcpToolsAreReadOnly = tools.data?.read_only === true;

  useEffect(() => {
    const callableTools = tools.data?.read_only ? tools.data.tools : [];
    if (callableTools.length === 0) {
      if (selectedTool) setSelectedTool("");
      return;
    }
    if (!selectedTool || !callableTools.includes(selectedTool)) setSelectedTool(callableTools[0]);
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
      if (!tools.data?.read_only) {
        throw new Error(t("assistant.mcp.writeToolsNeedControls"));
      }
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
        title={translateNow("source.assistant.391e405152")}
        titleId="assistant-heading"
        description="Grounded query, root-cause analysis, and read-only MCP tools."
        actions={
          tools.data ? (
            <span className="rounded-control border border-border bg-card px-3 py-2 text-caption font-medium shadow-elevation1">
              {tools.data.read_only ? "Read-only tools" : "Write-capable tools"}
            </span>
          ) : undefined
        }
      />
      <AssistantRuntimeDisclosure status={runtime.data} error={runtime.error} loading={runtime.loading} />

      <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label={translateNow("source.assistant.workflow.8962351a8a")}>
        <ToggleTab active={tab === "query"} onClick={() => setTab("query")} icon={<Search aria-hidden="true" className="h-4 w-4" />}>
          {translateNow("source.query.b80a37564f")}
        </ToggleTab>
        <ToggleTab active={tab === "rca"} onClick={() => setTab("rca")} icon={<ShieldAlert aria-hidden="true" className="h-4 w-4" />}>
          {translateNow("source.rca.d93580ed3a")}
        </ToggleTab>
        <ToggleTab active={tab === "mcp"} onClick={() => setTab("mcp")} icon={<Wrench aria-hidden="true" className="h-4 w-4" />}>
          <HelpTerm title={translateNow("source.model.context.protocol.read.only.assistant.6c1913a3c9")}>{translateNow("source.mcp.53f13ae99e")}</HelpTerm>{" "}
          {translateNow("source.tools.f9d35d4377")}
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
            <CardTitle>{translateNow("source.grounded.query.2a3d813fd7")}</CardTitle>
          </CardHeader>
          <CardContent>
            <QueryPreview surfaces={surfaces} subject={subject} />
            <form onSubmit={runQuery} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-body font-medium">
                  {translateNow("source.question.289aff12b0")}
                  <textarea
                    className="min-h-24 w-full rounded-control border border-border bg-background p-3 text-body font-normal"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder={translateNow("source.which.certificates.should.rotate.first.218489c622")}
                    required
                  />
                </label>
                <label className="space-y-2 text-body font-medium">
                  {translateNow("source.subject.6897128384")}
                  <input
                    className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder={translateNow("source.optional.59be71333c")}
                  />
                </label>
              </div>
              <fieldset className="space-y-2">
                <legend className="text-body font-medium">{translateNow("source.evidence.surfaces.6acbb05a44")}</legend>
                <div className="flex flex-wrap gap-3">
                  {surfaceOptions.map((surface) => (
                    <label key={surface.value} className="inline-flex items-center gap-2 text-body">
                      <input type="checkbox" checked={surfaces.includes(surface.value)} onChange={() => toggleSurface(surface.value)} />
                      {surface.value === "cbom" ? (
                        <HelpTerm title={translateNow("source.cryptographic.bill.of.materials.an.invento.b2a4a4fd81")}>
                          {translateNow("source.cbom.b79109c7e7")}
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
            <CardTitle>{translateNow("source.root.cause.analysis.fde4017d48")}</CardTitle>
          </CardHeader>
          <CardContent>
            <RCAWorkspaceDisclosure />
            <form onSubmit={runRCA} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-[2fr_1fr]">
                <label className="space-y-2 text-body font-medium">
                  {translateNow("source.question.289aff12b0")}
                  <textarea
                    className="min-h-24 w-full rounded-control border border-border bg-background p-3 text-body font-normal"
                    value={rcaQuestion}
                    onChange={(e) => setRCAQuestion(e.target.value)}
                    placeholder={translateNow("source.why.did.this.identity.become.high.risk.d0f95f73e1")}
                    required
                  />
                </label>
                <label className="space-y-2 text-body font-medium">
                  {translateNow("source.subject.6897128384")}
                  <input
                    className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                    value={rcaSubject}
                    onChange={(e) => setRCASubject(e.target.value)}
                    placeholder={translateNow("source.optional.59be71333c")}
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
            <CardTitle>{translateNow("source.mcp.tools.1a32c98e7f")}</CardTitle>
          </CardHeader>
          <CardContent>
            <MCPBoundary readOnly={tools.data?.read_only} />
            {tools.loading && (
              <p role="status" className="text-body text-muted-foreground">
                {translateNow("source.loading.tools.efc190cd4c")}
              </p>
            )}
            {tools.error && (
              <p role="alert" className="text-body text-destructive">
                {translateNow("source.could.not.load.tools.2e7b9eae6f")} {tools.error}
              </p>
            )}
            {tools.data && mcpToolCount === 0 && (
              <p className="text-body text-muted-foreground">{translateNow("source.no.mcp.tools.are.available.for.this.tenant.66ea7cda3e")}</p>
            )}
            {tools.data && !mcpToolsAreReadOnly && mcpToolCount > 0 && (
              <UnavailableState title={t("assistant.mcp.writeToolsNeedControls")}>{t("assistant.mcp.writeToolsSubjectFormDisabled")}</UnavailableState>
            )}
            {tools.data && mcpToolsAreReadOnly && mcpToolCount > 0 && (
              <form onSubmit={runTool} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[1fr_2fr]">
                  <label className="space-y-2 text-body font-medium">
                    {translateNow("source.tool.2e53bdcd07")}
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
                    {translateNow("source.subject.6897128384")}
                    <input
                      className="w-full rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                      value={toolSubject}
                      onChange={(e) => setToolSubject(e.target.value)}
                      placeholder={translateNow("source.optional.59be71333c")}
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
