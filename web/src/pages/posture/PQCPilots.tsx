import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { api, type PQCPilot, type PQCPilotStartRequest } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";
import { useApiQuery, useQueryClient } from "@/lib/query";

const waveSchema = z
  .array(
    z.object({
      name: z.string().trim().min(1),
      targets: z
        .array(
          z.object({
            target_id: z.string().trim().min(1),
            address: z.string().trim().min(1),
            server_name: z.string().trim().optional(),
            connector: z.string().trim().optional(),
            fingerprint: z
              .string()
              .trim()
              .regex(/^[0-9a-fA-F:]{64,95}$/),
          }),
        )
        .min(1),
    }),
  )
  .min(1);

const createSchema = z.object({
  name: z.string().trim().min(1, "Pilot name is required."),
  authorityId: z.string().trim().min(1, "The issuing authority is required."),
  waves: z
    .string()
    .trim()
    .superRefine((value, context) => {
      try {
        if (waveSchema.safeParse(JSON.parse(value)).success) return;
      } catch {
        // Invalid JSON and an invalid plan read the same way to the operator.
      }
      context.addIssue({ code: "custom", message: translateNow("posture.pqcPilot.wavesInvalid") });
    }),
});
type CreateValues = z.infer<typeof createSchema>;

const exampleWaves = JSON.stringify(
  [
    { name: "canary", targets: [{ target_id: "<target-id>", address: "api.internal:443", server_name: "api.internal", fingerprint: "<served-leaf-sha256>" }] },
    {
      name: "broad",
      targets: [{ target_id: "<second-target-id>", address: "web.internal:443", server_name: "web.internal", fingerprint: "<served-leaf-sha256>" }],
    },
  ],
  null,
  2,
);

function pilotTone(status: string): StatusTone {
  switch (status) {
    case "completed":
      return "success";
    case "halted":
      return "critical";
    case "running":
      return "warning";
    default:
      return "neutral";
  }
}

function outcomeTone(outcome: string): StatusTone {
  switch (outcome) {
    case "negotiated":
      return "success";
    case "rejected":
      return "critical";
    case "unreachable":
      return "warning";
    default:
      return "neutral";
  }
}

export function PQCPilots() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const pilots = useApiQuery(["pqc-pilots"], () => api.pqcPilots({ limit: 100 }));
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const selected = useApiQuery(["pqc-pilot", selectedID], () => api.pqcPilot(selectedID as string), { enabled: selectedID !== null });
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const createForm = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    mode: "onTouched",
    defaultValues: { name: "", authorityId: "", waves: exampleWaves },
  });

  const startPilot = createForm.handleSubmit(async (values) => {
    setBusy(true);
    setOperationError(null);
    setNotice(null);
    try {
      const request: PQCPilotStartRequest = {
        name: values.name,
        authority_id: values.authorityId,
        waves: JSON.parse(values.waves) as PQCPilotStartRequest["waves"],
      };
      const pilot = await api.startPQCPilot(request);
      createForm.reset({ name: "", authorityId: values.authorityId, waves: exampleWaves });
      setSelectedID(pilot.id);
      setNotice(t("posture.pqcPilot.created", { name: pilot.name }));
      await queryClient.invalidateQueries({ queryKey: ["pqc-pilots"] });
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : t("posture.pqcPilot.error"));
    } finally {
      setBusy(false);
    }
  });

  async function copyReport(pilot: PQCPilot) {
    if (!pilot.signed_report) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(pilot.signed_report, null, 2));
      setNotice(t("posture.pqcPilot.reportCopied"));
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : t("posture.pqcPilot.error"));
    }
  }

  const detail = selected.data;
  const report = detail?.signed_report as { key_id?: string; algorithm?: string } | undefined;

  return (
    <section className="grid gap-4 rounded-panel border border-border p-comfortable" aria-labelledby="pqc-pilots-heading">
      <div>
        <h3 id="pqc-pilots-heading" className="font-semibold">
          {t("posture.pqcPilot.heading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("posture.pqcPilot.description")}</p>
      </div>

      <form className="grid gap-3 rounded-control border border-border p-3" onSubmit={startPilot}>
        <h4 className="font-medium">{t("posture.pqcPilot.createHeading")}</h4>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label={t("posture.pqcPilot.name")} error={createForm.formState.errors.name?.message} required>
            {(control) => <Input {...control} {...createForm.register("name")} />}
          </Field>
          <Field
            label={t("posture.pqcPilot.authority")}
            description={t("posture.pqcPilot.authorityHelp")}
            error={createForm.formState.errors.authorityId?.message}
            required
          >
            {(control) => <Input {...control} {...createForm.register("authorityId")} />}
          </Field>
        </div>
        <Field label={t("posture.pqcPilot.waves")} description={t("posture.pqcPilot.wavesHelp")} error={createForm.formState.errors.waves?.message} required>
          {(control) => <Textarea {...control} {...createForm.register("waves")} className="min-h-40 font-mono text-xs" />}
        </Field>
        <Button type="submit" disabled={busy}>
          {busy ? t("posture.pqcPilot.creating") : t("posture.pqcPilot.create")}
        </Button>
      </form>

      {operationError ? <ErrorState title={t("posture.pqcPilot.error")}>{operationError}</ErrorState> : null}
      {notice ? (
        <p role="status" className="text-sm text-muted-foreground">
          {notice}
        </p>
      ) : null}

      <section className="grid gap-3" aria-labelledby="pqc-pilot-list-heading">
        <h4 id="pqc-pilot-list-heading" className="font-medium">
          {t("posture.pqcPilot.listHeading")}
        </h4>
        {pilots.loading ? <LoadingState>{t("posture.pqcPilot.loading")}</LoadingState> : null}
        {pilots.error ? <ErrorState title={t("posture.pqcPilot.error")}>{pilots.error}</ErrorState> : null}
        {!pilots.loading && !pilots.error && (pilots.data?.items ?? []).length === 0 ? (
          <EmptyState title={t("posture.pqcPilot.empty")}>{t("posture.pqcPilot.emptyBody")}</EmptyState>
        ) : null}
        <div className="grid gap-2">
          {(pilots.data?.items ?? []).map((pilot) => (
            <button
              key={pilot.id}
              type="button"
              className="grid gap-1 rounded-control border border-border p-3 text-left hover:bg-muted/30"
              aria-pressed={selectedID === pilot.id}
              onClick={() => setSelectedID(pilot.id)}
            >
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{pilot.name}</span>
                <StatusBadge value={pilot.status} label={pilot.status} tone={pilotTone(pilot.status)} vocabulary="lifecycle" />
              </span>
              <span className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span>{t("posture.pqcPilot.waveProgress", { current: pilot.current_wave, total: pilot.wave_count })}</span>
                {pilot.halted_at_wave ? <span>{t("posture.pqcPilot.haltedAt", { wave: pilot.halted_at_wave })}</span> : null}
              </span>
              {pilot.verdict_summary ? <span className="text-sm">{pilot.verdict_summary}</span> : null}
            </button>
          ))}
        </div>
      </section>

      {selectedID ? (
        <section className="grid gap-3" aria-labelledby="pqc-pilot-waves-heading">
          <h4 id="pqc-pilot-waves-heading" className="font-medium">
            {t("posture.pqcPilot.waveHeading")}
          </h4>
          {selected.loading ? <LoadingState>{t("posture.pqcPilot.loading")}</LoadingState> : null}
          {selected.error ? <ErrorState title={t("posture.pqcPilot.error")}>{selected.error}</ErrorState> : null}
          {(detail?.waves ?? []).map((wave) => (
            <div key={wave.index} className="grid gap-2 rounded-control border border-border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">
                  {wave.index}. {wave.name}
                </span>
                <StatusBadge
                  value={wave.status}
                  label={wave.status}
                  tone={wave.status === "assessed" ? (wave.verdict?.halt ? "critical" : "success") : wave.status === "skipped" ? "neutral" : "warning"}
                  vocabulary="lifecycle"
                />
              </div>
              {wave.verdict ? <p className="text-sm">{wave.verdict.summary}</p> : null}
              {wave.status === "skipped" ? <p className="text-sm text-muted-foreground">{t("posture.pqcPilot.notProbed")}</p> : null}
              {wave.status === "probing" ? <p className="text-sm text-muted-foreground">{t("posture.pqcPilot.awaitingRelay")}</p> : null}
              {wave.status === "pending" ? <p className="text-sm text-muted-foreground">{t("posture.pqcPilot.pending")}</p> : null}
              {(wave.results ?? []).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-muted-foreground">
                      <th scope="col" className="py-1 pr-2">
                        {t("posture.pqcPilot.target")}
                      </th>
                      <th scope="col" className="py-1 pr-2">
                        {t("posture.pqcPilot.outcome")}
                      </th>
                      <th scope="col" className="py-1 pr-2">
                        {t("posture.pqcPilot.handshake")}
                      </th>
                      <th scope="col" className="py-1">
                        {t("posture.pqcPilot.detail")}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {(wave.results ?? []).map((result) => (
                      <tr key={result.target_id} className="border-t border-border">
                        <td className="py-1 pr-2 font-mono text-xs">{result.target_id}</td>
                        <td className="py-1 pr-2">
                          <StatusBadge value={result.outcome} label={result.outcome} tone={outcomeTone(result.outcome)} vocabulary="lifecycle" />
                        </td>
                        <td className="py-1 pr-2 text-xs text-muted-foreground">
                          {t("posture.pqcPilot.handshakeCost", { ms: result.handshake_ms, bytes: result.chain_bytes })}
                        </td>
                        <td className="py-1 text-xs text-muted-foreground">{result.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}
            </div>
          ))}
          {detail ? (
            <div className="rounded-control border border-border bg-muted/30 p-3" role="note">
              <p className="font-medium">{t("posture.pqcPilot.report")}</p>
              {report?.key_id ? (
                <>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {t("posture.pqcPilot.reportBody", { keyId: report.key_id, algorithm: report.algorithm ?? "" })}
                  </p>
                  <Button type="button" variant="outline" className="mt-2" onClick={() => void copyReport(detail)}>
                    {t("posture.pqcPilot.reportDownload")}
                  </Button>
                </>
              ) : (
                <p className="mt-1 text-sm text-muted-foreground">{t("posture.pqcPilot.reportPending")}</p>
              )}
            </div>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
