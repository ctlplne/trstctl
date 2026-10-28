import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Num } from "@/components/typography";
import { StepShell } from "@/components/wizard/StepShell";
import { api, type TicketIntakeInput, type TicketIntakeSchedule } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { apiProblemMessage } from "@/lib/apiProblem";
import { translateNow as t } from "@/i18n/I18nProvider";

function intakeSchema() {
  const invalid = t("ticket.intake.setup.invalid");
  const field = z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_.-]{1,128}$/, invalid);
  const optionalField = z
    .string()
    .trim()
    .refine((value) => value === "" || /^[A-Za-z0-9_.-]{1,128}$/.test(value), invalid);
  return z
    .object({
      name: z
        .string()
        .trim()
        .regex(/^[a-z0-9][a-z0-9_-]{0,39}$/, t("ticket.intake.named.nameInvalid")),
      system: z.enum(["servicenow", "jira"]),
      instance_url: z
        .string()
        .trim()
        .url(invalid)
        .refine((value) => {
          try {
            const url = new URL(value);
            return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash;
          } catch {
            return false;
          }
        }, invalid),
      token_ref: z
        .string()
        .trim()
        .regex(/^secret:\/\/.+$/, invalid),
      sn_table: z.enum(["sc_req_item", "sc_request", "change_request", "incident"]),
      jira_project: z.string().trim(),
      query: z.string().trim(),
      subject_field: field,
      profile_field: field,
      requester_field: optionalField,
      justification_field: optionalField,
      owner_field: optionalField,
      interval_seconds: z.string().regex(/^\d+$/, invalid).transform(Number).pipe(z.number().int().min(300, invalid)),
      enabled: z.boolean(),
    })
    .superRefine((value, ctx) => {
      if (value.system === "jira" && !/^[A-Z][A-Z0-9_]{0,63}$/.test(value.jira_project)) {
        ctx.addIssue({ code: "custom", path: ["jira_project"], message: invalid });
      }
    });
}

type FormInput = z.input<ReturnType<typeof intakeSchema>>;
type FormOutput = z.output<ReturnType<typeof intakeSchema>>;
const mappingFields = ["subject_field", "profile_field", "requester_field", "justification_field", "owner_field"] as const;

function initialValues(initial?: TicketIntakeSchedule): FormInput {
  return {
    name: initial?.name ?? "",
    system: initial?.system ?? "servicenow",
    instance_url: initial?.instance_url ?? "",
    token_ref: initial?.token_ref ?? "",
    sn_table: initial?.sn_table ?? "sc_req_item",
    jira_project: initial?.jira_project ?? "",
    query: initial?.query ?? "",
    subject_field: initial?.subject_field ?? "",
    profile_field: initial?.profile_field ?? "",
    requester_field: initial?.requester_field ?? "",
    justification_field: initial?.justification_field ?? "",
    owner_field: initial?.owner_field ?? "",
    interval_seconds: String(initial?.interval_seconds ?? 3600),
    enabled: initial?.enabled ?? false,
  };
}

function requestInput(values: FormOutput): TicketIntakeInput {
  const { sn_table, jira_project, query, requester_field, justification_field, owner_field, ...shared } = values;
  return {
    ...shared,
    ...(values.system === "jira" ? { jira_project } : { sn_table }),
    ...(query ? { query } : {}),
    ...(requester_field ? { requester_field } : {}),
    ...(justification_field ? { justification_field } : {}),
    ...(owner_field ? { owner_field } : {}),
  };
}

export function TicketIntakeWizard({
  initial,
  onCancel,
  onSaved,
}: {
  initial?: TicketIntakeSchedule;
  onCancel: () => void;
  onSaved: (schedule: TicketIntakeSchedule) => void;
}) {
  const form = useForm<FormInput, unknown, FormOutput>({ resolver: zodResolver(intakeSchema()), defaultValues: initialValues(initial) });
  const system = useWatch({ control: form.control, name: "system" });
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<{ input: TicketIntakeInput; key: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errors = form.formState.errors;
  const steps = [
    { id: "source", label: t("ticket.intake.named.sourceStep"), description: t("ticket.intake.setup.help") },
    { id: "mapping", label: t("ticket.intake.named.mappingStep"), description: t("ticket.intake.named.ownerHelp") },
    { id: "review", label: t("ticket.intake.setup.reviewed"), description: t("ticket.intake.setup.relayBoundary") },
  ];

  async function next() {
    if (step === 0) {
      if (await form.trigger(["name", "system", "instance_url", "token_ref", "sn_table", "jira_project"])) setStep(1);
      return;
    }
    await form.handleSubmit((values) => {
      setReview({ input: requestInput(values), key: newIdempotencyKey() });
      setStep(2);
      setError(null);
    })();
  }

  async function save() {
    if (!review || saving) return;
    setSaving(true);
    setError(null);
    try {
      onSaved(await api.putTicketIntakeSchedule(review.input, review.key));
    } catch (failure) {
      setError(apiProblemMessage(failure, t("ticket.intake.named.saveFailed")));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-3">
      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("ticket.intake.setup.configure")}
        onPrevious={
          step > 0 && !saving
            ? () => {
                setStep(step - 1);
                setReview(null);
                setError(null);
              }
            : undefined
        }
        onNext={step < 2 ? () => void next() : undefined}
        nextLabel={step === 1 ? t("ticket.intake.setup.review") : undefined}
      >
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void (step === 2 ? save() : next());
          }}
        >
          {step === 0 ? (
            <>
              <Field label={t("ticket.intake.named.name")} description={t("ticket.intake.named.nameHelp")} error={errors.name?.message} required>
                {(control) => <Input {...control} {...form.register("name")} readOnly={Boolean(initial)} />}
              </Field>
              <Field label={t("ticket.intake.setup.provider")} error={errors.system?.message} required>
                {(control) =>
                  initial ? (
                    <Input {...control} {...form.register("system")} readOnly />
                  ) : (
                    <Select {...control} {...form.register("system")}>
                      <option value="servicenow">{t("ticket.intake.setup.providerServiceNow")}</option>
                      <option value="jira">{t("ticket.intake.setup.providerJira")}</option>
                    </Select>
                  )
                }
              </Field>
              <Field label={t("ticket.intake.setup.url")} error={errors.instance_url?.message} required>
                {(control) => <Input {...control} {...form.register("instance_url")} type="url" />}
              </Field>
              <Field label={t("cmdb.setup.tokenRef")} error={errors.token_ref?.message} required>
                {(control) => <Input {...control} {...form.register("token_ref")} autoComplete="off" />}
              </Field>
              {system === "jira" ? (
                <Field label={t("ticket.intake.setup.project")} error={errors.jira_project?.message} required>
                  {(control) => <Input {...control} {...form.register("jira_project")} />}
                </Field>
              ) : (
                <Field label={t("ticket.intake.setup.table")} error={errors.sn_table?.message} required>
                  {(control) => (
                    <Select {...control} {...form.register("sn_table")}>
                      {["sc_req_item", "sc_request", "change_request", "incident"].map((table) => (
                        <option key={table} value={table}>
                          {table}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              )}
              <Field label={t("ticket.intake.setup.query")} error={errors.query?.message}>
                {(control) => <Input {...control} {...form.register("query")} />}
              </Field>
            </>
          ) : null}
          {step === 1 ? (
            <>
              {mappingFields.map((field) => (
                <Field
                  key={field}
                  label={t(`ticket.intake.setup.${field}`)}
                  error={errors[field]?.message}
                  required={field === "subject_field" || field === "profile_field"}
                >
                  {(control) => <Input {...control} {...form.register(field)} />}
                </Field>
              ))}
              <Field label={t("cmdb.setup.interval")} error={errors.interval_seconds?.message} required>
                {(control) => <Input {...control} {...form.register("interval_seconds")} type="number" min={300} step={1} />}
              </Field>
              <label className="flex items-center gap-2">
                <input type="checkbox" {...form.register("enabled")} />
                {t("cmdb.setup.enabled")}
              </label>
            </>
          ) : null}
          {step === 2 && review ? (
            <section aria-label={t("ticket.intake.setup.reviewed")} className="grid gap-2 text-sm">
              <p>
                {t("ticket.intake.named.name")}: <Num>{review.input.name}</Num>
              </p>
              <p>
                {t("ticket.intake.setup.provider")}: <Num>{review.input.system}</Num>
              </p>
              <p>
                {t("ticket.intake.setup.url")}: <Num>{review.input.instance_url}</Num>
              </p>
              <p>
                {t("cmdb.setup.tokenRef")}: <Num>{review.input.token_ref}</Num>
              </p>
              <p>
                {t(system === "jira" ? "ticket.intake.setup.project" : "ticket.intake.setup.table")}:{" "}
                <Num>{review.input.jira_project || review.input.sn_table}</Num>
              </p>
              <p>
                {t("ticket.intake.setup.query")}: <Num>{review.input.query || t("ticket.intake.setup.none")}</Num>
              </p>
              {mappingFields.map((field) => (
                <p key={field}>
                  {t(`ticket.intake.setup.${field}`)}: <Num>{review.input[field] || t("ticket.intake.setup.none")}</Num>
                </p>
              ))}
              <p>
                {t("cmdb.setup.interval")}: <Num>{review.input.interval_seconds}</Num>
              </p>
              <p>{t(review.input.enabled ? "cmdb.setup.enabledState" : "cmdb.setup.pausedState")}</p>
              {error ? <p role="alert">{error}</p> : null}
              <Button type="submit" loading={saving}>
                {t("ticket.intake.setup.save")}
              </Button>
            </section>
          ) : null}
        </form>
      </StepShell>
      <Button type="button" variant="outline" disabled={saving} onClick={onCancel}>
        {t("cmdb.setup.cancel")}
      </Button>
    </div>
  );
}
