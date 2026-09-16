import { useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Dialog } from "@/components/Dialog";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { PolicyVersionRequest } from "@/lib/api";

const schema = z.object({
  description: z
    .string()
    .trim()
    .min(1, {
      get message() {
        return translateNow("policy.editor.descriptionRequired");
      },
    })
    .max(500, {
      get message() {
        return translateNow("apiExplorer.validation.maxLength", { name: translateNow("policy.versions.descriptionLabel"), value: "500" });
      },
    }),
  changeRef: z
    .string()
    .trim()
    .max(260, {
      get message() {
        return translateNow("apiExplorer.validation.maxLength", { name: translateNow("policy.versions.changeRef"), value: "260" });
      },
    }),
  evidenceRefs: z.string().trim(),
  module: z
    .string()
    .trim()
    .min(1, {
      get message() {
        return translateNow("policy.editor.moduleRequired");
      },
    }),
});
type Values = z.infer<typeof schema>;

export function PolicyRuleEditor({
  open,
  onClose,
  onCreate,
  busy,
  error,
  initialModule,
}: {
  open: boolean;
  onClose: () => void;
  onCreate: (input: PolicyVersionRequest) => Promise<void>;
  busy: boolean;
  error: string | null;
  initialModule: string;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const focus = useRef<HTMLInputElement | null>(null);
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { description: "", changeRef: "", evidenceRefs: "", module: initialModule } });
  const values = useWatch({ control: form.control });
  const description = form.register("description");
  const steps = [
    { id: "purpose", label: t("policy.editor.describe"), description: t("policy.editor.describeHelp") },
    { id: "module", label: t("policy.versions.lifecycleModule"), description: t("policy.design.moduleHelp") },
    { id: "review", label: t("policy.editor.review"), description: t("policy.design.createHelp") },
  ];
  async function next() {
    if (await form.trigger(step === 0 ? ["description", "changeRef", "evidenceRefs"] : ["module"])) setStep(step + 1);
  }
  const submit = form.handleSubmit(async (input) => {
    if (step !== 2) {
      await next();
      return;
    }
    await onCreate({
      kind: "lifecycle",
      description: input.description,
      change_ref: input.changeRef || undefined,
      evidence_refs: input.evidenceRefs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      module: input.module,
    });
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      titleId="create-rule-heading"
      descriptionId="create-rule-description"
      initialFocusRef={focus}
      panelAnimation="none"
      panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
    >
      <form className="grid min-w-0 gap-4 text-sm" onSubmit={(event) => void submit(event)}>
        <div>
          <h2 id="create-rule-heading" className="text-title font-semibold">
            {t("policy.design.create")}
          </h2>
          <p id="create-rule-description" className="mt-1 text-muted-foreground">
            {t("policy.design.createHelp")}
          </p>
        </div>
        {error && <ErrorState title={t("policy.editor.saveFailed")}>{error}</ErrorState>}
        <StepShell
          steps={steps}
          currentIndex={step}
          onPrevious={step > 0 && !busy ? () => setStep(step - 1) : undefined}
          onNext={step < 2 ? () => void next() : undefined}
          nextDisabled={busy}
          nextLabel={step === 0 ? t("policy.editor.nextModule") : t("policy.editor.review")}
          progressLabel={t("policy.design.create")}
        >
          <div className="grid min-w-0 gap-4 p-4">
            {step === 0 && (
              <>
                <Field label={t("policy.versions.descriptionLabel")} required error={form.formState.errors.description?.message}>
                  {(control) => (
                    <Input
                      {...control}
                      {...description}
                      ref={(node) => {
                        description.ref(node);
                        focus.current = node;
                      }}
                    />
                  )}
                </Field>
                <Field label={t("policy.versions.changeRef")} error={form.formState.errors.changeRef?.message}>
                  {(control) => <Input {...control} {...form.register("changeRef")} />}
                </Field>
                <Field
                  label={t("policy.versions.evidenceRefs")}
                  description={t("policy.editor.evidenceHelp")}
                  error={form.formState.errors.evidenceRefs?.message}
                >
                  {(control) => <Input {...control} {...form.register("evidenceRefs")} />}
                </Field>
              </>
            )}
            {step === 1 && (
              <Field label={t("policy.versions.lifecycleModule")} required error={form.formState.errors.module?.message}>
                {(control) => <Textarea {...control} {...form.register("module")} spellCheck={false} className="min-h-64 font-mono text-xs" />}
              </Field>
            )}
            {step === 2 && (
              <>
                <dl className="grid gap-2">
                  <dt>{t("policy.versions.descriptionLabel")}</dt>
                  <dd>{values.description?.trim()}</dd>
                  <dt>{t("policy.versions.changeRef")}</dt>
                  <dd>{values.changeRef?.trim() || t("policy.editor.none")}</dd>
                  <dt>{t("policy.versions.evidenceRefs")}</dt>
                  <dd>{values.evidenceRefs?.trim() || t("policy.editor.none")}</dd>
                </dl>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-control border border-border p-3 text-xs">
                  {values.module?.trim()}
                </pre>
                <Button type="submit" loading={busy} disabled={busy}>
                  {t("policy.design.create")}
                </Button>
              </>
            )}
          </div>
        </StepShell>
        <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
          {t("source.cancel.19766ed6cc")}
        </Button>
      </form>
    </Dialog>
  );
}
