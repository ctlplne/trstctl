import { z } from "zod";
import type { RelayPluginModuleInput } from "@/lib/api";
import { Field } from "@/components/ui/field";
import { useTranslation } from "@/i18n/I18nProvider";

const configSchema = z.record(z.string(), z.unknown());

// A242: a connector module's setup form, generated from the inputs its signed
// manifest declares. It edits the same configuration JSON the destination
// saves, so there is no second copy to drift; the API checks required inputs,
// types, and that a secret input holds a reference rather than a value.
export function ModuleSetupFields({ inputs, config, onChange }: { inputs: RelayPluginModuleInput[]; config: string; onChange: (value: string) => void }) {
  const { t } = useTranslation();
  let parsed: Record<string, unknown> | null = null;
  try {
    const result = configSchema.safeParse(JSON.parse(config));
    if (result.success) parsed = result.data;
  } catch {
    /* The configuration field keeps the invalid input; nothing to edit here. */
  }
  const set = (name: string, value: unknown) => {
    const next = { ...parsed };
    if (value === "" || value === undefined) delete next[name];
    else next[name] = value;
    onChange(JSON.stringify(next, null, 2));
  };
  return (
    <fieldset className="grid gap-3 rounded-control border border-border p-3">
      <legend className="px-1 text-sm font-semibold">{t("connectors.module.setupTitle")}</legend>
      <p className="text-caption text-muted-foreground">{t("connectors.module.setupHelp")}</p>
      {inputs.map((input) => {
        const value = parsed?.[input.name];
        const description = input.secret ? `${input.description ?? ""} ${t("connectors.module.secretHelp")}`.trim() : input.description;
        if (input.type === "boolean") {
          return (
            <label key={input.name} className="flex items-start gap-3 text-sm">
              <input
                type="checkbox"
                className="mt-1 size-4"
                disabled={!parsed}
                checked={value === true}
                onChange={(event) => set(input.name, event.target.checked)}
              />
              <span>
                <span className="font-mono font-semibold">{input.name}</span>
                {description ? <span className="mt-1 block text-muted-foreground">{description}</span> : null}
              </span>
            </label>
          );
        }
        return (
          <Field key={input.name} label={input.name} description={description} required={input.required}>
            {(control) => (
              <input
                {...control}
                className="ui-input font-mono text-xs font-normal"
                type={input.type === "integer" ? "number" : "text"}
                step={input.type === "integer" ? 1 : undefined}
                autoComplete="off"
                placeholder={input.secret ? t("connectors.module.secretPlaceholder") : undefined}
                disabled={!parsed}
                required={input.required}
                value={typeof value === "string" || typeof value === "number" ? String(value) : ""}
                onChange={(event) => set(input.name, input.type === "integer" && event.target.value !== "" ? Number(event.target.value) : event.target.value)}
              />
            )}
          </Field>
        );
      })}
    </fieldset>
  );
}
