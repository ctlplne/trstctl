import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { BrowserTerminal } from "@/components/access/BrowserTerminal";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";

const schema = z.object({
  command: z
    .string()
    .min(1)
    .refine((v) => new TextEncoder().encode(v).length <= 65536 && v.trim().length > 0 && !v.includes("\0")),
});
export function SSHCommandConsole({ sessionID }: { sessionID: string }) {
  const { t } = useTranslation();
  const [running, setRunning] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({ resolver: zodResolver(schema), defaultValues: { command: "" } });
  if (running !== null) return <BrowserTerminal sessionID={sessionID} sshCommand={running} commandRules onClose={() => setRunning(null)} />;
  return (
    <form className="grid gap-3" onSubmit={handleSubmit((v) => setRunning(v.command))}>
      <p>{t("admin.access.rules.sshHelp")}</p>
      <Field label={t("admin.access.rules.sshCommand")} error={errors.command ? t("admin.access.rules.invalid") : undefined} required>
        {(control) => <Textarea {...control} {...register("command")} spellCheck={false} />}
      </Field>
      <Button type="submit">{t("admin.access.rules.sshRun")}</Button>
    </form>
  );
}
