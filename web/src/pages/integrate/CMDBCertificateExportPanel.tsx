import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { SectionCard } from "@/components/dashboard";
import { Num } from "@/components/typography";
import { useTranslation } from "@/i18n/I18nProvider";
import { cmdbExportApi } from "@/lib/cmdbExportApi";
import { apiProblemMessage } from "@/lib/apiProblem";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery } from "@/lib/query";

const schema = z.object({ binding_id: z.string().min(1), certificate_id: z.uuid() });
type Values = z.infer<typeof schema>;

export function CMDBCertificateExportPanel() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const bindings = useApiQuery(["cmdb-certificate-export-bindings"], ({ signal }) => cmdbExportApi.bindings(signal), { retry: false });
  const [operationId, setOperationId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { binding_id: "", certificate_id: "" } });
  const status = useApiQuery(["cmdb-certificate-export", operationId], ({ signal }) => cmdbExportApi.status(operationId, signal), {
    enabled: operationId !== "",
    retry: false,
    live: { intervalMs: 5000 },
  });
  const enabled = (bindings.data?.items ?? []).filter((item) => item.enabled);

  const queue = form.handleSubmit(async (input) => {
    setError(null);
    try {
      const queued = await cmdbExportApi.queue(input, newIdempotencyKey());
      queryClient.setQueryData(["cmdb-certificate-export", queued.id], queued);
      setOperationId(queued.id);
      await queryClient.invalidateQueries({ queryKey: ["cmdb-certificate-export", queued.id] });
    } catch (failure) {
      setError(apiProblemMessage(failure, t("integrate.cmdb.failed")));
    }
  });

  return (
    <SectionCard title={t("integrate.cmdb.heading")} description={t("integrate.cmdb.description")}>
      {bindings.loading ? <p role="status">{t("integrate.cmdb.loading")}</p> : null}
      {bindings.error ? <p role="alert">{bindings.error}</p> : null}
      {!bindings.loading && !bindings.error && enabled.length === 0 ? <p>{t("integrate.cmdb.noBinding")}</p> : null}
      {enabled.length > 0 ? (
        <form className="grid gap-3" onSubmit={(event) => void queue(event)}>
          <Field label={t("integrate.cmdb.binding")} error={form.formState.errors.binding_id ? t("integrate.cmdb.invalid") : undefined} required>
            {(control) => (
              <Select {...control} {...form.register("binding_id")}>
                <option value="">{t("integrate.cmdb.chooseBinding")}</option>
                {enabled.map((binding) => (
                  <option key={binding.id} value={binding.id}>
                    {binding.id}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t("integrate.cmdb.certificate")} error={form.formState.errors.certificate_id ? t("integrate.cmdb.invalid") : undefined} required>
            {(control) => <Input {...control} {...form.register("certificate_id")} />}
          </Field>
          {form.formState.errors.certificate_id || form.formState.errors.binding_id ? <p role="alert">{t("integrate.cmdb.invalid")}</p> : null}
          <p className="text-sm text-muted-foreground">{t("integrate.cmdb.review")}</p>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {t("integrate.cmdb.export")}
          </Button>
        </form>
      ) : null}
      {error || status.error ? <p role="alert">{error ?? status.error}</p> : null}
      {operationId ? (
        <div className="mt-4 grid gap-2 text-sm" role="status">
          <p>{status.data?.status === "verified" ? t("integrate.cmdb.verified") : t("integrate.cmdb.pending", { status: status.data?.status ?? "pending" })}</p>
          <p>
            {t("integrate.cmdb.operation")} <Num>{operationId}</Num>
          </p>
          {status.data?.receipt ? (
            <p>
              {t("integrate.cmdb.record")} <Num>{status.data.receipt.sys_id}</Num>
            </p>
          ) : null}
          {status.data?.last_error ? <p>{status.data.last_error}</p> : null}
          <Button type="button" variant="outline" onClick={() => status.refetch()}>
            {t("integrate.cmdb.refresh")}
          </Button>
        </div>
      ) : null}
    </SectionCard>
  );
}
