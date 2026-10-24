import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import type { ComplianceReportSchedulePreview, ComplianceReportScheduleRequest } from "@/lib/api";
import { EvidenceList } from "./ComplianceReportingPanels";

// ServiceNow tables a report ticket can open in (A103); API identifiers, not copy.
export const serviceNowTables = ["incident", "change_request", "sc_task"] as const;
export type ServiceNowTable = (typeof serviceNowTables)[number];

export type ComplianceDispatchForm = {
  dispatchChannels: string;
  ticketEnabled: boolean;
  ticketInstanceURL: string;
  ticketTokenRef: string;
  ticketTable: ServiceNowTable;
};

export const emptyComplianceDispatchForm: ComplianceDispatchForm = {
  dispatchChannels: "",
  ticketEnabled: false,
  ticketInstanceURL: "",
  ticketTokenRef: "",
  ticketTable: "incident",
};

// A103: completed runs can also be announced on notification channels and in
// one ServiceNow ticket; the archive stays the record.
export function complianceDispatchRequest(form: ComplianceDispatchForm): ComplianceReportScheduleRequest["dispatch"] {
  const channels = form.dispatchChannels
    .split(",")
    .map((channel) => channel.trim())
    .filter(Boolean);
  if (channels.length === 0 && !form.ticketEnabled) return undefined;
  return {
    ...(channels.length > 0 ? { channels } : {}),
    ...(form.ticketEnabled
      ? {
          ticket: {
            provider: "servicenow" as const,
            instance_url: form.ticketInstanceURL.trim(),
            table: form.ticketTable,
            token_ref: form.ticketTokenRef.trim(),
          },
        }
      : {}),
  };
}

export function ComplianceDispatchFields({ form, onChange }: { form: ComplianceDispatchForm; onChange: (patch: Partial<ComplianceDispatchForm>) => void }) {
  const { t } = useTranslation();
  return (
    <>
      <Field className="lg:col-span-3" label={t("policy.reporting.dispatchChannels")} description={t("policy.reporting.dispatchChannelsHint")}>
        {(control) => (
          <Input
            {...control}
            value={form.dispatchChannels}
            placeholder={t("policy.reporting.dispatchChannelsPlaceholder")}
            onChange={(event) => onChange({ dispatchChannels: event.target.value })}
          />
        )}
      </Field>
      <label className="flex items-center gap-2 self-end text-body font-medium lg:col-span-3">
        <Checkbox checked={form.ticketEnabled} onChange={(event) => onChange({ ticketEnabled: event.target.checked })} />
        {t("policy.reporting.ticketEnabled")}
      </label>
      {form.ticketEnabled && (
        <>
          <Field className="lg:col-span-2" label={t("policy.reporting.ticketInstanceURL")}>
            {(control) => (
              <Input
                {...control}
                value={form.ticketInstanceURL}
                placeholder={t("policy.reporting.ticketInstanceURLPlaceholder")}
                onChange={(event) => onChange({ ticketInstanceURL: event.target.value })}
              />
            )}
          </Field>
          <Field className="lg:col-span-2" label={t("policy.reporting.ticketTokenRef")}>
            {(control) => <Input {...control} value={form.ticketTokenRef} onChange={(event) => onChange({ ticketTokenRef: event.target.value })} />}
          </Field>
          <Field className="lg:col-span-2" label={t("policy.reporting.ticketTable")}>
            {(control) => (
              <Select {...control} value={form.ticketTable} onChange={(event) => onChange({ ticketTable: event.target.value as ServiceNowTable })}>
                {serviceNowTables.map((table) => (
                  <option key={table} value={table}>
                    {table}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </>
      )}
    </>
  );
}

// The exact-schedule review: nothing changes until Create schedule is pressed.
export function ComplianceScheduleReview({ preview }: { preview: ComplianceReportSchedulePreview }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-md border border-border bg-muted/40 p-4 text-sm" aria-labelledby="compliance-schedule-review-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="compliance-schedule-review-heading" className="font-semibold">
            {t("policy.reporting.reviewHeading")}
          </h3>
          <p className="mt-1 text-muted-foreground">{t("policy.reporting.noStateChanged")}</p>
        </div>
        <span className="rounded-md border border-border bg-background px-2 py-1 text-xs font-medium">
          {preview.ready ? t("policy.reporting.ready") : t("policy.reporting.setupNeeded")}
        </span>
      </div>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <dt className="text-xs font-medium text-muted-foreground">{t("policy.reporting.fingerprint")}</dt>
          <dd className="mt-1 break-all font-mono text-xs">{preview.request_fingerprint}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-muted-foreground">{t("policy.reporting.permission")}</dt>
          <dd className="mt-1 font-mono text-xs">{preview.required_permission}</dd>
        </div>
      </dl>
      {preview.blockers.length > 0 && <EvidenceList title={t("policy.reporting.blockers")} items={preview.blockers} />}
      {preview.warnings.length > 0 && <EvidenceList title={t("policy.reporting.warnings")} items={preview.warnings} />}
      {preview.execute_external_effects.length > 0 && <EvidenceList title={t("policy.reporting.afterEachRun")} items={preview.execute_external_effects} />}
      <div className="mt-3 grid gap-3 lg:grid-cols-3">
        <EvidenceList title={t("policy.reporting.executeWrites")} items={preview.execute_writes} />
        <EvidenceList title={t("policy.reporting.recovery")} items={preview.recovery_steps} />
        <EvidenceList title={t("policy.reporting.verify")} items={preview.verification_steps} />
      </div>
      <p className="mt-3 text-xs text-muted-foreground">{preview.secret_data_handling}</p>
    </section>
  );
}
