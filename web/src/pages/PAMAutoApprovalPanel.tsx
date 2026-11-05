import { useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { api, type PAMAutoApprovalRule, type PAMAutoApprovalRuleRequest } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { DataGrid } from "@/components/DataGrid";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

const schema = z.object({
  name: z.string().trim().min(1).max(120),
  kind: z.enum(["session", "checkout", "both"]),
  targetTypes: z.string(),
  targetIDs: z.string(),
  folders: z.string(),
  roles: z.string(),
  days: z.string(),
  start: z.string(),
  end: z.string(),
  zone: z.string(),
  ticket: z.string().max(1024),
  ttl: z.coerce.number().int().min(1).max(86400),
  enabled: z.boolean(),
});
type Form = z.input<typeof schema>;
type Values = z.output<typeof schema>;
const empty: Form = {
  name: "",
  kind: "session",
  targetTypes: "",
  targetIDs: "",
  folders: "",
  roles: "",
  days: "",
  start: "",
  end: "",
  zone: "UTC",
  ticket: "",
  ttl: 120,
  enabled: true,
};
const list = (value: string) =>
  value
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean);

/** The review is effect-free. Saving records a revisioned policy; it never
 * approves an existing pending request or changes a frozen evaluation. */
export function PAMAutoApprovalPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const rules = useApiQuery(["pam-auto-approval-rules"], api.pamAutoApprovalRules, { retry: false });
  const [editing, setEditing] = useState<PAMAutoApprovalRule | null>(null);
  const [review, setReview] = useState<PAMAutoApprovalRuleRequest | null>(null);
  const [deleting, setDeleting] = useState<PAMAutoApprovalRule | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const saveKey = useRef(crypto.randomUUID());
  const [ruleID, setRuleID] = useState(() => crypto.randomUUID());
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<Form, unknown, Values>({ resolver: zodResolver(schema), defaultValues: empty });
  const act = async (work: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await work();
      await cache.invalidateQueries({ queryKey: ["pam-auto-approval-rules"] });
      setNotice(t("admin.access.auto.saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const prepare = (v: Values) => {
    if (!list(v.targetTypes).length && !list(v.targetIDs).length && !list(v.folders).length) {
      setError(t("admin.access.auto.scopeRequired"));
      return;
    }
    if ((v.start || v.end || v.days) && (!/^\d{2}:\d{2}$/.test(v.start) || !/^\d{2}:\d{2}$/.test(v.end) || v.start >= v.end || !v.zone.trim())) {
      setError(t("admin.access.auto.windowInvalid"));
      return;
    }
    const days = list(v.days);
    if (days.some((day) => !["mon", "tue", "wed", "thu", "fri", "sat", "sun"].includes(day))) {
      setError(t("admin.access.auto.windowInvalid"));
      return;
    }
    setError(null);
    setReview({
      name: v.name,
      applies_to: v.kind === "both" ? ["session", "checkout"] : [v.kind],
      target_types: list(v.targetTypes),
      target_ids: list(v.targetIDs),
      folders: list(v.folders),
      requester_roles: list(v.roles),
      ticket_pattern: v.ticket,
      max_ttl_seconds: v.ttl,
      enabled: v.enabled,
      revision: editing?.revision ?? 0,
      ...(v.start
        ? { window: { days: days as NonNullable<PAMAutoApprovalRuleRequest["window"]>["days"], start: v.start, end: v.end, time_zone: v.zone.trim() } }
        : {}),
    });
  };
  const save = () =>
    act(async () => {
      if (!review) return;
      await api.savePAMAutoApprovalRule(editing?.id ?? ruleID, review, saveKey.current);
      setRuleID(crypto.randomUUID());
      saveKey.current = crypto.randomUUID();
      setReview(null);
      setEditing(null);
      reset(empty);
    });
  const edit = (r: PAMAutoApprovalRule) => {
    setEditing(r);
    setReview(null);
    setError(null);
    saveKey.current = crypto.randomUUID();
    reset({
      name: r.name,
      kind: r.applies_to.length === 2 ? "both" : r.applies_to[0],
      targetTypes: r.target_types?.join(", ") ?? "",
      targetIDs: r.target_ids?.join(", ") ?? "",
      folders: r.folders?.join(", ") ?? "",
      roles: r.requester_roles?.join(", ") ?? "",
      days: r.window?.days?.join(", ") ?? "",
      start: r.window?.start ?? "",
      end: r.window?.end ?? "",
      zone: r.window?.time_zone ?? "UTC",
      ticket: r.ticket_pattern ?? "",
      ttl: r.max_ttl_seconds,
      enabled: r.enabled,
    });
  };
  return (
    <section className="grid gap-4" aria-labelledby="pam-auto-heading">
      <h3 id="pam-auto-heading" className="text-body font-semibold">
        {t("admin.access.auto.heading")}
      </h3>
      <p className="text-caption text-muted-foreground">{t("admin.access.auto.help")}</p>
      {error ? (
        <ErrorState title={t("admin.access.auto.failed")}>
          <p>{error}</p>
        </ErrorState>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <DataGrid<PAMAutoApprovalRule>
        ariaLabel={t("admin.access.auto.table")}
        rows={rules.data?.items ?? []}
        getRowId={(r) => r.id}
        state={rules.error ? "error" : rules.loading ? "loading" : "ready"}
        columns={[
          { id: "name", header: t("admin.access.auto.name"), cell: (r) => r.name },
          { id: "id", header: t("admin.access.auto.id"), cell: (r) => r.id },
          { id: "revision", header: t("admin.access.auto.revision"), cell: (r) => r.revision },
          {
            id: "scope",
            header: t("admin.access.auto.scope"),
            cell: (r) => [...(r.target_types ?? []), ...(r.target_ids ?? []), ...(r.folders ?? [])].join(", "),
          },
          {
            id: "kind",
            header: t("admin.access.auto.kind"),
            cell: (r) => r.applies_to.map((k) => t(k === "session" ? "admin.access.auto.session" : "admin.access.auto.checkout")).join(", "),
          },
          { id: "status", header: t("admin.access.auto.status"), cell: (r) => t(r.enabled ? "admin.access.auto.enabled" : "admin.access.auto.disabled") },
          {
            id: "action",
            header: t("admin.access.targetAction"),
            cell: (r) =>
              canManage ? (
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => edit(r)}>
                    {t("admin.access.auto.edit")}
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => setDeleting(r)}>
                    {t("admin.access.auto.delete")}
                  </Button>
                </div>
              ) : null,
          },
        ]}
      />
      {deleting && canManage ? (
        <div role="group" aria-label={t("admin.access.auto.deleteReview")} className="grid gap-2 rounded border p-4">
          <p>{t("admin.access.auto.deleteHelp", { name: deleting.name, revision: deleting.revision })}</p>
          <div className="flex gap-2">
            <Button
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  await api.deletePAMAutoApprovalRule(deleting.id, deleting.revision);
                  setDeleting(null);
                })
              }
            >
              {t("admin.access.auto.deleteConfirm")}
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => setDeleting(null)}>
              {t("admin.access.auto.back")}
            </Button>
          </div>
        </div>
      ) : null}
      {canManage && !review ? (
        <form className="grid gap-3" onSubmit={handleSubmit(prepare)}>
          <Field label={t("admin.access.auto.name")} error={errors.name?.message}>
            {(control) => <Input {...control} {...register("name")} />}
          </Field>
          <Field label={t("admin.access.auto.kind")}>
            {(control) => (
              <Select {...control} {...register("kind")}>
                <option value="session">{t("admin.access.auto.session")}</option>
                <option value="checkout">{t("admin.access.auto.checkout")}</option>
                <option value="both">{t("admin.access.auto.both")}</option>
              </Select>
            )}
          </Field>
          <p className="text-caption">{t("admin.access.auto.criteriaHelp")}</p>
          <Field label={t("admin.access.auto.types")}>{(control) => <Input {...control} {...register("targetTypes")} />}</Field>
          <Field label={t("admin.access.auto.targets")}>{(control) => <Input {...control} {...register("targetIDs")} />}</Field>
          <Field label={t("admin.access.auto.folders")}>{(control) => <Input {...control} {...register("folders")} />}</Field>
          <Field label={t("admin.access.auto.roles")}>{(control) => <Input {...control} {...register("roles")} />}</Field>
          <Field label={t("admin.access.auto.ticket")} description={t("admin.access.auto.ticketHelp")} error={errors.ticket?.message}>
            {(control) => <Input {...control} {...register("ticket")} />}
          </Field>
          <Field label={t("admin.access.auto.ttl")} error={errors.ttl?.message}>
            {(control) => <Input {...control} type="number" min="1" max="86400" {...register("ttl")} />}
          </Field>
          <details>
            <summary>{t("admin.access.auto.window")}</summary>
            <div className="grid gap-3 p-3">
              <p className="text-caption">{t("admin.access.auto.windowHelp")}</p>
              <Field label={t("admin.access.auto.days")}>{(control) => <Input {...control} {...register("days")} />}</Field>
              <Field label={t("admin.access.auto.start")}>{(control) => <Input {...control} type="time" {...register("start")} />}</Field>
              <Field label={t("admin.access.auto.end")}>{(control) => <Input {...control} type="time" {...register("end")} />}</Field>
              <Field label={t("admin.access.auto.zone")}>{(control) => <Input {...control} {...register("zone")} />}</Field>
            </div>
          </details>
          <label className="flex gap-2">
            <input type="checkbox" {...register("enabled")} />
            {t("admin.access.auto.enabled")}
          </label>
          <div>
            <Button type="submit" disabled={busy || !!rules.error}>
              {t("admin.access.auto.review")}
            </Button>
          </div>
        </form>
      ) : null}
      {review && canManage ? (
        <div role="group" aria-label={t("admin.access.auto.reviewHeading")} className="grid gap-3 rounded border p-4">
          <h4 className="font-semibold">{t("admin.access.auto.reviewHeading")}</h4>
          <p>{t("admin.access.auto.reviewHelp")}</p>
          <dl className="grid gap-2">
            {[
              ["admin.access.auto.name", review.name],
              ["admin.access.auto.id", editing?.id ?? ruleID],
              ["admin.access.auto.revision", review.revision ?? 0],
              [
                "admin.access.auto.kind",
                review.applies_to.map((k) => t(k === "session" ? "admin.access.auto.session" : "admin.access.auto.checkout")).join(", "),
              ],
              ["admin.access.auto.types", review.target_types?.join(", ")],
              ["admin.access.auto.targets", review.target_ids?.join(", ")],
              ["admin.access.auto.folders", review.folders?.join(", ")],
              ["admin.access.auto.roles", review.requester_roles?.join(", ")],
              ["admin.access.auto.ticket", review.ticket_pattern],
              ["admin.access.auto.ttl", review.max_ttl_seconds],
              [
                "admin.access.auto.window",
                review.window
                  ? [review.window.days?.join(", "), review.window.start, review.window.end, review.window.time_zone].filter(Boolean).join(" · ")
                  : t("admin.access.auto.anyTime"),
              ],
              ["admin.access.auto.status", t(review.enabled ? "admin.access.auto.enabled" : "admin.access.auto.disabled")],
            ].map(([key, value]) => (
              <div key={key}>
                <dt className="text-caption text-muted-foreground">{t(key as Parameters<typeof t>[0])}</dt>
                <dd>{value === undefined || value === "" ? t("admin.access.auto.unrestricted") : value}</dd>
              </div>
            ))}
          </dl>
          <div className="flex gap-2">
            <Button disabled={busy} onClick={() => void save()}>
              {t("admin.access.auto.save")}
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => setReview(null)}>
              {t("admin.access.auto.back")}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
