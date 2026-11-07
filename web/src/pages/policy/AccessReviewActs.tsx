import { type FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useCan } from "@/components/rbac";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type NHIReviewItem } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// Q1: access reviews that act. A review can be built from what trstctl records
// instead of a hand-typed list, a revoke decision revokes the credential once
// and its item closes only on evidence, and a keep decision renews the owner's
// attestation with a next review date.
type Source = "graph_reachers" | "stale_owner_attestation" | "pam_accounts";

export function AccessReviewGenerate({ onGenerated }: { onGenerated: (campaignId: string) => void }) {
  const { t } = useTranslation();
  const canWrite = useCan("access:write");
  const [form, setForm] = useState({ name: "", source: "graph_reachers" as Source, target: "", olderThanDays: "", reviewer: "" });
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<string | null>(null);
  if (!canWrite) return null;

  // A changed request is a new request: it never reuses the last key.
  const change = (patch: Partial<typeof form>) => {
    setForm((current) => ({ ...current, ...patch }));
    setPendingKey(null);
  };

  async function generate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    setCoverage(null);
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      const days = Number(form.olderThanDays);
      const result = await api.generateNHIReviewCampaign(
        {
          name: form.name.trim(),
          source: form.source,
          ...(form.source === "graph_reachers"
            ? { target: form.target.trim() }
            : form.source === "stale_owner_attestation" && days > 0
              ? { older_than_days: days }
              : {}),
          ...(form.reviewer.trim() ? { reviewer_subject: form.reviewer.trim() } : {}),
        },
        key,
      );
      setPendingKey(null);
      setMessage(t("policy.nhiReview.generate.done", { count: result.campaign.item_count }));
      setCoverage(result.coverage?.note ?? null);
      onGenerated(result.campaign.id);
    } catch (cause) {
      setMessage(apiProblemMessage(cause, t("policy.nhiReview.generate.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      aria-labelledby="nhi-review-generate-heading"
      className="grid gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6"
      onSubmit={(event) => void generate(event)}
    >
      <div className="lg:col-span-6">
        <h3 id="nhi-review-generate-heading" className="font-semibold">
          {t("policy.nhiReview.generate.heading")}
        </h3>
        <p className="mt-1 text-muted-foreground">{t("policy.nhiReview.generate.help")}</p>
      </div>
      <Field label={t("policy.nhiReview.generate.name")} className="lg:col-span-2">
        {(control) => <Input {...control} value={form.name} onChange={(event) => change({ name: event.target.value })} />}
      </Field>
      <Field label={t("policy.nhiReview.generate.source")} className="lg:col-span-2">
        {(control) => (
          <Select {...control} value={form.source} onChange={(event) => change({ source: event.target.value as Source })}>
            <option value="graph_reachers">{t("policy.nhiReview.generate.sourceGraph")}</option>
            <option value="stale_owner_attestation">{t("policy.nhiReview.generate.sourceStale")}</option>
            <option value="pam_accounts">{t("policy.nhiReview.generate.sourcePAM")}</option>
          </Select>
        )}
      </Field>
      <Field label={t("policy.nhiReview.generate.reviewer")} className="lg:col-span-2">
        {(control) => <Input {...control} value={form.reviewer} onChange={(event) => change({ reviewer: event.target.value })} />}
      </Field>
      {form.source === "graph_reachers" ? (
        <Field label={t("policy.nhiReview.generate.target")} className="lg:col-span-4">
          {(control) => (
            <Input
              {...control}
              value={form.target}
              placeholder={t("policy.nhiReview.generate.targetPlaceholder")}
              onChange={(event) => change({ target: event.target.value })}
            />
          )}
        </Field>
      ) : form.source === "pam_accounts" ? (
        <p className="text-muted-foreground lg:col-span-4">{t("policy.nhiReview.generate.pamHelp")}</p>
      ) : (
        <Field label={t("policy.nhiReview.generate.olderThanDays")} className="lg:col-span-4">
          {(control) => (
            <Input {...control} type="number" min={1} value={form.olderThanDays} onChange={(event) => change({ olderThanDays: event.target.value })} />
          )}
        </Field>
      )}
      <div className="flex items-end lg:col-span-2">
        <Button className="w-full" type="submit" disabled={busy || !form.name.trim() || (form.source === "graph_reachers" && !form.target.trim())}>
          {t("policy.nhiReview.generate.action")}
        </Button>
      </div>
      {message ? (
        <p role="status" className="lg:col-span-6">
          {message}
        </p>
      ) : null}
      {coverage ? <p className="text-muted-foreground lg:col-span-6">{t("policy.nhiReview.generate.coverage", { note: coverage })}</p> : null}
    </form>
  );
}

// AccessReviewOutcome says what a decision did: for a revoke, whether trstctl
// requested the credential's revoke, left it to its own revocation, failed, or
// closed the item on evidence; for a keep, the next review date.
export function AccessReviewOutcome({ item }: { item: NHIReviewItem }) {
  const { t, formatDate } = useTranslation();
  if (item.status === "certified" && item.next_review_at) {
    return <p className="mt-1 text-xs text-muted-foreground">{t("policy.nhiReview.outcome.nextReview", { date: formatDate(item.next_review_at) })}</p>;
  }
  if (item.status !== "revoked" || !item.revocation_status) return null;
  const label = {
    requested: t("policy.nhiReview.outcome.requested"),
    manual: t("policy.nhiReview.outcome.manual"),
    failed: t("policy.nhiReview.outcome.failed"),
    closed: t("policy.nhiReview.outcome.closed"),
  }[item.revocation_status];
  return (
    <div className="mt-1 text-xs">
      <p className={item.revocation_status === "failed" ? "font-medium text-destructive" : "font-medium"}>{label}</p>
      <p className="break-words text-muted-foreground">{item.revocation_status === "closed" ? item.closing_evidence : item.revocation_detail}</p>
    </div>
  );
}

// AccessReviewSignedResult (A276) downloads a completed campaign's result
// with the audit key's signature over it, for evidence kept outside
// trstctl; verify it with the audit verification keys.
export function AccessReviewSignedResult({ campaignId, completed }: { campaignId: string; completed: boolean }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  if (!completed) return null;

  async function download() {
    setBusy(true);
    setMessage(null);
    try {
      const signed = await api.nhiReviewResult(campaignId);
      const blob = new Blob([JSON.stringify(signed, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `access-certification-${campaignId}.json`;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(t("policy.nhiReview.result.downloaded"));
    } catch (cause) {
      setMessage(apiProblemMessage(cause, t("policy.nhiReview.result.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 flex flex-wrap items-center gap-3">
      <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void download()}>
        {t("policy.nhiReview.result.download")}
      </Button>
      {message ? (
        <p role="status" className="text-sm">
          {message}
        </p>
      ) : null}
    </div>
  );
}
