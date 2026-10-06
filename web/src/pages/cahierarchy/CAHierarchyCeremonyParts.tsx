import { X } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CredentialChip } from "@/components/CredentialChip";
import { Dialog } from "@/components/Dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { CAAuthority, CAAuthorityRotationPlanPreview, CACeremonyPlanPreview, CACeremonyStartRequest, CAKeyCeremony } from "@/lib/api";

const managedIntermediateSpec = z
  .object({
    common_name: z.string().trim().min(1),
    max_path_len: z.number().int().min(0).optional(),
    signature_algorithm: z.string().trim().min(1).optional(),
    ttl_seconds: z.number().int().positive().optional(),
    permitted_dns_domains: z.array(z.string().trim().min(1)).optional(),
    extended_key_usages: z.array(z.string().trim().min(1)).optional(),
  })
  .strict();

const managedIntermediateForm = z.object({
  parent_id: z.uuid(),
  spec_json: z
    .string()
    .trim()
    .min(1)
    .superRefine((value, context) => {
      try {
        if (managedIntermediateSpec.safeParse(JSON.parse(value)).success) return;
      } catch {
        // The same field error covers invalid JSON and an invalid CA spec.
      }
      context.addIssue({ code: "custom", message: translateNow("caHierarchy.managedIntermediate.invalidSpec") });
    }),
});

type ManagedIntermediateValues = z.infer<typeof managedIntermediateForm>;

export const managedIntermediateDefaultSpec: CACeremonyStartRequest["spec"] = {
  common_name: "Issuing Intermediate CA",
  max_path_len: 0,
  signature_algorithm: "ECDSA-P256",
  ttl_seconds: 71_280_000,
};

export function ManagedIntermediateCeremonyForm({
  busy,
  parents,
  onReview,
}: {
  busy: boolean;
  parents: CAAuthority[];
  onReview: (request: CACeremonyStartRequest) => void;
}) {
  const { t } = useTranslation();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ManagedIntermediateValues>({
    resolver: zodResolver(managedIntermediateForm),
    defaultValues: {
      parent_id: parents[0]?.id ?? "",
      spec_json: JSON.stringify(managedIntermediateDefaultSpec, null, 2),
    },
  });
  return (
    <form
      className="grid gap-3 rounded-control border border-border p-4"
      onSubmit={handleSubmit((values) =>
        onReview({
          operation: "create_intermediate",
          threshold: 2,
          parent_id: values.parent_id,
          spec: managedIntermediateSpec.parse(JSON.parse(values.spec_json)),
        }),
      )}
    >
      <h3 className="font-semibold">{t("caHierarchy.managedIntermediate.title")}</h3>
      <p className="text-sm text-muted-foreground">{t("caHierarchy.managedIntermediate.help")}</p>
      <label className="grid gap-1 text-sm font-medium">
        {t("caHierarchy.managedIntermediate.parent")}
        <select className="ui-input" {...register("parent_id")}>
          {parents.map((parent) => (
            <option key={parent.id} value={parent.id}>
              {parent.common_name} ({parent.kind}, {parent.status})
            </option>
          ))}
        </select>
      </label>
      {errors.parent_id ? (
        <p role="alert" className="text-sm text-destructive">
          {t("caHierarchy.managedIntermediate.parentRequired")}
        </p>
      ) : null}
      <label className="grid gap-1 text-sm font-medium">
        {t("caHierarchy.managedIntermediate.spec")}
        <textarea className="ui-input min-h-32 font-mono text-xs" rows={7} {...register("spec_json")} />
      </label>
      {errors.spec_json ? (
        <p role="alert" className="text-sm text-destructive">
          {errors.spec_json.message}
        </p>
      ) : null}
      <div>
        <Button type="submit" disabled={busy}>
          {t("caHierarchy.managedIntermediate.review")}
        </Button>
      </div>
    </form>
  );
}

export function CARotationReviewDialog({
  busy,
  error,
  onClose,
  onConfirm,
  preview,
}: {
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: () => void;
  preview: CAAuthorityRotationPlanPreview;
}) {
  const { t } = useTranslation();
  const titleId = "ca-rotation-review-heading";
  const descriptionId = "ca-rotation-review-description";
  return (
    <Dialog
      open
      onClose={busy ? () => undefined : onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      closeOnBackdropClick={!busy}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="text-title font-semibold">
            {t("caHierarchy.rotationPreview.title")}
          </h2>
          <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
            {t("caHierarchy.rotationPreview.description")}
          </p>
        </div>
        <Button type="button" variant="ghost" size="icon" disabled={busy} onClick={onClose} aria-label={t("caHierarchy.rotationPreview.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>

      <div className="grid gap-5 p-5 text-sm">
        <section className="rounded-control border border-status-success/35 bg-status-success/5 p-4" aria-label={t("caHierarchy.preview.effectFreeLabel")}>
          <p className="font-semibold text-foreground">{t("caHierarchy.preview.effectFree")}</p>
          <p className="mt-1 text-muted-foreground">{t("caHierarchy.rotationPreview.effectFreeDetail")}</p>
        </section>

        <dl className="grid gap-3 sm:grid-cols-2">
          <ReviewValue label={t("caHierarchy.rotationPreview.predecessor")} value={`${preview.predecessor.common_name} · ${preview.predecessor.status}`} />
          <ReviewValue label={t("caHierarchy.rotationPreview.successor")} value={`${preview.successor.common_name} · ${preview.successor.status}`} />
          <ReviewValue label={t("caHierarchy.preview.permission")} value={preview.required_permission} />
          <ReviewValue label={t("caHierarchy.rotationPreview.reason")} value={preview.reason || t("caHierarchy.rotationPreview.noReason")} />
          <div className="grid gap-1 sm:col-span-2">
            <dt className="text-caption text-muted-foreground">{t("caHierarchy.preview.fingerprint")}</dt>
            <dd>
              <CredentialChip value={preview.request_fingerprint} label={t("caHierarchy.preview.fingerprint")} head={12} tail={8} />
            </dd>
          </div>
        </dl>

        <ReviewList title={t("caHierarchy.rotationPreview.changes")} items={preview.changes} />
        <ReviewList title={t("caHierarchy.preview.risks")} items={preview.risks} />
        <ReviewList title={t("caHierarchy.preview.verify")} items={preview.verification_steps} />

        {error ? (
          <p className="rounded-control border border-destructive/35 bg-destructive/5 p-3 text-destructive" role="alert">
            {error}
          </p>
        ) : null}

        <footer className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
            {t("caHierarchy.preview.cancel")}
          </Button>
          <Button type="button" loading={busy} disabled={!preview.ready || busy} onClick={onConfirm}>
            {t("caHierarchy.rotationPreview.confirm")}
          </Button>
        </footer>
      </div>
    </Dialog>
  );
}

export function CACeremonyReviewDialog({
  busy,
  error,
  onClose,
  onConfirm,
  preview,
}: {
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: () => void;
  preview: CACeremonyPlanPreview;
}) {
  const { t } = useTranslation();
  const titleId = "ca-ceremony-review-heading";
  const descriptionId = "ca-ceremony-review-description";
  const authority = preview.authority ?? preview.parent;
  return (
    <Dialog
      open
      onClose={busy ? () => undefined : onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      closeOnBackdropClick={!busy}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="text-title font-semibold">
            {t("caHierarchy.preview.title")}
          </h2>
          <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
            {t("caHierarchy.preview.description")}
          </p>
        </div>
        <Button type="button" variant="ghost" size="icon" disabled={busy} onClick={onClose} aria-label={t("caHierarchy.preview.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>

      <div className="grid gap-5 p-5 text-sm">
        <section className="rounded-control border border-status-success/35 bg-status-success/5 p-4" aria-label={t("caHierarchy.preview.effectFreeLabel")}>
          <p className="font-semibold text-foreground">{t("caHierarchy.preview.effectFree")}</p>
          <p className="mt-1 text-muted-foreground">{t("caHierarchy.preview.effectFreeDetail")}</p>
        </section>

        <dl className="grid gap-3 sm:grid-cols-2">
          <ReviewValue label={t("caHierarchy.preview.operation")} value={preview.operation} />
          <ReviewValue
            label={t("caHierarchy.preview.approvals")}
            value={t("caHierarchy.preview.approvalCount", { count: String(preview.approval_threshold) })}
          />
          <ReviewValue label={t("caHierarchy.preview.permission")} value={preview.required_permission} />
          <ReviewValue label={t("caHierarchy.preview.commonName")} value={preview.normalized_spec.common_name} />
          {authority ? (
            <ReviewValue label={t("caHierarchy.preview.authority")} value={`${authority.common_name} · ${authority.kind} · ${authority.status}`} />
          ) : null}
          <div className="grid gap-1">
            <dt className="text-caption text-muted-foreground">{t("caHierarchy.preview.fingerprint")}</dt>
            <dd>
              <CredentialChip value={preview.request_fingerprint} label={t("caHierarchy.preview.fingerprint")} head={12} tail={8} />
            </dd>
          </div>
        </dl>

        <section className="border-t border-border pt-4">
          <h3 className="font-semibold">{t("caHierarchy.preview.exactSpec")}</h3>
          <pre className="mt-2 max-h-48 overflow-auto rounded-control bg-muted p-3 text-xs">{JSON.stringify(preview.normalized_spec, null, 2)}</pre>
        </section>

        <ReviewList title={t("caHierarchy.preview.changes")} items={preview.changes} />
        <ReviewList title={t("caHierarchy.preview.risks")} items={preview.risks} />
        <ReviewList title={t("caHierarchy.preview.verify")} items={preview.verification_steps} />

        {preview.sensitive_inputs.length > 0 ? (
          <section className="border-t border-border pt-4">
            <h3 className="font-semibold">{t("caHierarchy.preview.protectedInputs")}</h3>
            <p className="mt-1 text-muted-foreground">{t("caHierarchy.preview.protectedInputsDetail")}</p>
            <p className="mt-2 font-mono text-caption text-muted-foreground">{preview.sensitive_inputs.join(", ")}</p>
          </section>
        ) : null}

        {error ? (
          <p className="rounded-control border border-destructive/35 bg-destructive/5 p-3 text-destructive" role="alert">
            {error}
          </p>
        ) : null}

        <footer className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
            {t("caHierarchy.preview.cancel")}
          </Button>
          <Button type="button" loading={busy} disabled={!preview.ready || busy} onClick={onConfirm}>
            {t("caHierarchy.preview.confirm")}
          </Button>
        </footer>
      </div>
    </Dialog>
  );
}

function ReviewValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className="break-words font-medium text-foreground">{value}</dd>
    </div>
  );
}

function ReviewList({ items, title }: { items: string[]; title: string }) {
  return (
    <section className="border-t border-border pt-4">
      <h3 className="font-semibold">{title}</h3>
      <ul className="mt-2 grid gap-2 text-muted-foreground">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span aria-hidden="true" className="text-brand-accent">
              •
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function CeremonyPanel({
  busy,
  ceremony,
  onApprove,
  onView,
}: {
  busy: boolean;
  ceremony: CAKeyCeremony;
  onApprove: (id: string) => void;
  onView: (id: string) => void;
}) {
  const { t } = useTranslation();
  const complete = ceremony.approvals >= ceremony.threshold || ceremony.status !== "pending";
  return (
    <section aria-labelledby="active-ceremony-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="active-ceremony-heading" className="text-title font-semibold">
            {translateNow("source.active.ceremony.282727eb03")}
          </h3>
          <p className="mt-1 font-mono text-xs">{ceremony.id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={busy || complete}
            onClick={() => onApprove(ceremony.id)}
            aria-label={translateNow("source.approve.ceremony.value1.36200975a5", { value1: ceremony.id })}
          >
            {translateNow("source.approve.6007acbe30")}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={busy}
            onClick={() => onView(ceremony.id)}
            aria-label={translateNow("source.view.ceremony.value1.4ed0eab2e0", { value1: ceremony.id })}
          >
            {t("parity.view_69bd4e")}
          </Button>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <CeremonyValue label="Purpose" value={ceremony.purpose} mono />
        <CeremonyValue label="Approvals" value={`${ceremony.approvals} / ${ceremony.threshold} approvals`} />
        <CeremonyValue label="Status" value={ceremony.status} />
        <CeremonyValue label="Opened by" value={ceremony.opener || "-"} />
      </dl>
    </section>
  );
}

export function CeremonyLookupForm({ busy, id, onChange, onLoad }: { busy: boolean; id: string; onChange: (id: string) => void; onLoad: () => void }) {
  const { t } = useTranslation();
  const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id.trim());
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onLoad();
      }}
    >
      <label className="grid flex-1 gap-1 text-sm font-medium">
        {t("caHierarchy.ceremonyLookup.label")}
        <input
          className="ui-input"
          autoComplete="off"
          maxLength={36}
          value={id}
          onChange={(event) => onChange(event.target.value)}
          aria-describedby="ca-ceremony-lookup-help"
        />
      </label>
      <Button type="submit" variant="outline" disabled={busy || !valid}>
        {t("caHierarchy.ceremonyLookup.load")}
      </Button>
      <p id="ca-ceremony-lookup-help" className="w-full text-caption text-muted-foreground">
        {t("caHierarchy.ceremonyLookup.help")}
      </p>
    </form>
  );
}

export function CeremonyDetailDialog({ ceremony, onClose }: { ceremony: CAKeyCeremony; onClose: () => void }) {
  const { t } = useTranslation();
  const titleId = "ceremony-detail-heading";
  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="text-title font-semibold">
            {t("parity.ceremonyDetail_9cb326")}
          </h2>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{ceremony.id}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeCeremonyDetail_92fb97")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <div className="grid gap-4 p-5 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge vocabulary="lifecycle" value={ceremony.status} />
          <span className="text-body font-medium">
            {translateNow("source.value1.of.value2.approvals.cb7e517061", { value1: ceremony.approvals, value2: ceremony.threshold })}
          </span>
        </div>
        <dl className="grid gap-3 sm:grid-cols-2">
          <CeremonyValue label="Purpose" value={ceremony.purpose} mono />
          <CeremonyValue label="Opened by" value={ceremony.opener || "-"} />
          <CeremonyValue label="Created" value={ceremony.created_at} />
          <CeremonyValue label="Threshold" value={`${ceremony.threshold} approvals required`} />
        </dl>
        <footer className="flex justify-end border-t border-border pt-4">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.close.7d9eb7acb1")}
          </Button>
        </footer>
      </div>
    </Dialog>
  );
}

function CeremonyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-all text-sm ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}
