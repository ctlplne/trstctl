import { useState } from "react";
import { FileKey2 } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CAAuthority, type CACeremonyPlanPreview, type CACeremonyStartRequest, type CACrossSign, type CAKeyCeremony } from "@/lib/api";
import { LabeledInput, LabeledSelect } from "./CAHierarchyFormParts";

type Fields = { issuerID: string; targetPEM: string; crossPEM: string };

function publicCertificate(value: string): string | null {
  const pem = value.trim();
  const pattern = /-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g;
  const blocks = [...pem.matchAll(pattern)];
  if (blocks.length !== 1 || pem.replace(pattern, "").trim()) return null;
  return `${blocks[0][0].trim()}\n`;
}

async function certificateSHA256(pem: string): Promise<string> {
  const der = Uint8Array.from(atob(pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "")), (c) => c.charCodeAt(0));
  const hash = await crypto.subtle.digest("SHA-256", der);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function ceremonyFingerprint(ceremony: CAKeyCeremony): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify({ purpose: ceremony.purpose, threshold: ceremony.threshold }));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function requestFor(fields: Fields): CACeremonyStartRequest | null {
  const target = publicCertificate(fields.targetPEM);
  const cross = publicCertificate(fields.crossPEM);
  if (!fields.issuerID || !target || !cross) return null;
  return {
    operation: "import_offline_cross_sign",
    authority_id: fields.issuerID,
    target_certificate_pem: target,
    cross_certificate_pem: cross,
    threshold: 2,
  };
}

/** Imports only public material. The server verifies the offline signature and
 * exact quorum-bound certificate bytes before it appends a cross-sign event. */
export function CAOfflineCrossSignPanel({ authorities }: { authorities: CAAuthority[] }) {
  const { t } = useTranslation();
  const [fields, setFields] = useState<Fields>({ issuerID: "", targetPEM: "", crossPEM: "" });
  const [reviewed, setReviewed] = useState<{ request: CACeremonyStartRequest; preview: CACeremonyPlanPreview; targetSHA: string; crossSHA: string } | null>(
    null,
  );
  const [ceremonyID, setCeremonyID] = useState("");
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [matching, setMatching] = useState(false);
  const [receipt, setReceipt] = useState<CACrossSign | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const current = requestFor(fields);
  const unchanged = Boolean(current && reviewed && JSON.stringify(current) === JSON.stringify(reviewed.request));
  const issuers = authorities.filter((ca) => ca.kind === "root" && ca.status === "active" && !ca.signer_handle);

  function change(patch: Partial<Fields>) {
    setFields((old) => ({ ...old, ...patch }));
    setError("");
  }
  function fail(cause: unknown) {
    setError(cause instanceof Error ? cause.message : t("caHierarchy.offlineCross.actionFailed"));
  }

  async function review() {
    if (!current) {
      setError(t("caHierarchy.offlineCross.completeFields"));
      return;
    }
    setBusy(true);
    setError("");
    setReceipt(null);
    try {
      const preview = await api.previewCACeremony(current);
      if (!preview.ready || preview.preview_writes.length || preview.preview_external_effects.length || preview.approval_threshold !== 2) {
        throw new Error(t("caHierarchy.offlineCross.notReady"));
      }
      const [targetSHA, crossSHA] = await Promise.all([certificateSHA256(current.target_certificate_pem!), certificateSHA256(current.cross_certificate_pem!)]);
      setReviewed({ request: current, preview, targetSHA, crossSHA });
      if (ceremony) setMatching((await ceremonyFingerprint(ceremony)) === preview.request_fingerprint);
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }

  async function start() {
    if (!reviewed || !unchanged || ceremonyID) return;
    setBusy(true);
    setError("");
    try {
      const next = await api.createCACeremony(reviewed.request);
      setCeremonyID(next.id);
      setCeremony(next);
      setMatching((await ceremonyFingerprint(next)) === reviewed.preview.request_fingerprint);
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    if (!ceremonyID.trim()) return;
    setBusy(true);
    setError("");
    try {
      const next = await api.caCeremony(ceremonyID.trim());
      setCeremony(next);
      setMatching(Boolean(reviewed && (await ceremonyFingerprint(next)) === reviewed.preview.request_fingerprint));
      if (next.status === "completed") {
        const recovered = await api.getCACrossSignReceipt(next.id);
        if (!recovered.imported) throw new Error(t("caHierarchy.offlineCross.wrongReceipt"));
        setReceipt(recovered);
      } else setReceipt(null);
    } catch (cause) {
      setCeremony(null);
      setMatching(false);
      setReceipt(null);
      fail(cause);
    } finally {
      setBusy(false);
    }
  }

  async function activate() {
    if (!reviewed || !unchanged || !matching || !ceremony || ceremony.status !== "pending" || ceremony.approvals < ceremony.threshold) return;
    setBusy(true);
    setError("");
    try {
      const result = await api.importOfflineRootCrossSign(reviewed.request.authority_id!, {
        ceremony_id: ceremony.id,
        target_certificate_pem: reviewed.request.target_certificate_pem!,
        cross_certificate_pem: reviewed.request.cross_certificate_pem!,
      });
      if (
        !result.imported ||
        result.issuer_authority_id !== reviewed.request.authority_id ||
        result.target_sha256 !== reviewed.targetSHA ||
        result.certificate_pem !== reviewed.request.cross_certificate_pem
      ) {
        throw new Error(t("caHierarchy.offlineCross.receiptMismatch"));
      }
      setReceipt(result);
      setCeremony(await api.caCeremony(ceremony.id));
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="offline-cross-heading" className="grid gap-4 border-b border-border py-5">
      <div className="flex items-start gap-3">
        <FileKey2 className="mt-1 h-4 w-4 shrink-0" aria-hidden="true" />
        <div>
          <h2 id="offline-cross-heading" className="text-title font-semibold">
            {t("caHierarchy.offlineCross.heading")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("caHierarchy.offlineCross.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.offlineCross.actionFailed")}>{error}</ErrorState>}
      <div className="ui-panel grid gap-3 p-comfortable">
        <LabeledSelect
          id="offline-cross-issuer"
          label={t("caHierarchy.offlineCross.issuer")}
          value={fields.issuerID}
          onChange={(issuerID) => change({ issuerID })}
        >
          <option value="">{t("caHierarchy.offlineCross.selectIssuer")}</option>
          {issuers.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.common_name} ({ca.id})
            </option>
          ))}
        </LabeledSelect>
        {(["targetPEM", "crossPEM"] as const).map((field) => (
          <div className="grid gap-2" key={field}>
            <label htmlFor={`offline-cross-${field}`} className="text-sm font-medium">
              {t(field === "targetPEM" ? "caHierarchy.offlineCross.target" : "caHierarchy.offlineCross.cross")}
            </label>
            <textarea
              id={`offline-cross-${field}`}
              rows={4}
              value={fields[field]}
              onChange={(event) => change({ [field]: event.target.value })}
              className="rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
            />
          </div>
        ))}
        <p className="text-xs text-muted-foreground">{t("caHierarchy.offlineCross.publicOnly")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={busy || !current} onClick={() => void review()}>
            {t("caHierarchy.offlineCross.review")}
          </Button>
          <Button type="button" disabled={busy || !reviewed || !unchanged || Boolean(ceremonyID)} onClick={() => void start()}>
            {t("caHierarchy.offlineCross.start")}
          </Button>
        </div>
        {reviewed && (
          <div className="grid gap-2 rounded-control border border-border bg-muted/30 p-3 text-xs" role="status">
            <p className="font-medium">{t("caHierarchy.offlineCross.reviewed")}</p>
            <p>
              {t("caHierarchy.offlineCross.issuer")}: {reviewed.preview.authority?.common_name ?? fields.issuerID} ({reviewed.request.authority_id})
            </p>
            <p className="break-all">
              {t("caHierarchy.offlineCross.targetHash")}: {reviewed.targetSHA}
            </p>
            <p className="break-all">
              {t("caHierarchy.offlineCross.crossHash")}: {reviewed.crossSHA}
            </p>
            <p className="break-all">
              {t("caHierarchy.offlineCross.fingerprint")}: {reviewed.preview.request_fingerprint}
            </p>
            <p>{t("caHierarchy.offlineCross.quorum")}: 2</p>
            {reviewed.preview.risks?.map((risk) => (
              <p key={risk}>{risk}</p>
            ))}
          </div>
        )}
        {reviewed && !unchanged && (
          <p role="alert" className="text-sm text-destructive">
            {t("caHierarchy.offlineCross.changed")}
          </p>
        )}
      </div>
      <div className="ui-panel grid gap-3 p-comfortable">
        <LabeledInput
          id="offline-cross-ceremony"
          label={t("caHierarchy.offlineCross.ceremonyID")}
          value={ceremonyID}
          onChange={(value) => {
            setCeremonyID(value.trim());
            setCeremony(null);
            setMatching(false);
            setReceipt(null);
          }}
        />
        <p className="text-sm text-muted-foreground">{t("caHierarchy.offlineCross.approvalHelp")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={busy || !ceremonyID} onClick={() => void refresh()}>
            {t("caHierarchy.offlineCross.refresh")}
          </Button>
          <Button
            type="button"
            disabled={busy || !unchanged || !matching || ceremony?.status !== "pending" || ceremony.approvals < ceremony.threshold}
            onClick={() => void activate()}
          >
            {t("caHierarchy.offlineCross.activate")}
          </Button>
        </div>
        {ceremony && (
          <p role="status">
            {ceremony.status}; {ceremony.approvals}/{ceremony.threshold} {t("caHierarchy.offlineCross.approvals")};{" "}
            {matching ? t("caHierarchy.offlineCross.bound") : t("caHierarchy.offlineCross.unbound")}
          </p>
        )}
        {receipt && (
          <div className="grid gap-2">
            <p role="status">
              {t("caHierarchy.offlineCross.imported")}: {receipt.issuer_authority_id}; {t("caHierarchy.offlineCross.targetHash")}: {receipt.target_sha256}
            </p>
            <label htmlFor="offline-cross-receipt" className="text-sm font-medium">
              {t("caHierarchy.offlineCross.receipt")}
            </label>
            <textarea
              id="offline-cross-receipt"
              readOnly
              rows={5}
              value={receipt.certificate_pem}
              className="rounded-control border border-border bg-muted/40 p-2 font-mono text-xs"
            />
          </div>
        )}
      </div>
    </section>
  );
}
