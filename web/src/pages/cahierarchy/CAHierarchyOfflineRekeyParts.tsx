import { useState } from "react";
import { FileKey2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CAAuthority, type CACeremonyPlanPreview, type CACeremonyStartRequest, type CAKeyCeremony, type CAOfflineRootRekey } from "@/lib/api";
import { LabeledInput, LabeledSelect } from "./CAHierarchyFormParts";

type Fields = {
  predecessorID: string;
  successorPEM: string;
  newByPreviousPEM: string;
  previousByNewPEM: string;
  reason: string;
  commonName: string;
  dnsDomains: string;
  extendedKeyUsages: string;
  maxPathLen: string;
  ttlDays: string;
};

const initial: Fields = {
  predecessorID: "",
  successorPEM: "",
  newByPreviousPEM: "",
  previousByNewPEM: "",
  reason: "planned offline-root succession",
  commonName: "",
  dnsDomains: "",
  extendedKeyUsages: "",
  maxPathLen: "1",
  ttlDays: "3650",
};

function singlePublicCertificate(value: string): string | null {
  const pem = value.trim();
  const pattern = /-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g;
  const matches = [...pem.matchAll(pattern)];
  if (matches.length !== 1 || pem.replace(pattern, "").trim()) return null;
  return `${matches[0][0].trim()}\n`;
}

async function certificateSHA256(pem: string): Promise<string> {
  const encoded = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
  const der = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  const hash = await crypto.subtle.digest("SHA-256", der);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function requestFor(form: Fields): CACeremonyStartRequest | null {
  const successor = singlePublicCertificate(form.successorPEM);
  const newByPrevious = singlePublicCertificate(form.newByPreviousPEM);
  const previousByNew = singlePublicCertificate(form.previousByNewPEM);
  const ttlDays = Number(form.ttlDays);
  const maxPathLen = Number(form.maxPathLen);
  if (
    !form.predecessorID ||
    !successor ||
    !newByPrevious ||
    !previousByNew ||
    !form.reason.trim() ||
    !form.commonName.trim() ||
    !Number.isSafeInteger(ttlDays) ||
    ttlDays <= 0 ||
    !Number.isSafeInteger(ttlDays * 86400) ||
    !Number.isSafeInteger(maxPathLen) ||
    maxPathLen < 0
  )
    return null;
  const extendedKeyUsages = form.extendedKeyUsages
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  return {
    operation: "rekey_offline_root",
    authority_id: form.predecessorID,
    certificate_pem: successor,
    cross_certificate_pem: newByPrevious,
    reverse_cross_certificate_pem: previousByNew,
    threshold: 2,
    reason: form.reason.trim(),
    spec: {
      common_name: form.commonName.trim(),
      permitted_dns_domains: form.dnsDomains
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean),
      max_path_len: maxPathLen,
      ttl_seconds: ttlDays * 86400,
      signature_algorithm: "ECDSA-P256",
      ...(extendedKeyUsages.length ? { extended_key_usages: extendedKeyUsages } : {}),
    },
  };
}

async function ceremonyFingerprint(ceremony: CAKeyCeremony): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify({ purpose: ceremony.purpose, threshold: ceremony.threshold }));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Public-only succession. The server independently verifies every signature,
 * constraint and exact ceremony purpose before the event append. */
export function CAOfflineRootRekeyPanel({ authorities, onActivated }: { authorities: CAAuthority[]; onActivated: () => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState<Fields>(initial);
  const [reviewed, setReviewed] = useState<{
    request: CACeremonyStartRequest;
    preview: CACeremonyPlanPreview;
    certificateHashes: string[];
  } | null>(null);
  const [ceremonyID, setCeremonyID] = useState("");
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [matching, setMatching] = useState<boolean | null>(null);
  const [receipt, setReceipt] = useState<CAOfflineRootRekey | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const current = requestFor(form);
  const unchanged = Boolean(current && reviewed && JSON.stringify(current) === JSON.stringify(reviewed.request));
  const eligible = authorities.filter((ca) => ca.kind === "root" && ca.status === "active" && !ca.signer_handle);

  function change(patch: Partial<Fields>) {
    setForm((old) => ({ ...old, ...patch }));
    setError("");
  }

  function fail(cause: unknown) {
    setError(cause instanceof Error ? cause.message : t("caHierarchy.offlineRekey.actionFailed"));
  }

  async function review() {
    if (!current) {
      setError(t("caHierarchy.offlineRekey.completeFields"));
      return;
    }
    setBusy(true);
    setError("");
    setReceipt(null);
    try {
      const preview = await api.previewCACeremony(current);
      if (!preview.ready || preview.preview_writes.length || preview.preview_external_effects.length || preview.approval_threshold !== 2) {
        throw new Error(t("caHierarchy.offlineRekey.notReady"));
      }
      const certificateHashes = await Promise.all(
        [current.certificate_pem!, current.cross_certificate_pem!, current.reverse_cross_certificate_pem!].map(certificateSHA256),
      );
      setReviewed({ request: current, preview, certificateHashes });
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
      setMatching(reviewed ? (await ceremonyFingerprint(next)) === reviewed.preview.request_fingerprint : null);
      if (next.status === "completed") setReceipt(await api.getOfflineRootRekeyReceipt(next.id));
      else setReceipt(null);
    } catch (cause) {
      setCeremony(null);
      setMatching(null);
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
      const request = reviewed.request;
      const result = await api.rekeyOfflineRoot(request.authority_id!, {
        ceremony_id: ceremony.id,
        successor_certificate_pem: request.certificate_pem!,
        new_signed_by_previous_pem: request.cross_certificate_pem!,
        previous_signed_by_new_pem: request.reverse_cross_certificate_pem!,
        reason: request.reason!,
        spec: request.spec!,
      });
      setReceipt(result);
      setCeremony(await api.caCeremony(ceremony.id));
      onActivated();
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="offline-rekey-heading" className="grid gap-4 border-b border-border py-5">
      <div className="flex items-start gap-3">
        <FileKey2 className="mt-1 h-4 w-4 shrink-0" aria-hidden="true" />
        <div>
          <h2 id="offline-rekey-heading" className="text-title font-semibold">
            {t("caHierarchy.offlineRekey.heading")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("caHierarchy.offlineRekey.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.offlineRekey.actionFailed")}>{error}</ErrorState>}
      <div className="ui-panel grid gap-3 p-comfortable">
        <LabeledSelect
          id="offline-rekey-predecessor"
          label={t("caHierarchy.offlineRekey.predecessor")}
          value={form.predecessorID}
          onChange={(v) => change({ predecessorID: v })}
        >
          <option value="">{t("caHierarchy.offlineRekey.selectPredecessor")}</option>
          {eligible.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.common_name} ({ca.id})
            </option>
          ))}
        </LabeledSelect>
        <div className="grid gap-3 md:grid-cols-2">
          <LabeledInput
            id="offline-rekey-name"
            label={t("caHierarchy.offlineRekey.name")}
            value={form.commonName}
            onChange={(v) => change({ commonName: v })}
          />
          <LabeledInput id="offline-rekey-dns" label={t("caHierarchy.offlineRekey.dns")} value={form.dnsDomains} onChange={(v) => change({ dnsDomains: v })} />
          <LabeledInput
            id="offline-rekey-eku"
            label={t("caHierarchy.offlineRekey.eku")}
            value={form.extendedKeyUsages}
            onChange={(v) => change({ extendedKeyUsages: v })}
          />
          <LabeledInput
            id="offline-rekey-path"
            label={t("caHierarchy.offlineRekey.pathLen")}
            value={form.maxPathLen}
            type="number"
            onChange={(v) => change({ maxPathLen: v })}
          />
          <LabeledInput
            id="offline-rekey-ttl"
            label={t("caHierarchy.offlineRekey.ttlDays")}
            value={form.ttlDays}
            type="number"
            onChange={(v) => change({ ttlDays: v })}
          />
        </div>
        <LabeledInput id="offline-rekey-reason" label={t("caHierarchy.offlineRekey.reason")} value={form.reason} onChange={(v) => change({ reason: v })} />
        {(
          [
            ["successorPEM", "successor"],
            ["newByPreviousPEM", "newByPrevious"],
            ["previousByNewPEM", "previousByNew"],
          ] as const
        ).map(([field, label]) => (
          <div className="grid gap-2" key={field}>
            <label htmlFor={`offline-rekey-${field}`} className="text-sm font-medium">
              {t(`caHierarchy.offlineRekey.${label}`)}
            </label>
            <textarea
              id={`offline-rekey-${field}`}
              rows={4}
              value={form[field]}
              onChange={(event) => change({ [field]: event.target.value })}
              className="rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
            />
          </div>
        ))}
        <p className="text-xs text-muted-foreground">{t("caHierarchy.offlineRekey.publicOnly")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={busy || !current} onClick={() => void review()}>
            {t("caHierarchy.offlineRekey.review")}
          </Button>
          <Button type="button" disabled={busy || !reviewed || !unchanged || Boolean(ceremonyID)} onClick={() => void start()}>
            {t("caHierarchy.offlineRekey.start")}
          </Button>
        </div>
        {reviewed && (
          <div className="grid gap-2 rounded-control border border-border bg-muted/30 p-3 text-xs" role="status">
            <p className="font-medium">{t("caHierarchy.offlineRekey.reviewedPackage")}</p>
            <p>
              {t("caHierarchy.offlineRekey.predecessor")}: {reviewed.preview.authority?.common_name ?? form.predecessorID} ({reviewed.request.authority_id})
            </p>
            <p>
              {t("caHierarchy.offlineRekey.reason")}: {reviewed.request.reason}
            </p>
            <pre className="overflow-x-auto whitespace-pre-wrap">{JSON.stringify(reviewed.preview.normalized_spec ?? reviewed.request.spec, null, 2)}</pre>
            {reviewed.certificateHashes.map((hash, index) => (
              <p key={index} className="break-all">
                {t("caHierarchy.offlineRekey.certHash")} {index + 1}: {hash}
              </p>
            ))}
            <p className="break-all">
              {t("caHierarchy.offlineRekey.fingerprint")}: {reviewed.preview.request_fingerprint}
            </p>
            <p>{t("caHierarchy.offlineRekey.approvals")}: 2</p>
            {reviewed.preview.risks?.map((risk) => (
              <p key={risk}>{risk}</p>
            ))}
          </div>
        )}
        {reviewed && !unchanged && (
          <p role="alert" className="text-sm text-destructive">
            {t("caHierarchy.offlineRekey.changed")}
          </p>
        )}
      </div>
      <div className="ui-panel grid gap-3 p-comfortable">
        <LabeledInput
          id="offline-rekey-ceremony"
          label={t("caHierarchy.offlineRekey.ceremonyID")}
          value={ceremonyID}
          onChange={(v) => {
            setCeremonyID(v.trim());
            setCeremony(null);
            setMatching(null);
            setReceipt(null);
          }}
        />
        <p className="text-sm text-muted-foreground">{t("caHierarchy.offlineRekey.approvalHelp")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={busy || !ceremonyID} onClick={() => void refresh()}>
            {t("caHierarchy.offlineRekey.refresh")}
          </Button>
          <Button
            type="button"
            disabled={busy || !unchanged || !matching || ceremony?.status !== "pending" || ceremony.approvals < ceremony.threshold}
            onClick={() => void activate()}
          >
            {t("caHierarchy.offlineRekey.activate")}
          </Button>
        </div>
        {ceremony && (
          <p role="status">
            {ceremony.status}; {ceremony.approvals}/{ceremony.threshold} {t("caHierarchy.offlineRekey.approvals")};{" "}
            {matching === null
              ? receipt
                ? t("caHierarchy.offlineRekey.receiptRecoveredUncompared")
                : t("caHierarchy.offlineRekey.notCompared")
              : matching
                ? t("caHierarchy.offlineRekey.bound")
                : t("caHierarchy.offlineRekey.unbound")}
          </p>
        )}
        {receipt && (
          <div className="grid gap-2">
            <p role="status">
              {t("caHierarchy.offlineRekey.completed")}: {receipt.rotation.predecessor.id} → {receipt.rotation.successor.id}
            </p>
            <label htmlFor="offline-rekey-receipt-new" className="text-sm font-medium">
              {t("caHierarchy.offlineRekey.recoveredNewByPrevious")}
            </label>
            <textarea
              id="offline-rekey-receipt-new"
              readOnly
              rows={4}
              value={receipt.new_signed_by_previous_pem}
              className="rounded-control border border-border bg-muted/40 p-2 font-mono text-xs"
            />
            <label htmlFor="offline-rekey-receipt-old" className="text-sm font-medium">
              {t("caHierarchy.offlineRekey.recoveredPreviousByNew")}
            </label>
            <textarea
              id="offline-rekey-receipt-old"
              readOnly
              rows={4}
              value={receipt.previous_signed_by_new_pem}
              className="rounded-control border border-border bg-muted/40 p-2 font-mono text-xs"
            />
          </div>
        )}
      </div>
    </section>
  );
}
