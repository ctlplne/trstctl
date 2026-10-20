import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type CAAuthority,
  type CAReprotectionPlan,
  type CAReprotectionPreview,
  type CAReprotectionSelection,
  type CAReprotectionStartReceipt,
  type Certificate,
  type DeploymentTarget,
} from "@/lib/api";

const planFields = [
  "job_id",
  "identity_id",
  "certificate_id",
  "successor_authority_id",
  "predecessor_fingerprint",
  "predecessor_spki_sha256",
  "target_id",
  "target_revision_id",
  "required_agent_id",
  "connector",
  "verify_address",
  "verify_server_name",
  "ttl_seconds",
] as const;

function samePlan(a: CAReprotectionPlan, b: CAReprotectionPlan, allowLegacyPolicy = false): boolean {
  return planFields.every((field) => a[field] === b[field]) && (a.profile_name === b.profile_name || (allowLegacyPolicy && !b.profile_name));
}

function errorText(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    try {
      const problem = JSON.parse(error.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return error.body || fallback;
    }
  }
  return error instanceof Error ? error.message : fallback;
}

export function CAReprotectionPanel({ keyId, certificateIDs, onRefresh }: { keyId: string; certificateIDs: string[]; onRefresh: () => Promise<unknown> }) {
  const [certificateID, setCertificateID] = useState(certificateIDs[0] ?? "");
  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const [authorities, setAuthorities] = useState<CAAuthority[]>([]);
  const [targets, setTargets] = useState<DeploymentTarget[]>([]);
  const [successorID, setSuccessorID] = useState("");
  const [targetID, setTargetID] = useState("");
  const [ttlText, setTTLText] = useState("86400");
  const [preview, setPreview] = useState<CAReprotectionPreview | null>(null);
  const [previewSelection, setPreviewSelection] = useState<CAReprotectionSelection | null>(null);
  const [recorded, setRecorded] = useState<CAReprotectionPlan | null>(null);
  const [recoveryJobID, setRecoveryJobID] = useState("");
  const [started, setStarted] = useState<CAReprotectionStartReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const successors = useMemo(() => authorities.filter((ca) => ca.status === "active" && ca.replaces_id === keyId), [authorities, keyId]);
  const enabledTargets = useMemo(() => targets.filter((target) => target.enabled), [targets]);
  const target = enabledTargets.find((item) => item.id === targetID);
  const ttl = Number(ttlText);
  const canPreview =
    certificate?.id === certificateID &&
    certificate.key_origin === "host_agent" &&
    certificate.key_storage === "file" &&
    !!successorID &&
    !!target?.revision_id &&
    Number.isSafeInteger(ttl) &&
    ttl >= 60 &&
    ttl <= 90 * 24 * 3600;

  useEffect(() => {
    let active = true;
    setLoadError(null);
    Promise.all([api.caAuthorities(), api.connectorTargets()])
      .then(([caList, targetList]) => {
        if (!active) return;
        setAuthorities(caList.items ?? []);
        setTargets(targetList.items ?? []);
      })
      .catch((cause) => {
        if (active) setLoadError(errorText(cause, translateNow("caHierarchy.reprotect.loadFailed")));
      });
    return () => {
      active = false;
    };
  }, [keyId]);

  useEffect(() => {
    let active = true;
    setCertificate(null);
    if (certificateID) {
      api
        .getCertificate(certificateID)
        .then((result) => {
          if (active) setCertificate(result);
        })
        .catch((cause) => {
          if (active) setLoadError(errorText(cause, translateNow("caHierarchy.reprotect.loadFailed")));
        });
    }
    return () => {
      active = false;
    };
  }, [certificateID]);

  function clearReview() {
    setPreview(null);
    setPreviewSelection(null);
    setRecorded(null);
    setStarted(null);
    setError(null);
  }

  async function review() {
    if (!canPreview || !certificate || !target) return;
    const selection: CAReprotectionSelection = {
      certificate_id: certificate.id,
      successor_authority_id: successorID,
      target_id: target.id,
      expected_target_revision: target.revision_id,
      expected_fingerprint: certificate.fingerprint,
      ttl_seconds: ttl,
    };
    setBusy(true);
    clearReview();
    try {
      const result = await api.previewCAKeyReprotectionPlan(keyId, selection);
      if (
        !result.ready ||
        !result.effect_free ||
        result.recorded ||
        result.certificate_id !== selection.certificate_id ||
        result.successor_authority_id !== selection.successor_authority_id ||
        result.target_id !== selection.target_id ||
        result.target_revision_id !== selection.expected_target_revision ||
        result.predecessor_fingerprint !== selection.expected_fingerprint ||
        result.ttl_seconds !== selection.ttl_seconds
      ) {
        throw new Error(translateNow("caHierarchy.reprotect.changed"));
      }
      setPreviewSelection(selection);
      setPreview(result);
      setRecoveryJobID(result.job_id);
    } catch (cause) {
      setError(errorText(cause, translateNow("caHierarchy.reprotect.previewFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function registerPlan() {
    if (!preview || !previewSelection) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.registerCAKeyReprotectionPlan(keyId, previewSelection);
      if (!samePlan(preview, result, !result.recorded)) throw new Error(translateNow("caHierarchy.reprotect.changed"));
      const readback = await api.caKeyReprotectionPlan(keyId, preview.job_id);
      if (!readback.recorded || !samePlan(preview, readback, !result.recorded)) throw new Error(translateNow("caHierarchy.reprotect.changed"));
      setRecorded(readback);
      setPreview(null);
      setPreviewSelection(null);
    } catch (cause) {
      setError(errorText(cause, translateNow("caHierarchy.reprotect.recordFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function recoverPlan() {
    const id = recoveryJobID.trim();
    if (!id) return;
    setBusy(true);
    setError(null);
    setRecorded(null);
    setStarted(null);
    try {
      const readback = await api.caKeyReprotectionPlan(keyId, id);
      if (!readback.recorded || readback.job_id !== id) throw new Error(translateNow("caHierarchy.reprotect.changed"));
      setPreview(null);
      setPreviewSelection(null);
      setRecorded(readback);
    } catch (cause) {
      setError(errorText(cause, translateNow("caHierarchy.reprotect.recoverFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function start() {
    if (!recorded) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.startCAKeyReprotection(keyId);
      if (result.key_id !== keyId || !result.jobs.some((job) => job.id === recorded.job_id && job.dependent_ref === recorded.certificate_id)) {
        throw new Error(translateNow("caHierarchy.reprotect.startMismatch"));
      }
      setStarted(result);
      await onRefresh();
    } catch (cause) {
      setError(errorText(cause, translateNow("caHierarchy.reprotect.startFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label={translateNow("caHierarchy.reprotect.heading")} className="grid gap-3 rounded-md border p-3">
      <h4 className="font-semibold">{translateNow("caHierarchy.reprotect.heading")}</h4>
      <p className="text-sm text-muted-foreground">{translateNow("caHierarchy.reprotect.explanation")}</p>
      {loadError && (
        <p className="text-sm text-destructive" role="alert">
          {loadError}
        </p>
      )}
      <Field label={translateNow("caHierarchy.reprotect.certificate")}>
        {(field) => (
          <Select
            {...field}
            value={certificateID}
            onChange={(event) => {
              setCertificateID(event.target.value);
              clearReview();
            }}
          >
            {certificateIDs.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {certificate && (
        <p className="break-all text-xs">
          {certificate.subject} · {translateNow("caHierarchy.reprotect.fingerprint")} {certificate.fingerprint} · {certificate.key_origin}/
          {certificate.key_storage}
        </p>
      )}
      {certificate && (certificate.key_origin !== "host_agent" || certificate.key_storage !== "file") && (
        <p className="text-sm">{translateNow("caHierarchy.reprotect.custodyRequired")}</p>
      )}
      <Field label={translateNow("caHierarchy.reprotect.successor")}>
        {(field) => (
          <Select
            {...field}
            value={successorID}
            onChange={(event) => {
              setSuccessorID(event.target.value);
              clearReview();
            }}
          >
            <option value="">{translateNow("caHierarchy.reprotect.chooseSuccessor")}</option>
            {successors.map((ca) => (
              <option key={ca.id} value={ca.id}>
                {ca.common_name} ({ca.id})
              </option>
            ))}
          </Select>
        )}
      </Field>
      {successors.length === 0 && <p className="text-sm">{translateNow("caHierarchy.reprotect.noSuccessor")}</p>}
      <Field label={translateNow("caHierarchy.reprotect.target")}>
        {(field) => (
          <Select
            {...field}
            value={targetID}
            onChange={(event) => {
              setTargetID(event.target.value);
              clearReview();
            }}
          >
            <option value="">{translateNow("caHierarchy.reprotect.chooseTarget")}</option>
            {enabledTargets.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.connector}, {item.id})
              </option>
            ))}
          </Select>
        )}
      </Field>
      {target && (
        <p className="break-all text-xs">
          {translateNow("caHierarchy.reprotect.targetRevision")}: {target.revision_id}
        </p>
      )}
      <Field label={translateNow("caHierarchy.reprotect.ttl")}>
        {(field) => (
          <Input
            {...field}
            type="number"
            min={60}
            max={90 * 24 * 3600}
            value={ttlText}
            onChange={(event) => {
              setTTLText(event.target.value);
              clearReview();
            }}
          />
        )}
      </Field>
      <Button type="button" variant="outline" disabled={busy || !!loadError || !canPreview} onClick={() => void review()}>
        {translateNow("caHierarchy.reprotect.review")}
      </Button>
      {preview && (
        <>
          <PlanEvidence plan={preview} />
          <p className="text-sm">{translateNow("caHierarchy.reprotect.effectFree")}</p>
          <Button type="button" disabled={busy} onClick={() => void registerPlan()}>
            {translateNow("caHierarchy.reprotect.record")}
          </Button>
        </>
      )}
      <div className="grid gap-2 rounded-md border p-3">
        <Field label={translateNow("caHierarchy.reprotect.recoverID")}>
          {(field) => <Input {...field} value={recoveryJobID} onChange={(event) => setRecoveryJobID(event.target.value)} />}
        </Field>
        <Button type="button" variant="outline" disabled={busy || !recoveryJobID.trim()} onClick={() => void recoverPlan()}>
          {translateNow("caHierarchy.reprotect.loadRecorded")}
        </Button>
      </div>
      {recorded && (
        <>
          <p className="text-sm font-medium">{translateNow("caHierarchy.reprotect.recorded")}</p>
          <PlanEvidence plan={recorded} />
          <p className="text-sm">{translateNow("caHierarchy.reprotect.startGuidance")}</p>
          <Button type="button" disabled={busy} onClick={() => void start()}>
            {translateNow("caHierarchy.reprotect.start")}
          </Button>
        </>
      )}
      {started && (
        <p className="text-sm" role="status">
          {translateNow("caHierarchy.reprotect.queued", { value1: String(started.enqueued), value2: String(started.planned) })}
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

function PlanEvidence({ plan }: { plan: CAReprotectionPlan }) {
  return (
    <dl className="grid gap-1 break-all text-xs sm:grid-cols-2">
      <dt>{translateNow("caHierarchy.reprotect.jobID")}</dt>
      <dd className="font-mono">{plan.job_id}</dd>
      <dt>{translateNow("caHierarchy.reprotect.identityID")}</dt>
      <dd className="font-mono">{plan.identity_id}</dd>
      <dt>{translateNow("caHierarchy.reprotect.profile")}</dt>
      <dd>{plan.profile_name || translateNow("caHierarchy.reprotect.noProfile")}</dd>
      <dt>{translateNow("caHierarchy.reprotect.certificate")}</dt>
      <dd className="font-mono">{plan.certificate_id}</dd>
      <dt>{translateNow("caHierarchy.reprotect.successor")}</dt>
      <dd className="font-mono">{plan.successor_authority_id}</dd>
      <dt>{translateNow("caHierarchy.reprotect.fingerprint")}</dt>
      <dd className="font-mono">{plan.predecessor_fingerprint}</dd>
      <dt>{translateNow("caHierarchy.reprotect.spki")}</dt>
      <dd className="font-mono">{plan.predecessor_spki_sha256}</dd>
      <dt>{translateNow("caHierarchy.reprotect.target")}</dt>
      <dd className="font-mono">
        {plan.target_id} · {plan.target_revision_id}
      </dd>
      <dt>{translateNow("caHierarchy.reprotect.agent")}</dt>
      <dd className="font-mono">{plan.required_agent_id}</dd>
      <dt>{translateNow("caHierarchy.reprotect.connector")}</dt>
      <dd>{plan.connector}</dd>
      <dt>{translateNow("caHierarchy.reprotect.probe")}</dt>
      <dd>
        {plan.verify_address} · {plan.verify_server_name}
      </dd>
      <dt>{translateNow("caHierarchy.reprotect.ttl")}</dt>
      <dd>{plan.ttl_seconds}</dd>
    </dl>
  );
}
