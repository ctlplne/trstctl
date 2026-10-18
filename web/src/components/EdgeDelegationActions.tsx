// SPDX-License-Identifier: BUSL-1.1

import { useState, type ChangeEvent } from "react";
import { translateNow } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { EdgeDelegationList, EdgeDelegationMintInput, EdgeReconcileInput, EdgeSegmentPolicyList } from "@/lib/api-types.gen";
import { newIdempotencyKey } from "@/lib/apiTransport";

type Props = {
  policies: EdgeSegmentPolicyList["items"];
  delegations: EdgeDelegationList["items"];
  onChanged: () => void;
  onClose: () => void;
};
type ReviewedMint = { input: EdgeDelegationMintInput; key: string };
type ReviewedReconcile = { id: string; input: EdgeReconcileInput; key: string };
type ReviewedRevoke = { id: string; serial: string; host: string; reason: string; key: string };
type Action = "mint" | "reconcile" | "revoke";

const uuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const certificatePEM = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----$/;
const mintFields = new Set(["segment_id", "ca_id", "host", "common_name", "ttl_seconds", "csr_der", "attestation_credential_json", "key_provider"]);

function objectFromJSON(text: string): Record<string, unknown> {
  if (text.length === 0 || text.length > 2_000_000) throw new Error(translateNow("edge.actions.jsonSize"));
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(translateNow("edge.actions.jsonObject"));
  return value as Record<string, unknown>;
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function parseMint(text: string, policies: Props["policies"]): EdgeDelegationMintInput {
  const raw = objectFromJSON(text);
  if (Object.keys(raw).some((key) => !mintFields.has(key))) throw new Error(translateNow("edge.actions.unknownField"));
  if (!nonempty(raw.segment_id) || !uuid.test(raw.segment_id) || !nonempty(raw.ca_id) || !uuid.test(raw.ca_id) || !nonempty(raw.host)) {
    throw new Error(translateNow("edge.actions.mintIdentifiers"));
  }
  if (
    !nonempty(raw.csr_der) ||
    !nonempty(raw.attestation_credential_json) ||
    raw.csr_der.length > 200_000 ||
    raw.attestation_credential_json.length > 1_400_000
  ) {
    throw new Error(translateNow("edge.actions.mintEvidence"));
  }
  const provider = raw.key_provider ?? "tpm2";
  if (provider !== "tpm2" && provider !== "pkcs11" && provider !== "software") throw new Error(translateNow("edge.actions.mintProvider"));
  const policy = policies.find((item) => item.segment_id === raw.segment_id);
  if (!policy?.enabled || !policy.allowed_key_providers.includes(provider)) throw new Error(translateNow("edge.actions.mintPolicy"));
  if (raw.ttl_seconds !== undefined && (!Number.isInteger(raw.ttl_seconds) || Number(raw.ttl_seconds) < 1 || Number(raw.ttl_seconds) > 30 * 24 * 3600)) {
    throw new Error(translateNow("edge.actions.mintTTL"));
  }
  if (raw.common_name !== undefined && !nonempty(raw.common_name)) throw new Error(translateNow("edge.actions.mintIdentifiers"));
  return {
    segment_id: raw.segment_id,
    ca_id: raw.ca_id,
    host: raw.host.trim(),
    csr_der: raw.csr_der,
    attestation_credential_json: raw.attestation_credential_json,
    key_provider: provider,
    ...(raw.common_name === undefined ? {} : { common_name: String(raw.common_name).trim() }),
    ...(raw.ttl_seconds === undefined ? {} : { ttl_seconds: Number(raw.ttl_seconds) }),
  };
}

function parseJournal(text: string, delegation: Props["delegations"][number]): EdgeReconcileInput {
  const raw = objectFromJSON(text);
  if (Object.keys(raw).some((key) => key !== "host" && key !== "certificates_pem")) throw new Error(translateNow("edge.actions.unknownField"));
  if (raw.host !== undefined && (typeof raw.host !== "string" || (raw.host.trim() !== "" && raw.host.trim() !== delegation.host))) {
    throw new Error(translateNow("edge.actions.journalHost"));
  }
  if (
    !Array.isArray(raw.certificates_pem) ||
    raw.certificates_pem.length < 1 ||
    raw.certificates_pem.length > 100 ||
    raw.certificates_pem.some((item) => typeof item !== "string" || !certificatePEM.test(item.trim()))
  ) {
    throw new Error(translateNow("edge.actions.journalCertificates"));
  }
  return { host: delegation.host, certificates_pem: raw.certificates_pem as string[] };
}

export function EdgeDelegationActions({ policies, delegations, onChanged, onClose }: Props) {
  const [action, setAction] = useState<Action>("mint");
  const [mintJSON, setMintJSON] = useState("");
  const [journalJSON, setJournalJSON] = useState("");
  const [selectedID, setSelectedID] = useState("");
  const [reason, setReason] = useState("");
  const [reviewedMint, setReviewedMint] = useState<ReviewedMint | null>(null);
  const [reviewedReconcile, setReviewedReconcile] = useState<ReviewedReconcile | null>(null);
  const [reviewedRevoke, setReviewedRevoke] = useState<ReviewedRevoke | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [mintedChain, setMintedChain] = useState<string | null>(null);

  function selectAction(next: Action) {
    setAction(next);
    setReviewedMint(null);
    setReviewedReconcile(null);
    setReviewedRevoke(null);
    setError(null);
    setResult(null);
    setMintedChain(null);
  }

  async function loadFile(event: ChangeEvent<HTMLInputElement>, target: "mint" | "journal") {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 2_000_000) {
      setError(translateNow("edge.actions.jsonSize"));
      return;
    }
    const text = await file.text();
    if (target === "mint") setMintJSON(text);
    else setJournalJSON(text);
    setError(null);
  }

  async function mint() {
    if (!reviewedMint || busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.mintEdgeDelegation(reviewedMint.input, reviewedMint.key);
      const readback = await api.edgeDelegation(created.id);
      if (
        readback.delegation.id !== created.id ||
        readback.delegation.status !== "active" ||
        readback.delegation.csr_key_sha256 !== created.csr_key_sha256 ||
        !created.certificate_pem ||
        !readback.delegation.certificate_pem ||
        readback.delegation.certificate_pem !== created.certificate_pem
      ) {
        throw new Error(translateNow("edge.actions.readbackMismatch"));
      }
      setResult(`${translateNow("edge.actions.minted")} ${created.id} · ${created.key_storage} · ${created.not_after}`);
      setMintedChain(readback.delegation.certificate_pem);
      setReviewedMint(null);
      onChanged();
    } catch (cause) {
      // The same reviewed input and idempotency key remain for a lost response.
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function reconcile() {
    if (!reviewedReconcile || busy) return;
    setBusy(true);
    setError(null);
    try {
      const before = await api.edgeDelegation(reviewedReconcile.id);
      if (before.delegation.id !== reviewedReconcile.id) throw new Error(translateNow("edge.actions.readbackMismatch"));
      const outcome = await api.reconcileEdgeDelegation(reviewedReconcile.id, reviewedReconcile.input, reviewedReconcile.key);
      const readback = await api.edgeDelegation(reviewedReconcile.id);
      if (readback.delegation.id !== reviewedReconcile.id || (readback.issuances?.length ?? 0) < (before.issuances?.length ?? 0) + outcome.reconciled)
        throw new Error(translateNow("edge.actions.readbackMismatch"));
      setResult(
        `${translateNow("edge.actions.reconciled")} ${outcome.reconciled} · ${translateNow("edge.actions.already")} ${outcome.already} · ${translateNow("edge.actions.violations")} ${outcome.violations} · ${translateNow("edge.actions.rejected")} ${outcome.rejected}`,
      );
      setReviewedReconcile(null);
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!reviewedRevoke || busy) return;
    setBusy(true);
    setError(null);
    try {
      const revoked = await api.revokeEdgeDelegation(reviewedRevoke.id, { reason: reviewedRevoke.reason }, reviewedRevoke.key);
      const readback = await api.edgeDelegation(reviewedRevoke.id);
      if (revoked.status !== "revoked" || readback.delegation.status !== "revoked" || readback.delegation.serial !== reviewedRevoke.serial) {
        throw new Error(translateNow("edge.actions.readbackMismatch"));
      }
      setResult(`${translateNow("edge.actions.revoked")} ${reviewedRevoke.id} · ${reviewedRevoke.serial}`);
      setReviewedRevoke(null);
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  const selected = delegations.find((item) => item.id === selectedID);
  return (
    <section className="mt-4 rounded-lg border border-border p-comfortable" aria-label={translateNow("edge.actions.title")}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="mr-auto text-title font-semibold">{translateNow("edge.actions.title")}</h3>
        <button type="button" className="rounded-md border px-3 py-2 text-caption" onClick={onClose} disabled={busy}>
          {translateNow("edge.actions.close")}
        </button>
      </div>
      <p className="mt-2 text-caption text-muted-foreground">{translateNow("edge.actions.guidance")}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {(["mint", "reconcile", "revoke"] as const).map((value) => (
          <button
            key={value}
            type="button"
            className={`rounded-md border px-3 py-2 text-caption ${action === value ? "border-primary font-semibold" : "border-border"}`}
            onClick={() => selectAction(value)}
            disabled={busy}
          >
            {translateNow(`edge.actions.${value}`)}
          </button>
        ))}
      </div>
      {error ? (
        <p role="alert" className="mt-3 text-caption text-status-danger">
          {error}
        </p>
      ) : null}
      {result ? (
        <p role="status" className="mt-3 text-caption">
          {result}
        </p>
      ) : null}
      {mintedChain ? (
        <div className="mt-3 grid gap-2 text-caption">
          <label htmlFor="edge-minted-chain">{translateNow("edge.actions.mintedChain")}</label>
          <textarea id="edge-minted-chain" rows={8} readOnly className="rounded-md border border-border p-2 font-mono text-xs" value={mintedChain} />
          <p className="text-muted-foreground">{translateNow("edge.actions.installChain")}</p>
        </div>
      ) : null}
      {action === "mint" ? (
        <div className="mt-3 grid gap-3 text-caption">
          {!reviewedMint ? (
            <>
              <label htmlFor="edge-mint-file">{translateNow("edge.actions.mintFile")}</label>
              <input id="edge-mint-file" type="file" accept=".json,application/json" onChange={(event) => void loadFile(event, "mint")} />
              <label htmlFor="edge-mint-json">{translateNow("edge.actions.mintJSON")}</label>
              <textarea
                id="edge-mint-json"
                rows={5}
                className="rounded-md border border-border p-2 font-mono text-xs"
                value={mintJSON}
                onChange={(event) => setMintJSON(event.target.value)}
              />
              <button
                type="button"
                className="w-fit rounded-md bg-primary px-3 py-2 text-primary-foreground"
                onClick={() => {
                  try {
                    setReviewedMint({ input: parseMint(mintJSON, policies), key: newIdempotencyKey() });
                    setError(null);
                  } catch (cause) {
                    setError(cause instanceof Error ? cause.message : String(cause));
                  }
                }}
              >
                {translateNow("edge.actions.reviewMint")}
              </button>
            </>
          ) : (
            <>
              <p>{translateNow("edge.actions.reviewMintSummary")}</p>
              <dl className="grid gap-1 font-mono text-xs">
                <div>
                  <dt>{translateNow("edge.actions.segment")}</dt>
                  <dd>{reviewedMint.input.segment_id}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.actions.parentCA")}</dt>
                  <dd>{reviewedMint.input.ca_id}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.actions.host")}</dt>
                  <dd>{reviewedMint.input.host}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.actions.provider")}</dt>
                  <dd>{reviewedMint.input.key_provider}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.actions.ttl")}</dt>
                  <dd>{reviewedMint.input.ttl_seconds ?? 7 * 24 * 3600}</dd>
                </div>
              </dl>
              <details>
                <summary>{translateNow("edge.actions.exactPayload")}</summary>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">{JSON.stringify(reviewedMint.input, null, 2)}</pre>
              </details>
              <div className="flex gap-2">
                <button type="button" className="rounded-md border px-3 py-2" disabled={busy} onClick={() => setReviewedMint(null)}>
                  {translateNow("edge.actions.edit")}
                </button>
                <button type="button" className="rounded-md bg-primary px-3 py-2 text-primary-foreground" disabled={busy} onClick={() => void mint()}>
                  {translateNow("edge.actions.confirmMint")}
                </button>
              </div>
            </>
          )}
        </div>
      ) : null}
      {action !== "mint" ? (
        <div className="mt-3 grid gap-3 text-caption">
          <label htmlFor="edge-delegation-select">{translateNow("edge.actions.selectDelegation")}</label>
          <select
            id="edge-delegation-select"
            className="rounded-md border border-border p-2"
            value={selectedID}
            onChange={(event) => {
              setSelectedID(event.target.value);
              setReviewedReconcile(null);
              setReviewedRevoke(null);
            }}
          >
            <option value="">{translateNow("edge.actions.chooseDelegation")}</option>
            {delegations
              .filter((item) => action === "reconcile" || item.status === "active")
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.host} · {item.id} · {item.status}
                </option>
              ))}
          </select>
          {action === "reconcile" && selected ? (
            !reviewedReconcile ? (
              <>
                <label htmlFor="edge-journal-file">{translateNow("edge.actions.journalFile")}</label>
                <input id="edge-journal-file" type="file" accept=".json,application/json" onChange={(event) => void loadFile(event, "journal")} />
                <label htmlFor="edge-journal-json">{translateNow("edge.actions.journalJSON")}</label>
                <textarea
                  id="edge-journal-json"
                  rows={5}
                  className="rounded-md border border-border p-2 font-mono text-xs"
                  value={journalJSON}
                  onChange={(event) => setJournalJSON(event.target.value)}
                />
                <button
                  type="button"
                  className="w-fit rounded-md bg-primary px-3 py-2 text-primary-foreground"
                  onClick={() => {
                    try {
                      setReviewedReconcile({ id: selected.id, input: parseJournal(journalJSON, selected), key: newIdempotencyKey() });
                      setError(null);
                    } catch (cause) {
                      setError(cause instanceof Error ? cause.message : String(cause));
                    }
                  }}
                >
                  {translateNow("edge.actions.reviewReconcile")}
                </button>
              </>
            ) : (
              <>
                <p>
                  {selected.id} · {selected.serial} · {reviewedReconcile.input.certificates_pem.length} {translateNow("edge.actions.certificates")}
                </p>
                <details>
                  <summary>{translateNow("edge.actions.exactPayload")}</summary>
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">
                    {JSON.stringify(reviewedReconcile.input, null, 2)}
                  </pre>
                </details>
                <div className="flex gap-2">
                  <button type="button" className="rounded-md border px-3 py-2" disabled={busy} onClick={() => setReviewedReconcile(null)}>
                    {translateNow("edge.actions.edit")}
                  </button>
                  <button type="button" className="rounded-md bg-primary px-3 py-2 text-primary-foreground" disabled={busy} onClick={() => void reconcile()}>
                    {translateNow("edge.actions.confirmReconcile")}
                  </button>
                </div>
              </>
            )
          ) : null}
          {action === "revoke" && selected ? (
            !reviewedRevoke ? (
              <>
                <label htmlFor="edge-revoke-reason">{translateNow("edge.actions.reason")}</label>
                <textarea
                  id="edge-revoke-reason"
                  rows={2}
                  className="rounded-md border border-border p-2"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
                <button
                  type="button"
                  className="w-fit rounded-md bg-primary px-3 py-2 text-primary-foreground"
                  onClick={() => {
                    if (reason.trim().length < 10 || reason.length > 512) {
                      setError(translateNow("edge.actions.reasonRequired"));
                      return;
                    }
                    setReviewedRevoke({ id: selected.id, serial: selected.serial, host: selected.host, reason: reason.trim(), key: newIdempotencyKey() });
                    setError(null);
                  }}
                >
                  {translateNow("edge.actions.reviewRevoke")}
                </button>
              </>
            ) : (
              <>
                <p>{translateNow("edge.actions.reviewRevokeSummary")}</p>
                <dl className="font-mono text-xs">
                  <dt>{translateNow("edge.actions.host")}</dt>
                  <dd>{reviewedRevoke.host}</dd>
                  <dt>{translateNow("edge.actions.id")}</dt>
                  <dd>{reviewedRevoke.id}</dd>
                  <dt>{translateNow("edge.actions.serial")}</dt>
                  <dd>{reviewedRevoke.serial}</dd>
                  <dt>{translateNow("edge.actions.reason")}</dt>
                  <dd>{reviewedRevoke.reason}</dd>
                </dl>
                <div className="flex gap-2">
                  <button type="button" className="rounded-md border px-3 py-2" disabled={busy} onClick={() => setReviewedRevoke(null)}>
                    {translateNow("edge.actions.edit")}
                  </button>
                  <button type="button" className="rounded-md bg-primary px-3 py-2 text-primary-foreground" disabled={busy} onClick={() => void revoke()}>
                    {translateNow("edge.actions.confirmRevoke")}
                  </button>
                </div>
              </>
            )
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
