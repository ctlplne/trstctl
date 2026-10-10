import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { pcasApi, type PCASAcceptedRequest, type PCASChain, type PCASRequestStatus } from "@/lib/pcasApi";

const genesisAlgorithms = ["ECDSA-P256", "ECDSA-P384", "Ed25519"];
const successorAlgorithms = ["ECDSA-P384", "ECDSA-P521", "ML-DSA-65"];
const credentialTypes = ["workload-svid", "x509", "ssh", "api-token", "secret"];

async function publicKeySHA256(base64DER: string): Promise<string> {
  const bytes = Uint8Array.from(atob(base64DER), (char) => char.charCodeAt(0));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function PCASSuccessionWorkflow() {
  const { t } = useTranslation();
  const [identityID, setIdentityID] = useState("");
  const [scope, setScope] = useState("");
  const [genesisAlgorithm, setGenesisAlgorithm] = useState("ECDSA-P256");
  const [targetAlgorithm, setTargetAlgorithm] = useState("ECDSA-P384");
  const [credentialType, setCredentialType] = useState("workload-svid");
  const [policyRef, setPolicyRef] = useState("");
  const [reviewed, setReviewed] = useState<"genesis" | "succession" | null>(null);
  const [reviewTuple, setReviewTuple] = useState("");
  const [request, setRequest] = useState<PCASAcceptedRequest | null>(null);
  const [requestIdentityID, setRequestIdentityID] = useState("");
  const [requestStatus, setRequestStatus] = useState<PCASRequestStatus | null>(null);
  const [chain, setChain] = useState<PCASChain | null>(null);
  const [rootFingerprint, setRootFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const genesisTuple = JSON.stringify([identityID.trim(), scope.trim(), genesisAlgorithm]);
  const successionTuple = JSON.stringify([identityID.trim(), scope.trim(), credentialType, targetAlgorithm, policyRef.trim()]);

  async function loadChain() {
    if (!identityID.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await pcasApi.chain(identityID.trim());
      setChain(next);
      setRootFingerprint(next.trust_root_public_der ? await publicKeySHA256(next.trust_root_public_der) : "");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.error.read"));
    } finally {
      setBusy(false);
    }
  }

  async function refreshRequest() {
    if (!request) return;
    setBusy(true);
    setError(null);
    try {
      const next = await pcasApi.requestStatus(request.request_id);
      setRequestStatus(next);
      if (next.status === "delivered") {
        const served = await pcasApi.chain(requestIdentityID);
        setChain(served);
        setRootFingerprint(served.trust_root_public_der ? await publicKeySHA256(served.trust_root_public_der) : "");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.error.read"));
    } finally {
      setBusy(false);
    }
  }

  async function registerGenesis() {
    if (reviewed !== "genesis" || reviewTuple !== genesisTuple) {
      setReviewed(null);
      setError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const accepted = await pcasApi.registerGenesis({
        identity_id: identityID.trim(),
        algorithm: genesisAlgorithm,
        deployment_scope: scope.trim(),
      });
      setRequest(accepted);
      setRequestIdentityID(identityID.trim());
      setRequestStatus(null);
      setReviewed(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.error.register"));
    } finally {
      setBusy(false);
    }
  }

  async function requestSuccession() {
    if (reviewed !== "succession" || reviewTuple !== successionTuple) {
      setReviewed(null);
      setError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const accepted = await pcasApi.requestSuccession({
        identity_id: identityID.trim(),
        credential_type: credentialType,
        target_algorithm: targetAlgorithm,
        policy_ref: policyRef.trim(),
        deployment_scope: scope.trim(),
      });
      setRequest(accepted);
      setRequestIdentityID(identityID.trim());
      setRequestStatus(null);
      setReviewed(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.error.succession"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="pcas-heading" className="grid gap-4 rounded-panel border border-border bg-card p-comfortable">
      <div>
        <h2 id="pcas-heading" className="text-title font-semibold">
          {t("pcas.title")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("pcas.description")}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.identity")}</span>
          <input
            className="ui-input"
            value={identityID}
            onChange={(event) => {
              setIdentityID(event.target.value);
              setReviewed(null);
              setChain(null);
              setRequest(null);
              setRequestStatus(null);
            }}
            placeholder={t("pcas.identityExample")}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.scope")}</span>
          <input
            className="ui-input"
            value={scope}
            onChange={(event) => {
              setScope(event.target.value);
              setReviewed(null);
              setChain(null);
              setRequest(null);
              setRequestStatus(null);
            }}
            placeholder={t("pcas.scopeExample")}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.genesisAlgorithm")}</span>
          <select
            className="ui-input"
            value={genesisAlgorithm}
            onChange={(event) => {
              setGenesisAlgorithm(event.target.value);
              setReviewed(null);
            }}
          >
            {genesisAlgorithms.map((algorithm) => (
              <option key={algorithm} value={algorithm}>
                {algorithm}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={busy || !identityID.trim() || !scope.trim()}
          onClick={() => {
            setReviewed("genesis");
            setReviewTuple(genesisTuple);
          }}
        >
          {t("pcas.reviewGenesis")}
        </Button>
        <Button type="button" variant="outline" disabled={busy || !identityID.trim()} onClick={() => void loadChain()}>
          {t("pcas.readChain")}
        </Button>
      </div>
      {reviewed === "genesis" ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <strong>{t("pcas.genesisReview")}</strong>
          <p>{t("pcas.genesisEffect")}</p>
          <code className="break-all">{[identityID.trim(), scope.trim(), genesisAlgorithm].join(" · ")}</code>
          <Button type="button" disabled={busy} onClick={() => void registerGenesis()}>
            {t("pcas.registerGenesis")}
          </Button>
        </div>
      ) : null}
      {request ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <p>
            {t("pcas.requestAccepted")}: <code>{request.request_id}</code>
          </p>
          <p>
            {t("pcas.requestStatus")}: {requestStatus?.status ?? request.status}
            {requestStatus ? t("pcas.attemptCount", { count: requestStatus.attempts }) : ""}
          </p>
          <Button type="button" variant="outline" disabled={busy} onClick={() => void refreshRequest()}>
            {t("pcas.refresh")}
          </Button>
        </div>
      ) : null}
      {chain?.genesis ? (
        <div className="grid gap-3 rounded-panel border border-border bg-background p-3 text-sm">
          <h3 className="font-semibold">{t("pcas.anchorReady")}</h3>
          <p>
            {t("pcas.anchorAlgorithm")}: {chain.genesis.algorithm} · {t("pcas.epoch")}: {chain.genesis.epoch}
          </p>
          <p>
            {t("pcas.rootFingerprint")}: <code className="break-all">{rootFingerprint || t("pcas.fingerprintPending")}</code>
          </p>
          <p>
            {t("pcas.chainCount")}: {chain.count}
          </p>
          <p className="text-muted-foreground">{t("pcas.verifyOffline")}</p>
        </div>
      ) : null}
      {chain?.genesis ? (
        <div className="grid gap-3 border-t border-border pt-4">
          <h3 className="font-semibold">{t("pcas.successionTitle")}</h3>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm">
              <span>{t("pcas.credentialType")}</span>
              <select
                className="ui-input"
                value={credentialType}
                onChange={(event) => {
                  setCredentialType(event.target.value);
                  setReviewed(null);
                }}
              >
                {credentialTypes.map((kind) => (
                  <option key={kind} value={kind}>
                    {kind}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              <span>{t("pcas.targetAlgorithm")}</span>
              <select
                className="ui-input"
                value={targetAlgorithm}
                onChange={(event) => {
                  setTargetAlgorithm(event.target.value);
                  setReviewed(null);
                }}
              >
                {successorAlgorithms.map((algorithm) => (
                  <option key={algorithm} value={algorithm}>
                    {algorithm}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              <span>{t("pcas.policyRef")}</span>
              <input
                className="ui-input"
                value={policyRef}
                onChange={(event) => {
                  setPolicyRef(event.target.value);
                  setReviewed(null);
                }}
                placeholder={t("pcas.policyExample")}
              />
            </label>
          </div>
          <Button
            type="button"
            disabled={busy || !policyRef.trim() || targetAlgorithm === chain.genesis.algorithm}
            onClick={() => {
              setReviewed("succession");
              setReviewTuple(successionTuple);
            }}
          >
            {t("pcas.reviewSuccession")}
          </Button>
          {reviewed === "succession" ? (
            <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
              <strong>{t("pcas.successionReview")}</strong>
              <code className="break-all">
                {identityID.trim()} · {credentialType} · {chain.genesis.algorithm} → {targetAlgorithm} · {policyRef.trim()}
              </code>
              <Button type="button" disabled={busy} onClick={() => void requestSuccession()}>
                {t("pcas.startSuccession")}
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
