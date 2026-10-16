import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { pcasApi, type PCASDelegationAccepted, type PCASDelegationScope, type PCASRequestStatus } from "@/lib/pcasApi";

export function PCASDelegationPanel() {
  const { t } = useTranslation();
  const [scopeID, setScopeID] = useState("");
  const [parentID, setParentID] = useState("");
  const [floor, setFloor] = useState("1");
  const [review, setReview] = useState<"scope" | "floor" | null>(null);
  const [reviewTuple, setReviewTuple] = useState("");
  const [accepted, setAccepted] = useState<PCASDelegationAccepted | null>(null);
  const [status, setStatus] = useState<PCASRequestStatus | null>(null);
  const [scopes, setScopes] = useState<PCASDelegationScope[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tuple = JSON.stringify([scopeID.trim(), parentID.trim(), floor]);
  const parsedFloor = Number(floor);
  const validFloor = Number.isSafeInteger(parsedFloor) && parsedFloor >= 0;

  async function loadScopes() {
    setBusy(true);
    setError(null);
    try {
      const result = await pcasApi.delegationScopes();
      setScopes(result.scopes);
      setLoaded(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.delegation.error"));
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    if (!accepted) return;
    setBusy(true);
    setError(null);
    try {
      const next = await pcasApi.requestStatus(accepted.request_id);
      setStatus(next);
      if (next.status === "delivered") {
        const result = await pcasApi.delegationScopes();
        setScopes(result.scopes);
        setLoaded(true);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.delegation.error"));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (!review || reviewTuple !== tuple || !scopeID.trim() || !validFloor || (review === "scope" && scopeID.trim() === parentID.trim())) {
      setReview(null);
      setError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result =
        review === "scope"
          ? await pcasApi.configureDelegationScope({ scope_id: scopeID.trim(), parent_scope_id: parentID.trim(), epoch_floor: parsedFloor })
          : await pcasApi.raiseDelegationFloor({ scope_id: scopeID.trim(), epoch_floor: parsedFloor });
      setAccepted(result);
      setStatus(null);
      setReview(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.delegation.error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="pcas-delegation-heading" className="grid gap-3 border-t border-border pt-4">
      <div>
        <h3 id="pcas-delegation-heading" className="font-semibold">
          {t("pcas.delegation.title")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("pcas.delegation.description")}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.delegation.scope")}</span>
          <input
            className="ui-input"
            value={scopeID}
            onChange={(event) => {
              setScopeID(event.target.value);
              setReview(null);
            }}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.delegation.parent")}</span>
          <input
            className="ui-input"
            value={parentID}
            onChange={(event) => {
              setParentID(event.target.value);
              setReview(null);
            }}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.delegation.floor")}</span>
          <input
            className="ui-input"
            type="number"
            min="0"
            step="1"
            value={floor}
            onChange={(event) => {
              setFloor(event.target.value);
              setReview(null);
            }}
          />
        </label>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={busy || !scopeID.trim() || !validFloor || scopeID.trim() === parentID.trim()}
          onClick={() => {
            setReview("scope");
            setReviewTuple(tuple);
          }}
        >
          {t("pcas.delegation.reviewScope")}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={busy || !scopeID.trim() || !validFloor}
          onClick={() => {
            setReview("floor");
            setReviewTuple(tuple);
          }}
        >
          {t("pcas.delegation.reviewFloor")}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={() => void loadScopes()}>
          {t("pcas.delegation.readScopes")}
        </Button>
      </div>
      {review ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <strong>{review === "scope" ? t("pcas.delegation.reviewScope") : t("pcas.delegation.reviewFloor")}</strong>
          <p>{t("pcas.delegation.effect")}</p>
          <code className="break-all">
            {scopeID.trim()} · {review === "scope" ? parentID.trim() || t("pcas.delegation.root") : t("pcas.delegation.existingParent")} · {parsedFloor}
          </code>
          <Button type="button" disabled={busy} onClick={() => void apply()}>
            {t("pcas.delegation.queue")}
          </Button>
        </div>
      ) : null}
      {accepted ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <p>
            {t("pcas.requestAccepted")}: <code>{accepted.request_id}</code>
          </p>
          <p>
            {t("pcas.requestStatus")}: {status?.status ?? accepted.status}
          </p>
          <Button type="button" variant="outline" disabled={busy} onClick={() => void refresh()}>
            {t("pcas.delegation.refresh")}
          </Button>
        </div>
      ) : null}
      {scopes.length > 0 ? (
        <div className="grid gap-2 text-sm">
          <h4 className="font-semibold">{t("pcas.delegation.readScopes")}</h4>
          {scopes.map((item) => (
            <div key={item.scope_id} className="rounded-panel border border-border bg-background p-3">
              <code>{item.scope_id}</code> · {item.parent_scope_id || t("pcas.delegation.root")} · {t("pcas.delegation.floor")}: {item.epoch_floor}
              <p>{item.signer_confirmed ? t("pcas.delegation.confirmed") : t("pcas.delegation.unconfirmed")}</p>
              {item.signer_receipt ? (
                <p className="break-all">
                  {t("pcas.delegation.receipt")}: <code>{item.signer_receipt.operation_id}</code>
                </p>
              ) : null}
              {item.signer_receipt ? (
                <p className="break-all">
                  {t("pcas.delegation.publicKey")}: <code>{item.signer_receipt.public_key_der}</code>
                </p>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      {loaded && scopes.length === 0 ? <p className="text-sm text-muted-foreground">{t("pcas.delegation.empty")}</p> : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
